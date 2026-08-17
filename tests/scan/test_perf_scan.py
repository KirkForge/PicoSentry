"""WO4.0.0-014 — scan throughput + daemon responsiveness.

Covers:
1. Halo-banded trie search in CorpusIndex is exact vs brute-force
   Levenshtein/keyboard distance over an exhaustive small corpus.
2. Shared stat-keyed byte-read cache: reuse on identity hit, re-read on
   mtime/size change, oversized files not cached, missing files -> None.
3. iter_source_files: one sorted walk, suffix filter, max_files cap,
   symlink and skip-dir handling.
4. Per-process corpus-version cache: stable across engine rebuilds,
   recomputed when a corpus file changes.
5. Scan daemon stays responsive while a /scan is in flight and builds its
   engine exactly once (cache reuse across /scan and /ready).
"""

from __future__ import annotations

import itertools
import json
import os
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path

from picosentry.scan.daemon.handler import HealthHandler
from picosentry.scan.engine import ScanEngine, _CORPUS_VERSION_CACHE
from picosentry.scan.rules.corpus_index import CorpusIndex
from picosentry.scan.rules.typosquat_utils import edit_distance, keyboard_distance
from picosentry.scan.rules.utils import iter_source_files, read_scannable_bytes


class TestBandedTrieExactness(unittest.TestCase):
    """_search_banded must return exactly what a brute-force scan returns."""

    def test_exhaustive_small_corpus(self) -> None:
        alpha = "abc"
        names = []
        for n in range(1, 4):
            names.extend("".join(p) for p in itertools.product(alpha, repeat=n))
        names += ["abab", "bcbc", "cab", "abac", "abcabc", "aaaa"]
        index = CorpusIndex(sorted(set(names)), priority_names=set(names))

        queries = ["".join(p) for p in itertools.product(alpha, repeat=3)]
        queries += ["abab", "abcabc", "cab", "cbbc"]

        for q in queries:
            for maxd in (1.0, 2.0):
                for kb in (False, True):
                    with self.subTest(query=q, maxd=maxd, keyboard=kb):
                        got = sorted(
                            {
                                (n, round(d, 2))
                                for n, d in index.near_matches(q, max_distance=maxd, use_keyboard=kb)
                                if n != q
                            }
                        )
                        want = set()
                        for c in index.names:
                            if c == q:
                                continue
                            d = keyboard_distance(q, c) if kb else edit_distance(q, c)
                            if d <= maxd:
                                want.add((c, round(float(d), 2)))
                        if len(q) < 4:
                            # near_matches' documented short-query guards: short
                            # candidates must be within distance 1, 4+ char
                            # candidates must share the query's first character.
                            want = {
                                m
                                for m in want
                                if not (len(m[0]) < 4 and m[1] > 1.0)
                                and not (len(m[0]) >= 4 and not m[0].startswith(q[0]))
                            }
                        self.assertEqual(got, sorted(want))


class TestReadScannableBytes(unittest.TestCase):
    def test_identity_hit_and_mtime_invalidation(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "f.js"
            p.write_text("hello world")
            first = read_scannable_bytes(p)
            self.assertEqual(first, b"hello world")
            # Same identity -> cached object returned.
            self.assertIs(read_scannable_bytes(p), first)
            # Rewrite (new mtime/size) -> fresh read.
            p.write_text("changed content!")
            self.assertEqual(read_scannable_bytes(p), b"changed content!")

    def test_oversized_not_cached_but_read(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "big.js"
            blob = b"x" * (512_001)
            p.write_bytes(blob)
            a = read_scannable_bytes(p)
            self.assertEqual(len(a or b""), 512_001)
            # Not cached: a second read is a distinct object.
            self.assertIsNot(read_scannable_bytes(p), a)

    def test_missing_file_returns_none(self) -> None:
        self.assertIsNone(read_scannable_bytes(Path("/nonexistent/does-not-exist.js")))


class TestIterSourceFiles(unittest.TestCase):
    def setUp(self) -> None:
        import tempfile

        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.pkg = Path(self.td.name) / "pkg"
        (self.pkg / "sub").mkdir(parents=True)
        (self.pkg / "b.js").write_text("// b")
        (self.pkg / "a.js").write_text("// a")
        (self.pkg / "sub" / "c.js").write_text("// c")
        (self.pkg / "skipme.txt").write_text("no")
        (self.pkg / "build" / "d.js").parent.mkdir()
        (self.pkg / "build" / "d.js").write_text("// d")

    def test_sorted_walk_with_filters(self) -> None:
        files = list(iter_source_files(self.pkg, {".js"}, max_files=200, skip_dirs=frozenset({"build"})))
        self.assertEqual([f.name for f in files], ["a.js", "b.js", "c.js"])

    def test_max_files_cap(self) -> None:
        files = list(iter_source_files(self.pkg, {".js"}, max_files=1, skip_dirs=frozenset({"build"})))
        self.assertEqual([f.name for f in files], ["a.js"])


class TestCorpusVersionCache(unittest.TestCase):
    def test_stable_and_invalidated(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            cdir = Path(td)
            (cdir / "npm_top_packages.json").write_text(json.dumps(["a", "b"]))
            e1 = ScanEngine(corpus_dir=cdir)
            v1 = e1._corpus_version
            self.assertNotEqual(v1, "0.1.0-empty")
            # Cached: fingerprint recorded, second engine matches without rehash.
            e2 = ScanEngine(corpus_dir=cdir)
            self.assertEqual(e2._corpus_version, v1)
            self.assertIn(str(cdir), _CORPUS_VERSION_CACHE)
            # Content change -> new fingerprint -> recomputed version.
            (cdir / "npm_top_packages.json").write_text(json.dumps(["a", "b", "c"]))
            os.utime(cdir / "npm_top_packages.json")  # ensure mtime moves on coarse fs
            e3 = ScanEngine(corpus_dir=cdir)
            self.assertNotEqual(e3._corpus_version, v1)


class _SilentHandler(HealthHandler):
    def log_message(self, format, *args):  # stdlib signature
        pass


class TestDaemonResponsiveness(unittest.TestCase):
    """ThreadingHTTPServer must keep /health live while /scan is running."""

    def test_daemon_binds_threading_server(self) -> None:
        from picosentry.scan import daemon as scan_daemon

        # The daemon exports HTTPServer (tests patch that name) but it must be
        # the threading implementation — the single-threaded server serialized
        # /health behind /scan and k8s killed the pod (WO4.0.0-014).
        self.assertIs(scan_daemon.HTTPServer, ThreadingHTTPServer)

    def _make_tree(self, root: Path, packages: int = 120, files: int = 10) -> None:
        code = "function calc(x) { return x * 2; }\n"
        for i in range(packages):
            d = root / "node_modules" / f"pkg-{i}"
            d.mkdir(parents=True)
            (d / "package.json").write_text(json.dumps({"name": f"pkg-{i}", "version": "1.0.0"}))
            for j in range(files):
                (d / f"m{j}.js").write_text(code)
        (root / "package.json").write_text(
            json.dumps({"name": "t", "dependencies": {f"pkg-{i}": "^1" for i in range(packages)}})
        )

    def _post_scan(self, port: int, root: Path) -> int:
        import urllib.request

        body = json.dumps({"target": "node_modules/pkg-0"}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/scan",
            data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer test-token"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status

    def test_health_responds_during_scan(self) -> None:
        import tempfile
        import urllib.request

        # Reset per-class state so engine caching does not leak across tests.
        HealthHandler._engine_cache = None
        HealthHandler.auth_config = type(HealthHandler.auth_config)(
            mode="token", token="test-token", default_scopes=["read", "scan"]
        )
        HealthHandler.rate_limiter = type(HealthHandler.rate_limiter)(rps=0)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._make_tree(root)
            server = ThreadingHTTPServer(("127.0.0.1", 0), _SilentHandler)
            port = server.server_address[1]
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            old_root = os.environ.get("PICOSENTRY_SCAN_ROOT")
            os.environ["PICOSENTRY_SCAN_ROOT"] = str(root)
            try:
                scan_done = threading.Event()
                scan_statuses: list[int] = []

                def run_scan() -> None:
                    try:
                        scan_statuses.append(self._post_scan(port, root))
                    except Exception as exc:  # pragma: no cover - surfaced via assert below
                        scan_statuses.append(getattr(exc, "code", 599))
                    finally:
                        scan_done.set()

                scan_thread = threading.Thread(target=run_scan, daemon=True)
                scan_thread.start()

                # While the scan is in flight /health must answer promptly —
                # a single-threaded server would serialize it behind the scan.
                deadline = time.monotonic() + 10.0
                health_while_scanning = False
                while time.monotonic() < deadline:
                    t0 = time.monotonic()
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=10) as resp:
                        self.assertEqual(resp.status, 200)
                    rtt = time.monotonic() - t0
                    if not scan_done.is_set() and rtt < 1.0:
                        health_while_scanning = True
                        break
                    if scan_done.is_set():
                        break
                    time.sleep(0.02)

                self.assertTrue(scan_done.wait(timeout=60), "scan request never completed")
                self.assertEqual(scan_statuses, [200])
                self.assertTrue(
                    health_while_scanning,
                    "/health never answered <1s while /scan was in flight (server serialized requests)",
                )
            finally:
                if old_root is None:
                    os.environ.pop("PICOSENTRY_SCAN_ROOT", None)
                else:
                    os.environ["PICOSENTRY_SCAN_ROOT"] = old_root
                server.shutdown()
                server.server_close()

    def test_scan_reuses_cached_engine(self) -> None:
        import tempfile
        import urllib.request
        from unittest.mock import patch

        import picosentry.scan.engine as engine_mod

        HealthHandler._engine_cache = None
        HealthHandler.auth_config = type(HealthHandler.auth_config)(
            mode="token", token="test-token", default_scopes=["read", "scan"]
        )
        HealthHandler.rate_limiter = type(HealthHandler.rate_limiter)(rps=0)

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self._make_tree(root, packages=2, files=2)
            server = ThreadingHTTPServer(("127.0.0.1", 0), _SilentHandler)
            port = server.server_address[1]
            threading.Thread(target=server.serve_forever, daemon=True).start()
            old_root = os.environ.get("PICOSENTRY_SCAN_ROOT")
            os.environ["PICOSENTRY_SCAN_ROOT"] = str(root)
            try:
                calls = {"n": 0}
                real_builder = engine_mod.create_default_engine

                def counting_builder(*args, **kwargs):
                    calls["n"] += 1
                    return real_builder(*args, **kwargs)

                with patch.object(engine_mod, "create_default_engine", counting_builder):
                    self.assertEqual(self._post_scan(port, root), 200)
                    self.assertEqual(self._post_scan(port, root), 200)
                    with urllib.request.urlopen(f"http://127.0.0.1:{port}/ready", timeout=60) as resp:
                        self.assertEqual(resp.status, 200)
                self.assertEqual(calls["n"], 1, "engine must be built once and reused across /scan + /ready")
            finally:
                if old_root is None:
                    os.environ.pop("PICOSENTRY_SCAN_ROOT", None)
                else:
                    os.environ["PICOSENTRY_SCAN_ROOT"] = old_root
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    unittest.main()
