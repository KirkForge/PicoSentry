"""WO5.0.0-015 — rule-selection & worker honesty.

Covers:
1. Explicitly requested rules dropped by ecosystem detection are recorded as
   skipped RuleExecutions (visible in scan_completeness), not a silent clean
   scan; the CLI exits 2 (input error) when nothing ran.
2. ``rules=[]`` runs zero rules (is-not-None semantics, not truthiness).
3. The ``--timeout`` worker process receives the configured intelligence mode.
"""

from __future__ import annotations

import argparse
import multiprocessing
import threading
from pathlib import Path

from picosentry.scan._cli_service_worker import _scan_worker
from picosentry.scan.config import PicoSentryConfig
from picosentry.scan.engine import create_default_engine
from picosentry.scan.models import ScanResult


def _go_project(tmp_path: Path) -> Path:
    target = tmp_path / "goproj"
    target.mkdir()
    (target / "go.mod").write_text("module example.com/x\n\ngo 1.21\n")
    return target


def _scan_args(target: Path, *extra: str) -> argparse.Namespace:
    from picosentry.scan.cli_commands.scan import add_arguments

    parser = argparse.ArgumentParser()
    add_arguments(parser.add_subparsers())
    return parser.parse_args(["scan", str(target), "--no-cache", "--offline", *extra])


class TestExplicitRulesDropped:
    def test_deselected_rule_recorded_as_skipped(self, tmp_path):
        result = create_default_engine().scan(_go_project(tmp_path), rules=["L2-POST-001"])
        assert result.findings == []
        assert [(r.rule_id, r.status) for r in result.rule_executions] == [("L2-POST-001", "skipped")]
        ex = result.rule_executions[0]
        assert ex.error == "ecosystem npm not detected"
        assert result.to_dict()["scan_completeness"] == "partial"

    def test_unknown_rule_recorded_as_skipped(self, tmp_path):
        result = create_default_engine().scan(_go_project(tmp_path), rules=["L2-NOPE-001"])
        skipped = [r for r in result.rule_executions if r.status == "skipped"]
        assert [r.rule_id for r in skipped] == ["L2-NOPE-001"]
        assert "not registered" in skipped[0].error

    def test_applicable_explicit_rule_still_runs(self, tmp_path):
        # L2-ADV-001 is registered and cross-ecosystem: it must run on a go
        # project even though npm rules are deselected.
        result = create_default_engine().scan(_go_project(tmp_path), rules=["L2-ADV-001"])
        statuses = {r.rule_id: r.status for r in result.rule_executions}
        assert statuses.get("L2-ADV-001") == "ok"
        assert not any(r.status == "skipped" for r in result.rule_executions)

    def test_mixed_selection_reports_skipped_and_runs_rest(self, tmp_path):
        result = create_default_engine().scan(_go_project(tmp_path), rules=["L2-POST-001", "L2-ADV-001"])
        statuses = {r.rule_id: r.status for r in result.rule_executions}
        assert statuses["L2-POST-001"] == "skipped"
        assert statuses["L2-ADV-001"] == "ok"

    def test_rules_none_still_means_all_rules(self, tmp_path):
        result = create_default_engine().scan(_go_project(tmp_path), rules=None)
        assert len(result.rule_executions) >= 3  # cross-ecosystem rules still run
        assert not any(r.status == "skipped" for r in result.rule_executions)

    def test_cli_exits_2_when_no_requested_rule_ran(self, tmp_path, monkeypatch, capsys):
        from picosentry.scan.cli_service import ScanOrchestrator

        monkeypatch.setenv("PICOSENTRY_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setenv("PICOSENTRY_ADVISORY_DIR", str(tmp_path / "no-adv"))
        monkeypatch.setenv("PICOSENTRY_CORPUS_DIR", str(tmp_path / "no-user-corpus"))

        args = _scan_args(_go_project(tmp_path), "--rules", "L2-POST-001", "--format", "json")
        assert ScanOrchestrator(args).run() == 2
        assert "no rules ran" in capsys.readouterr().err

    def test_cli_partial_selection_keeps_normal_exit_code(self, tmp_path, monkeypatch, capsys):
        from picosentry.scan.cli_service import ScanOrchestrator

        monkeypatch.setenv("PICOSENTRY_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setenv("PICOSENTRY_ADVISORY_DIR", str(tmp_path / "no-adv"))
        monkeypatch.setenv("PICOSENTRY_CORPUS_DIR", str(tmp_path / "no-user-corpus"))

        args = _scan_args(_go_project(tmp_path), "--rules", "L2-POST-001", "L2-ADV-001")
        # Some requested rule ran: not an input error, normal clean exit.
        assert ScanOrchestrator(args).run() == 0


class TestExplicitEmptyRules:
    def test_empty_list_runs_zero_rules(self, tmp_path):
        result = create_default_engine().scan(_go_project(tmp_path), rules=[])
        assert result.findings == []
        assert result.rule_executions == []

    def test_cli_empty_selection_is_clean_not_full_scan(self, tmp_path, monkeypatch, capsys):
        from picosentry.scan.cli_service import ScanOrchestrator

        monkeypatch.setenv("PICOSENTRY_CACHE_DIR", str(tmp_path / "cache"))
        monkeypatch.setenv("PICOSENTRY_ADVISORY_DIR", str(tmp_path / "no-adv"))
        monkeypatch.setenv("PICOSENTRY_CORPUS_DIR", str(tmp_path / "no-user-corpus"))

        args = _scan_args(_go_project(tmp_path), "--format", "json")
        args.rules = []  # argparse can't produce this; daemon/API clients can
        assert ScanOrchestrator(args).run() == 0
        assert result_has_zero_executions(capsys.readouterr().out)


def result_has_zero_executions(json_out: str) -> bool:
    import json

    data = json.loads(json_out)
    return data.get("rule_status", {}) == {}


class TestWorkerIntelligenceMode:
    def test_worker_passes_intelligence_to_engine(self, tmp_path, monkeypatch):
        import picosentry.scan.engine as engine_mod

        seen: dict = {}

        class _FakeEngine:
            def scan(self, *a, **k):
                return ScanResult(target=str(a[0]) if a else "")

        def _record_create(**kwargs):
            seen.update(kwargs)
            return _FakeEngine()

        monkeypatch.setattr(engine_mod, "create_default_engine", _record_create)

        q: multiprocessing.Queue = multiprocessing.Queue()
        _scan_worker(str(_go_project(tmp_path)), None, None, None, q, intelligence_mode="connected")
        status, _result = q.get(timeout=5)
        q.close()
        q.join_thread()
        assert status == "ok"
        assert seen["intelligence_mode"] == "connected"

    def test_worker_defaults_to_offline(self, tmp_path, monkeypatch):
        import picosentry.scan.engine as engine_mod

        seen: dict = {}

        class _FakeEngine:
            def scan(self, *a, **k):
                return ScanResult(target=str(a[0]) if a else "")

        monkeypatch.setattr(engine_mod, "create_default_engine", lambda **kw: (seen.update(kw), _FakeEngine())[1])

        q: multiprocessing.Queue = multiprocessing.Queue()
        _scan_worker(str(_go_project(tmp_path)), None, None, None, q)
        status, _result = q.get(timeout=5)
        q.close()
        q.join_thread()
        assert status == "ok"
        assert seen["intelligence_mode"] == "offline"

    def test_run_scan_forwards_configured_intelligence_to_worker(self, tmp_path, monkeypatch):
        import picosentry.scan.cli_service as cli_service
        from picosentry.scan.cli_service import ScanOrchestrator

        captured: dict = {}

        def _recording_worker(
            target_path, rules, corpus_dir, advisory_db_path, result_queue, intelligence_mode="offline"
        ):
            captured["intelligence_mode"] = intelligence_mode
            result_queue.put(("ok", ScanResult(target=target_path)))

        class _FakeProcess:
            def __init__(self, target, args=None, kwargs=None):
                captured["args"] = args
                captured["kwargs"] = kwargs
                self._thread = threading.Thread(target=self._run, args=(target, args, kwargs))

            @staticmethod
            def _run(target, args, kwargs):
                try:
                    target(*(args or ()), **(kwargs or {}))
                except BaseException as exc:  # pragma: no cover - surfaced via queue
                    args[-1].put(("error", {"type": type(exc).__name__, "message": str(exc), "traceback": ""}))

            def start(self):
                self._thread.start()

            def join(self, timeout=None):
                self._thread.join(timeout)

            def is_alive(self):
                return self._thread.is_alive()

        monkeypatch.setattr("picosentry.scan._cli_service_worker._scan_worker", _recording_worker)
        monkeypatch.setattr(cli_service.multiprocessing, "Process", _FakeProcess)

        cfg = PicoSentryConfig()
        cfg.intelligence = "connected"
        result = ScanOrchestrator(argparse.Namespace(timeout=30))._run_scan(_go_project(tmp_path), merged_config=cfg)
        assert captured["kwargs"] == {"intelligence_mode": "connected"}
        assert result.findings == []


class TestValidateHelpFloors:
    def test_help_text_matches_code_floors(self):
        from picosentry.scan.cli_commands import scan as scan_cmd

        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        scan_cmd.add_arguments(subparsers)
        help_text = subparsers.choices["scan"].format_help()
        assert "precision >= 0.94" in help_text
        assert "recall >= 0.84" in help_text
        assert "0.84 and mean recall >= 0.70" not in help_text
