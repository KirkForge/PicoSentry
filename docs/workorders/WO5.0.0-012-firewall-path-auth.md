# WO5.0.0-012 — Firewall: path classification on the query-less path + auth crash

**Series:** WO5.0.0 (exploration round 2026-08-18)
**Status:** DONE (2026-08-18, merge `f2bd9115`, worker SA-Z) — `classify_path` runs on `urlsplit(path).path.rstrip("/")`: query-decorated metadata URLs scanned under clean names (query preserved upstream), trailing-slash variant fixed; `_authorized` compares UTF-8 bytes (mirrors watch) — non-ASCII Authorization → clean 401. 9 classify + 3 handler-level + 2 auth regression tests.
**Owner:** (unassigned — worktree `wo/5.0.0/firewall-path`)
**Priority:** P0 · Effort S-M · Risk L
**Scope:** `picosentry/firewall/{scanner.py,proxy.py}`, `tests/firewall/`

**Gate:** `bash scripts/test.sh fast` + new tests: `classify_path("/pypi/requests/2.31.0/json?refresh=1")` → scanned (not passthrough); npm name never carries a query string; non-ASCII Authorization header → clean 401, no traceback.

## Objective
The firewall's core promise (scan registry metadata) must survive URL decoration, and auth must not crash on hostile headers.

## Evidence (verified 2026-08-18, explorer SA-U; live repros)
1. **Query-string/trailing-slash bypass** (HIGH): `$`-anchored regexes run on `self.path` including the query (`scanner.py:18-19,61-74`; `proxy.py:117-119`). Live: `/pypi/requests/2.31.0/json?refresh=1` → `None` → `_proxy_pass()` → metadata served with `X-PicoSentry-Verdict: passthrough`, never scanned. npm side: `/lodash?meta=1` → `("npm","lodash?meta=1","latest")` — scanned under a polluted name (name-vs-intel rules evaluate garbage; verdict never joins the clean-name cache entry). Tests exercise only clean paths.
2. **Auth crashes on non-ASCII Authorization** (MEDIUM): `hmac.compare_digest("Bearer café", …)` → `TypeError` (`proxy.py:100-106`); header values arrive latin-1-decoded; exception escapes `do_GET` → connection dropped with traceback per request. The identical bug was fixed watch-side (UTF-8 bytes compare); firewall missed the sweep.

## Deliverables
1. `urllib.parse.urlsplit(path).path` before classify; strip query from the scanning/caching name.
2. UTF-8 bytes before `compare_digest`, mirroring `watch/server.py:126`; regression test.
