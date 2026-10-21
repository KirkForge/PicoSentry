# WO9.0.0-001 — Sandbox: Admission scanner reads wrong response field names (verdict/findings vs l3_verdict/l4_verdict/findings_count) — admission control is a complete no-op

**Series:** WO9.0.0 (audit round 2026-08-23)
**Status:** DONE (2026-10-21, worktree `wo/9.0.0/p0-cluster`) — the scanner read `verdict`/`findings`; the daemon emits `l3_verdict`/`l4_verdict`/`findings_count` + an `analysis` dict, so admission control never blocked a pod. Now reads the real shape, normalizes finding severity case (findings are UPPERCASE, SEVERITY_LEVELS is lowercase — a HIGH finding scored 0), and treats a response with no verdict and no findings as UNREADABLE (deny under the fail-closed default) so the next contract drift cannot silently re-enable the no-op. The old mock daemon spoke the made-up shape the scanner read — the mock was validating the bug; it now speaks the real shape. Evidence: tests/sandbox/test_admission_scanner.py (35 passed; new TestImageScannerRealDaemonShape + TestUnreadableScanResponse).
**Owner:** (unassigned)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/sandbox/admission/scanner.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: a mock scan API response with `l4_verdict="MALICIOUS"` and `findings_count=5` is correctly parsed by `ImageScanner._scan_image` and returns `(False, reason)`.

## Objective
The admission scanner (`ImageScanner._scan_image`) reads `result.get("verdict", "CLEAN")` and `result.get("findings", [])` from the PicoDome daemon's `/api/v1/scan` response. But the scan API returns `l3_verdict`, `l4_verdict`, and `findings_count` — NOT `verdict` or `findings`. So the admission scanner always sees `verdict="CLEAN"` (the default) and `findings=[]` (the default), and NEVER blocks any pod. Even if the sandbox returns `MALICIOUS` with 100 critical findings, the admission controller allows the pod. This is a complete bypass of the Kubernetes admission webhook — the entire admission control feature is a no-op.

## Evidence (verified 2026-08-23, read-only explorer; live repro + file:line chain)
- `scanner.py:127`: `verdict = result.get("verdict", "CLEAN")` — the scan API response has no `"verdict"` key.
- `scanner.py:128`: `findings = result.get("findings", [])` — the scan API response has no `"findings"` key (it has `"findings_count"`, an integer).
- `scanner.py:130`: `if verdict == "DENY":` — always False because `verdict` is always `"CLEAN"`.
- `scanner.py:133-135`: `blocking_findings = [f for f in findings if ...]` — always empty because `findings` is always `[]`.
- Compare `handler_routes_post.py:312-326`: the HTTP scan response dict has keys `l3_verdict`, `l4_verdict`, `findings_count` — NOT `verdict` or `findings`.
- Compare `_servicer.py:134-141`: the gRPC scan result dict has the same keys (`l3_verdict`, `l4_verdict`, `findings_count`).
- Live repro (python3 in /tmp/opencode): simulating the scan API response and reading it with the admission scanner's field names → `verdict="CLEAN"`, `findings=[]`, `verdict == "DENY": False`, `blocking_findings: []`. The admission scanner ALWAYS allows.

## Deliverables
1. In `_scan_image`, read `result.get("l3_verdict")` and/or `result.get("l4_verdict")` for the verdict, and read `result.get("findings_count", 0)` for the findings count (or parse `result.get("analysis", {}).get("findings", [])` for per-finding severity). The blocking logic should check if `l4_verdict` is `"MALICIOUS"` or `"SUSPICIOUS"`, or if `findings_count > 0` with severity >= `min_severity`.
2. Regression test: mock the scan API to return `{"l3_verdict": "DENY", "l4_verdict": "MALICIOUS", "findings_count": 5, "analysis": {"findings": [{"severity": "critical"}, ...]}}` and assert `ImageScanner._scan_image` returns `(False, reason)`.