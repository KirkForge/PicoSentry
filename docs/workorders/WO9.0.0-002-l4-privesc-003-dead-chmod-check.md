# WO9.0.0-002 — Sandbox: L4-PRIVESC-003 setuid chmod detection is dead — checks command string in file path

**Series:** WO9.0.0 (audit round 2026-08-23)
**Status:** DONE (2026-10-21, worktree `wo/9.0.0/p0-cluster`) — the rule matched command prefixes ("chmod 4", "chmod 47") against `op.path`, a FILE PATH, so it could never fire on real data. The setuid/setgid bits live in the chmod MODE argument, which the profiler matched with `\S+` and discarded. `FileOperation` now carries a `mode` field (from the stdout chmod regex and from a file_chmod event's detail: "chmod 4755 /path", "mode=4755", or a bare mode), and the rule tests the setuid (04000) / setgid (02000) bits of the octal mode. Only numeric modes count — a symbolic "+x" says nothing about setuid, and guessing would produce false CRITICALs; a chmod with no reported mode is NOT flagged, because the mode is the only evidence. The old test used the fake path shape "chmod 4755 /usr/bin/custom" that no backend produces — it validated the bug. Evidence: tests/sandbox/test_l4_behavioral.py (82 passed; new TestSetuidChmodDetection, TestChmodModeIsProfiled, TestChmodModeFromEvents).
**Owner:** (unassigned)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/sandbox/l4/rules/privilege_escalation.py`, `tests/sandbox/`

**Gate:** `bash scripts/test.sh fast` + test: a `FileOperation(path="/usr/bin/sudo", operation="chmod")` with the chmod mode in a separate field (e.g. `detail` or a new `mode` attribute) produces an L4-PRIVESC-003 finding.

## Objective
L4-PRIVESC-003 (setuid/setgid chmod detection) checks `if pattern in op.path` where `pattern` is from `SETUID_PATTERNS = ("chmod 4", "chmod 2", "chmod 6", "chmod 47", "chmod 27", "chmod 67")`. But `op.path` is a FILE PATH (e.g. `/usr/bin/sudo`), not a command string. The setuid mode (e.g. `4755`) would be in the event's `detail` field, not the path. So `"chmod 4" in "/usr/bin/sudo"` is always False, and L4-PRIVESC-003 NEVER fires. A malicious package that runs `chmod 4755 /usr/bin/sudo` in its postinstall script goes undetected by this rule.

The rule only fires if `op.path` literally contains the string "chmod 4755 ..." (a command string), which no backend ever produces — `FileOperation.path` is always the file path.

## Evidence (verified 2026-08-23, read-only explorer; live repro)
- `privilege_escalation.py:34`: `SETUID_PATTERNS = ("chmod 4", "chmod 2", "chmod 6", "chmod 47", "chmod 27", "chmod 67")` — these are command-string prefixes, not file-path substrings.
- `privilege_escalation.py:70-83`: L4-PRIVESC-003 loops over `profile.fs_ops`, checks `if op.operation == "chmod"`, then `for pattern in SETUID_PATTERNS: if pattern in op.path:` — checks if the command string is a substring of the FILE PATH.
- `profiler.py:86-91`: `_extract_fs_from_events` sets `path = ev.path.strip()` — `ev.path` is the file path, not the command.
- `models.py (l4):51-53`: `FileOperation.path: str` — documented as the file path; `operation: str` is the operation type.
- Live repro (python3 in /tmp/opencode): `FileOperation(path="/usr/bin/sudo", operation="chmod")` → 0 findings. `FileOperation(path="chmod 4755 /usr/bin/sudo", operation="chmod")` → 1 finding (but no backend produces this path shape).

## Deliverables
1. The setuid mode (e.g. "4755") needs to come from a field other than `path`. Options: (a) extend `FileOperation` with a `mode` or `detail` field and have the profiler populate it from `ev.detail`; (b) check `op.path` against known setuid-target paths (`/usr/bin/sudo`, `/usr/bin/su`, etc.) when `op.operation == "chmod"` — a chmod to any of these paths is inherently suspicious; (c) parse the mode from the stdout regex fallback (`_extract_file_operations`) where the full command may appear.
2. Regression test: a chmod event to `/usr/bin/sudo` produces an L4-PRIVESC-003 finding (via whichever mechanism is chosen).