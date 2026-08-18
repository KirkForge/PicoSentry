# WO6.0.0-003 — Watch: output FP + gateway message-shape holes

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/output-gateway-holes`)
**Priority:** P0 · Effort M · Risk L
**Scope:** `picosentry/watch/rules/output_policy/format_violation.yaml`, `picosentry/watch/gateway.py`, `picosentry/watch/output_guard/__init__.py`, `tests/watch/`

**Gate:** `bash scripts/test.sh fast` + benign-English FP pins ("the system is down for maintenance", "here is my public key") pass clean; string-message injection blocked or 400; legacy function_call args scanned.

## Objective
Close the remaining holes in WO5-013/023's "every delivered token attested" claim and kill a shipped-FP class that rejects ordinary English output.

## Evidence (verified 2026-08-18, explorer SA-AS; live repros /tmp/opencode/sa-as/t7*, t8*)
1. **`out_fmt_xml_injection` bare `SYSTEM\s+|PUBLIC\s+`** (MED FP): with IGNORECASE+DOTALL, "the system is down for maintenance" / "here is my public key" → `valid=False ['out_fmt_xml_injection']` — and `valid = score<threshold AND no violations`, so any WARN-tier FP rejects output outright (`output_guard/__init__.py:158`).
2. **Gateway skips non-dict messages** (MED): `gateway.py:271-273` — `messages: ["<full injection>"]` (plain string) → **200, forwarded unscanned**.
3. **Legacy `function_call` unscanned** (MED): only `content` + `tool_calls` attested; `message.function_call.arguments` → `output_valid=True` with a secret inside.
4. **Upstream 200 + non-JSON body** → returned unscanned with no metadata (`gateway.py:323`) — matters under `block_on_output_violation`.

## Deliverables
1. XML rule: require DTD context (`(?:SYSTEM|PUBLIC)\s+["']`) or case-sensitivity; benign-English pins added.
2. Gateway: reject non-dict/empty-content messages (400) or scan `str(m)`; add `function_call` to scanned fields + `output_fields_scanned`; non-JSON 200 handled honestly under block-mode.
3. Output guard: surface `decode_budget_exhausted` (currently discarded — `__init__.py:113` binds `_exhausted` unused; prompt side surfaces it).
