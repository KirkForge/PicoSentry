# WO9.0.0-101 — Serve: Webhook SSRF bypass via empty `pinned_ips` from `_load_webhooks` (DNS-rebind guard disabled)

**Series:** WO9.0.0 (audit round 2026-08-23)
**Status:** DONE (2026-10-21, worktree `wo/9.0.0/p0-cluster`) — `_load_webhooks` set `pinned_ips = resolve(host) or []` with no empty-check, so a hostname that did not resolve was loaded with an EMPTY pin set; at dispatch `set().issubset(set())` is True, so the guard passed vacuously and the POST went out with no IP restriction. `_load_webhooks` now skips a webhook whose hostname does not resolve (mirroring create()'s guard), and the dispatch guard rejects an empty pin set or an empty current set so an empty set can never satisfy the subset check. `pinned_ips` is now always a non-empty list in the dispatch path, so the `if wh.pinned_ips else None` copy was dead. Evidence: tests/serve/services/test_webhooks.py (19 passed; new TestEmptyPinnedIPsRejected — empty pin set, empty dispatch-time resolve, and an unresolvable hostname at load are all rejected without reaching requests.post).
**Owner:** (unassigned)
**Priority:** P0 · Effort S · Risk M
**Scope:** `picosentry/serve/services/webhooks.py`, `tests/serve/`

**Gate:** `bash scripts/test.sh fast` + test: a webhook loaded from the DB whose hostname no longer resolves to a non-empty IP set is NOT dispatched (guard rejects empty `pinned_ips`), and a webhook whose dispatch-time resolve returns empty is rejected.

## Objective
`WebhookManager._load_webhooks` (line 126) sets `pinned_ips = resolve(urlparse(url).hostname or "") or []` with NO empty-check, unlike `create()` (line 156: `if not pinned_ips: raise ValueError`). When `resolve` returns `[]` (empty list, not None) — e.g. a transient DNS blip between the `_is_safe_webhook_url` probe (line 121) and the `resolve` call (line 126), or a hostname that resolves to an empty record set — the webhook is loaded with `pinned_ips=[]` (an empty list, NOT None). At dispatch time, the DNS-rebind guard (line 250) is `if webhook.pinned_ips is not None and not current_ips.issubset(allowed_ips)`. With `pinned_ips=[]` (not None) and `current_ips=set()` (DNS dead at dispatch), `set().issubset(set())` is `True`, so the guard does NOT block, and `requests.post(webhook.url, ...)` proceeds with NO IP restriction. An attacker controlling the webhook hostname (or racing a DNS rebinding) can redirect the POST to an internal IP (127.0.0.1, 169.254.169.254) that was never SSRF-checked at dispatch time.

## Evidence (verified 2026-08-23, explorer; live repro + airtight file:line chain)
- `webhooks.py:126`: `pinned_ips = resolve(urlparse(url).hostname or "") or []` — NO empty-check (unlike create()).
- `webhooks.py:155-157`: `create()` guards `if not pinned_ips: raise ValueError` — the guard exists but is missing from the load path.
- `webhooks.py:248-250`: dispatch guard `current_ips = set(_resolve_hostname(parsed.hostname) or [])`; `allowed_ips = set(webhook.pinned_ips or [])`; `if webhook.pinned_ips is not None and not current_ips.issubset(allowed_ips)`.
- `webhooks.py:250`: `webhook.pinned_ips is not None` is `True` when `pinned_ips=[]` (empty list is not None), so the guard runs but `set().issubset(set())` is `True` → no block.
- Live repro (`/tmp/opencode/test_webhook_e2e.py`):
  ```
  Webhook(pinned_ips=[]) -> dispatch with current_ips=set()
  guard_blocks = (pinned_ips is not None) and (not set().issubset(set())) = False
  => dispatch proceeds to requests.post with NO IP check: YES (BYPASS)
  ```
- Confirmed `_load_webhooks` has the `or []` guard but NO `if not pinned_ips` check (`/tmp/opencode/test_webhook_load2.py`):
  ```
  Line 126 has 'or []' guard: True
  Line 126 has empty check: False
  ```

## Deliverables
1. Add `if not pinned_ips: logger.warning(...); continue` in `_load_webhooks` (line 126-127) — skip loading a webhook whose hostname resolves to empty at load time, mirroring `create()`'s guard.
2. Harden the dispatch guard: reject when `not webhook.pinned_ips` (empty) OR `not current_ips` (empty at dispatch) — an empty pin set must never satisfy `issubset`. Change line 250 to `if not webhook.pinned_ips or not current_ips or not current_ips.issubset(allowed_ips):`.
3. Regression test per the gate.