# WO3.0.0-005 — Backup Encryption + Offsite (S3/GCS)

**Series:** WO3.0.0 (improvement loop)
**Status:** OPEN
**Owner:** subagent (worktree `wo/3.0.0/backup-encryption`)
**Gate:** `uv run ruff check picosentry/ tests/ scripts/` + `uv run mypy picosentry/` + `uv run pytest tests/serve/ -m "not slow"`

## Objective
Close the backup gap: encrypt backups and add offsite (S3/GCS) upload + restore verification.

## Root cause being addressed
Backup/DR 6/10: backups are plain `tar.gz` (no encryption), local-only (no offsite), and not verified.

## Scope
- `picosentry/serve/services/backup.py` — add encryption (AES-GCM with a key from env/secret) to the archive before writing; add a `.enc` suffix / envelope
- Add an S3/GCS upload path (optional dependency, degrade gracefully offline)
- Restore: decrypt + verify checksum/integrity before extracting (tar-safe extraction already exists)
- Backup verification (dry-run: create, restore, verify)
- Config knobs: `PICOSHOGUN_BACKUP_ENCRYPT_KEY`, `PICOSHOGUN_BACKUP_S3_*`

## Done-condition
- Backups are encrypted at rest
- Offsite upload works when configured (degrades gracefully offline)
- Restore verifies integrity before extraction
- All gates green

## Notes
- Do NOT rewrite tests to pass.
- Do NOT commit any encryption key or secret.
- Preserve honest-doc annotations.
