# ADR-005: Picoshogun → PicoSentry public rename; `picoshogun` retained as internal codename

**Status:** Accepted
**Date:** 2026-07

## Context

The project was developed under the internal codename **Picoshogun**. The
public product name is **PicoSentry** (PyPI package, Docker image
`kirkforge/picodome`, README, docs). The codename survives in:

- the `PICOSHOGUN_*` environment-variable prefix (secret key, backend, plugin
  config, TLS, signed-plugins, … — ~22 distinct vars);
- the SQLite database filename `picoshogun.db` and logger names
  (`picoshogun.PluginHost`, `picoshogun.config`, …);
- the on-disk audit DB and backup filenames.

A complete rename would touch 146 references across 57 Python files and break
every deployed configuration that sets `PICOSHOGUN_SECRET_KEY`,
`PICOSHOGUN_DATABASE_BACKEND`, etc.

## Decision

**Retain `picoshogun` as the internal codename and configuration prefix. The
public surface (package name, image, README, user-facing docs) is PicoSentry.**

The split is intentional and permanent, not a TODO. `grep -rni picoshogun` is
expected to return the internal references listed above; these are
intentional, not stale renames.

## Rationale

- **Config stability:** operators have `PICOSHOGUN_*` in systemd units, Helm
  values, CI env, and `.env` files. Renaming the prefix silently breaks every
  deployment and (worse) makes `assert_secure()` fall back to the empty secret
  → fail-closed boot failures with no migration path.
- **No user-facing confusion:** the codename only appears in logs, env vars,
  and on-disk filenames — surfaces an operator reads, not marketing.
- **A clean rename is a separate, scheduled migration** (alias env vars, a
  deprecation window, DB filename migration), not a drive-by edit. It is not
  justified by this workorder's scope.

## Consequences

- Public docs and the package name say PicoSentry; internals say picoshogun.
  New code and docs should use `PicoSentry` for prose and reserve `picoshogun`
  for the env-var prefix and existing logger/filenames.
- A future rename must ship `PICOSENTRY_*` aliases that accept the new names
  while still reading `PICOSHOGUN_*`, with a deprecation period, plus a DB
  filename migration helper. Do not attempt a find-and-replace rename.
- `PICOSHOGUN_SKIP_SECURE_ASSERT` and `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS` in
  particular are safety-critical env vars; renaming them without an alias
  would silently disable boot-time security gates.