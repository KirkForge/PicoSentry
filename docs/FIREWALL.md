# PicoSentry Registry Firewall

A metadata firewall: a local HTTP proxy in front of npm / PyPI that scans
package **metadata** before your machine ever fetches an artifact. Start it
with `picosentry firewall` (see `picosentry firewall --help`).

```
npm --registry http://127.0.0.1:3132 install left-pad
pip install --index-url http://127.0.0.1:3132/pypi/simple requests
```

## What gets scanned

| Path shape | Example | Treatment |
|---|---|---|
| npm manifest | `/left-pad`, `/left-pad/1.3.0` | scanned, verdict applied |
| PyPI JSON | `/pypi/requests/json`, `/pypi/requests/2.31.0/json` | scanned, verdict applied |
| Everything else (tarballs, static assets) | `/left-pad/-/left-pad-1.3.0.tgz` | **passed through unscanned** (see below) |

### Tarball decision (explicit, not accidental)

This is a **metadata** firewall. Tarballs are streamed through **without
inspection** and tagged `X-PicoSentry-Verdict: passthrough`. Rationale:

- Metadata (name, scripts, dependencies, maintainers) is small, fetchable in
  one request, and catches the dominant registry attacks (typosquats,
  dependency confusion, malicious install hooks) before any code lands on
  disk.
- Scanning tarballs synchronously in the proxy path would mean downloading,
  extracting and scanning every artifact every client pulls — that is
  `picosentry scan`'s job, run where you extract/install artifacts.
- If you need artifact scanning, run `picosentry scan` on the installed tree
  or CI workspace; the firewall is the metadata gate, not the artifact gate.

### Version-scoped verdicts

Verdicts are computed from the **requested version's manifest slice**, not the
whole-catalog document npm returns for `/pkg`:

- `GET /pkg` → the `dist-tags.latest` version's manifest from `versions`
- `GET /pkg/1.2.3` → the `1.2.3` manifest
- PyPI → the `info` object (already the requested version's metadata)

A malicious 0.9.0 therefore does not poison the verdict for a clean 1.0.0, and
a clean latest is not judged blind from root-level catalog fields. Verdicts
are cached per `(ecosystem, name, version)` for `cache_ttl_seconds`.

### Rules applied

The firewall scans with the default engine **minus artifact rules** — rules
that require local artifacts registry metadata can never contain and that
would therefore fire on every package:

- `L2-LOCK-001` (lockfile drift — a manifest has no lockfile by definition)
- `L2-PNPM-001` (pnpm workspace config — likewise absent from metadata)

## Verdicts and headers

Every scanned response carries `X-PicoSentry-Verdict`; pass-through responses
carry `X-PicoSentry-Proxy: true` too.

| Verdict | Meaning | Default response |
|---|---|---|
| `allow` | no findings at/above quarantine threshold | body served |
| `quarantine` | HIGH/MEDIUM findings (e.g. install scripts present) | body served + `X-PicoSentry-Reasons: <rule ids>` |
| `block` | CRITICAL findings (verified typosquat, dep confusion, worm patterns) | `403` + JSON reasons body |

Default severity mapping is **BLOCK on CRITICAL only**. HIGH/MEDIUM findings
quarantine-tag instead of failing the install: a metadata firewall that
403s every package shipping an install script (esbuild & co.) breaks more
builds than it protects. CI can enforce stricter postures from the headers:
set `block_severities=["CRITICAL","HIGH"]` and/or
`quarantine_action="block"` to make quarantine a hard 403.

## Configuration (`FirewallConfig`)

| Option | Default | Notes |
|---|---|---|
| `listen_host` | `127.0.0.1` | Loopback by default — the proxy is unauthenticated unless `auth_token` is set. Set `"0.0.0.0"` explicitly to expose. |
| `listen_port` | `3132` | |
| `auth_token` | `None` | If set, clients must send `Authorization: Bearer <token>`; compared constant-time. |
| `upstream_npm` / `upstream_pypi` | npmjs.org / pypi.org | Must be `https://` (enforced). |
| `block_severities` | `["CRITICAL"]` | See verdicts above. |
| `quarantine_severities` | `["HIGH", "MEDIUM"]` | |
| `quarantine_action` | `"tag"` | `"tag"` serves the body with warning headers; `"block"` returns 403. |
| `pass_through_max_bytes` | 512 MiB | Pass-through streams in 64 KiB chunks; bodies exceeding this are truncated and the connection closed — memory stays bounded regardless of artifact size. |
| `cache_ttl_seconds` / `cache_max_entries` | 3600 / 10000 | Verdict cache. |
| `scan_timeout_seconds` | 30 | Upstream fetch + rule timebox. |

The server is a `ThreadingHTTPServer` (`daemon_threads=True`) — one slow
client cannot head-of-line-block the proxy.

## Known limitations (honest-doc)

- **Short generic names can still hard-BLOCK via `L2-TYPO-001`.** e.g. `pkg`
  is edit-distance 1 from `pg` → CRITICAL → 403. This is scan-rule
  calibration (known-legitimate allowlist in `picosentry/scan/rules/typosquat.py`),
  not firewall logic; track under the scan detection-quality workorders.
- **PyPI metadata coverage is thin.** Of the metadata rules only the
  typosquat family reads PyPI shapes today, so PyPI verdicts are
  allow/quarantine-by-typo; there is no PyPI-side install-script signal in
  registry metadata to scan.
- **Upstream must be HTTPS.** `http://` upstreams are refused even for local
  mirrors; terminate TLS or extend `allow_http` support if you need one.
- **No lockfile/pnpm enforcement, by design** — those rules cannot see
  registry metadata. Run `picosentry scan` on the project tree for that.
