# PicoDome — L4 Behavioral Rule Reference

Per-rule documentation for the L4 behavioral engine (`picosentry/sandbox/l4/rules/`).
L3 rules have their own per-rule files in this directory; this document is the
L4 counterpart. Severity changes from the WO4.0.0-018 FP-tuning round are
marked **(recalibrated)**.

Evidence policy (WO4.0.0-018): kernel events carrying addresses/paths are
authoritative per behavior category; otherwise stdout-derived regex evidence
fills the gap (SCMP_ACT_LOG records carry no addresses/paths, v2.0.8
limitation). Trade-off: printed text can add uncorroborated findings; kernel
data always wins when present.

## L4-TIME — timing anomalies (`timing.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-TIME-001 | Run completed <5 ms with exit 0 — possible no-op | LOW **(recalibrated from MEDIUM: trivial fast commands are legitimate)** |
| L4-TIME-002 | Single operation >60 s — busy-wait/sleep | MEDIUM |
| L4-TIME-003 | Runtime drift outside baseline range | HIGH |

## L4-EXFIL — data exfiltration (`exfil.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-EXFIL-001..004 | Large outbound transfer / beaconing / DNS exfil patterns | HIGH–CRITICAL |
| L4-EXFIL-005 | Credential file read followed by egress (e.g. `.env` then network) | CRITICAL |

## L4-ENTROPY — entropy anomalies (`entropy.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-ENTROPY-001 | High-entropy filenames (packed/obfuscated payloads) | MEDIUM |
| L4-ENTROPY-002 | DGA-like domain names | HIGH |

## L4-HONEY — honeypot paths & privilege brokers (`honeypot.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-HONEY-001 | Honeypot path touched (/etc/shadow, /root/.ssh, …) | CRITICAL |
| L4-HONEY-002 | Privilege BROKER spawned (sudo, su, pkexec, doas) | CRITICAL |
| L4-HONEY-003 | Ownership tool spawned (chmod/chown/chgrp) | LOW **(recalibrated from CRITICAL in HONEY-002: every benign postinstall chmods its bin shims; setuid chmods remain covered by L4-PRIVESC-003)** |

## L4-BASE — baseline drift (`baseline_drift.py`, `differ.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-BASE-001 | Drift vs best-matching baseline | INFO–CRITICAL by category |
| L4-BASE-002/003 | No baseline / unknown-package drift | INFO/MEDIUM |

Domain comparison matches the URL's HOST against the baseline's domain list
(`_host_of`) — raw-URL-vs-domain never matched and drifted every benign npm
fetch **(recalibrated, WO4.0.0-018)**.

## L4-ENV — environment secrets (`env_leak.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-ENV-001 | `.env` / dotenv file read | HIGH |
| L4-ENV-002 | Secret-shaped variable access | HIGH |
| L4-ENV-003 | Env-dump command spawned (env, printenv) | CRITICAL |

## L4-PROC — process anomalies (`process_anomaly.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-PROC-001 | Shell spawned mid-execution | HIGH |
| L4-PROC-002 | Reverse-shell / C2 tool spawned | CRITICAL |
| L4-PROC-003 | >10 processes spawned | MEDIUM **(recalibrated from >5: npm/pip routinely spawn 6+ helpers)** |
| L4-PROC-004 | Spawn count exceeds baseline by >3 | MEDIUM |

## L4-FS — filesystem anomalies (`filesystem.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-FS-001 | Write to protected system path | CRITICAL |
| L4-FS-002 | Executable/script written — absolute paths outside /tmp only | MEDIUM **(recalibrated: workspace-relative writes (npm shims, install scripts) are exempt)** |
| L4-FS-003 | Deletion of critical system file | CRITICAL |
| L4-FS-004 | Path traversal (`../`) | HIGH |
| L4-FS-006 | >100 write operations | MEDIUM |

## L4-NET — network anomalies (`network.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-NET-001 | Connection to suspicious port | MEDIUM–HIGH |
| L4-NET-002 | Raw-IP connection (no DNS) | MEDIUM |
| L4-NET-003 | Suspicious TLD (.xyz, .top, …) | MEDIUM |
| L4-NET-004 | Long hostname (DNS tunneling) | MEDIUM |
| L4-NET-005 | Excessive distinct connections | MEDIUM |

## L4-SC — supply-chain patterns (`supply_chain.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-SC-001..004 | Obfuscated payloads, remote code fetch, curl|pipe, reverse shells | HIGH–CRITICAL |
| L4-SC-005 | Paste-site / known payload-host DNS | HIGH |

## L4-PRIVESC — privilege escalation (`privilege_escalation.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-PRIVESC-001 | sudoers/shadow write | CRITICAL |
| L4-PRIVESC-002 | sudo spawned | HIGH |
| L4-PRIVESC-003 | setuid-style chmod (4755…) | CRITICAL |
| L4-PRIVESC-004 | Capability manipulation (setcap) | CRITICAL |
| L4-PRIVESC-005 | Cron abuse | HIGH |

## L4-PERSIST — persistence (`persistence.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-PERSIST-001 | Persistence path written (systemd, rc.local, ssh authorized_keys, launch agents, …). Matching is prefix-based for absolute paths; suffix semantics ONLY for user-home dotfile entries (`/.ssh/…`) and `~`-relative macOS paths **(recalibrated: blanket endswith matched any path tail)** | MEDIUM–CRITICAL |
| L4-PERSIST-002 | crontab/at spawned | HIGH |
| L4-PERSIST-003 | systemctl enable/start/mask | HIGH |
| L4-PERSIST-004 | User/profile editors (usermod, passwd…) | MEDIUM |
| L4-PERSIST-005 | launchctl load/enable | HIGH |

## L4-CRYPTO — cryptomining (`crypto_mining.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-CRYPTO-001/003 | Mining-pool ports/DNS (3333, stratum, monero…) | HIGH–CRITICAL |
| L4-CRYPTO-002 | Known miner binary (xmrig…) | CRITICAL |
| L4-CRYPTO-004 | CPU/memory abuse signature | MEDIUM |
| L4-CRYPTO-005/006 | Mining config access / stratum arguments | HIGH |

## L4-CONTAINER — container escape (`container_escape.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-CONTAINER-001 | /proc/1, docker.sock, host FS probes | CRITICAL |
| L4-CONTAINER-002 | Container runtime spawned (docker…) | CRITICAL |
| L4-CONTAINER-003 | Cloud metadata endpoint (169.254.169.254) | HIGH |
| L4-CONTAINER-004 | /proc/self/mountinfo read | MEDIUM |
| L4-CONTAINER-005 | Namespace escape (nsenter -t 1) | CRITICAL |
| L4-CONTAINER-006 | Metadata DNS (metadata.google.internal) | HIGH |

## L4-DEP — dependency confusion (`dependency_confusion.py`)

| Rule | Detects | Severity |
|------|---------|----------|
| L4-DEP-001 | DNS to internal/suspicious registry (.internal/.local/company) | HIGH |
| L4-DEP-002 | Publish command during install (npm publish, twine upload) | CRITICAL |
| L4-DEP-003 | Suspicious install URL (git+http, http://, file:///, /tmp/) | HIGH |
| L4-DEP-004 | Registry override attempt (`--registry=`, `--index-url=`, …) | MEDIUM; HIGH only when the value points internal/off-TLS **(recalibrated: public mirror flags are routine CI practice)** |
| L4-DEP-005 | Registry connection on non-standard port | MEDIUM |
| L4-DEP-006 | Package registry config read/write (.npmrc, pip.conf) | LOW/HIGH |

## Verdicts

No findings → CLEAN. Any HIGH/CRITICAL → MALICIOUS. Any MEDIUM → SUSPICIOUS.
LOW/INFO findings alone do not change the verdict (they are visible telemetry).
