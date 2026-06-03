# PicoDome — Rule Documentation

This directory contains detailed documentation for each detection rule.

## L3 Sandbox Rules

### Suspicious Pattern Detectors (Subprocess Backend)

These rules detect suspicious patterns in sandboxed command output when using the subprocess backend.

| Rule | File | Detects |
|------|------|---------|
| L3-SUS-001 | [L3-SUS-001.md](L3-SUS-001.md) | Dynamic code execution (eval, exec, compile) |
| L3-SUS-002 | [L3-SUS-002.md](L3-SUS-002.md) | Shell execution (subprocess, os.system, os.popen) |
| L3-SUS-003 | [L3-SUS-003.md](L3-SUS-003.md) | Sensitive file access (/etc/passwd, /etc/shadow) |
| L3-SUS-004 | [L3-SUS-004.md](L3-SUS-004.md) | Network tool usage (curl, wget, nc, telnet) |
| L3-SUS-005 | [L3-SUS-005.md](L3-SUS-005.md) | Permission escalation (chmod +x, chmod 777) |
| L3-SUS-006 | [L3-SUS-006.md](L3-SUS-006.md) | Base64 decoding |
| L3-SUS-007 | [L3-SUS-007.md](L3-SUS-007.md) | Destructive commands (rm -rf /, dd if=/dev) |
| L3-SUS-008 | [L3-SUS-008.md](L3-SUS-008.md) | Process introspection (/proc/self, ptrace) |
| L3-SUS-009 | [L3-SUS-009.md](L3-SUS-009.md) | SSH key access (.ssh/, id_rsa, id_ed25519) |
| L3-SUS-010 | [L3-SUS-010.md](L3-SUS-010.md) | Dotfile access (/root/, /home/*/.) |

### Kernel-Level Enforcement

| Rule | File | Detects |
|------|------|---------|
| L3-SECCOMP-KILL | [L3-SECCOMP-KILL.md](L3-SECCOMP-KILL.md) | Seccomp-bpf syscall violation (process killed by kernel) |
| L3-TIMEOUT-001 | [L3-TIMEOUT-001.md](L3-TIMEOUT-001.md) | Sandbox timeout exceeded |

## L4 Behavioral Detector Rules

| Rule | Detects | Severity |
|------|---------|----------|
| L4-TIME | Anomalous timing, no-op, busy-wait | MEDIUM/HIGH |
| L4-EXFIL | Data exfiltration, suspicious DNS, credential theft | CRITICAL/HIGH/MEDIUM |
| L4-ENTROPY | High-entropy filenames, DGA domains | MEDIUM/HIGH |
| L4-HONEY | Honeypot path access, priv-esc binaries | CRITICAL |
| L4-BASE | Baseline drift from known-good profiles | CRITICAL/MEDIUM/INFO |
| L4-ENV | .env access, env-dump commands, secret var exfil | HIGH/CRITICAL |
| L4-PROC | Shell spawning, reverse shells, excessive spawns | HIGH/CRITICAL/MEDIUM |
| L4-FS | Protected path writes, path traversal, critical deletes | CRITICAL/HIGH/MEDIUM |
| L4-NET | Suspicious ports, DNS tunneling, suspicious TLDs | HIGH/MEDIUM |
| L4-SC | Obfuscated payloads, remote code exec, DNS exfiltration | CRITICAL/HIGH |
| L4-PRIVESC | Sudoers/shadow writes, setuid chmod, cap manipulation, cron abuse | CRITICAL/HIGH |
| L4-PERSIST | Crontab/systemd/SSH persistence, launch agents, shell profiles | CRITICAL/HIGH/MEDIUM |
| L4-CRYPTO | Mining pool connections, mining binaries, crypto config, resource abuse | CRITICAL/HIGH/MEDIUM |
| L4-CONTAINER | Container escape probes, docker socket, cloud metadata, namespace escape | CRITICAL/HIGH/MEDIUM/INFO |
| L4-DEP | Registry overrides, publish during install, suspicious URLs, config tampering | CRITICAL/HIGH/MEDIUM/LOW |

## Adding a New Rule

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the step-by-step guide to adding new rules.

Every rule **must** be deterministic: same command + same policy = same findings, every time.
