# Sandbox Security Model

## Attack Model

The PicoSentry sandbox defends against **untrusted input executed in a controlled environment**. Specifically:

- **Supply-chain attacks**: Malicious code in packages (postinstall scripts, native extensions) that attempts filesystem access, network exfiltration, or privilege escalation.
- **Data exfiltration**: Outbound network connections, DNS tunneling, or credential harvesting from the sandboxed process.
- **Unauthorized syscalls**: Kernel interfaces that enable container escapes, privilege escalation, or resource abuse (e.g., io_uring exploitation surfaces).

The sandbox does **not** defend against kernel exploits that bypass seccomp-bpf entirely, or against physical/local attacks on the host.

## Backend Comparison

### seccomp-bpf (Linux)

- **Isolation level**: `syscall_policy` — kernel-enforced syscall filtering.
- **Enforcement guarantee**: `moderate` — blocks syscalls at kernel level, but the filter is loaded in a forked child process (see fork-safety limitation below).
- **Mechanism**: Uses `libseccomp` via ctypes. Forks the target process, loads a BPF filter in the child before `execve`. The kernel kills the process on a denied syscall (`SIGSYS`).
- **What it blocks**: Any syscall group the policy denies. Default-deny policies block everything except `SAFE_SYSCALLS` and explicit ALLOW rules.
- **Availability**: Requires `libseccomp.so.2`. Falls back to subprocess if unavailable (unless `fail_closed=True`).

### seatbelt (macOS)

- **Isolation level**: `os_policy_enforced` — macOS kernel sandbox.
- **Enforcement guarantee**: `hard` — the macOS kernel enforces the policy. Violations produce `deny` messages on stderr.
- **Mechanism**: Generates a Seatbelt (`sandbox-exec`) profile from the policy, runs the command under it.
- **What it blocks**: Filesystem paths (read/write/exec), network (outbound/inbound/bind), process spawn/fork, DNS (port 53 only). Enforced by the macOS sandbox kernel extension.
- **Availability**: macOS only. Requires `sandbox-exec` binary.

### subprocess (observational only)

- **Isolation level**: `observational_only` — no enforcement, only post-hoc detection.
- **Enforcement guarantee**: `best_effort` — inspects stdout/stderr after the command completes. Damage is already done.
- **Mechanism**: Runs the command in a plain `subprocess.Popen` with a restricted environment allowlist. Scans output for suspicious patterns (dynamic code execution, shell invocation, sensitive file access, network tool usage, base64 decoding, destructive commands, process introspection, SSH key access).
- **What it blocks**: **Nothing.** Patterns are detected and reported as findings, but the sandboxed code runs unrestricted.
- **Availability**: Always available on every platform. Used as a fallback when seccomp/seatbelt are unavailable.

## Known Limitations

### Fork-safety gap (seccomp-bpf)

Between `os.fork()` and `seccomp_load()`, the Python runtime executes code in the child process. During this window, the child has no seccomp filter and can make any syscall. This is inherent to the fork-then-filter model. Mitigations:

- The window is short (tens of microseconds) and occurs before `execve`.
- `fail_closed=True` policies refuse to degrade, so a seccomp failure kills the child immediately (`os._exit(127)`).

### Subprocess backend is observational only

The subprocess backend provides zero enforcement. Any damage from the sandboxed code is already done when findings are reported. Never rely on it in production.

### No network namespace isolation by default

The seccomp backend blocks `connect`, `bind`, `sendto`, and other network syscalls via policy, but it does not create a separate network namespace. A compromised process that bypasses seccomp (e.g., via an allowed syscall path) can access the host network. For full network isolation, run inside a container or VM with `--network none`, or use the gRPC transport to sandbox on a separate host.

### Environment variable leakage

The subprocess backend passes `PYTHONPATH`, `PYTHONHOME`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `NODE_PATH`, and `NPM_CONFIG_PREFIX` to child processes. These can influence library loading and are a potential attack vector.

## Hardening Recommendations

1. **Always use seccomp or seatbelt in production.** Set `PICODOME_ALLOW_DEGRADED=0` or remove it entirely so that a missing backend causes a hard failure rather than silent degradation to subprocess.
2. **Use `fail_closed=True` in policies.** This prevents the seccomp backend from degrading to subprocess even when `PICODOME_ALLOW_DEGRADED` is set.
3. **Use the gRPC transport for remote sandboxing.** The gRPC transport runs sandboxed workloads on a separate host, eliminating local attack surface. See `picosentry/sandbox/grpc_transport/`.
4. **Add network namespace isolation.** Run PicoSentry in a container with `--network none` or use Docker's network isolation.
5. **Block dangerous syscalls in policy.** Add explicit DENY rules for `prctl`, `memfd_create`, `io_uring_setup`, and `io_uring_enter` (see below).

## Dangerous Syscalls in SAFE_SYSCALLS

The following syscalls are currently in the `SAFE_SYSCALLS` allowlist, meaning they are permitted by default even in deny-default policies. Explicit policy rules are required to block them.

| Syscall | Risk | Why it's dangerous |
|---|---|---|
| `prctl` | Privilege escalation | Can modify process properties (dumpable flag, name, seccomp filters from userspace). An attacker can use `prctl(PR_SET_DUMPABLE, ...)` to enable core dumps of sensitive processes, or `prctl(PR_SET_SECCOMP, ...)` to install a permissive filter. |
| `memfd_create` | Fileless malware | Creates anonymous in-memory files that can be `execve`'d without touching disk. A common technique for dropping and executing payloads that evade filesystem-based detection. |
| `io_uring_setup` | Kernel exploitation | io_uring has a history of kernel vulnerabilities (CVE-2024-0582, CVE-2024-41073, etc.). The attack surface is large and new bugs are found regularly. |
| `io_uring_enter` | Kernel exploitation | Companion to `io_uring_setup`. Submitting uring requests can trigger kernel code paths with known privilege-escalation vulnerabilities. |

**Recommendation**: Add explicit DENY rules for these syscalls in production policies unless the workload specifically requires them.