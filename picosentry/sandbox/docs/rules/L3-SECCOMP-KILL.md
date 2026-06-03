# L3-SECCOMP-KILL — Seccomp Syscall Kill

**Rule ID:** L3-SECCOMP-KILL  
**Backend:** Seccomp-bpf (Linux)  
**Verdict:** KILL  

## Detection

Triggered when the seccomp-bpf sandbox backend kills a process for attempting a blocked syscall. This is kernel-level enforcement — the process receives SIGSYS and is terminated immediately.

## How It Works

The Linux kernel enforces seccomp-bpf rules before the syscall executes:

1. Process attempts a blocked syscall (e.g., `connect()`)
2. Kernel evaluates the BPF filter
3. If the filter returns `SECCOMP_RET_KILL`, the process is terminated with SIGSYS
4. The event is logged by the parent process

## Supply-Chain Relevance

Seccomp kills are definitive evidence of policy violation:

- **No false positives**: The kernel blocked an actual syscall, not a string pattern
- **No escape**: The process cannot bypass kernel-level filtering
- **Audit trail**: Every kill is logged with the syscall name and arguments

## When This Triggers

- Process attempts network connection when `network_out: deny` is set
- Process attempts to spawn a child when `process_spawn: deny` is set
- Process attempts to write to protected paths when `file_write: deny` is set

## Mitigation

1. Review the policy to ensure it matches your requirements
2. Use the `node` or `python` policy for permissive but monitored execution
3. Add specific path/syscall allowlist entries to your policy