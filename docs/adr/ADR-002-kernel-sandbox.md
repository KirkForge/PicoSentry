# ADR-002: Kernel sandbox via seccomp-bpf + landlock

**Status:** Accepted (Beta)  
**Date:** 2026-06

## Context

Static scanning alone cannot detect runtime behavior: a package that looks clean may phone home or exfiltrate secrets when its post-install hook runs.

## Decision

`picosentry sandbox` enforces a syscall allowlist via `seccomp-bpf` and filesystem access restrictions via `landlock` (Linux 5.13+). The daemon exposes an HTTP + gRPC API so CI pipelines can submit install commands and receive structured behavioral reports.

## Rationale

- Kernel enforcement is stronger than process-level sandboxing (ptrace, LD_PRELOAD); cannot be bypassed from userspace
- seccomp-bpf blocks unexpected syscalls at the kernel level; violations are logged via audit
- landlock restricts file paths without requiring root or namespaces

## Consequences

- Linux-only: macOS and Windows CI agents cannot run sandbox mode; scanner-only mode remains cross-platform
- Requires kernel ≥ 5.13 for landlock; older kernels fall back to seccomp-only
- Non-root container operation requires `CAP_SYS_ADMIN` or a privileged sidecar for seccomp filter installation
