# ADR-002: Kernel sandbox via seccomp-bpf

**Status:** Accepted (Beta)
**Date:** 2026-06 (corrected 2026-07: landlock claim removed — see below)

## Context

Static scanning alone cannot detect runtime behavior: a package that looks clean may phone home or exfiltrate secrets when its post-install hook runs.

## Decision

`picosentry sandbox` enforces a syscall allowlist via `seccomp-bpf` (Linux). The
daemon exposes an HTTP + gRPC API so CI pipelines can submit install commands
and receive structured behavioral reports.

## Rationale

- Kernel enforcement is stronger than process-level sandboxing (ptrace, LD_PRELOAD); cannot be bypassed from userspace.
- seccomp-bpf blocks unexpected syscalls at the kernel level; violations are logged via audit.
- Filesystem access is controlled by the seccomp syscall allowlist plus the
  sandboxed child's working directory; there is **no** path-based filesystem
  access-control layer in the sandbox today.

## Correction (2026-07): landlock claim was fiction

A prior revision of this ADR (and `docs/THREAT_MODEL.md`) claimed the sandbox
combined `seccomp-bpf` **and** `landlock` (Linux 5.13+) for filesystem
restrictions. That was inaccurate: `grep -rni landlock picosentry/sandbox/`
returned zero hits — no landlock backend has ever been implemented. The only
occurrence of the string `landlock` in the tree was a PyPI package name in the
scan corpus. The correction here drops the landlock claim rather than ship a
partial, untested backend to match the documentation.

The implement option (raw `ctypes` `landlock_*` syscalls or `pylandlock`, with
graceful fallback to seccomp-only on kernels < 5.13) remains a viable future
hardening step. It was not taken now because an untested or shallow landlock
backend would be worse than honest seccomp-only documentation, and a real
backend requires its own test matrix on ≥5.13 kernels plus a fallback path.

## Consequences

- Linux-only: macOS and Windows CI agents cannot run sandbox mode; scanner-only mode remains cross-platform.
- seccomp-bpf is the only kernel sandbox; there is no filesystem path
  restriction layer beyond the child's CWD and the syscall allowlist.
- Non-root container operation requires `CAP_SYS_ADMIN` or a privileged sidecar for seccomp filter installation.