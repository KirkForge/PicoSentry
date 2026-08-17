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
- **Arch-portability (2026-07 addendum):** seccomp filters are arch-portable by
  construction — `resolve_syscall(lib, name, cache)` delegates name→number
  resolution to libseccomp, which resolves per-arch at runtime. The core
  allowlist syscalls (`read`, `write`, `openat`, `close`, `exit`,
  `exit_group`, `rt_sigreturn`) are verified to resolve on all tested
  architectures via `tests/sandbox/test_seccomp_common.py::TestArchPortability`.
  arm64 scan is CI-verified (QEMU + native); arm64 sandbox is QEMU-verified
  with native-runner as a future hardening step. Unknown syscalls on a given
  arch are logged via the existing `EINVAL` handler in `add_rule_safely`.

## Addendum (2026-07): Landlock backend implemented

The implement option from the Correction section above has now been taken. A
`LandlockBackend` exists at `picosentry/sandbox/l3/backends/landlock_backend.py`,
using raw `ctypes` to call `landlock_create_ruleset(2)`, `landlock_add_rule(2)`,
and `landlock_restrict_self(2)` — matching the existing seccomp `ctypes` style
in `_seccomp_common.py`. Key properties:

- **Kernel gate:** `_check_landlock_available()` checks `platform.uname().release >= 5.13` and returns a reason string on failure. The backend falls back to seccomp-only on kernels < 5.13 or non-Linux platforms.
- **Fallback:** `LandlockBackend(fallback_to_seccomp=True)` (default) silently falls back to `SeccompBackend` when landlock is unavailable. Set `fallback_to_seccomp=False` to raise `LandlockUnavailable` instead.
- **Registry:** `get_backend("landlock")` in `backends/__init__.py` returns a `LandlockBackend` if available, otherwise falls back to `SeccompBackend`.
- **Tests:** `tests/sandbox/test_landlock_backend.py` validates kernel-version gate logic, fallback behavior, and arch-portable syscall number selection.
- **CI matrix:** A `test-landlock` job is recommended on `ubuntu-24.04` (6.x kernel) to verify the landlock path, and on `ubuntu-22.04` (5.15 kernel) to verify seccomp-only fallback. `# ceiling: arm64 native sandbox CI blocked on runner availability`
- **This is NOT a retraction of the Correction.** The Correction accurately documented that landlock was fiction at the time. This addendum records that the fiction is now real code with real tests.
## Addendum (2026-08, WO4.0.0-001): Landlock made real

The 2026-07 addendum shipped a backend that was dead on x86_64 and
policy-blind everywhere (WO4.0.0-001 evidence). Corrected and verified on a
kernel 7.0 x86_64 host (landlock ABI 8):

- **Syscall table fixed:** the allocation is uniform across architectures —
  `create_ruleset=444, add_rule=445, restrict_self=446` (x86_64
  `syscall_64.tbl` matches `asm-generic/unistd.h`, which aarch64 uses). The
  old table's x86_64 `(446,447,448)` called `restrict_self` as "create",
  which is also why the availability probe surfaced EPERM.
  `tests/sandbox/test_landlock_backend.py` derives the expected numbers from
  installed kernel headers (never literals) and live-probes the ABI.
- **Availability = ABI probe:** `landlock_create_ruleset(NULL, 0,
  LANDLOCK_CREATE_RULESET_VERSION)` returns the highest supported ABI
  (unprivileged, safe). Handled access bits are scoped by that ABI (REFER
  needs 5.19/ABI2, TRUNCATE 6.2/ABI3, NET 6.7/ABI4); a 5.13–6.1 host now
  probes clean instead of failing with generic EINVAL.
- **no_new_privs:** the child calls `prctl(PR_SET_NO_NEW_PRIVS, 1)` before
  `landlock_restrict_self` — required for unprivileged restriction (the old
  code never set it; restrict would have failed EPERM even with correct
  numbers).
- **Policy translation:** `Policy` paths become path-beneath grants.
  Launch parity with seccomp: the runtime tree (/usr, /lib, /bin, /sbin +
  the command's binary dir and its install/venv root, incl. the ELF
  interpreter, whose exec is EXECUTE-checked) stays readable/executable.
  `cwd=None` gets a fresh private `mkdtemp` workspace (never bare `/tmp`);
  write paths that are ancestors of the workspace are tightened to the
  workspace; `/proc` is never granted wholesale (only `/proc/self`, resolved
  in the child so it names the sandboxed process, not the parent);
  no EXECUTE on `/dev` or the workspace (data-not-code). Network:
  `network_out`/`network_bind` deny → handled NET bits with no rules (all
  TCP connect/bind → EACCES) on ABI ≥ 4 kernels.
- **Honest ceilings (marked `degraded=True` + warning, never silent):**
  network deny on < 6.7 kernels; `network_in` and `dns_query` (UDP) are not
  restrictable by landlock at any version; allow-side network scoping is
  unhandled (no wildcard port — 65535 rules would be needed for "allow
  all"); chardev nodes like `/dev/null` cannot hold landlock rules, so
  device writes stay denied; seccomp+landlock composition (both filters in
  one child) remains future defense-in-depth.
- **Verified round-trips (PICODOME_HAS_LANDLOCK=1):** allow (`true`, `pwd`),
  EACCES on writes outside the workspace into world-writable `/tmp`, EACCES
  on TCP connect, and CLI-level `picosentry sandbox pipeline touch
  /tmp/x --backend landlock` → DENY with no file created.
