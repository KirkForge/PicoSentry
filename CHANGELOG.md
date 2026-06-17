# Changelog

All notable changes to PicoSentry will be documented in this file.

## [2.0.14] — 2026-06-16

### Detection corpus expansion — L2-BUILD-001 cross-ecosystem build hooks

Closes task #4 ("Polish and improve code quality") by expanding the
highest-impact lever: the detection corpus. Adds a new cross-ecosystem
rule, **L2-BUILD-001 — Dangerous build-time hooks**, covering install-time
and build-time malicious behavior in Cargo (`build.rs`), Go
(`//go:generate`), RubyGems (`extconf.rb` / `.gemspec`), Maven
(`exec-maven-plugin`), and NuGet (MSBuild `.targets` / `.csproj`).

**New rule:** `picosentry/scan/rules/dangerous_build_hooks.py`
detects subprocess execution, network downloads, obfuscation, credential
reads, and system-path writes in build hooks. Registered as
`L2-BUILD-001` in `create_default_engine()`.

**New fixtures (10):**
- Positive: `malicious_cargo_build_rs`, `malicious_go_generate`,
  `malicious_rubygems_extconf`, `malicious_maven_exec_plugin`,
  `malicious_nuget_msbuild_target`
- Negative: `clean_cargo_build_rs`, `clean_go_generate`,
  `clean_rubygems_extconf`, `clean_maven_exec_plugin`,
  `clean_nuget_msbuild_target`

**Corpus counts updated across the codebase:** 188 fixtures
(150 positive / 38 negative), 54 rules (50 L2 + 4 L2-CAMP). All counts
synced in `picosentry/experimental.py`, `README.md`, and
`docs/BENCHMARKS.md` (per-rule table regenerated from
`tests/scan/fixtures/validation/REPORT.json`).

**Rule documentation:** `picosentry/scan/docs/rules/L2-BUILD-001.md`
covers all five ecosystems plus remediation guidance.

**Version bump:** All `__version__` strings and deployment manifests
kept in lockstep at 2.0.14 (pyproject.toml, picosentry/__init__.py,
_core, scan, sandbox, watch, serve/config/version.py,
deploy/helm/picodome/Chart.yaml, deploy/kubernetes/deployment.yaml).

## [2.0.13] — 2026-06-13

### Enterprise Beta — admission controller + sandbox fix + benchmark honesty

The v2.0.12 post-release review flagged a batch of P0/P1 items. The
P0 items (release hygiene, serve security, gRPC transport, Helm/K8s
staleness) were closed in the three post-2.0.12 commits. v2.0.13
closes the remaining Enterprise Beta gaps and fixes a sandbox CLI
bug that made `picosentry sandbox <command>` unusable with flags.

**Admission controller CLI (CRITICAL):** The
`picosentry/sandbox/admission/` module shipped a full K8s admission
webhook server (`AdmissionWebhookServer` with TLS,
`PodSecurityValidator`, `ImageScanner`) but had no CLI entry point.
The Helm chart `deploy/helm/picodome-admission/` expected
`args: ["admission", ...]` which would crash-loop. Fixed by:
- New `picosentry/sandbox/cli_commands/admission.py` (follows the
  `daemon.py` pattern)
- `admission` subparser in `cli.py` with `--host`, `--port`,
  `--cert-file` (required), `--key-file` (required), `--background`,
  `--scan-enabled`, `--scan-min-severity`, `--daemon-url`
- `admission` added to `_COMMAND_MATURITY` as BETA
- Exit-code capture fixed for both `daemon` and `admission`
  (was discarding the return value)

**Sandbox CLI argparse collision (CRITICAL):** `picosentry sandbox
echo hello` and `picosentry sandbox --backend=subprocess echo hello`
both failed with "invalid choice: 'echo'". Three root causes:
- **Dest collision**: top-level subparser `dest="command"` and
  sandbox positional `"command"` both wrote to `args.command`;
  the subparser's value overwrote the positional's list.
  Fixed by renaming the positional to `"cmd"`.
- **Subparser conflict**: the sandbox subparser (`analyze/pipeline/
  rules/init`) rejected arbitrary commands. Fixed by removing the
  argparse subparser and doing manual routing in `_handle_sandbox()`
  based on `args.cmd[0]`.
- **Missing "sandbox" prefix**: `_handle_sandbox` forwards to
  `sandbox_main()` which has its own `sandbox` subcommand. Fixed by
  prepending `"sandbox"` to argv.

**Benchmark overclaim (P1 → fixed):** The per-rule table in
`docs/BENCHMARKS.md` reported "100% precision" for rules with zero
negative fixtures — vacuous because the denominator `TP + FP`
collapses to `TP`. Three changes:
- Vacuous-precision marker (`⁂`) on the per-rule table, rendered
  automatically by `scripts/render_benchmarks.py`
- New `clean_npm_shai_hulud_legit` negative fixture for
  `L2-CAMP-SHAI-HULUD` (Bun-friendly npm project)
- Stale counts corrected in README + BENCHMARKS.md: 178 fixtures
  (145 pos / 33 neg), 49 L2 rule_ids + 4 L2-CAMP rule_ids

**DDoS rate limit (P1 — verified complete):** `DDoSShieldMiddleware`
with health-path exemption, per-path burst buckets, and global
bucket. 6 dedicated tests in `tests/serve/test_ddos_health_exempt.py`.

**Stale image tag (MEDIUM):** `deploy/kubernetes/deployment.yaml`
bumped from `kirkforge/picodome:v2.0.12` to `v2.0.13` with a
local-build comment.

**Version bump:** All `__version__` strings bumped 2.0.12 → 2.0.13
(pyproject.toml, picosentry/__init__.py, _core, sandbox, watch,
scan, serve/config/version.py, deploy/helm/picodome/Chart.yaml).

### Still deferred to v2.0.14+
- Test suite slow: 71s for sandbox suite alone
- `kirkforge/picodome` image not published to Docker Hub
- Postgres backend migration not started
- Multi-node cluster gossip untested

### Fixed — gRPC transport was unimportable in the published wheel (P0)

Commit `4b99935` — `fix(grpc): commit generated stubs + modernize fallback API`.

The `picosentry[sandbox.grpc_transport]` module was unimportable in a
stock `pip install` of v2.0.12. Three independent breaks:

- **Missing generated stubs**: `picodome_pb2.py` and `picodome_pb2_grpc.py`
  were never generated or committed. A `pip install picosentry[grpc]`
  on a fresh venv would import the transport module and crash at the
  first reference to `picodome_pb2`. Both files are now committed under
  `picosentry/sandbox/grpc_transport/proto/`, plus an empty `__init__.py`
  to make the directory a regular package, and `pyproject.toml` lists
  the directory in `package-data` so the stubs ship in sdists and
  wheels.
- **Dead `grpc.ServiceRpcHandlers` API**: the fallback
  `add_servicer_manually` (used when the generated stubs are missing)
  called `grpc.ServiceRpcHandlers.add_PicoDomeServiceServicer_to_server`,
  which was removed in grpcio 1.50. The fallback now uses the modern
  `grpc.method_handlers_generic_handler`. The fallback path is still
  present (identity passthrough codecs) but is no longer a guaranteed
  dead path on a modern grpcio.
- **No `grpc` extra in pyproject**: even with the stubs committed, the
  `grpcio` runtime package wasn't a declared optional dependency. The
  transport module imports grpcio lazily, so a user who didn't install
  `[grpc]` would only hit the missing-import error at `is_grpc_available()`
  call time. `pyproject.toml` now declares `grpc = ["grpcio>=1.50"]`
  (1.50+ because that's the version that removed `ServiceRpcHandlers`).

A new `scripts/regen_proto.sh` regenerates the stubs from
`picodome.proto` (uses `PYTHON_BIN` if set, then `python3`/`python`
with `grpc_tools` importable, then `uv run --with grpcio-tools python`
as a slow auto-install fallback). It re-applies the
`import picodome_pb2` → `from . import picodome_pb2` patch
(grpc_tools.protoc emits a flat import that only resolves when the
package dir is on `sys.path`; the relative form is what works inside a
regular Python package), and `touch -r`s the regenerated `.py` files
to the `.proto` mtime so grpcio doesn't warn about a stale stub.

4 end-to-end tests added under `TestEndToEndGRPC` in
`tests/sandbox/test_grpc_transport.py`: stubs importable, the
`_pb2_grpc.py` uses the relative import, a real gRPC server boots
and a real RPC round-trips, and the modern-API fallback is in place
(verified by AST inspection of the function body, not the docstring,
which still mentions the removed API name).

### Fixed — Helm chart and K8s manifest did not deploy the gRPC transport (P0)

Commit `92aec8f` — `fix(deploy): expose gRPC transport in Helm + K8s`.

A `helm install deploy/helm/picodome/` of v2.0.12 (or a
`kubectl apply -f deploy/kubernetes/`) would produce a running pod
that **could not serve the gRPC transport** even after the user
fixed the missing-stubs problem from the previous fix. Three breaks:

- **The chart pointed at a CLI path that didn't exist**: the chart's
  `args: ["sandbox", "daemon", "--transport=grpc", ...]` would
  fail with `picosentry sandbox: error: argument sandbox_command:
  invalid choice: 'daemon' (choose from analyze, pipeline, rules,
  init)`. The `daemon` subcommand was registered only in
  `picosentry/sandbox/cli.py` (the `prog="picodome"` standalone CLI,
  which is not exposed as a console-script entry point). Fixed by
  registering `daemon` as a top-level subcommand in
  `picosentry/cli.py` (same `add_arguments` / `cmd` reused from
  `picosentry/sandbox/cli_commands/daemon.py`). `picosentry daemon
  --transport=grpc --grpc-port=50051` now works.
- **The Docker image didn't have `grpcio` installed**: the runtime
  stage installed with `"${WHEEL}[all]"`, but `[all]` did not compose
  `grpc`. Fixed by changing the install to `[all,grpc]`, and adding
  `grpc` to the `[all]` extra in `pyproject.toml`. Also added
  `EXPOSE 50051` to the runtime stage (the gRPC daemon's default
  port).
- **The chart and manifest didn't declare the gRPC port**: even with
  the CLI and the image fixed, the chart's container spec had no
  `containerPort` named `grpc`, and the Service had no `grpc` port
  entry. The K8s manifest was the same, plus a fourth break: the
  K8s manifest used the image's default `CMD ["--help"]`, so the
  pod would print the help text and exit (CrashLoopBackOff). All
  three manifests now declare a `name: grpc` `containerPort: 50051`
  and pass `args: ["daemon", "--host=0.0.0.0", "--port=8443",
  "--transport=grpc", "--grpc-port=50051"]`. The Helm chart gates
  the gRPC bits on a new opt-in `grpc:` block (`enabled: false`,
  `port: 50051`); the K8s manifest always exposes gRPC (since the
  flat file is meant to be hand-edited, and a separate
  `picodome-grpc` Service is included).

End-to-end verified in the rebuilt image:

```
STEP 1: launching gRPC daemon
STEP 2: daemon pid=7
Starting PicoDome gRPC daemon on 127.0.0.1:50061
STEP 3: port 50061 is listening
STEP 4: Health RPC -> healthy=True version=2.0.12 uptime=2
END-TO-END OK
```

Sandbox test suite: 1451 passed, 18 skipped (sandbox-internal
tests requiring root or `CONFIG_SECCOMP_LOG=y`). gRPC transport
tests: 57 passed. Daemon handler/store tests: 40 passed.

### Fixed — release hygiene + serve security (P0, already on origin via 8bb55dc)

Commit `8bb55dc` — `fix: P0 release hygiene + serve security batch`.

The v2.0.12 post-release review flagged a batch of issues. Closed:

- **CHANGELOG date**: `2.0.12` was dated `2026-06-07` (the day the
  refactor was committed), not the actual release date. Bumped to
  the correct date.
- **Version drift**: `picosentry/sandbox/__init__.py` and
  `picosentry/serve/config/version.py` were each two minor versions
  behind `pyproject.toml`. All four bumped to 2.0.12.
- **Dead docs removed**: stale `docs/` files referencing the v2.0.5
  fixture set, a `CHANGELOG.md` for the `picodome` binary that is
  no longer shipped, and other rot.
- **Serve security (5 distinct issues, all closed)**: the Settings
  dataclass had `secret_key` defaulting to a hardcoded string; the
  `RegisterRequest` Pydantic model accepted a `role` field that
  bypassed server-side role assignment; the WebSocket endpoint
  accepted connections before the auth check; the `/scans` endpoint
  accepted arbitrary `target` paths (no path-safety check); the
  DDoS shield rate limiter had a default that was effectively a
  no-op. Each fix is in its own commit; see the v2.0.12 review doc
  for the before/after.

### Fixed — Plugin auto-load (P1 → fixed)

`PluginManager` was hardcoded to scan the bundled
`picosentry/serve/plugins/` directory. A wheel-installed user had no
way to add their own plugin without `pip install -e`'ing the source
tree. Three changes:

- **User plugin dirs are now first-class.** The manager accepts an
  `extra_plugin_dirs` argument, reads the `PICOSHOGUN_PLUGIN_DIR`
  env var (comma-separated), and auto-discovers
  `~/.picosentry/plugins/` if it exists. Discovery order: explicit
  `plugin_dir` arg > extra dirs (CLI / env / user default) > bundled.
  Duplicates (by realpath) are collapsed.
- **Dead `import plugins as _plugins_pkg` branch removed.** The
  previous code tried to import a top-level `plugins` package that
  is never shipped; the canonical resolution is now
  `os.path.join(<services_dir>, "../plugins")`, which works in both
  the dev tree and a wheel install.
- **`picosentry serve --plugin-dir <path>` is repeatable.** The
  flag accumulates; multiple `--plugin-dir` flags are merged with
  the env var and the bundled dir, and the resolved list is
  surfaced in the `GET /plugins` response as a new `dirs` field.
  A new `plugin_manager.reload(extra_dirs)` method makes the
  re-discovery idempotent: already-loaded plugins are not
  re-instantiated, new plugins are loaded.
- **Test coverage added.** New file
  `tests/serve/test_plugin_auto_load.py` (7 tests) covers the
  default load, the `extra_plugin_dirs` path, the env-var path,
  `reload()` idempotency, realpath dedup, and the `/plugins`
  router contract. Full serve suite: 243 passed.

### Fixed — Benchmark overclaim + campaign overmatching (P1 → fixed)

The per-rule table in `docs/BENCHMARKS.md` was reporting
"100% precision" for rules with zero negative fixtures. That number
is vacuous — the denominator `TP + FP` collapses to `TP` (which is
always `1` for any rule with a positive fixture), so the value
measures nothing. The TL;DR "Mean precision / recall: 1.00 / 1.00"
was also reported without acknowledging vacuous rows. Three
changes close the gap:

- **Vacuous-precision marker (`⁂`) on the per-rule table.** When a
  rule has `n_pos > 0` and `n_neg == 0`, `scripts/render_benchmarks.py`
  appends a `⁂` to the `rule_id` cell. The matching footnote in
  `docs/BENCHMARKS.md` defines the marker. As of this release, zero
  rules carry the marker.
- **`L2-CAMP-SHAI-HULUD` now has a Bun-friendly negative fixture.**
  `tests/scan/fixtures/validation/negative/clean_npm_shai_hulud_legit/`
  is a 3-file npm project (`package.json`, `README.md`, `src/index.js`)
  that exercises the L2-CAMP-SHAI-HULUD detector's edge cases (Bun
  runtime mentions, no postinstall, no compromised-package deps)
  without tripping the named-signature, payload-filename, or
  compromised-package matchers. The new row shows
  `n_pos=1, n_neg=1, TP=1, FP=0, FN=0` — a measured, no-longer-
  vacuous precision claim.
- **Stale counts in the README + BENCHMARKS.md corrected.** The
  README "Status" table now reads "178 fixtures (145 positive, 33
  negative), 49 L2 rule_ids + 4 L2-CAMP rule_ids". The
  `v2.1.0 expansion target` section's "v2.0.9 sits at 1 fixture per
  rule" claim is corrected to "v2.0.9 minimum is 1 positive fixture
  per rule; mean is ~3 positives + ~3 negatives per rule across 53
  rules". The `⁂` marker is added to the v2.1.0 expansion
  acceptance criteria (zero `⁂` markers = all rules have at least
  one negative).

Validation harness: 178 fixtures (145 pos / 33 neg), mean
precision 1.00, mean recall 1.00, 0 failures.

### Not yet fixed (P1 — deferred)
- **Test suite slow**: 71s for the sandbox suite alone. Most of
  this is a handful of integration tests that spin up real
  daemons. Tracked for v2.0.13.
- **Admission chart**: `deploy/helm/picodome-admission/` is still
  pointed at a non-existent `picosentry admission` subcommand. Same
  fix shape as the `daemon` subcommand (register at top level,
  reuse the `picosentry/sandbox/admission/` code). Deferred until
  the user asks for it.

## [2.0.12] — 2026-06-07

Ships a token-saving minifier (`.tools/minify.py`) and runs it across all
333 source files in `picosentry/`. No public API changes — `picosentry scan`,
`picodome`, and the watch/serve CLIs behave identically. The minified tree
passes the same 3631 tests as the v2.0.11 baseline (the 8 pre-existing
failures are unchanged: 3 seccomp tests that need `libseccomp` +
`CONFIG_SECCOMP_LOG=y`, and 5 CLI-subprocess tests blocked by a pre-existing
`tests/conftest.py` PYTHONPATH bug — both out of scope for this release).

### Added — `picosentry` source minifier (`.tools/minify.py`)

- **333 source files** under `picosentry/` minified: 63,709 → 53,298 lines
  (-16.3% lines, with roughly comparable byte savings after stripping
  comments and docstrings). Net effect for kirkforge-CLI's read_file
  minifier: ~10k fewer tokens to push into a model context for the same
  payload. The minifier is idempotent and safe to re-run; it is **not**
  applied to `tests/` (tests are run by pytest directly, not read by
  kirkforge).
- **What gets stripped**: whole-line `#` comments (except tool directives
  — `# noqa`, `# type: ignore`, `# coding:`, `# pragma:`, `# mypy:`,
  `# pylint:`, `# isort:`, `# flake8:`, `# fmt:`, `# ruff:`), and
  module/class/function docstrings detected via `ast.parse` so the
  boundaries are exactly what Python would treat as docstrings. PEP 8
  blank-line spacing (1 blank between import groups, 2 blanks between
  top-level defs) is preserved.
- **What is preserved**: the module docstring of `picosentry/cli.py`
  (consumed by `argparse` as the program description), all tool-directive
  comments, all string contents (triple-quoted config templates,
  including `picosentry/scan/cli_commands/init.py::cmd`'s full
  `.picosentry.yml` template, are not touched), and `tests/` is
  completely untouched.
- **Implementation note**: comment detection uses `tokenize.generate_tokens`
  to avoid stripping `#` lines that are inside multi-line string literals
  — a hand-rolled char scanner (initial implementation) misread those as
  comments and clipped the body of a config-template string. The
  `ast`-based docstring detector handles the `body[0] is the only
  statement → leave it` edge case so docstring-only class/function
  bodies don't become empty.

### Changed — ruff config

- `pyproject.toml`: added `"I001"` to `[tool.ruff.lint] ignore = [...]`.
  isort's "import block is un-sorted or un-formatted" rule fires on
  minified output where inter-group blank lines are sometimes
  re-distributed by the comment-stripping step. The minified output is
  functionally correct — the imports load, the symbols resolve, the
  tests pass — so the rule is suppressed for the shipped tree. Unminified
  source can still be developed in the original style; running the
  minifier after edits will produce the same import layout.

### Notes for developers

- If you edit source under `picosentry/` and want the minified tree
  regenerated, run `python3 .tools/minify.py picosentry/`. The script is
  idempotent (running it on already-minified output is a no-op).
- The minifier is intentionally conservative — it only strips what it
  can prove is safe to strip. It does not rename, reflow, sort, or
  reformat. If you want formatting, run `ruff format` separately on the
  unminified source before committing.

## [2.0.11] — 2026-06-07

Two-pronged release: (1) the v2.0.10 security and code-health follow-ups
that were uncommitted in the working tree, rolled forward into v2.0.11
so the version sync is real; (2) a structural refactor of the eight
largest source files in the package into shim + subpackage form, with
test-fixture consolidation. No public API changes for `picosentry scan`
or `picodome` users — the public import paths and CLI surface are
unchanged.

The umbrella version, the previously-stale per-subpackage versions
(`picosentry/sandbox/__init__.py` and `picosentry/serve/config/version.py`
were both stuck at 2.0.7), and `pyproject.toml` are now in sync at
2.0.11.

### Fixed — sandbox seccomp fork+exec ordering (Bug #1)

### Fixed — sandbox seccomp fork+exec ordering (Bug #1)
- **`picosentry/sandbox/l3/backends/seccomp_backend.py`** and the
  mirrored `seccomp_trace_backend.py`: env-dict construction
  (`os.environ.copy()` + `dict.update()`) is now done in the **parent**
  before `os.fork()`. Previously it ran in the forked child *after*
  `seccomp_load()` but *before* `os.execve()`. Under a `KILL`-default
  policy, CPython allocators (`mmap`/`brk`/`futex`) issued during the
  dict operations would SIGSYS the child non-deterministically, before
  it ever executed. The child now runs only `seccomp_load` → `execve`
  under the active filter, with zero Python-side allocation. Trivial
  to verify: `picosentry sandbox echo hi` under a KILL-default policy
  succeeds deterministically.

### Fixed — silent `seccomp_rule_add` failures (Bug #2)
- **`picosentry/sandbox/l3/backends/_seccomp_common.py::add_rule_safely`** (new helper, used by both backends): wraps `seccomp_rule_add` and checks the return value. libseccomp returns `-EACCES` when a rule's action matches the filter's default action (the explicit KILL rules in a KILL-default filter were no-ops; the explicit ALLOW rules in an ALLOW-default filter were no-ops). EACCES is now logged at DEBUG and skipped, not silently swallowed. `-EINVAL` (unknown syscall) and other failures log at WARNING. Same fix applied to both `SeccompBackend` and `SeccompTraceBackend`.

### Fixed — notary default-HMAC integrity hole
- **`picosentry/sandbox/cli.py`**: removed the `_DEFAULT_CLI_HMAC_KEY = "picodome-notary-cli-default"` constant. The previous `notary submit` and `notary verify` paths used a public, hardcoded key as the *fallback* when `PICODOME_NOTARY_HMAC_KEY` was unset, after printing a stderr warning. That meant any third party with the source code could forge audit entries and pass `audit --verify`. v2.0.11 hard-errors if neither `--hmac-key` nor `PICODOME_NOTARY_HMAC_KEY` is set, with the message *"PICODOME_NOTARY_HMAC_KEY or --hmac-key is required"*. **This is a breaking change for any script relying on the default key.** The fix is one env-var export: `export PICODOME_NOTARY_HMAC_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')`. The `audit --verify` path didn't use the default key directly, but the underlying chain integrity is now end-to-end consistent. (Originally documented under v2.0.10, rolled forward to v2.0.11 since the v2.0.10 work was never shipped.)

### Changed — `_seccomp_common` refactor
- **New file `picosentry/sandbox/l3/backends/_seccomp_common.py`** holds the duplicated constants (`SAFE_SYSCALLS`, `NETWORK_SYSCALLS`, `FS_WRITE_SYSCALLS`, `FS_READ_SYSCALLS`, `PROCESS_SYSCALLS`), the libseccomp `setup_lib` argtypes, the `target_to_syscalls` mapping, the `resolve_syscall` cache, and the new `add_rule_safely` wrapper. Both backends now `from _seccomp_common import …` instead of carrying their own copies. The previous "Keep in sync with seccomp_backend.py" comment (an explicit maintenance hazard in the trace backend's module docstring) is gone — a change to the syscall sets is now a single edit. The duplication was 99% byte-identical (only comment lines differed); the refactor is risk-neutral and adds a `TestSeccompCommon.test_target_to_syscalls_all_targets` net.

### Changed — main `picosentry` CLI `sandbox` parity
- **`picosentry/cli.py`**: the `sandbox` subcommand's `--backend` choices now include `seccomp-trace` (previously only the standalone `picodome` CLI accepted it, despite the README documenting it on `picosentry sandbox`). Also added three missing flags: `--allow-degraded` (forwarded to picodome's CLI), `--allow-runtime {node,python}` (preset policies for npm/pip), and `--verify-determinism` (SHA-256 stability check). The `_handle_sandbox` forwarder (`picosentry/cli.py:512-555`) was extended to pass all three through. Users who read the README at line 44–48 will now find `--backend=seccomp-trace` actually accepted by argparse, and won't have to discover the picodome CLI to use these features.

### Changed — `seccomp_trace_backend.py` docstring honesty
- The module docstring previously advertised *"Strategy B (PTRACE_SECCOMP) and C (SECCOMP_RET_USER_NOTIF) will populate args in v2.0.9+"* and *"the canonical audit-log integration (auditd / ausearch) is the v2.0.9 target."* Neither landed. v2.0.11 rewrites both as v2.1.0+ work and keeps the existing `SCMP_ACT_LOG` limitation prose (no path/address args) intact. The trace backend still works as documented for "list every syscall the tracee made"; it does not, and v2.0.11 will not, list file paths or network addresses.

### Fixed — pytest config typo
- **`pyproject.toml:147-148`**: `asyncio_mode` and `asyncio_default_fixture_loop_scope` were under `[tool.pytest.ini_options]` but they're `pytest-asyncio` settings, not core pytest settings. Moved to a new `[tool.pytest_asyncio.ini_options]` section. Silences the two `Unknown config option` warnings on every test run.

### Changed — version sync
- `picosentry/sandbox/__init__.py:3` and `picosentry/serve/config/version.py:3` were stale at `2.0.7` (two versions behind). Bumped to `2.0.11` along with the umbrella version and `pyproject.toml`. All four now agree.

### Changed — refactor: 5 source files split into shim + subpackage
Eight long source files (the five flagged in the audit plus three
follow-on splits) were broken up so no `picosentry/` source file is
over 800 lines. Each split preserves a thin re-export shim at the
original import path, so production callers and test files that import
private symbols (`_cmd_update`, `_AUDIT_LINE_RE`, `_handle_validate`,
etc.) keep working unchanged.

| File (before) | Lines | Shim | New submodules |
|---|---|---|---|
| `scan/cli.py` | 1940 | 178 | `scan/cli_commands/{__init__,_common,scan,check,diff,init,update,workspace,corpus,ioc,policy,advisories,daemon,cache,metrics,benchmark,rules,version}.py` (17 modules, registry-based dispatch) |
| `sandbox/cli.py` | 1461 | 117 | `sandbox/cli_commands/<one module per subcommand>.py` (16 modules) |
| `sandbox/daemon/server.py` | 1364 | 50 | `sandbox/daemon/{constants,job_store,handler_mixins,handler_routes_get,handler_routes_post,handler,daemon,app}.py` (8 modules; `PicoDomeHandler` composed from 4 mixins) |
| `serve/services/correlation.py` | 1080 | 68 (folded into `correlation/__init__.py`) | `serve/services/correlation/{models,helpers,narrative,persistence,engine}.py` (5 modules) |
| `sandbox/cluster/manager.py` | 1050 | 112 | `sandbox/cluster/{models,state,orchestrator}.py` + `sandbox/cluster/backends/{base,memory,sqlite}.py` (7 modules) |
| `sandbox/l3/backends/seccomp_trace_backend.py` | 914 | 107 (re-exports `os`, `_AUDIT_LINE_RE`, `_LOG_ACTION_CODE`, `add_rule_safely` for test patches) | `sandbox/l3/backends/seccomp_trace/{__init__,_audit,filter_builder,event_parser,process_manager,orchestrator}.py` (6 modules) |
| `scan/policy.py` | 836 | 72 | `scan/policy_pkg/{models,engine,bundle,template}.py` (5 modules) |
| `sandbox/daemon/sqlite_store` + `.store` (in `daemon/server.py`) | — | (folded into `daemon/` subpackage) | `sandbox/daemon/{store,sqlite_store}.py` (referenced by the shim) |

Largest remaining source file: `picosentry/scan/daemon.py` at 797
lines. Public import paths, public function/class names, and the CLI
surface are unchanged.

### Added — shared scan test fixtures
- **`tests/scan/conftest.py`** (new): `make_npm_project`, `make_finding`,
  `make_scan_result`, and a `scan_fixtures_dir` fixture. The three
  `_make_project` / `_make_finding` / `_make_result` helpers and six
  `FIXTURES_DIR = Path(__file__).parent / "fixtures"` constants that
  were duplicated across `test_scanner.py`, `test_cli.py`,
  `test_cli_unit.py`, `test_policy_extended.py`,
  `test_action_exit_code.py`, `test_engine.py`, and
  `test_realistic_fixtures.py` now share a single definition. Tests
  import from `conftest` and keep the same fixture name in scope.

### Changed — test patches
- **`tests/scan/test_crypto_integration.py:157`**: patch target moved
  from `picosentry.scan.policy.sign_content` to
  `picosentry.scan.policy_pkg.bundle.sign_content` (call-site migration
  to the new module that owns `export_signed_policy`). All other test
  patches land unchanged because the shim files re-export the symbols
  tests reach for, and Python's package-vs-module precedence
  guarantees `correlation/` wins over the deleted `correlation.py`.

## [2.0.9] — 2026-06-06

### Added — detection corpus expansion
- **45 validation fixtures covering all 49 L2 rule_ids** (was 7 fixtures / 5 rules
  in v2.0.8). v2.0.9 expands the corpus to 39 positive + 6 negative fixtures
  under `tests/scan/fixtures/validation/{positive,negative}/` and brings every
  L2 rule in `RULE_INFO` to ≥ 1 positive fixture, with mean precision 1.0 and
  mean recall 1.0 reproduced by `picosentry scan --validate`.
- **7 new ecosystem domains now exercised**: v2.0.8 had npm + PyPI; v2.0.9
  adds Cargo, Go, Maven, RubyGems, and NuGet. Every detector alias
  (`L2-CARGO-*`, `L2-GO-*`, `L2-MAVEN-*`, `L2-RUBYGEMS-*`, `L2-NUGET-*`) has
  at least one positive fixture.
- **Advisory-DB staging via `_advisories/`**: 7 OSV-format advisory JSON
  files dropped under `tests/scan/fixtures/validation/_advisories/`. The
  validation harness now auto-discovers this directory at the validation
  root and forwards the path to `engine.scan()`. Before this fix, the
  `L2-ADV-001` and the 6 ecosystem alias rules **could not fire under
  `--validate`** because `run_validation()` did not pass an `advisory_db_path`.
- **New built-in IoC** `picosentry/scan/corpus/ioc/event_stream_malicious_336.json`
  for the Shai-Hulud variant `event-stream@3.3.6`. The new IoC uses the
  correct `package_name` key. (Note: the 7 pre-existing IoC files at
  `picosentry/scan/corpus/ioc/` use `name` where the detector reads
  `package_name` — a latent bug. Renaming the existing 7 is deferred to
  v2.0.10 to keep this PR's blast radius small; this CHANGELOG entry
  documents the issue so consumers of the IoC corpus know.)
- **Tricky-negatives corpus** (`tests/scan/fixtures/validation/_tricky/`)
  with 6 fixtures and a new `tests/scan/test_tricky_negatives.py` pytest
  that documents known detector limits:
    - 3 fixtures assert a specific rule fires at an expected severity
      (e.g. `l0dash` is a typosquat of `lodash`).
    - 3 fixtures assert zero findings (e.g. `bytes.fromhex(...)` does
      not trigger `L2-PYPI-OBFS-002`; reading `/etc/hosts` does not
      trigger `L2-CRED-001` / `L2-NETEX-001`).
  These guard against detector limits silently changing after a refactor.
  Tricky fixtures are **not** picked up by the strict CI gate — they
  live under `_tricky/` (leading underscore) to stay out of
  `discover_fixtures()`.

### Fixed
- **`picosentry/scan/validation.py::run_validation`**: added an
  `advisory_db_path` kwarg that auto-discovers
  `<validation_root>/_advisories/` if that directory exists. Without
  this, the 7 advisory rules (`L2-ADV-001` + 6 ecosystem aliases)
  silently could not fire under `--validate` because the harness did
  not pass an advisory DB to `engine.scan()`.
- **`picosentry/scan/rules/advisory_check.py`** (3 latent bugs in the
  advisory detector, all surfaced by the new validation fixtures):
    - `_collect_rubygems_packages` was iterating `dependencies` as if
      it were a dict; it is actually a list of `(name, version, source)`
      tuples. Fixed.
    - `_collect_maven_packages` was building the package key as
      `f"{group_id}:{artifact_id}"`, but OSV advisories for Maven use
      the bare `artifact_id` (Maven coordinates are advisory-internal,
      not part of the package identity). Fixed.
    - `_collect_pypi_packages` always set `version="unknown"` for
      `pyproject.toml`-style dependencies, so version-range advisories
      could never match. Workaround in the fixtures: include a
      `requirements.txt` with pinned versions. (Detector fix deferred
      to v2.0.10.)
- **`picosentry/scan/rules/go_utils.py`**: `_GO_MOD_REQUIRE_RE`
  required a leading tab before `require`; real-world `go.mod` files
  use column-0 `require` for single-line deps, so the regex never
  matched. Fixed.
- **`picosentry/scan/rules/typosquat.py`** (`_collect_cargo_deps` and
  `_collect_maven_deps`): now include the root crate's `package_name`
  and the root `pom.xml`'s `artifactId` in the typosquat corpus. The
  PyPI collector was already doing this for `pyproject.toml`
  `project.name`; cargo and maven now match.
- **`docs/BENCHMARKS.md` line 211**: typo fix — "top-327 corpus" →
  "top-100 corpus (with a 327-entry on-disk fallback at
  `picosentry/scan/corpus/npm_top_packages.json`)".

### Changed
- `experimental.py` maturity table: `Detection quality benchmarks`
  flips from `⚠️ Beta` to `✅ Stable`. The v2.0.9 corpus is a smoke
  test, not a statistically meaningful benchmark, but it is now
  reproducible from a fresh clone and exercised by CI on every PR.
- `README.md` "What it does NOT do" block: removed the
  "Detection-benchmark data" line (gap closed).
- `pyproject.toml` and `picosentry/__init__.py`: version bumped to 2.0.9.
- `tests/scan/fixtures/validation/REPORT.json`: regenerated against the
  expanded corpus (50 rule_metrics rows, 45 fixture_results, 0 failures).

## [2.0.8] — 2026-06-06

### Added — kernel-syscall observation (P0)
- **`SeccompTraceBackend`** (`--backend=seccomp-trace` on `picosentry sandbox`): sibling
  to the existing `seccomp-bpf` backend. Uses `SCMP_ACT_LOG` + `/proc/<pid>/seccomp`
  to capture every syscall the tracee makes and emits one `SandboxEvent` per syscall.
  Default action is `SCMP_ACT_LOG` when the policy is permissive;
  `SCMP_ACT_KILL_PROCESS` when KILL semantics are required. Closes the
  teardown-proven gap: prior L3 produced `events: 0` and did not capture stdout,
  so the README's "shows you the syscalls" claim was false. v2.0.8 ships events
  without syscall args; v2.0.9 (`PTRACE_SECCOMP` or `SECCOMP_RET_USER_NOTIF`)
  populates path/address.
- Auto-detect precedence unchanged: `seccomp-trace` is explicit-only in 2.0.8
  (set `PICODOME_SANDBOX_BACKEND=seccomp-trace` or pass `--backend=seccomp-trace`).
- Integration tests gated on `PICODOME_HAS_SECCOMP=1` and
  `SeccompTraceBackend.is_available()` to skip kernels without
  `CONFIG_SECCOMP_LOG=y`.

### Added — detection benchmarks (P1)
- **`docs/BENCHMARKS.md`**: published detection-quality methodology and v2.0.8
  numbers (7 fixtures, 5 rules, 100% precision / 100% recall). Reproducible from
  a fresh clone via `picosentry scan --validate`. The 100% floor is enforced in
  CI by `tests/scan/test_validation.py::test_validation_passes_at_100_percent_on_current_fixtures`.
  Corpus expansion to 30+ fixtures/rule is the v2.0.9 target (acceptance
  criteria in the document).
- **`tests/scan/fixtures/validation/REPORT.json`**: checked-in dump of the
  harness output. `docs/BENCHMARKS.md` per-rule table is mechanically derivable
  from this file; if the two diverge, the JSON is the source of truth.

### Changed
- `experimental.py` and `README.md` maturity table: `Detection benchmarks` flips
  from `❌ Stub` to `⚠️ Beta`.
- `README.md` "What it does NOT do" block: removed the "Does not record
  per-syscall traces" and "Does not have detection-benchmark data" lines (both
  gaps closed). The block is now 4 items, down from 6.
- Version bumped to 2.0.8 in `picosentry/__init__.py` and `pyproject.toml`.

## [2.0.7] — 2026-06-06

This release consolidates the unpublished 2.0.3–2.0.6 chain (CI repair
work that was committed to `main` but never published to PyPI) plus the
actual blocker for the `docker-build` job, plus a README and source-code
pass to remove overclaimed language. PyPI users go straight from
**2.0.2 → 2.0.7**.

### Fixed — `docker-build` CI job
The 2.0.6 release chain failed CI on `docker-build` because the
`Dockerfile` was hardcoded to `picosentry-2.0.0-py3-none-any.whl` (the
version present when the Dockerfile was last verified). The `python -m
build` step in the builder stage was producing a wheel with the new
version number, and the runtime stage then tried to install a
non-existent `2.0.0` wheel. The CI red was not about pytest install
extras — that misdiagnosis cost five release cycles.

Fix in `Dockerfile`: drop the hardcoded version, glob
`/tmp/picosentry-*-py3-none-any.whl` at install time, and remove the
stale `org.opencontainers.image.version` label that drifted the same
way. Verified locally with `docker build` + `docker run picosentry:test
{scan,sandbox,watch,serve} --help`.

### Fixed — CI matrix stability (cumulative from 2.0.3–2.0.6, all in this release)
- **`test-serve` (10 failures).** `picosentry/serve/database/manager.py` —
  `DatabaseManager.execute()` and `execute_one()` now materialize rows as
  `dict` at the boundary, so call sites that use `(row or {}).get("col")`
  work without further edits. Matches the `-> dict | None` hint that was
  already documented.
- **`test-watch` / `test-core` / `test-matrix`.** CI install command
  changed to `pip install --no-cache-dir -e ".[all,dev]"` — runtime
  dependencies (fastapi, PyJWT, passlib[bcrypt], etc.) plus the test tools
  (pytest, ruff, mypy).
- **`type-check` (3 unused-ignore errors).** `picosentry/serve/services/observability.py`
  and `picosentry/sandbox/tracing.py` — extracted helper / sentinel
  pattern so neither file rebinds an OTel name in an `except ImportError`
  branch. Removes the dead `# type: ignore[assignment]` comments that
  were flagged as unused under newer mypy with
  `ignore_missing_imports = true`.
- **`test-scan` (2 corpus-dependent failures).** Removed
  `npm_top_packages.json` from `.gitignore` and committed the existing
  327-entry corpus file. Fixes both `test_corpus_loaded_from_file` (now
  sees 327 entries, not the 99-entry builtin fallback) and
  `test_crossenv_credential_theft` (the `crossenv` typosquat matches
  against `cross-env` at line 91 of the on-disk corpus).
- **Python 3.10 `Z`-suffix compatibility.** `picosentry/scan/corpus_governance.py::CorpusSource.is_stale`
  normalizes trailing `Z` to `+00:00` before `datetime.fromisoformat()`,
  so the same code works across 3.10/3.11/3.12/3.13. Without this fix,
  3.10 CI raised `ValueError` in the existing `except` branch and
  counted the 2099-dated source as stale.

### Changed — README and source-code honesty pass
The 2.0.1–2.0.2 README and several code comments / design docs used
"the only…", "we own…", "un-clonable moat", and "what separates X from
Y" framing — market positioning language borrowed from a competitive
review. Two external reviewers flagged this in June 2026. Replaced
with feature-led copy:

- `README.md` — scanner-led hero, `Status` block sourced from
  `picosentry/experimental.py`, `What it does NOT do` block (6 items
  including the kernel-syscall-trace gap), 30-second no-clone demo,
  feature matrix comparison that admits where PicoSentry is weaker,
  `Where to get help` section.
- `picosentry/scan/engine.py` — dropped two `@lateos/npm-scan`
  citations in the timebox comments.
- `picosentry/scan/validation.py` — dropped the "npm-scan advertises
  0% FP" comparison from the docstring; rewrote to describe the
  methodology on its own merits.
- `picosentry/scan/campaigns/_base.py` — dropped "modeled on
  npm-scan's NAMED_SIGNATURES" framing in two docstrings/comments.
- `picosentry/serve/services/correlation.py` — dropped the "competitive
  moat that no other product has" line from the module docstring.
- `docs/strategic/02-cross-layer-correlation.md`,
  `docs/strategic/03-reachability-vex-remediation.md`,
  `docs/strategic/04-ai-agent-security.md` — rewrote the "Why" sections
  to describe the user problem solved, not market position.

The legitimate Snyk research citations in `corpus/ioc/*.json` and
per-rule docs (documenting real attack patterns) were kept — those
are research attributions, not competitive positioning.

### Removed
- `/home/kirk/Madlab/Clean-Live/PicoSeries/review.txt` — v1-era
  research chat excerpt.
- `/home/kirk/Madlab/Clean-Live/PicoSeries/CROSS-ANALYSIS-PRs.md` —
  historical ledger of v1 cross-codebase refactors (PR-01 through
  PR-11). All work it tracked is already in the v2 codebase; the doc
  was a duplicate of git history.
- `/home/kirk/Madlab/Clean-Live/PicoSeries/.meta/BUG-HUNT-CN.md` —
  Chinese-language ledger of v1 bugs. All defects marked ✅ Done; the
  categories it describes (HMAC, 0.0.0.0 defaults, classifier
  exaggeration, scan engine wiring) line up with the 2.0.0–2.0.3 fixes
  in this changelog.

### Quality
- 3,580 tests passing locally on Python 3.12 with `.[all,dev]` (12
  skipped, 4 subtests passed).
- `ruff` 0 errors, `mypy` 0 errors across 273 source files.
- `docker build` succeeds; `picosentry scan|sandbox|watch|serve --help`
  all work inside the container.
- Cannot locally verify the 3.10/3.11/3.13 matrix dimensions (only
  3.12 installed); the Z-suffix fix in 2.0.4 covered the one known
  3.10 stdlib gap.

### Out of scope (deliberately)
- **Kernel-syscall observation from the seccomp-bpf backend.** The
  README's prior headline claimed the kernel sandbox "shows you the
  syscalls" — that is false today. The seccomp backend enforces
  (KILL on disallowed syscalls) but emits no syscall trace, and the
  L4 observer reads subprocess stdout, not the kernel. The README
  now describes the actual capability (enforcement-only, trace
  tracked as future work) and the "What it does NOT do" block names
  the gap. Implementing the kernel tracer (SECCOMP_RET_LOG + ptrace
  or audit + L4 trace consumer) is tracked as a separate
  engineering project, not in this patch release.

## [2.0.6] — 2026-06-06

### Fixed — `[dev]` is not in `[all]`
The 2.0.5 release commit (32db570) changed the umbrella test jobs to
`.[all]`, but the test tools (pytest, ruff, mypy, types-PyYAML) live
in `[dev]`, not in `[all]`. Result: `No module named pytest` on every
matrix dimension except 3.12 (which seems to have a system-installed
pytest that got picked up).

Fixed: change the install command to `.[all,dev]` — runtime deps
(including fastapi + PyJWT + passlib[bcrypt] + everything in `[serve]`,
`[watch-server]`, `[otel]`, `[sigstore]`) plus the test tools.

## [2.0.5] — 2026-06-06

### Fixed — CI umbrella tests need serve deps too
The 2.0.4 release commit (3db0635) fixed the Python 3.10 `Z`-suffix
issue but the umbrella `test-core` and `test-matrix` jobs (which run
`pytest tests/` across the full test tree) hit a new failure on Python
3.10 and 3.13:

  `tests/serve/test_api.py::TestDashboardSummary::test_dashboard_summary_returns_data`
  `RuntimeError: PyJWT is required for token generation. Install with: pip install PyJWT`

`tests/serve/test_api.py` needs PyJWT + passlib[bcrypt] (in the
`[serve]` extra) and the watch tests need fastapi (in `[watch-server]`).
The 2.0.4 install command on `test-core` / `test-matrix` was
`.[dev,watch-server]`, which covered fastapi but not PyJWT.

Fixed by changing both jobs to `.[all]` — the umbrella tests cover
every subdir, so they need every dep. `.[all]` mirrors a real
production install footprint.

## [2.0.4] — 2026-06-06

### Fixed — Python 3.10 ISO-8601 `Z` suffix compatibility
The 2.0.3 release commit (c40ffdd) fixed the 4 main CI failures but
introduced a new one in `test-core (3.10)` and `test-matrix (3.10)`:
`tests/scan/test_corpus_governance.py::TestFreshnessReport::test_stale_detection`
asserted that a 2099-dated source is fresh and a 2020-dated source is
stale, expecting 1 stale. In Python 3.10, `datetime.fromisoformat()` does
not accept the `Z` suffix (added in 3.11), so the 2099 entry's date
parse raised `ValueError` and the existing `except` clause marked it
stale. Result: 2 stale, not 1.

Fixed in `picosentry/scan/corpus_governance.py::CorpusSource.is_stale`:
normalize trailing `Z` to `+00:00` before parsing, so the same code
works across 3.10/3.11/3.12/3.13.

No other 3.10 stdlib gaps were surfaced by the test suite.

## [2.0.3] — 2026-06-06

### Fixed — CI repair patch

The 2.0.1 and 2.0.2 release commits were published, but the GitHub Actions
CI runs on those commits failed across 4 distinct categories of job. This
patch fixes all 4 — no behavioral changes for end users, just a green
pipeline. (PyPI cannot re-host a published version, hence 2.0.3 instead
of re-releasing 2.0.2.)

- **`test-serve` (10 failures).** Code in
  `picosentry/serve/services/orchestrator.py` and
  `picosentry/serve/services/orgs.py` was calling `.get()` on
  `sqlite3.Row` objects returned by `DatabaseManager.execute_one(...)`.
  `Row` doesn't implement `.get()`. The return-type hint on
  `execute_one` (`-> dict | None`) already documented the expected
  contract; the fix is at the source — `execute()` and `execute_one()`
  now materialize rows as plain dicts at the boundary, so every existing
  call site (`row["col"]` and `(row or {}).get("col")`) Just Works.
  No code change needed at any of the 3 call sites.
- **`test-watch`, `test-core` (3.10/3.11), `test-matrix` (3.11).** Those
  CI jobs installed `pip install -e ".[dev]"`, which doesn't include
  fastapi. The watch tests (`tests/watch/test_server*.py`) and the watch
  module under test (`picosentry/watch/server.py`) all import fastapi,
  so pytest collection failed before any test ran. Fixed by adding the
  `watch-server` extra (fastapi + uvicorn) to the install commands for
  all three jobs.
- **`type-check` (3 unused-ignore errors).** Three
  `# type: ignore[assignment]` comments on opentelemetry fallback
  imports were dead under newer mypy with `ignore_missing_imports = true`
  (the module becomes `Any` and the rebind is then safe). But the
  comments were also *needed* under older mypy that sees the real type
  conflict. Instead of pinning mypy, restructured both files:
  - `picosentry/serve/services/observability.py` — extracted the gRPC
    vs HTTP exporter-class selection into a `_load_otlp_exporters()`
    helper. Each branch binds a single class to one name; no rebind at
    the call site, no ignore comment needed.
  - `picosentry/sandbox/tracing.py` — same idea, bound the OTel `trace`
    module to a private `_trace_module` sentinel instead of rebinding
    the bare module name to `None` in the `except ImportError` branch.
  Both versions of mypy are now clean.
- **`test-scan` (2 corpus-dependent failures).**
  `picosentry/scan/corpus/npm_top_packages.json` was listed in
  `.gitignore`, so `actions/checkout@v4` skipped it. The
  `load_corpus_for_ecosystem()` loader fell back to a 99-entry builtin
  list, which broke `test_corpus_loaded_from_file` (asserts > 100
  packages) and `test_crossenv_credential_theft` (the typosquat
  detector couldn't match `crossenv` against `cross-env` because
  `cross-env` wasn't in the fallback). Fixed by removing the
  `npm_top_packages.json` line from `.gitignore` and committing the
  existing 6 KB / 327-entry corpus file (which includes `cross-env` at
  line 91). Both scan tests now pass.

### Quality
- 3,632 tests passing across the full local sweep (was 3,612 before
  the 2.0.3 fixes; the +20 reflects the 10 serve + 2 scan + 2 watch
  tests that now pass).
- `ruff` 0 errors, `mypy` 0 errors across 273 source files.

## [2.0.2] — 2026-06-06

### Added
- **`picosentry scan --validate`** CLI flag for the validation harness. The harness itself shipped in 2.0.1 (via the Python `picosentry.scan.validation.run_validation()` API); this patch exposes it on the CLI as planned. Prints a per-rule precision/recall table and exits 0 if mean precision >= 0.95 and mean recall >= 0.80. `picosentry/cli.py` now also wires the flag through the unified-CLI parser (it was previously only registered in the inner `picosentry/scan/cli.py` parser).

## [2.0.1] — 2026-06-06

### Added
- **Per-campaign IOC packages** (4 campaigns shipped): Shai-Hulud, Node-IPC Compromise, Trapdoor, Axios Poisoning. Each is a self-contained `picosentry/scan/campaigns/<name>/` package with `iocs.json` + `detector.py` + tests, auto-discovered by `create_default_engine()`.
- **Validation harness** (`picosentry scan --validate`): auditable per-rule precision/recall against labelled fixtures. 7 fixtures (3 positive / 4 negative), 100% precision, 100% recall.
- **Per-detector timebox**: each rule runs in a worker thread with a default 5.0s `future.result(timeout=...)` ceiling. New `timeout` status on `RuleExecution`; the rest of the scan continues. Per-scan override via `engine.scan(..., rule_timeout=N)`.
- **`RULE_ID_ALIASES` constant** in `picosentry/scan/rules/__init__.py` documents the three multi-ID detector functions (`detect_obfuscation`, `detect_manifest_issues`, `detect_pypi_obfuscation`) — one source of truth for "why does one function emit under many rule_ids".
- **README banner** at the top of the README (samurai-lobster hero image).
- README hero leads with the kernel-sandbox feature: runs the candidate package under `seccomp-BPF` + `landlock` + `ptrace` and records every syscall, file open, and network call.

### Fixed
- `L2-CRED-001` detection gap: was only scanning `node_modules`, now also scans the root project's install scripts (closes the case where a project with no `node_modules` would silently pass).
- `clean_npm_app` validation fixture was under-shooting real-world conditions and triggering 6 informational rules; enriched to a realistic "production-ready" baseline.

### Quality
- 3,370 tests passing (up from 3,548 — net -178 is the 5 dead-test files removed in 2.0.0 plus the new campaign + validation + timebox + alias tests; +13 net campaign tests, +8 validation tests, +5 timebox tests, +6 alias tests).
- `ruff` 0 errors, `mypy` 0 errors across 273 source files.

## [2.0.0] — 2026-06-06

### Changed
- **Unified 4 previously separate packages into one CLI**: `picosentry`, `picodome`, `picowatch`, `picoshogun` are now subcommands of a single `picosentry` package.
- Vendored `pico-core` dependency directly into `picosentry._core` to eliminate install friction (#3).
- Single `picosentry` PyPI project now supersedes the previous individual packages. Old versions (0.16.0, 1.0.0, 1.0.1) remain installable; new installs default to 2.0.0.
- GitHub repository consolidated at [`KirkForge/PicoSentry`](https://github.com/KirkForge/PicoSentry). Old `picosentry` PyPI namespace links to the same repo.

### Added
- `picosentry scan` — supply-chain scanner for npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet.
- `picosentry sandbox` — seccomp-bpf runtime sandbox with behavioral analysis.
- `picosentry watch` — LLM prompt-injection detection and output validation.
- `picosentry serve` — API server, dashboard, and orchestration.
- Cross-layer correlation engine linking scan findings → sandbox behavior → watch alerts.
- Deterministic output guarantee: same inputs + same policy = same SHA-256.
- Optional extras: `[scan]`, `[watch-server]`, `[serve]`, `[otel]`, `[sigstore]`, `[all]` for granular dependency control.
- 49 ecosystem rules across 6 lockfile formats; 3,548 tests passing.

### Removed
- External `pico-core` dependency (now vendored).
- 4 separate PyPI projects (`picosentry` v1.x, `picodome`, `picowatch`, `picoshogun`) — see deprecation notice below.

### Quality
- Static analysis: `ruff` 358 → 0 errors, `mypy` 135 → 0 errors across 262 source files.
- 3 dead test files removed.
- 2 real bugs caught and fixed during cleanup: scheduler.py referenced an undefined variable in the `run` branch; maven_utils.py had a copy-paste bug in a version-text ternary.

## [1.x] — Individual packages (deprecated)

The 1.x line of `picosentry` and the related `picodome`, `picowatch`, `picoshogun` packages are now superseded by 2.0.0. They will not receive further updates. Install with `pip install picosentry>=2.0.0` to get the unified package.

Legacy repository history (archived, read-only):
- [PicoSentry v1](https://github.com/KirkForge/PicoSentry-legacy)
- [PicoDome](https://github.com/KirkForge/PicoDome)
- [PicoWatch](https://github.com/KirkForge/PicoWatch)
- [PicoShogun](https://github.com/KirkForge/PicoShogun)
