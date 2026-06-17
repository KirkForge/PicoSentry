# L2-BUILD-001 — Dangerous build-time hooks

**Severity:** CRITICAL  
**Category:** execution  
**Ecosystems:** Cargo, Go, RubyGems, Maven, NuGet

## What it detects

`L2-BUILD-001` flags build scripts and manifest entries that perform dangerous
actions during dependency installation or package build. Unlike `L2-POST-001`
(npm lifecycle scripts) and `L2-PYPI-POST-001` (`setup.py`), this rule covers the
build-time hooks used by compiled and JVM ecosystems:

| Ecosystem | Files scanned | Dangerous signals |
|-----------|---------------|-------------------|
| Cargo | `Cargo.toml`, `build.rs`, `*.rs`, `*.toml` | `Command::new`, downloads via `reqwest`, credential reads, obfuscated payloads |
| Go | `go.mod`, `*.go`, `*.mod` | `//go:generate` running `curl`/`go run`/shell, network downloads, `exec` |
| RubyGems | `.gemspec`, `Rakefile`, `extconf.rb`, `Gemfile`, `*.rb` | `system`, backticks, native compile with network/credential access |
| Maven | `pom.xml`, `*.xml` | `exec-maven-plugin`, `maven-antrun-plugin`, shell executions, credential reads |
| NuGet | `.csproj`, `.nuspec`, `.targets`, `.props`, `.ps1` | MSBuild targets running PowerShell, `Invoke-WebRequest`, `Start-Process` |

A finding is raised when a build-time file contains any of these patterns:

- **Subprocess execution** during build (`Command::new`, `os.system`, `child_process`,
  `Start-Process`, `IEX`, backticks, `sh -c`, etc.)
- **Network downloads** during build (`curl`, `wget`, `Invoke-WebRequest`,
  `reqwest`, `go run`, package-manager installs)
- **Obfuscated payloads** adjacent to build hooks (base64, hex escapes,
  `include_bytes!`, compressed data)
- **Credential reads** (`.cargo/credentials`, `~/.ssh`, `CARGO_REGISTRY_TOKEN`,
  `NPM_TOKEN`, `process.env.*SECRET*`)
- **System path writes** (`/usr/bin`, `C:\Windows`, `~/.bashrc`, `PATH=...`)

## Why this matters

Malicious build hooks are a common supply-chain attack vector because they run
automatically when a developer installs or builds a dependency:

- **Rust:** malicious `build.rs` can download and execute payloads during `cargo build`.
- **Go:** `//go:generate` directives can run arbitrary shell commands.
- **RubyGems:** `extconf.rb` can compile native extensions that include malicious
  behavior or exfiltrate credentials.
- **Maven:** plugin executions in `pom.xml` can run shell commands as part of the build.
- **NuGet:** MSBuild targets and init scripts run during restore/build and can
  execute PowerShell payloads.

## Remediation

- Move any required shell/network work out of dependency build scripts and into
  explicit, reviewed CI steps.
- Vendor downloaded artifacts in the repository instead of fetching them at
  build time.
- Never read credential files or secret env vars from a dependency build hook.
- Audit every `build.rs`, `extconf.rb`, `go:generate`, Maven plugin, and NuGet
  target before adding it to your dependency tree.

## False-positive guidance

Legitimate build scripts sometimes compile native code or read benign env vars.
If a finding is expected (e.g., a project-local `build.rs` that only writes to
`OUT_DIR`), suppress it via a baseline fingerprint or policy exclusion.

## References

- [crates.io security incident postmortem](https://blog.rust-lang.org/2023/10/25/crates-io-postmortem.html)
- [Dependency confusion — Alex Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec61c)
