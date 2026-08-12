# Security Attack Surface — PicoSentry

*Primary scope reference for pentest engagement. Cross-references ADR-001 through ADR-005.*

## 1. Entry points

### 1.1 CLI arguments (`picosentry scan`)

- **Input**: Package manifest + lockfile path (npm `package.json`/`package-lock.json`, PyPI `requirements.txt`, Maven `pom.xml`, NuGet `.csproj`, RubyGems `Gemfile`, Cargo `Cargo.toml`, Go `go.sum`)
- **Trust boundary**: User-controlled filesystem path; scanner reads only the declared manifest files. No `--include` / recursive glob that could drag in unexpected files.
- **Attack surface**: A crafted manifest could exploit parser vulnerabilities in the JSON/YAML/TOML/XML parsers. All parsers are stdlib or well-vetted (`pyyaml`, `tomli`, `xml.etree.ElementTree`).

### 1.2 Corpus pack import (`picosentry corpus import`)

- **Input**: Signed JSON corpus pack (`.json` or `.json.gz`)
- **Trust boundary**: Corpus packs are signature-verified against a trusted Ed25519 key before ingestion (ADR-003). Unsigned packs are rejected in production mode.
- **Attack surface**: A maliciously crafted corpus pack could inject false-positive/negative rules. Mitigated by signature verification and the offline deterministic design (ADR-001).

### 1.3 Sandbox backends (`picosentry sandbox`)

| Backend | Trust boundary | Status |
|---------|---------------|--------|
| seccomp-bpf (ADR-002) | Kernel-level syscall allowlist; blocks unexpected syscalls at the kernel boundary | Active (Beta) |
| landlock | Path-based filesystem ACL | **Not implemented** (ADR-002 correction) |
| firejail | Process-level sandboxing; weaker than kernel seccomp | Not implemented |
| Docker | Container isolation; strongest boundary but requires Docker daemon | Not implemented as sandbox backend |

- **Attack surface**: seccomp-bpf is the only kernel sandbox. There is no filesystem path restriction layer beyond the child's CWD and the syscall allowlist. Non-root container operation requires `CAP_SYS_ADMIN`.

### 1.4 Plugin system (ADR-004)

- **Entry point**: `picosentry serve` loads plugins from `plugins/` directory
- **Trust boundary**: Ed25519 manifest signature verification (authenticity) + `PluginHost` subprocess sandbox with deny-by-default capabilities (safety)
- **Attack surface**: A signed-but-malicious plugin is confined to its declared capabilities. Unsigned plugins load in non-production but are sandboxed. Production requires `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`.

### 1.5 Watch daemon (`picosentry watch`)

- **Entry point**: HTTP endpoint receiving LLM output for prompt-injection classification
- **Trust boundary**: Deterministic regex + lexical analysis; no LLM calls in the hot path (ADR-001)
- **Attack surface**: Crafted prompt-injection payloads could bypass the regex classifier. The classifier is deterministic but may miss novel injection patterns.

### 1.6 Serve API (`picosentry serve`)

- **Entry point**: FastAPI HTTP server with JWT + API-key authentication
- **Trust boundary**: Token/API-key auth, tenant isolation via `org_id`, role-scoped API keys
- **Attack surface**: API auth bypass, tenant isolation failure, JWT token handling, credential brute force

### 1.7 Admission webhook (`picosentry admission`)

- **Entry point**: Kubernetes admission webhook (HTTPS)
- **Trust boundary**: TLS mutual authentication, Kubernetes API server trust
- **Attack surface**: MITM on webhook TLS, misconfiguration of admission rules

## 2. Trust boundaries

| Boundary | Enforcement | ADR |
|----------|-------------|-----|
| Scanner offline mode | No outbound network calls in scan path | ADR-001 |
| Kernel sandbox | seccomp-bpf syscall allowlist | ADR-002 |
| Plugin admission | Ed25519 signature verification | ADR-004 |
| Plugin safety | Deny-by-default subprocess sandbox | ADR-004 |
| Corpus pack integrity | Signature verification before ingestion | ADR-003 |
| Supply-chain build | uv lockfile + pyproject.toml pinning | ADR-003 |
| Component naming | Public vs internal split (PicoSentry vs picoshogun) | ADR-005 |

## 3. Secrets handling

| Secret | Storage | Scope |
|--------|---------|-------|
| `PICOSHOGUN_SECRET_KEY` | Environment variable (never in code) | JWT signing, session tokens |
| Plugin signing keys | Ed25519 keypair; private key in env var | Plugin manifest verification |
| Docker Hub credentials | GitHub Actions secrets (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`) | CI/CD image push only |
| Sigstore signing | Keyless OIDC (no stored secrets) | Wheel/sdist signing |
| Database credentials | Environment variable (`PICOSHOGUN_DATABASE_URL`) | Serve backend only |

**Policy**: No secrets are committed to the repository. All signing is keyless (OIDC) in CI. Local development uses environment variables.

## 4. Previously-fixed findings (verify by pentester)

| ID | Finding | Fixed in | Verification |
|----|---------|----------|--------------|
| PS-001 | Scanner symlink traversal | v0.1.x | Verify no path traversal via symlinks in manifest |
| PS-002 | Sandbox seccomp allowlist gap | v0.1.x | Verify all unexpected syscalls are blocked |
| PS-003 | Watch prompt injection bypass (basic) | v0.1.x | Verify prompt injection regex covers basic payloads |
| PS-004 | Serve token handling in logs | v0.1.x | Verify no tokens appear in log output |
| PS-005 | Daemon socket permission | v0.1.x | Verify daemon socket has correct permissions |

## 5. Known hardening

| Feature | Description | Ref |
|---------|-------------|-----|
| Offline deterministic scanning | 50 rules across 7 ecosystems, no model calls in scan path | ADR-001 |
| Kernel sandbox (seccomp-bpf) | Syscall allowlist enforced at kernel level | ADR-002 |
| Python/uv packaging | Lockfile pinning, reproducible builds, sigstore signing | ADR-003 |
| Plugin trust boundary | Signing = admission, sandbox = safety; never conflated | ADR-004 |
| Supply-chain evidence | CycloneDX SBOM, SLSA provenance, sigstore wheel signatures | release.yml |
| Docker cosign signing | Container image signed with cosign (pending release.yml update) | Task 2 |
| MFA / TOTP | Login requires a TOTP code when enabled; enroll/verify via `/auth/mfa/*` (`services/auth.py`) | WO2.0.0-007 |
| JWT `jti` revocation | JWTs carry a `jti`; `POST /auth/revoke` adds to a `revoked_tokens` table, `validate_token` rejects revoked `jti`s | WO2.0.0-007 |
| Account lockout | After `LOCKOUT_MAX_ATTEMPTS` (5) failed logins an account locks for `LOCKOUT_WINDOW_MINUTES` (15) | WO2.0.0-007 |
| Role-scoped API keys | Keys minted scoped to a role + org; `get_current_user` accepts `X-API-Key` (`api/deps.py`) | WO2.0.0-010 |
| CORS hardening | Wildcard `*` origin with credentials rejected in `settings.validate()` | WO2.0.0-010 |
| Audit fsync | Audit JSONL writes are fsync'd by default (`PICODOME_AUDIT_FSYNC`) | WO2.0.0-008 |
| Reachability | Advisory findings flag `reachable: bool` (package imported/used) | WO2.0.0-011 |
| Package intel depth | `download_count` + `package_age_days`; `L2-INTEL-001` flags new low-download packages | WO2.0.0-012 |

## 6. Out-of-scope items

- Denial-of-service against production infrastructure
- Social engineering / phishing against KirkForge staff
- Physical attacks on data centers
- Third-party service dependencies (GitHub, PyPI, npm) — mitigated by offline mode (ADR-001)
- Vulnerabilities in upstream dependencies (pyyaml, fastapi, etc.) — tracked by Dependabot

## 7. Cross-references

| Document | Path |
|----------|------|
| ADR-001: Offline deterministic scanner | [`docs/adr/ADR-001-offline-deterministic-scanner.md`](adr/ADR-001-offline-deterministic-scanner.md) |
| ADR-002: Kernel sandbox | [`docs/adr/ADR-002-kernel-sandbox.md`](adr/ADR-002-kernel-sandbox.md) |
| ADR-003: Python/uv packaging | [`docs/adr/ADR-003-python-uv-packaging.md`](adr/ADR-003-python-uv-packaging.md) |
| ADR-004: Plugin trust boundary | [`docs/adr/ADR-004-plugin-trust-boundary.md`](adr/ADR-004-plugin-trust-boundary.md) |
| ADR-005: Component naming | [`docs/adr/ADR-005-picoshogun-picosentry-naming.md`](adr/ADR-005-picoshogun-picosentry-naming.md) |
| Threat model | [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) |
| Pentest engagement guide | [`docs/PENTEST-README.md`](PENTEST-README.md) |
| Model card | [`docs/model-card.md`](model-card.md) |
