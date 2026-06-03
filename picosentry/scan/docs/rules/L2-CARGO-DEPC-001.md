# L2-CARGO-DEPC-001: Cargo Dependency Confusion

**Severity:** CRITICAL  
**Category:** dependency  
**Ecosystem:** cargo  

## Description

Detects private/internal-looking crate names declared in Cargo.toml without
a private registry configuration. Attackers can register internal-looking
crate names on crates.io, causing `cargo build` to resolve the public malicious
version instead of the intended private one.

## Detection Method

The rule checks each dependency in Cargo.toml for patterns that suggest
internal/private usage (e.g., `internal-*`, `private-*`, `my-*`, `company-*`).
If no private registry is configured (via `[registries]` in `.cargo/config.toml`,
or `[patch]` sections in Cargo.toml, or path dependencies), the dependency is
flagged.

## Mitigation

- Configure a private registry via `[registries]` in `.cargo/config.toml`.
- Use `[patch]` sections to pin internal crates to local paths.
- Use path dependencies for local development crates.

## References

- [Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d6086b0d4)
- [Cargo Registries Documentation](https://doc.rust-lang.org/cargo/reference/registries.html)