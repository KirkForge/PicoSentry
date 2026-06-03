# L2-CARGO-ADV-001: Cargo Advisory Vulnerability Detection

**Severity:** HIGH  
**Category:** vulnerability  
**Ecosystem:** cargo  

## Description

Checks Rust crate dependencies against a local OSV-format advisory database.
Flags crates with known CVEs or Rust-specific security advisories.

## Detection Method

The rule collects all crate names and versions from Cargo.toml and Cargo.lock,
then checks each against the local advisory database. The advisory database
is loaded from the most specific available source:
1. Explicit `--advisory-db` CLI argument
2. Built-in corpus advisories directory
3. Default advisory directory (`~/.local/share/picosentry/advisories/`)

## Mitigation

- Update affected crates to their patched versions.
- Run `cargo audit` regularly.
- Subscribe to RustSec advisory announcements.

## References

- [RustSec Advisory Database](https://rustsec.org/)
- [OSV Format](https://ossf.github.io/osv-schema/)