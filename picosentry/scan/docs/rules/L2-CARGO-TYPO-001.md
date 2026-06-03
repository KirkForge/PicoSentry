# L2-CARGO-TYPO-001: Cargo Crate Typosquatting

**Severity:** HIGH  
**Category:** typosquat  
**Ecosystem:** cargo  

## Description

Detects Rust crate dependencies whose names are within edit distance ≤2 of
popular crates in the cargo corpus. Attackers register misspelled crate names
on crates.io to trick developers into importing malicious code.

## Detection Method

The rule extracts all dependency names from `Cargo.toml` (including `[dependencies]`,
`[dev-dependencies]`, and `[build-dependencies]`), then compares each name against
the corpus of top Rust crates using Levenshtein edit distance.

## Mitigation

- Double-check crate names before adding them to your Cargo.toml.
- Verify the crate source and author before importing.
- Use `cargo audit` to check for known vulnerabilities in dependencies.

## References

- [Typosquatting on npm (similar pattern)](https://blog.npmjs.org/post/186451959906/typosquatting-on-npm)
- [Snyk: Typosquatting Attacks](https://snyk.io/blog/typosquatting-attacks/)