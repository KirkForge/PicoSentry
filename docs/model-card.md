# Detection Benchmarks — PicoSentry

*Generated 2026-07-21. Corpus: 1048 fixtures (899 positive, 142 negative, 7 tricky) across 7 ecosystems.*

## Summary

| Metric | Value |
|---|---|
| **Fixtures** | 1048 (899 pos / 142 neg / 7 tricky) |
| **Rules** | 54 |
| **Mean precision** | 94.44% |
| **Mean recall** | 73.79% |
| **Ecosystems** | npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| **Corpus source** | Generated combinatorial variants + hand-curated real-world malware patterns |

## Per-rule precision/recall

| Rule ID | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| L2-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-BUILD-001 | 11 | 0 | 4 | 100.00% | 73.33% |
| L2-BUND-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-AXIOS-POISONING | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-NODE-IPC-COMPROMISE | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-SHAI-HULUD | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-TRAPDOOR | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CARGO-ADV-001 | 2 | 0 | 1 | 100.00% | 66.67% |
| L2-CARGO-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-CARGO-TYPO-001 | 40 | 0 | 0 | 100.00% | 100.00% |
| L2-CRED-001 | 2 | 0 | 2 | 100.00% | 50.00% |
| L2-DEPC-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-ENGIN-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-FORK-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-GO-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-GO-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-GO-TYPO-001 | 26 | 0 | 4 | 100.00% | 86.67% |
| L2-IOC-001 | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-LICENSE-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-LOCK-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-MAINT-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-MANI-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-MANI-002 | 0 | 0 | 1 | 0.00% | 0.00% |
| L2-MAVEN-ADV-001 | 2 | 0 | 1 | 100.00% | 66.67% |
| L2-MAVEN-DEPC-001 | 0 | 0 | 3 | 0.00% | 0.00% |
| L2-MAVEN-TYPO-001 | 18 | 0 | 14 | 100.00% | 56.25% |
| L2-NETEX-001 | 3 | 0 | 2 | 100.00% | 60.00% |
| L2-NUGET-ADV-001 | 2 | 0 | 1 | 100.00% | 66.67% |
| L2-NUGET-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-NUGET-TYPO-001 | 30 | 0 | 0 | 100.00% | 100.00% |
| L2-OBFS-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-OBFS-002 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-OBFS-003 | 1 | 0 | 3 | 100.00% | 25.00% |
| L2-OBFS-004 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-PNPM-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-POST-001 | 34 | 0 | 0 | 100.00% | 100.00% |
| L2-PROV-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-PYPI-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-PYPI-DEPC-001 | 0 | 0 | 3 | 0.00% | 0.00% |
| L2-PYPI-OBFS-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-002 | 5 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-003 | 2 | 0 | 2 | 100.00% | 50.00% |
| L2-PYPI-OBFS-004 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-PYPI-OBFS-005 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-PYPI-OBFS-006 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-OBFS-007 | 3 | 0 | 1 | 100.00% | 75.00% |
| L2-PYPI-POST-001 | 22 | 0 | 0 | 100.00% | 100.00% |
| L2-PYPI-TYPO-001 | 150 | 0 | 0 | 100.00% | 100.00% |
| L2-RUBYGEMS-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-RUBYGEMS-DEPC-001 | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-RUBYGEMS-TYPO-001 | 36 | 0 | 0 | 100.00% | 100.00% |
| L2-SIDELOAD-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-TYPO-001 | 440 | 0 | 0 | 100.00% | 100.00% |
| L2-WORM-001 | 3 | 0 | 0 | 100.00% | 100.00% |

## Honest limitations

1. **Advisory rules (L2-*-ADV-001)** show low recall because the OSV advisory database is not available in offline validation mode. These rules require `--advisory-db` or network access to the OSV API. Precision is 100% when the DB is present.
2. **L2-MAVEN-DEPC-001 and L2-PYPI-DEPC-001** show 0% recall — the dep-confusion detector requires a private-registry configuration marker that the generated fixtures do not include. Hand-curated fixtures in the original 188 cover these.
3. **L2-MANI-002** (optional dependency lifecycle) has 0% recall — the detector looks for a specific combination of optionalDependencies + lifecycle scripts that the generated fixture does not trigger.
4. **Zero false positives** across all 54 rules on the 142 negative fixtures — the precision floor is 100% for every rule that fires.
5. The corpus is synthetically generated from combinatorial templates. Real-world malware may exhibit patterns not covered here. The `datasets/malware/` directory contains 16,402+ real OSV advisories for offline benchmarking.

## Running validation

```bash
# Full validation against built-in fixtures
picosentry scan --validate

# With advisory DB for CVE rules
picosentry scan --validate --advisory-db datasets/malware/

# Generate machine-readable report
picosentry scan --validate --output tests/scan/fixtures/validation/REPORT.json
```
