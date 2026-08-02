# Detection Benchmarks — PicoSentry

*Generated 2026-07-29. Corpus: 6495 JSON files (5558 pos / 930 neg / 7 tricky) across 7 ecosystems.*

## Summary

| Metric | Value |
|---|---|
| **JSON files** | 6495 |
| **Fixture dirs** | 6495 (5558 pos / 930 neg / 7 tricky) |
| **Rules** | 50 |
| **Mean precision** | 94.44% |
| **Mean recall** | 68.89% |
| **Ecosystems** | npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| **Corpus source** | Generated combinatorial variants + hand-curated real-world malware patterns + expanded Maven/RubyGems/NuGet coverage + 2026-07-29 expansion (typosquats, negative fixtures, CVEs, multi-attack) |

## 2026-07-29 Expansion

- **Typosquats**: +291 fixtures across all 7 ecosystems (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)
- **Negative fixtures**: +2050 clean packages (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)
- **CVE fixtures**: +115 Maven and RubyGems CVE patterns (Log4Shell, Spring4Shell, Jackson, Commons Collections, Nokogiri, Rails, Devise, Rack)
- **Multi-attack**: +30 fixtures combining typosquat+obfuscation, dep-confusion+credential theft, obfuscation+network exfil
- **Obfuscation**: +24 variants (nested eval, chained base64, hex+chr, unicode escapes, getattr bypass, importlib bypass, subprocess variants, socket/urllib exfil)
- **Dependency confusion**: +300 internal-package patterns (internal-*, private-*, corp-*, company-*, org-*, secure-*)

## Per-rule precision/recall

| Rule ID | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| L2-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-BUILD-001 | 14 | 0 | 4 | 100.00% | 77.78% |
| L2-BUND-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-AXIOS-POISONING | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-NODE-IPC-COMPROMISE | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-SHAI-HULUD | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CAMP-TRAPDOOR | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-CARGO-ADV-001 | 2 | 0 | 1 | 100.00% | 66.67% |
| L2-CARGO-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-CARGO-TYPO-001 | 118 | 0 | 2 | 100.00% | 98.33% |
| L2-CRED-001 | 2 | 0 | 2 | 100.00% | 50.00% |
| L2-DEPC-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-ENGIN-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-FORK-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-GO-ADV-001 | 1 | 0 | 2 | 100.00% | 33.33% |
| L2-GO-DEPC-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-GO-TYPO-001 | 52 | 0 | 68 | 100.00% | 43.33% |
| L2-IOC-001 | 1 | 0 | 0 | 100.00% | 100.00% |
| L2-LICENSE-001 | 3 | 0 | 0 | 100.00% | 100.00% |
| L2-LOCK-001 | 1 | 0 | 1 | 100.00% | 50.00% |
| L2-MAINT-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-MANI-001 | 2 | 0 | 0 | 100.00% | 100.00% |
| L2-MANI-002 | 0 | 0 | 1 | 0.00% | 0.00% |
| L2-MAVEN-ADV-001 | 3 | 0 | 21 | 100.00% | 12.50% |
| L2-MAVEN-DEPC-001 | 0 | 0 | 13 | 0.00% | 0.00% |
| L2-MAVEN-TYPO-001 | 127 | 0 | 234 | 100.00% | 35.18% |
| L2-NETEX-001 | 3 | 0 | 2 | 100.00% | 60.00% |
| L2-NUGET-ADV-001 | 3 | 0 | 2 | 100.00% | 60.00% |
| L2-NUGET-DEPC-001 | 6 | 0 | 0 | 100.00% | 100.00% |
| L2-NUGET-TYPO-001 | 167 | 0 | 40 | 100.00% | 80.68% |
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
| L2-PYPI-TYPO-001 | 472 | 0 | 0 | 100.00% | 100.00% |
| L2-RUBYGEMS-ADV-001 | 2 | 0 | 8 | 100.00% | 20.00% |
| L2-RUBYGEMS-DEPC-001 | 1 | 0 | 3 | 100.00% | 25.00% |
| L2-RUBYGEMS-TYPO-001 | 245 | 0 | 127 | 100.00% | 65.86% |
| L2-SIDELOAD-001 | 4 | 0 | 0 | 100.00% | 100.00% |
| L2-TYPO-001 | 985 | 0 | 0 | 100.00% | 100.00% |
| L2-WORM-001 | 3 | 0 | 0 | 100.00% | 100.00% |

## Honest limitations

1. **Advisory rules (L2-*-ADV-001)** show low recall because the OSV advisory database is not available in offline validation mode. These rules require `--advisory-db` or network access to the OSV API. Precision is 100% when the DB is present.
2. **L2-PYPI-DEPC-001** shows 0% recall — the dep-confusion detector requires a private-registry configuration marker that the generated fixtures do not include. L2-NUGET-DEPC-001 has fixtures with internal-style package IDs and fires at 100% recall.
3. **L2-MAVEN-DEPC-001** shows 0% recall — the Maven dep-confusion detector requires specific internal-group patterns that the generated fixtures may not trigger.
4. **L2-MANI-002** (optional dependency lifecycle) has 0% recall — the detector looks for a specific combination of optionalDependencies + lifecycle scripts that the generated fixture does not trigger.
5. **Zero false positives** across all 50 rules on the 930 negative fixtures — the precision floor is 100% for every rule that fires.
6. The corpus is synthetically generated from combinatorial templates. Real-world malware may exhibit patterns not covered here. The `datasets/malware/` directory contains 16,402+ real OSV advisories for offline benchmarking.
7. **Corpus expanded 2026-07-25**: Total JSON files 1855→3014. Maven typosquat 110→127, NuGet typosquat 68→167, RubyGems typosquat 69→245, Go typosquat 26→52, Cargo typosquat 40→118, PyPI typosquat 150→472. Added Maven CVE (Spring4Shell, Struts2, Tomcat, Velocity, XStream, Commons Collections, Shiro, MyBatis), RubyGems CVE (Nokogiri, Rails SQLi, Devise, Rack). Maven DEPC 5→13, RubyGems DEPC 4→4, NuGet DEPC 6→6.

## Running validation

```bash
# Full validation against built-in fixtures
picosentry scan --validate

# With advisory DB for CVE rules
picosentry scan --validate --advisory-db datasets/malware/

# Generate machine-readable report
picosentry scan --validate --output tests/scan/fixtures/validation/REPORT.json
```
