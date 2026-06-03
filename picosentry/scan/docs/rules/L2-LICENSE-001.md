# L2-LICENSE-001: License Compliance

**Severity:** MEDIUM / HIGH / LOW  
**Category:** compliance  
**Since:** v0.3.0

## What It Detects

Packages with missing, problematic, or copyleft license fields:

| Finding | Severity | Description |
|---------|----------|-------------|
| No license field | MEDIUM | Cannot determine redistribution rights |
| `UNLICENSED` or `SEE LICENSE IN` | HIGH | No rights to use, modify, or redistribute |
| Copyleft licenses | MEDIUM | GPL, AGPL, LGPL, MPL — may require source disclosure |
| Unrecognized license | LOW | License string not in known permissive or copyleft lists |

### Recognized permissive licenses:
MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, Unlicense, 0BSD, CC0-1.0, WTFPL, Zlib

### Copyleft licenses detected:
GPL-2.0, GPL-3.0, AGPL-3.0, LGPL-2.1, LGPL-3.0, MPL-2.0, EUPL-1.2, CPAL-1.0, OSL-3.0

### Dual licenses:
Handled correctly — `(MIT OR Apache-2.0)` is recognized as permissive.

## Why It Matters

License compliance affects your entire project:

- **No license**: You have no legal right to use, modify, or redistribute the code
- **UNLICENSED**: The author explicitly denies all rights
- **Copyleft**: Using GPL/AGPL code may require you to release your own source code under the same license
- **Unrecognized**: Unknown license terms create legal risk

For ML pipelines specifically, license compliance is critical because:
- Training data may include copyleft-licensed code
- Model outputs may be considered derivative works
- Enterprise users need clear license information for compliance audits

## How to Fix

1. **Check npmjs.com**: Look for license information on the package page
2. **Contact the author**: If there's no license, ask the maintainer to add one
3. **Find an alternative**: If the license is incompatible with your project
4. **Document exceptions**: Use `.picosentry.yml` to acknowledge known license issues

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-LICENSE-001: LOW  # if your project tolerates copyleft dependencies
ignore_packages:
  - some-gpl-package     # if you've explicitly accepted the copyleft terms
```

## References

- [npm: license field](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#license)
- [SPDX License List](https://spdx.org/licenses/)