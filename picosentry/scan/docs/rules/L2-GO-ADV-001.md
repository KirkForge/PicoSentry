# L2-GO-ADV-001: Go Advisory Vulnerability Check

**Severity:** HIGH  
**Category:** Vulnerability  
**Ecosystem:** Go

Checks Go module dependencies against a local OSV-format advisory database. Flags modules with known CVEs, Go security advisories, or other published vulnerabilities.

## Detection

Matches each Go module and version (from go.mod and go.sum) against a locally-loaded advisory database. Requires an advisory database to be present (bundled, in corpus/advisories/, or fetched with `picosentry advisories fetch`).

## Remediation

Upgrade affected Go modules to a patched version as recommended by the advisory.