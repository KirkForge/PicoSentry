# L2-GO-TYPO-001: Go Module Typosquatting

**Severity:** HIGH  
**Category:** Typosquat  
**Ecosystem:** Go

Detects Go module dependencies whose short names are within edit distance ≤2 of popular Go packages. Attackers register misspelled module paths on the Go module proxy to trick developers into importing malicious code.

## Detection

Compares the last path segment of each Go module dependency (e.g., `gin` from `github.com/gin-gonic/gin`) against a corpus of 200+ popular Go packages using edit distance and keyboard adjacency distance.

## Remediation

Verify that the module path is the intended package, not a misspelling of a popular one. Check the module path and author before importing.