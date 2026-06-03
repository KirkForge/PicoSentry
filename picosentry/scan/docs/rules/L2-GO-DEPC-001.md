# L2-GO-DEPC-001: Go Dependency Confusion

**Severity:** CRITICAL  
**Category:** Dependency  
**Ecosystem:** Go

Detects private/internal Go module paths that could be squatted on the public Go module proxy. Attackers register internal-looking module paths on proxy.golang.org to inject malicious code when `go get` resolves the public module.

## Detection

Flags module paths matching internal patterns (e.g., `internal-`, `private-`, `company-`) when no `GOPRIVATE`, `GONOSUMDB`, or private proxy configuration is present.

## Remediation

Set `GOPRIVATE` or `GONOSUMDB` for internal modules to prevent resolution from the public Go module proxy. Alternatively, add a `replace` directive in go.mod to pin local/alternative sources.