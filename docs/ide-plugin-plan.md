# IDE Plugin Plan

**Status:** Planned (not implemented)
**Timeline:** Post-v1.0, after serve mode reaches stable

## Scope

VS Code extension and JetBrains plugin. Both wrap `picosentry scan` CLI.

## Architecture

No language server, no daemon. Shell out to `picosentry scan`, parse JSON/SARIF output, surface diagnostics.

```
Editor extension -> `picosentry scan --format sarif <path>` -> SARIF JSON -> editor diagnostics
```

## Features

- **Inline diagnostics:** Squiggles on lines flagged by scan findings
- **Quick-fix suggestions:** From the `remediation` field in scan output
- **Severity filtering:** Show only HIGH/CRITICAL findings
- **Config detection:** Auto-detect `.picosentry.toml` in workspace root

## Implementation Notes

### VS Code

Use `vscode.languages.registerDiagnosticProvider` (proposed API) or shell out in a `Task` with `--format json`. Parse SARIF, map `ruleId` + `message` + `location` to `vscode.Diagnostic`.

### JetBrains

Use `ExternalAnnotator` with `ExternalProcessRunner`. Invoke `picosentry scan --format sarif`, parse output, map to `HighlightInfo` instances.

### Both

Parse SARIF output. Map each result to an editor diagnostic with severity, message, and source location. Debounce scans on file save (not on every keystroke).

## Open Questions

- Watch mode integration (re-scan on file change) vs save-only
- Whether to bundle a picosentry binary or require PATH