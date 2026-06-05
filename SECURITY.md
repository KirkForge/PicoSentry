# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.x     | ✅ Active          |
| 1.x     | ⚠️ Critical only   |

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Use one of these channels:

- **Email**: [security@kirkforge.dev](mailto:security@kirkforge.dev)
- **GitHub**: [Private vulnerability report](https://github.com/KirkForge/PicoSentry/security/advisories/new)

We aim to acknowledge receipt within 48 hours and provide a triage timeline within 5 business days.

## What to report

We are especially interested in:

- Determinism bypasses (same input produces different output)
- Detector evasion (malicious packages that avoid detection)
- Sandbox escape (breakout from seccomp-bpf confinement)
- Prompt injection that bypasses the LLM guard layer
- Supply-chain risks in PicoSentry's own dependency tree

## Disclosure policy

We follow coordinated disclosure: we fix first, you publish after the release is out. We will credit you in the release notes unless you prefer to remain anonymous.

## Security-relevant configuration

PicoSentry includes an `assert_secure()` startup gate that checks for insecure defaults at boot (weak secret keys, debug mode in production, CORS wildcards). See `picosentry._core.config.assert_secure` for the full list.

## Bug bounty

This project does not currently offer a paid bug bounty. Hardware donations accepted via [Buy Me A Coffee](https://buymeacoffee.com/kirkforge).