# npm Postinstall Exfiltration — example vulnerability

This project demonstrates PicoSentry's ability to detect malicious
npm packages that use `postinstall` scripts to exfiltrate data.

## What it does

The `package.json` defines a `postinstall` script that sends
environment variables to a remote server. This is a pattern used
by real supply-chain attacks (e.g., `event-stream`, `eslint-scope`).

## What PicoSentry catches

```bash
picosentry scan examples/npm-postinstall-exfil/
```

Expected findings:
- **L2-POST-001**: Postinstall script execution
- **L2-EXFIL-003**: postinstall script contains network calls
- **L2-OBF-001**: Base64-encoded hostnames