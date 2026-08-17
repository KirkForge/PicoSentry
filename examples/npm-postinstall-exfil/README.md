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

Expected findings (rule IDs as of v2.1.1):

- **L2-POST-001**: Install scripts with network/credential access
- **L2-CRED-001**: Install script reading credentials/env vars
- **L2-PROV-001** / **L2-FORK-001** / **L2-MAINT-001**: provenance and maintainer red flags
- **L2-LOCK-001**, **L2-ENGIN-001**, **L2-LICENSE-001**: lockfile/engine/license issues
