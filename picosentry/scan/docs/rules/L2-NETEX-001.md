# L2-NETEX-001: Network Exfiltration and C2 Domain Detection

**Severity:** CRITICAL / HIGH  
**Category:** supply-chain  
**Since:** v0.16.0

## What It Detects

Connections to known command-and-control domains, cloud metadata endpoints, phishing/typosquatting domains, and credential exfiltration patterns in install scripts and source code.

C2 domains detected:
- **shai-hulud.cc** — Shai-Hulud worm C2
- **firebase.su** — CVE-2025-54313 (Scavenger) C2
- **dieorsuffer.com** — CVE-2025-54313 (Scavenger) C2
- **smartscreen-api.com** — CVE-2025-54313 (Scavenger) phishing
- **webhook.site/bb8ca5f6-...** — Shai-Hulud exfiltration endpoint

Cloud metadata endpoints:
- **169.254.169.254** — AWS IMDS (credential exfiltration)
- **metadata.google.internal** — GCP metadata
- **metadata.azure.com** — Azure metadata

Phishing domains:
- **npmjs.help**, **npmjs.support**, **npmjs.security** — npm impersonation
- **npnjs.com** — npm typosquat

Additional patterns:
- **Environment variable exfiltration** — `fetch(process.env)`, `curl $AWS_*`
- **Scavenger malware DLLs** — `node-gyp.dll`, `loader.so`, etc. (CVE-2025-54313)
- **Azure metadata header** — `Metadata: true`

## Why It Matters

Supply chain worms like Shai-Hulud and Scavenger exfiltrate credentials by connecting to C2 infrastructure during npm install. Cloud metadata endpoints (AWS IMDS, GCP, Azure) are targeted to steal IAM credentials and deployment secrets. Phishing domains impersonate npmjs.com to harvest developer credentials.

## Severity Levels

| Level | Condition |
|-------|-----------|
| CRITICAL | Known C2 domains, cloud metadata endpoints, Scavenger DLLs |
| HIGH | Phishing/typosquat domains, Azure metadata headers |

## How to Fix

1. **Remove the dependency**: Any package connecting to C2 infrastructure is compromised
2. **Rotate all credentials**: Assume AWS keys, npm tokens, and GitHub tokens are exfiltrated
3. **Block IMDS**: Ensure your environment blocks cloud metadata endpoint access from npm install
4. **Audit npm credentials**: Check for unauthorized packages published under your account
5. **Use `--ignore-scripts`**: Prevent postinstall scripts from running

## References

- [Phylum: Shai-Hulud the npm worm is still crawling](https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/)
- [Unit42: Shai-Hulud 2.0](https://unit42.paloaltonetworks.com/npm-supply-chain-attack-shai-hulud-2-0/)
- [OWASP: SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
