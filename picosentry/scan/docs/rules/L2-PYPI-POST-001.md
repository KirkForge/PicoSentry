# L2-PYPI-POST-001: PyPI Post-Install Code Execution

**Severity:** CRITICAL / HIGH  
**Category:** execution  
**Since:** v1.1.0

## What It Detects

setup.py or pyproject.toml files with suspicious build-time code execution — subprocess calls, os.system, network requests, credential reading during installation.

## Why It Matters

Python's setup.py executes arbitrary code during `pip install`. Malicious packages exploit this to exfiltrate credentials, install backdoors, or download payloads at install time.

## How It Works

1. Scans setup.py for subprocess.call, os.system, eval(), exec(), and network calls
2. Scans pyproject.toml for Poetry build scripts with suspicious patterns
3. CRITICAL severity if network access or credential reading is detected

## Remediation

Audit setup.py before installing. Prefer pyproject.toml with static metadata. Use `pip install --no-build-isolation` only from trusted sources.