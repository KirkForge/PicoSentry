# L3-TIMEOUT-001 — Process Timeout Exceeded

**Rule ID:** L3-TIMEOUT-001  
**Backend:** All  
**Verdict:** KILL  

## Detection

Triggered when a sandboxed process exceeds the configured timeout (default: 30 seconds). The process is killed via SIGKILL (or `proc.kill()` on subprocess backend).

## Supply-Chain Relevance

Timeouts are a critical safety mechanism:

- **Cryptocurrency miners**: Often run indefinitely, consuming CPU
- **Infinite loops**: May indicate bugs or intentional resource exhaustion
- **Deadlocks**: Malicious code may attempt to hang the CI pipeline
- **Network hangs**: Waiting for C2 server response

## Configuration

```yaml
# .picodome.yml
timeout: 60.0  # seconds (default: 30.0)
```

Or via CLI:
```bash
picodome sandbox --timeout 60 npm install some-package
```

## False Positives

- Long-running test suites
- Legitimate compilation of native modules
- Network-heavy operations (use `node` or `python` policy)

## Mitigation

1. Increase timeout for known-slow operations
2. Use the `node` policy for npm installs (allows network)
3. Consider splitting long operations into smaller steps