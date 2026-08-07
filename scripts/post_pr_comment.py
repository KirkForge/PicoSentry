"""Post PicoSentry scan results as a PR comment.

Reads a SARIF file produced by ``picosentry scan --format sarif``,
converts the results to a Markdown summary, and posts them as a
GitHub Pull Request comment via the GitHub REST API.

Environment variables:
    GITHUB_REPOSITORY  Owner/repo, e.g. "KirkForge/PicoSentry"
    GITHUB_TOKEN       Personal access token or GitHub App
                       installation token
    GITHUB_PR_NUMBER   Pull request number
    SARIF_FILE         Path to the SARIF JSON file (default: sarif.json)

Authentication:
    Uses GITHUB_TOKEN in the Authorization header. For GitHub Actions,
    ``secrets.GITHUB_TOKEN`` works. For external CI, generate a token
    with ``repo`` scope or a GitHub App installation token.

Usage:
    python scripts/post_pr_comment.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

_SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


def _severity_from_level(level: str) -> str:
    if level == "error":
        return "CRITICAL"
    if level == "warning":
        return "MEDIUM"
    return "INFO"


def sarif_to_markdown(sarif: dict) -> str:
    runs = sarif.get("runs", [])
    if not runs:
        return "## PicoSentry Security Scan\n\nNo SARIF runs found."
    run = runs[0]
    driver = run.get("tool", {}).get("driver", {})
    version = driver.get("version", "unknown")
    results = run.get("results", [])

    if not results:
        return f"## PicoSentry Security Scan\n\nNo findings. Dependencies appear safe.\n\n*PicoSentry v{version}*"

    by_sev: dict[str, int] = {}
    for r in results:
        sev = _severity_from_level(r.get("level", "warning"))
        by_sev[sev] = by_sev.get(sev, 0) + 1

    parts: list[str] = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        c = by_sev.get(sev, 0)
        if c:
            parts.append(f"{c} {sev}")

    lines = [
        "## PicoSentry Security Scan",
        "",
        f"Found {len(results)} findings ({', '.join(parts)})",
        "",
        "| Severity | Rule | Message |",
        "|----------|------|---------|",
    ]
    for r in sorted(
        results,
        key=lambda r: (
            _SEVERITY_ORDER.get(_severity_from_level(r.get("level", "warning")), 99),
            r.get("ruleId", ""),
        ),
    ):
        sev = _severity_from_level(r.get("level", "warning"))
        rule = r.get("ruleId", "")
        msg = r.get("message", {}).get("text", "")
        lines.append(f"| {sev} | {rule} | {msg} |")

    lines.append("")
    lines.append(f"*PicoSentry v{version}*")
    return "\n".join(lines)


def post_comment(repo: str, token: str, pr_number: int, body: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "PicoSentry-PR-Comment")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        print(
            f"GitHub API error {exc.code}: {body_text}",
            file=sys.stderr,
        )
        sys.exit(1)


def main() -> None:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    pr_number = int(os.environ.get("GITHUB_PR_NUMBER", "0"))
    sarif_file = os.environ.get("SARIF_FILE", "sarif.json")

    env_checks = [
        ("GITHUB_REPOSITORY", repo),
        ("GITHUB_TOKEN", token),
        ("GITHUB_PR_NUMBER", pr_number),
    ]
    missing = [k for k, v in env_checks if not v]
    if missing:
        print(
            f"Missing required environment variables: {', '.join(missing)}",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(sarif_file) as f:
        sarif = json.load(f)

    markdown = sarif_to_markdown(sarif)
    result = post_comment(repo, token, pr_number, markdown)
    print(f"Posted comment: {result.get('html_url', result.get('id', 'unknown'))}")


if __name__ == "__main__":
    main()
