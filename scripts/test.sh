#!/usr/bin/env bash
# Named test profiles — marker/timeout policy lives here, not inline in CI YAML.
# Usage: scripts/test.sh <profile> [extra pytest args...]; --list prints profiles.
set -eo pipefail

profile="${1:-fast}"
[ $# -gt 0 ] && shift

case "$profile" in
  --list)
    echo "fast integration full nightly (default: fast)"
    exit 0
    ;;
  fast)
    marker='not slow and not network and not benchmark_realworld and not malicious_workload'
    extra=(--timeout=60 --durations=25 --durations-min=0.25)
    ;;
  integration)
    marker='not slow and not network and not benchmark_realworld'
    extra=(--timeout=120 --durations=25 --durations-min=0.25)
    ;;
  full)
    marker='not slow'
    extra=(--timeout=300 --durations=25 --durations-min=0.25)
    ;;
  nightly)
    marker=''
    export PICODOME_SANDBOX_TESTS=1
    extra=(--timeout=900 --durations=25 --durations-min=0.25 --junitxml=.pytest-artifacts/junit.xml)
    mkdir -p .pytest-artifacts
    ;;
  *)
    echo "unknown profile: $profile (use --list)" >&2
    exit 2
    ;;
esac

args=()
[ -n "$marker" ] && args+=(-m "$marker")
exec uv run --extra all --extra dev pytest "${args[@]}" "${extra[@]}" "$@"
