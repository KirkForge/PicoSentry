#!/usr/bin/env bash
# Named test profiles — marker/timeout policy lives here, not inline in CI YAML.
# Usage: scripts/test.sh <profile> [--junit] [extra pytest args...]; --list prints profiles.
# --junit writes .pytest-artifacts/junit-<profile>.xml (nightly always writes
# .pytest-artifacts/junit.xml) for scripts/check-test-budget.py.
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
    # junit on every tier: a flaky failure must always leave a name behind
    # (identifiable from the CI artifact instead of vanishing in the log).
    extra=(--timeout=60 --durations=25 --durations-min=0.25 --junitxml=.pytest-artifacts/junit-fast.xml)
    mkdir -p .pytest-artifacts
    ;;
  integration)
    marker='not slow and not network and not benchmark_realworld'
    # WO4.0.0-017: make the push matrix broader than fast — malicious_workload
    # tests skip unless the sandbox env is set. ~21s of extra tests per leg.
    export PICODOME_SANDBOX_TESTS=1
    # Real-execution backend tests (landlock / seccomp-trace) self-gate via
    # each backend's is_available() probe — they run wherever the kernel
    # actually supports them and skip honestly elsewhere.
    export PICODOME_HAS_LANDLOCK=1
    export PICODOME_HAS_SECCOMP=1
    extra=(--timeout=120 --durations=25 --durations-min=0.25)
    ;;
  full)
    marker='not slow'
    extra=(--timeout=300 --durations=25 --durations-min=0.25)
    ;;
  nightly)
    marker=''
    export PICODOME_SANDBOX_TESTS=1
    export PICODOME_HAS_LANDLOCK=1
    export PICODOME_HAS_SECCOMP=1
    extra=(--timeout=900 --durations=25 --durations-min=0.25 --junitxml=.pytest-artifacts/junit.xml)
    mkdir -p .pytest-artifacts
    ;;
  *)
    echo "unknown profile: $profile (use --list)" >&2
    exit 2
    ;;
esac

args=()
junit=0
for a in "$@"; do
  case "$a" in
    --junit) junit=1 ;;
    *) args+=("$a") ;;
  esac
done
if [ "$junit" = 1 ] && [ "$profile" != nightly ]; then
  extra+=(--junitxml=".pytest-artifacts/junit-${profile}.xml")
  mkdir -p .pytest-artifacts
fi
[ -n "$marker" ] && args+=(-m "$marker")
exec uv run --extra all --extra dev pytest "${args[@]}" "${extra[@]}"
