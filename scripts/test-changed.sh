#!/usr/bin/env bash
# LOCAL dev helper: run only the fast-suite test dirs affected by your diff.
#
# NOT wired into PR CI on purpose (#35/#81): at ~4-5 min the full fast suite is
# cheap, and a missed path->dir mapping here would give a green local run and a
# red PR. CI keeps the full fast suite as the PR gate; this script is for
# pre-push iteration speed only.
#
# Usage: scripts/test-changed.sh [base]
#   base  — ref to diff against (default: origin/main, falls back to main).
#           Uses merge-base, so it works on feature branches with merges.
set -eo pipefail

case "${1:-}" in
  -h|--help)
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
    ;;
esac

base="${1:-origin/main}"
git rev-parse --verify -q "$base" >/dev/null || base="main"
merge_base=$(git merge-base "$base" HEAD) || { echo "no merge-base with $base" >&2; exit 2; }
mapfile -t files < <(git diff --name-only "$merge_base" HEAD)

dirs=()
run_all=0
for f in "${files[@]}"; do
  case "$f" in
    picosentry/scan/*|tests/scan/*)             dirs+=(tests/scan tests/firewall) ;;
    picosentry/firewall/*|tests/firewall/*)     dirs+=(tests/firewall) ;;
    picosentry/sandbox/*|tests/sandbox/*)       dirs+=(tests/sandbox) ;;
    picosentry/watch/*|tests/watch/*)           dirs+=(tests/watch) ;;
    picosentry/serve/*|tests/serve/*)           dirs+=(tests/serve) ;;
    picosentry/_core/*|picosentry/cli*|pyproject.toml|uv.lock|tests/integration/*) run_all=1 ;;
    *) run_all=1 ;;
  esac
done

if [ "$run_all" = 1 ] || [ ${#dirs[@]} -eq 0 ]; then
  echo "changed-path selection: FULL fast suite (base: $merge_base, ${#files[@]} file(s))"
  exec bash "$(dirname "$0")/test.sh" fast
fi
mapfile -t dirs < <(printf '%s\n' "${dirs[@]}" | sort -u)
echo "changed-path selection: ${dirs[*]} (base: $merge_base, ${#files[@]} file(s))"
exec bash "$(dirname "$0")/test.sh" fast "${dirs[@]}"
