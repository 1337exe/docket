#!/usr/bin/env bash
# Reproduce the public-code runs from the README.
#   bash benchmarks/run_public.sh [workdir]
# Clones public repositories, runs Bandit on them, then runs Docket on Bandit's output.
# Needs: git, python3, pip (installs bandit if missing). Only reads public code; nothing is sent anywhere.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${1:-./docket-benchmark}"; mkdir -p "$WORK"; cd "$WORK"
command -v bandit >/dev/null || pip install --quiet bandit
command -v docket >/dev/null || pip install --quiet "$HERE/.." 2>/dev/null || true
cp "$HERE/scope.json" scope.json
REPOS="${DOCKET_BENCH_REPOS:-we45/Vulnerable-Flask-App erev0s/VAmPI adeyosemanputra/pygoat anxolerd/dvpwa pallets/flask psf/requests}"
for r in $REPOS; do
  n=$(basename "$r")
  [ -d "$n" ] || git clone -q --depth 1 "https://github.com/$r.git" "$n"
  (cd "$n" && bandit -r . -f json -q -o "../bandit-$n.json" 2>/dev/null || true)
  echo "== $n"
  docket try "bandit-$n.json" --scope scope.json --target "$n" --out "$n.html" --json "$n.json" --markdown-out "$n.md" > "$n.log"; head -1 "$n.log"
done
echo "reports: $WORK/*.html"
