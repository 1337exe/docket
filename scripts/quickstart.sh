#!/usr/bin/env bash
# Set up an isolated environment and check the install end to end (Linux / macOS, Python 3.10+).
# Everything stays on localhost. Usage: bash scripts/quickstart.sh
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
. .venv/bin/activate
pip install -q -e ".[dev]"
echo "== 1/3 unit tests (includes hostile-input fuzzing)"
python -m pytest -q
echo "== 2/3 self-test (lab with known ground truth, demo case, canary, MCP, judge contract, scope guard)"
docket selftest --out-dir ./docket-out
echo "== 3/3 write the testing kit"
docket kit ./docket-kit
echo
echo "Open docket-out/lab-report.html and docket-out/demo-report.html in a browser."
echo "Next: read docket-kit/KIT.md  (activate the venv first:  . .venv/bin/activate)"
