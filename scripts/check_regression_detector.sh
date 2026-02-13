#!/usr/bin/env bash
# CI gate: Regression detection + baseline management integrity (bd-2icq.12).
#
# Checks:
# 1. check_regressions.py and update_baseline.py have valid Python syntax
# 2. baseline.json exists with valid schema
# 3. Dry-run regression detection produces valid output
# 4. Dry-run baseline creation works
# 5. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REGRESSION_SCRIPT="${ROOT}/scripts/gentoo/check_regressions.py"
BASELINE_SCRIPT="${ROOT}/scripts/gentoo/update_baseline.py"
BASELINE_FILE="${ROOT}/data/gentoo/baseline.json"
TEST_FILE="${ROOT}/tests/gentoo/test_regression_detector.py"

echo "=== Regression Detection Gate (bd-2icq.12) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Scripts have valid Python syntax
[[ -f "${REGRESSION_SCRIPT}" ]] || fail "check_regressions.py not found"
[[ -f "${BASELINE_SCRIPT}" ]] || fail "update_baseline.py not found"
python3 -c "import py_compile; py_compile.compile('${REGRESSION_SCRIPT}', doraise=True)" \
  || fail "check_regressions.py has syntax errors"
python3 -c "import py_compile; py_compile.compile('${BASELINE_SCRIPT}', doraise=True)" \
  || fail "update_baseline.py has syntax errors"
echo "PASS: scripts syntax valid"

# 2. baseline.json exists with valid schema
[[ -f "${BASELINE_FILE}" ]] || fail "baseline.json not found"
python3 -c "
import json, sys
data = json.load(open('${BASELINE_FILE}'))
required = ['schema_version', 'bead', 'timestamp', 'packages']
missing = [k for k in required if k not in data]
if missing:
    print(f'Missing keys: {missing}', file=sys.stderr)
    sys.exit(1)
if data['schema_version'] != 'v1':
    print(f'Bad schema_version: {data[\"schema_version\"]}', file=sys.stderr)
    sys.exit(1)
if len(data['packages']) < 1:
    print('No packages in baseline', file=sys.stderr)
    sys.exit(1)
" || fail "baseline.json schema validation failed"
echo "PASS: baseline.json schema valid"

# 3. Dry-run regression detection
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

RC=0
python3 "${REGRESSION_SCRIPT}" --dry-run \
  --output "${TMPDIR}/regression_report.json" > /dev/null 2>&1 || RC=$?
# Dry run may return 1 (regressions found) - that's expected
[[ "${RC}" -le 1 ]] || fail "regression detector dry-run failed with rc=${RC}"
[[ -f "${TMPDIR}/regression_report.json" ]] || fail "no regression report produced"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/regression_report.json'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if data.get('bead') != 'bd-2icq.12':
    sys.exit(1)
if not data.get('dry_run'):
    sys.exit(1)
" || fail "regression report schema invalid"
echo "PASS: dry-run regression detection produces valid output"

# 4. Dry-run baseline creation
python3 "${BASELINE_SCRIPT}" --dry-run \
  --output "${TMPDIR}/baseline.json" > /dev/null 2>&1 \
  || fail "baseline dry-run failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/baseline.json'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if len(data.get('packages', [])) != 5:
    sys.exit(1)
" || fail "baseline schema invalid"
echo "PASS: dry-run baseline creation works"

# 5. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_regression_detector.py tests passed"
fi

echo ""
echo "PASS: Regression Detection gate (bd-2icq.12) all checks passed"
