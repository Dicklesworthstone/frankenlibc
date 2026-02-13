#!/usr/bin/env bash
# CI gate: Resource constraint testing integrity (bd-2icq.20).
#
# Checks:
# 1. resource_constraints.py exists with valid Python syntax
# 2. Dry-run produces valid output with correct schema
# 3. All constraint types produce passing results
# 4. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/gentoo/resource_constraints.py"
TEST_FILE="${ROOT}/tests/gentoo/test_resource_constraints.py"

echo "=== Resource Constraint Testing Gate (bd-2icq.20) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Script exists with valid syntax
[[ -f "${SCRIPT}" ]] || fail "resource_constraints.py not found"
python3 -c "import py_compile; py_compile.compile('${SCRIPT}', doraise=True)" \
  || fail "resource_constraints.py has syntax errors"
echo "PASS: script syntax valid"

# 2. Dry-run produces valid output
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

python3 "${SCRIPT}" --mode dry-run --package sys-apps/coreutils \
  --output "${TMPDIR}/report.json" > /dev/null 2>&1 \
  || fail "dry-run failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if data.get('bead') != 'bd-2icq.20':
    sys.exit(1)
if data.get('total_tests', 0) < 5:
    print(f'Expected >= 5 tests, got {data.get(\"total_tests\")}', file=sys.stderr)
    sys.exit(1)
if data.get('passed') != data.get('total_tests'):
    print(f'Not all tests passed: {data.get(\"passed\")}/{data.get(\"total_tests\")}', file=sys.stderr)
    sys.exit(1)
" || fail "output schema validation failed"
echo "PASS: dry-run output valid"

# 3. All constraint types present
python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
types = data.get('by_type', {})
expected = {'baseline', 'oom', 'timeout', 'disk_full', 'contention'}
missing = expected - set(types.keys())
if missing:
    print(f'Missing constraint types: {missing}', file=sys.stderr)
    sys.exit(1)
" || fail "not all constraint types covered"
echo "PASS: all constraint types present"

# 4. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_resource_constraints.py tests passed"
fi

echo ""
echo "PASS: Resource Constraint Testing gate (bd-2icq.20) all checks passed"
