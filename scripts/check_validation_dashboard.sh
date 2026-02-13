#!/usr/bin/env bash
# CI gate: Validation dashboard aggregator integrity (bd-2icq.11).
#
# Checks:
# 1. validation_dashboard.py exists with valid Python syntax
# 2. Dry-run produces valid JSON with correct schema
# 3. Markdown output is generated
# 4. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/gentoo/validation_dashboard.py"
TEST_FILE="${ROOT}/tests/gentoo/test_validation_dashboard.py"

echo "=== Validation Dashboard Gate (bd-2icq.11) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Script exists with valid syntax
[[ -f "${SCRIPT}" ]] || fail "validation_dashboard.py not found"
python3 -c "import py_compile; py_compile.compile('${SCRIPT}', doraise=True)" \
  || fail "validation_dashboard.py has syntax errors"
echo "PASS: script syntax valid"

# 2. Dry-run produces valid JSON with correct schema
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

python3 "${SCRIPT}" --dry-run --format json \
  --output "${TMPDIR}/dashboard.json" > /dev/null 2>&1 \
  || fail "dry-run JSON mode failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/dashboard.json'))
if data.get('schema_version') != 'v1':
    print('bad schema_version'); sys.exit(1)
if data.get('bead') != 'bd-2icq.11':
    print('bad bead'); sys.exit(1)
if not isinstance(data.get('sections'), list):
    print('missing sections'); sys.exit(1)
if len(data['sections']) < 1:
    print('no sections'); sys.exit(1)
if 'overall_status' not in data:
    print('missing overall_status'); sys.exit(1)
" || fail "JSON schema validation failed"
echo "PASS: JSON output schema valid"

# 3. Markdown output is generated
python3 "${SCRIPT}" --dry-run --format both \
  --output "${TMPDIR}/dash.json" > /dev/null 2>&1 \
  || fail "dry-run both mode failed"

[[ -f "${TMPDIR}/dash.md" ]] || fail "markdown output not generated"
grep -q "FrankenLibC Gentoo Validation Dashboard" "${TMPDIR}/dash.md" \
  || fail "markdown missing header"
echo "PASS: markdown output valid"

# 4. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_validation_dashboard.py tests passed"
fi

echo ""
echo "PASS: Validation Dashboard gate (bd-2icq.11) all checks passed"
