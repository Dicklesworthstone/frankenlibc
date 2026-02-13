#!/usr/bin/env bash
# CI gate: Progress reporting infrastructure integrity (bd-2icq.21).
#
# Checks:
# 1. progress_reporter.py exists with valid Python syntax
# 2. Dry-run produces valid terminal output
# 3. JSON output has correct schema
# 4. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/gentoo/progress_reporter.py"
TEST_FILE="${ROOT}/tests/gentoo/test_progress_reporter.py"

echo "=== Progress Reporter Gate (bd-2icq.21) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Script exists with valid syntax
[[ -f "${SCRIPT}" ]] || fail "progress_reporter.py not found"
python3 -c "import py_compile; py_compile.compile('${SCRIPT}', doraise=True)" \
  || fail "progress_reporter.py has syntax errors"
echo "PASS: script syntax valid"

# 2. Dry-run produces valid terminal output
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

python3 "${SCRIPT}" --mode dry-run > "${TMPDIR}/terminal.txt" 2>&1 \
  || fail "dry-run terminal mode failed"

grep -q "FrankenLibC Gentoo Validation" "${TMPDIR}/terminal.txt" \
  || fail "terminal output missing header"
grep -q "Progress:" "${TMPDIR}/terminal.txt" \
  || fail "terminal output missing progress"
echo "PASS: dry-run terminal output valid"

# 3. JSON output has correct schema
python3 "${SCRIPT}" --mode dry-run \
  --output "${TMPDIR}/progress.json" > /dev/null 2>&1 \
  || fail "dry-run JSON mode failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/progress.json'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if data.get('bead') != 'bd-2icq.21':
    sys.exit(1)
if 'progress' not in data:
    sys.exit(1)
if 'resources' not in data:
    sys.exit(1)
if 'timing' not in data:
    sys.exit(1)
" || fail "JSON schema validation failed"
echo "PASS: JSON output schema valid"

# 4. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_progress_reporter.py tests passed"
fi

echo ""
echo "PASS: Progress Reporter gate (bd-2icq.21) all checks passed"
