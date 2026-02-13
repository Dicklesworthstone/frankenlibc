#!/usr/bin/env bash
# CI gate: Flaky test quarantine infrastructure integrity (bd-2icq.24).
#
# Checks:
# 1. flaky_detector.py and quarantine_manager.py exist with valid Python syntax
# 2. quarantine.json exists and has valid schema
# 3. Dry-run detection produces valid output
# 4. Quarantine manager init/add/list roundtrip works
# 5. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DETECTOR="${ROOT}/scripts/gentoo/flaky_detector.py"
MANAGER="${ROOT}/scripts/gentoo/quarantine_manager.py"
QUARANTINE_DB="${ROOT}/data/gentoo/quarantine.json"
TEST_FILE="${ROOT}/tests/gentoo/test_flaky_detector.py"

echo "=== Flaky Test Quarantine Gate (bd-2icq.24) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Scripts exist and have valid Python syntax
[[ -f "${DETECTOR}" ]] || fail "flaky_detector.py not found"
[[ -f "${MANAGER}" ]] || fail "quarantine_manager.py not found"
python3 -c "import py_compile; py_compile.compile('${DETECTOR}', doraise=True)" \
  || fail "flaky_detector.py has syntax errors"
python3 -c "import py_compile; py_compile.compile('${MANAGER}', doraise=True)" \
  || fail "quarantine_manager.py has syntax errors"
echo "PASS: scripts syntax valid"

# 2. quarantine.json exists and has valid schema
[[ -f "${QUARANTINE_DB}" ]] || fail "quarantine.json not found"
python3 -c "
import json, sys
data = json.load(open('${QUARANTINE_DB}'))
required = ['version', 'last_updated', 'quarantined_tests', 'statistics']
missing = [k for k in required if k not in data]
if missing:
    print(f'Missing keys in quarantine.json: {missing}', file=sys.stderr)
    sys.exit(1)
if data['version'] != 1:
    print(f'Bad version: {data[\"version\"]}', file=sys.stderr)
    sys.exit(1)
" || fail "quarantine.json schema validation failed"
echo "PASS: quarantine.json schema valid"

# 3. Dry-run detection
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

python3 "${DETECTOR}" --dry-run --package sys-apps/coreutils \
  --output "${TMPDIR}/report.json" > /dev/null 2>&1 \
  || fail "detector dry-run failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if data.get('bead') != 'bd-2icq.24':
    sys.exit(1)
if data.get('packages_scanned', 0) < 1:
    sys.exit(1)
" || fail "detector output schema invalid"
echo "PASS: dry-run detection produces valid output"

# 4. Quarantine manager roundtrip
python3 "${MANAGER}" --action init --db "${TMPDIR}/qdb.json" > /dev/null 2>&1 \
  || fail "quarantine init failed"
python3 "${MANAGER}" --action add --package a/b --test t1 \
  --reason timing_sensitive --db "${TMPDIR}/qdb.json" > /dev/null 2>&1 \
  || fail "quarantine add failed"
RC=0
python3 "${MANAGER}" --action check --package a/b --test t1 \
  --db "${TMPDIR}/qdb.json" > /dev/null 2>&1 || RC=$?
# check returns 1 for quarantined (expected)
[[ "${RC}" -eq 1 ]] || fail "quarantine check should return 1 for quarantined test (got rc=${RC})"
echo "PASS: quarantine manager roundtrip works"

# 5. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_flaky_detector.py tests passed"
fi

echo ""
echo "PASS: Flaky Test Quarantine gate (bd-2icq.24) all checks passed"
