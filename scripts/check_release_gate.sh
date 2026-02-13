#!/usr/bin/env bash
# CI gate: Release qualification gate integrity (bd-2icq.17).
#
# Checks:
# 1. release_gate.py exists with valid Python syntax
# 2. Gate config exists and is valid JSON
# 3. Dry-run produces valid JSON with correct schema
# 4. All three gate levels checked in dry-run
# 5. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/gentoo/release_gate.py"
CONFIG="${ROOT}/configs/gentoo/release-gates.json"
TEST_FILE="${ROOT}/tests/gentoo/test_release_gate.py"

echo "=== Release Qualification Gate (bd-2icq.17) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Script exists with valid syntax
[[ -f "${SCRIPT}" ]] || fail "release_gate.py not found"
python3 -c "import py_compile; py_compile.compile('${SCRIPT}', doraise=True)" \
  || fail "release_gate.py has syntax errors"
echo "PASS: script syntax valid"

# 2. Gate config exists and is valid
[[ -f "${CONFIG}" ]] || fail "release-gates.json not found"
python3 -c "
import json, sys
data = json.load(open('${CONFIG}'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
gates = data.get('gates', {})
if 'tier1' not in gates or 'top20' not in gates or 'top100' not in gates:
    sys.exit(1)
for level, cfg in gates.items():
    t = cfg.get('thresholds', {})
    if 'build_success_rate_pct' not in t:
        sys.exit(1)
" || fail "release-gates.json schema invalid"
echo "PASS: gate config valid"

# 3. Dry-run produces valid JSON
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

python3 "${SCRIPT}" --dry-run --format json \
  --output "${TMPDIR}/report.json" > /dev/null 2>&1 \
  || fail "dry-run JSON mode failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
if data.get('schema_version') != 'v1':
    print('bad schema_version'); sys.exit(1)
if data.get('bead') != 'bd-2icq.17':
    print('bad bead'); sys.exit(1)
if not isinstance(data.get('gates'), list):
    print('missing gates'); sys.exit(1)
if 'release_blocked' not in data:
    print('missing release_blocked'); sys.exit(1)
" || fail "JSON schema validation failed"
echo "PASS: JSON output schema valid"

# 4. All three gate levels checked
python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
levels = [g['gate_level'] for g in data['gates']]
if 'tier1' not in levels: sys.exit(1)
if 'top20' not in levels: sys.exit(1)
if 'top100' not in levels: sys.exit(1)
" || fail "not all gate levels present"
echo "PASS: all three gate levels checked"

# 5. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_release_gate.py tests passed"
fi

echo ""
echo "PASS: Release Qualification gate (bd-2icq.17) all checks passed"
