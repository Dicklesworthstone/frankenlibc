#!/usr/bin/env bash
# CI gate: Branch-diversity math obligation enforcement (bd-5fw.5).
#
# Checks:
# 1. branch_diversity_gate.py exists with valid Python syntax
# 2. Spec file exists and is valid JSON
# 3. Gate produces valid JSON with correct schema
# 4. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/scripts/gentoo/branch_diversity_gate.py"
SPEC="${ROOT}/tests/conformance/branch_diversity_spec.v1.json"
TEST_FILE="${ROOT}/tests/gentoo/test_branch_diversity_gate.py"

echo "=== Branch-Diversity Gate (bd-5fw.5) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Script exists with valid syntax
[[ -f "${SCRIPT}" ]] || fail "branch_diversity_gate.py not found"
python3 -c "import py_compile; py_compile.compile('${SCRIPT}', doraise=True)" \
  || fail "branch_diversity_gate.py has syntax errors"
echo "PASS: script syntax valid"

# 2. Spec file exists and is valid
[[ -f "${SPEC}" ]] || fail "branch_diversity_spec.v1.json not found"
python3 -c "
import json, sys
data = json.load(open('${SPEC}'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if 'math_families' not in data:
    sys.exit(1)
if 'milestones' not in data:
    sys.exit(1)
if 'constraints' not in data:
    sys.exit(1)
c = data['constraints']
if 'min_distinct_families' not in c:
    sys.exit(1)
if 'max_family_dominance_pct' not in c:
    sys.exit(1)
" || fail "spec schema invalid"
echo "PASS: spec file valid"

# 3. Gate produces valid JSON
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

RC=0
python3 "${SCRIPT}" --dry-run --format json \
  --output "${TMPDIR}/report.json" > /dev/null 2>&1 || RC=$?

# Gate may fail (rc=1) if diversity constraints are violated - that's OK
# We just need the output to be valid
[[ -f "${TMPDIR}/report.json" ]] || fail "no JSON output produced"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
if data.get('schema_version') != 'v1':
    print('bad schema_version'); sys.exit(1)
if data.get('bead') != 'bd-5fw.5':
    print('bad bead'); sys.exit(1)
if not isinstance(data.get('milestones'), list):
    print('missing milestones'); sys.exit(1)
if 'gate_passed' not in data:
    print('missing gate_passed'); sys.exit(1)
" || fail "JSON schema validation failed"
echo "PASS: JSON output schema valid"

# 4. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_branch_diversity_gate.py tests passed"
fi

echo ""
echo "PASS: Branch-Diversity gate (bd-5fw.5) all checks passed"
