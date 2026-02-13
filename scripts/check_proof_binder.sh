#!/usr/bin/env bash
# CI gate: Proof obligations binder integrity (bd-5fw.4).
#
# Checks:
# 1. Binder JSON exists with correct schema
# 2. Validator script has valid syntax
# 3. Validator produces valid output
# 4. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINDER="${ROOT}/tests/conformance/proof_obligations_binder.v1.json"
VALIDATOR="${ROOT}/scripts/gentoo/proof_binder_validator.py"
TEST_FILE="${ROOT}/tests/gentoo/test_proof_binder.py"

echo "=== Proof Obligations Binder Gate (bd-5fw.4) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Binder exists with correct schema
[[ -f "${BINDER}" ]] || fail "proof_obligations_binder.v1.json not found"
python3 -c "
import json, sys
data = json.load(open('${BINDER}'))
if data.get('schema_version') != 'v1':
    sys.exit(1)
if data.get('bead') != 'bd-5fw.4':
    sys.exit(1)
obs = data.get('obligations', [])
if len(obs) < 10:
    print(f'Too few obligations: {len(obs)}'); sys.exit(1)
ids = [o['id'] for o in obs]
if len(ids) != len(set(ids)):
    print('Duplicate obligation IDs'); sys.exit(1)
for o in obs:
    if 'evidence_artifacts' not in o:
        print(f'Missing evidence_artifacts in {o[\"id\"]}'); sys.exit(1)
    if 'gates' not in o:
        print(f'Missing gates in {o[\"id\"]}'); sys.exit(1)
" || fail "binder schema invalid"
echo "PASS: binder schema valid"

# 2. Validator script has valid syntax
[[ -f "${VALIDATOR}" ]] || fail "proof_binder_validator.py not found"
python3 -c "import py_compile; py_compile.compile('${VALIDATOR}', doraise=True)" \
  || fail "proof_binder_validator.py has syntax errors"
echo "PASS: validator syntax valid"

# 3. Validator produces valid output
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

RC=0
python3 "${VALIDATOR}" --dry-run --format json --no-hashes \
  --output "${TMPDIR}/report.json" > /dev/null 2>&1 || RC=$?

[[ -f "${TMPDIR}/report.json" ]] || fail "no JSON output produced"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/report.json'))
if data.get('schema_version') != 'v1':
    print('bad schema_version'); sys.exit(1)
if data.get('bead') != 'bd-5fw.4':
    print('bad bead'); sys.exit(1)
if not isinstance(data.get('obligations'), list):
    print('missing obligations'); sys.exit(1)
if 'binder_valid' not in data:
    print('missing binder_valid'); sys.exit(1)
" || fail "validator output schema invalid"
echo "PASS: validator output valid"

# 4. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_proof_binder.py tests passed"
fi

echo ""
echo "PASS: Proof Obligations Binder gate (bd-5fw.4) all checks passed"
