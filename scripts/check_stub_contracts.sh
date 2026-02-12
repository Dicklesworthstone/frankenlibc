#!/usr/bin/env bash
# check_stub_contracts.sh — CI gate for bd-2y6
#
# Validates:
# 1. stub_contracts.json exists and is valid JSON.
# 2. Every symbol listed has required contract fields.
# 3. All symbols marked Stub in support_matrix.json appear in contracts.
# 4. No contract claims panics=true or calls_todo=true.
# 5. Every contracted symbol exists in the ABI source.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

CONTRACTS="${ROOT}/tests/conformance/stub_contracts.json"
MATRIX="${ROOT}/support_matrix.json"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"

failures=0

echo "=== Stub Contracts Gate (bd-2y6) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Contracts file exists and is valid JSON
# ---------------------------------------------------------------------------
echo "--- Check 1: Contracts file exists and is valid ---"

if [[ ! -f "${CONTRACTS}" ]]; then
    echo "FAIL: tests/conformance/stub_contracts.json not found"
    failures=$((failures + 1))
elif ! python3 -c "import json; json.load(open('${CONTRACTS}'))" 2>/dev/null; then
    echo "FAIL: stub_contracts.json is not valid JSON"
    failures=$((failures + 1))
else
    echo "PASS: stub_contracts.json exists and is valid JSON"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Contract schema validation
# ---------------------------------------------------------------------------
echo "--- Check 2: Contract schema validation ---"

schema_check=$(python3 -c "
import json, sys
errors = []
with open('${CONTRACTS}') as f:
    data = json.load(f)

if 'contract_version' not in data:
    errors.append('Missing contract_version')
if 'contracts' not in data:
    errors.append('Missing contracts array')
    print(f'ERRORS={len(errors)}')
    for e in errors: print(f'  {e}')
    sys.exit(0)

required_fields = ['symbol', 'matrix_status', 'actual_status', 'module', 'behavior', 'rationale']
behavior_fields = ['description', 'panics', 'calls_todo', 'deterministic']

for i, c in enumerate(data['contracts']):
    sym = c.get('symbol', f'<contract #{i}>')
    for field in required_fields:
        if field not in c:
            errors.append(f'{sym}: missing required field \"{field}\"')
    if 'behavior' in c:
        for field in behavior_fields:
            if field not in c['behavior']:
                errors.append(f'{sym}: behavior missing \"{field}\"')

print(f'CONTRACTS={len(data[\"contracts\"])}')
print(f'ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

schema_contracts=$(echo "${schema_check}" | grep 'CONTRACTS=' | cut -d= -f2)
schema_errors=$(echo "${schema_check}" | grep 'ERRORS=' | cut -d= -f2)

if [[ "${schema_errors}" -gt 0 ]]; then
    echo "FAIL: ${schema_errors} schema error(s):"
    echo "${schema_check}" | grep -v 'CONTRACTS=' | grep -v 'ERRORS='
    failures=$((failures + 1))
else
    echo "PASS: ${schema_contracts} contracts, all schema-valid"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Coverage — all Stub symbols from matrix are contracted
# ---------------------------------------------------------------------------
echo "--- Check 3: Stub symbol coverage ---"

coverage_check=$(python3 -c "
import json
with open('${MATRIX}') as f:
    matrix = json.load(f)
with open('${CONTRACTS}') as f:
    contracts = json.load(f)

# Find all Stub symbols in support_matrix (symbols is a list of objects)
stub_symbols = set()
for entry in matrix.get('symbols', []):
    if entry.get('status') == 'Stub':
        stub_symbols.add(entry['symbol'])

# Find all contracted symbols
contracted = set()
for c in contracts.get('contracts', []):
    contracted.add(c['symbol'])

missing = stub_symbols - contracted
extra = contracted - stub_symbols

print(f'STUB_COUNT={len(stub_symbols)}')
print(f'CONTRACTED={len(contracted)}')
print(f'MISSING={len(missing)}')
print(f'EXTRA={len(extra)}')
for s in sorted(missing):
    print(f'  MISSING: {s}')
for s in sorted(extra):
    print(f'  EXTRA: {s} (contracted but not marked Stub)')
")

cov_missing=$(echo "${coverage_check}" | grep '^MISSING=' | cut -d= -f2)
cov_stub=$(echo "${coverage_check}" | grep '^STUB_COUNT=' | cut -d= -f2)
cov_contracted=$(echo "${coverage_check}" | grep '^CONTRACTED=' | cut -d= -f2)

if [[ "${cov_missing}" -gt 0 ]]; then
    echo "FAIL: ${cov_missing} Stub symbol(s) not covered by contracts:"
    echo "${coverage_check}" | grep '  MISSING:'
    failures=$((failures + 1))
else
    echo "PASS: All ${cov_stub} Stub symbols covered (${cov_contracted} contracts total)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Safety — no panics or todo!() in contracts
# ---------------------------------------------------------------------------
echo "--- Check 4: Safety invariants ---"

safety_check=$(python3 -c "
import json
with open('${CONTRACTS}') as f:
    data = json.load(f)

violations = []
for c in data.get('contracts', []):
    sym = c['symbol']
    b = c.get('behavior', {})
    if b.get('panics', False):
        violations.append(f'{sym}: panics=true')
    if b.get('calls_todo', False):
        violations.append(f'{sym}: calls_todo=true')
    if not b.get('deterministic', True):
        violations.append(f'{sym}: deterministic=false')

print(f'VIOLATIONS={len(violations)}')
for v in violations:
    print(f'  {v}')
")

safety_violations=$(echo "${safety_check}" | grep 'VIOLATIONS=' | cut -d= -f2)

if [[ "${safety_violations}" -gt 0 ]]; then
    echo "FAIL: ${safety_violations} safety violation(s):"
    echo "${safety_check}" | grep -v 'VIOLATIONS='
    failures=$((failures + 1))
else
    echo "PASS: No panics, no todo!(), all deterministic"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: ABI source existence — every contracted symbol exists in source
# ---------------------------------------------------------------------------
echo "--- Check 5: ABI source cross-reference ---"

source_check=$(python3 -c "
import json, os, re

with open('${CONTRACTS}') as f:
    data = json.load(f)

abi_src = '${ABI_SRC}'
missing = []

for c in data.get('contracts', []):
    sym = c['symbol']
    module = c.get('module', '')
    src_file = os.path.join(abi_src, f'{module}.rs')

    if not os.path.exists(src_file):
        missing.append(f'{sym}: module file {module}.rs not found')
        continue

    with open(src_file) as f:
        content = f.read()

    pattern = rf'pub\s+unsafe\s+extern\s+\"C\"\s+fn\s+{re.escape(sym)}\s*\('
    if not re.search(pattern, content):
        missing.append(f'{sym}: extern \"C\" fn not found in {module}.rs')

print(f'MISSING={len(missing)}')
for m in missing:
    print(f'  {m}')
")

src_missing=$(echo "${source_check}" | grep 'MISSING=' | cut -d= -f2)

if [[ "${src_missing}" -gt 0 ]]; then
    echo "FAIL: ${src_missing} symbol(s) not found in ABI source:"
    echo "${source_check}" | grep -v 'MISSING='
    failures=$((failures + 1))
else
    echo "PASS: All contracted symbols found in ABI source"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_stub_contracts: FAILED"
    exit 1
fi

echo ""
echo "check_stub_contracts: PASS"
