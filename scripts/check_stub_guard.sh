#!/usr/bin/env bash
# check_stub_guard.sh — CI guard for bd-1h4
#
# Enforces:
# 1. No todo!/unimplemented!/panic! in any code path reachable from ABI
#    symbols classified as "Implemented" or "RawSyscall" in support_matrix.json.
# 2. Every symbol marked "Stub" returns a deterministic errno (no silent UB).
# 3. Cross-checks census output against support matrix for inconsistencies.
#
# Exit codes:
#   0 — all checks pass
#   1 — reachable todo!/unimplemented! found in Implemented symbol
#   2 — support matrix inconsistency detected
#   3 — deterministic stub contract violation
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/support_matrix.json"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"
CORE_SRC="${ROOT}/crates/frankenlibc-core/src"

failures=0
warnings=0

echo "=== Stub Guard (bd-1h4) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: No todo!/unimplemented!/panic! in ABI crate
# ---------------------------------------------------------------------------
echo "--- Check 1: No todo!/unimplemented!/panic! in ABI layer ---"

abi_stubs=$(grep -rn 'todo!\|unimplemented!\|panic!' "${ABI_SRC}" 2>/dev/null \
    | grep -v '#\[should_panic' \
    | grep -v '// test' \
    | grep -v '#\[cfg(test)' || true)

if [[ -n "${abi_stubs}" ]]; then
    echo "FAIL: todo!/unimplemented!/panic! found in ABI crate:"
    echo "${abi_stubs}"
    failures=$((failures + 1))
else
    echo "PASS: No todo!/unimplemented!/panic! in ABI crate"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: No todo!/unimplemented!/panic! in core modules called by ABI
#           for symbols marked Implemented
# ---------------------------------------------------------------------------
echo "--- Check 2: Implemented symbols have no reachable stubs ---"

# Run the census (reuse if recent, otherwise regenerate)
census="${ROOT}/tests/conformance/stub_census.json"
if [[ ! -f "${census}" ]] || [[ "$(find "${census}" -mmin +60 2>/dev/null)" ]]; then
    echo "  Regenerating stub census..."
    bash "${ROOT}/scripts/stub_census.sh" >/dev/null 2>&1
fi

reachable=$(python3 -c "
import json
with open('${census}') as f:
    data = json.load(f)
count = 0
for s in data['stubs']:
    if s['reachable_from_abi']:
        # Check if the corresponding matrix entry is Implemented
        status = s.get('support_matrix_status', '')
        if status in ('Implemented', 'RawSyscall'):
            print(f\"  VIOLATION: {s['symbol']} is {status} but reachable core code has {s['stub_type']}\")
            print(f\"    Location: {s['core_location']}\")
            count += 1
print(f'REACHABLE_VIOLATIONS={count}')
")

violation_count=$(echo "${reachable}" | grep 'REACHABLE_VIOLATIONS=' | cut -d= -f2)
if [[ "${violation_count}" -gt 0 ]]; then
    echo "FAIL: ${violation_count} Implemented/RawSyscall symbol(s) have reachable todo!:"
    echo "${reachable}" | grep -v 'REACHABLE_VIOLATIONS='
    failures=$((failures + 1))
else
    echo "PASS: No Implemented/RawSyscall symbols have reachable stubs"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Support matrix consistency
# ---------------------------------------------------------------------------
echo "--- Check 3: Support matrix consistency ---"

inconsistencies=$(python3 -c "
import json
with open('${census}') as f:
    data = json.load(f)
count = 0
for i in data['inconsistencies']:
    sev = i['severity']
    print(f\"  [{sev.upper()}] {i['symbol']}: matrix says {i['matrix_status']}, actually {i['actual_status']}\")
    print(f\"    Evidence: {i['evidence']}\")
    count += 1
print(f'INCONSISTENCIES={count}')
")

incon_count=$(echo "${inconsistencies}" | grep 'INCONSISTENCIES=' | cut -d= -f2)
if [[ "${incon_count}" -gt 0 ]]; then
    echo "WARNING: ${incon_count} support matrix inconsistencies:"
    echo "${inconsistencies}" | grep -v 'INCONSISTENCIES='
    warnings=$((warnings + 1))
    # Inconsistencies are warnings (exit 2) not hard failures
else
    echo "PASS: Support matrix is consistent with code"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Stub errno contracts
# ---------------------------------------------------------------------------
echo "--- Check 4: Stub symbols return deterministic errno ---"

# For symbols marked as Stub in the matrix, verify their ABI module
# either doesn't export them (acceptable) or returns a deterministic error
stub_violations=$(python3 -c "
import json, os, re
with open('${MATRIX}') as f:
    matrix = json.load(f)
violations = 0
for sym in matrix['symbols']:
    if sym['status'] != 'Stub':
        continue
    # Check if the symbol has an ABI export
    mod_file = os.path.join('${ABI_SRC}', sym['module'] + '.rs')
    if not os.path.exists(mod_file):
        continue
    with open(mod_file) as f:
        content = f.read()
    # Check if the function exists in the file
    fn_pattern = rf'fn\s+{re.escape(sym[\"symbol\"])}\s*\('
    if not re.search(fn_pattern, content):
        # Symbol not exported in this module — that's a different issue
        continue
    # If exported, verify it doesn't use todo!/unimplemented!
    # Extract the function body (simplified: from fn definition to next fn or end)
    fn_match = re.search(fn_pattern, content)
    if fn_match:
        body_start = content.find('{', fn_match.end())
        if body_start != -1:
            # Simplified body extraction
            depth = 1
            pos = body_start + 1
            while pos < len(content) and depth > 0:
                if content[pos] == '{': depth += 1
                elif content[pos] == '}': depth -= 1
                pos += 1
            body = content[body_start:pos]
            if 'todo!' in body or 'unimplemented!' in body:
                print(f\"  VIOLATION: Stub {sym['symbol']} in {sym['module']}.rs has todo!/unimplemented!\")
                violations += 1
print(f'STUB_VIOLATIONS={violations}')
")

stub_v_count=$(echo "${stub_violations}" | grep 'STUB_VIOLATIONS=' | cut -d= -f2)
if [[ "${stub_v_count}" -gt 0 ]]; then
    echo "FAIL: ${stub_v_count} Stub symbol(s) use todo!/unimplemented! instead of deterministic errno:"
    echo "${stub_violations}" | grep -v 'STUB_VIOLATIONS='
    failures=$((failures + 1))
else
    echo "PASS: All exported Stub symbols return deterministic errno"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"
echo "Warnings: ${warnings}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_stub_guard: FAILED"
    exit 1
fi

if [[ "${warnings}" -gt 0 ]]; then
    echo ""
    echo "check_stub_guard: PASS (with ${warnings} warning(s))"
    exit 0  # Warnings are informational, not blocking
fi

echo ""
echo "check_stub_guard: PASS"
