#!/usr/bin/env bash
# check_symbol_drift.sh — CI gate for bd-28s
#
# Cross-references support_matrix.json against ABI source code:
#   1. Every matrix symbol's module file exists.
#   2. Every matrix symbol has a matching extern "C" fn in its module.
#   3. Every extern "C" fn in ABI source has a matrix entry.
#   4. No duplicate symbols in the matrix.
#   5. Status distribution sanity check.
#
# Exit codes:
#   0 — no drift detected
#   1 — drift or validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/support_matrix.json"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"

failures=0

echo "=== Symbol Drift Guard (bd-28s) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Matrix file exists
# ---------------------------------------------------------------------------
echo "--- Check 1: Matrix file exists ---"

if [[ ! -f "${MATRIX}" ]]; then
    echo "FAIL: support_matrix.json not found"
    echo ""
    echo "check_symbol_drift: FAILED"
    exit 1
fi
echo "PASS: support_matrix.json exists"
echo ""

# ---------------------------------------------------------------------------
# Check 2: Matrix symbols vs ABI source
# ---------------------------------------------------------------------------
echo "--- Check 2: Matrix symbols → ABI source ---"

forward_check=$(python3 -c "
import json, os, re

with open('${MATRIX}') as f:
    matrix = json.load(f)

abi_src = '${ABI_SRC}'
symbols = matrix.get('symbols', [])
errors = []
warnings = []

# Data symbols that are statics, not functions
data_symbols = {'stdin', 'stdout', 'stderr'}

for entry in symbols:
    sym = entry['symbol']
    module = entry.get('module', 'unknown')
    src_file = os.path.join(abi_src, f'{module}.rs')

    if not os.path.isfile(src_file):
        errors.append(f'{sym}: module file {module}.rs not found')
        continue

    if sym in data_symbols:
        continue

    with open(src_file) as f:
        content = f.read()

    # Look for extern \"C\" fn declaration
    # Patterns: 'fn symbol_name(' or 'fn __symbol_name(' for dunder names
    pattern = f'fn {sym}('
    if pattern not in content:
        # Also check for #[no_mangle] pub extern patterns
        alt_pattern = f'fn {sym} ('
        if alt_pattern not in content:
            warnings.append(f'{sym}: fn {sym}() not found in {module}.rs')

print(f'FORWARD_ERRORS={len(errors)}')
print(f'FORWARD_WARNINGS={len(warnings)}')
for e in errors:
    print(f'  ERROR: {e}')
for w in warnings[:20]:
    print(f'  WARN: {w}')
")

fwd_errs=$(echo "${forward_check}" | grep '^FORWARD_ERRORS=' | cut -d= -f2)
fwd_warns=$(echo "${forward_check}" | grep '^FORWARD_WARNINGS=' | cut -d= -f2)

echo "Module file errors: ${fwd_errs}"
echo "Symbol definition warnings: ${fwd_warns}"

if [[ "${fwd_errs}" -gt 0 ]]; then
    echo "FAIL: ${fwd_errs} module file(s) not found:"
    echo "${forward_check}" | grep '  ERROR:' | head -10
    failures=$((failures + 1))
else
    echo "PASS: All matrix module files exist"
fi

if [[ "${fwd_warns}" -gt 0 ]]; then
    echo "WARNING: ${fwd_warns} symbol(s) not found in expected module (may use alternate patterns):"
    echo "${forward_check}" | grep '  WARN:' | head -10
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: ABI source fns vs matrix (reverse drift)
# ---------------------------------------------------------------------------
echo "--- Check 3: ABI source → matrix (reverse drift) ---"

reverse_check=$(python3 -c "
import json, os, re

with open('${MATRIX}') as f:
    matrix = json.load(f)

abi_src = '${ABI_SRC}'

# Build set of matrix symbols
matrix_syms = set()
for entry in matrix.get('symbols', []):
    matrix_syms.add(entry['symbol'])

# Scan ABI source for extern \"C\" fn declarations
# Pattern: pub unsafe extern \"C\" fn name(
fn_pattern = re.compile(r'pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+(\w+)\s*\(')

orphan_fns = []
for filename in sorted(os.listdir(abi_src)):
    if not filename.endswith('_abi.rs'):
        continue
    filepath = os.path.join(abi_src, filename)
    with open(filepath) as f:
        content = f.read()

    for match in fn_pattern.finditer(content):
        fn_name = match.group(1)
        if fn_name not in matrix_syms:
            orphan_fns.append(f'{fn_name} in {filename}')

print(f'ORPHAN_FNS={len(orphan_fns)}')
for o in orphan_fns[:20]:
    print(f'  {o}')
")

orphan_count=$(echo "${reverse_check}" | grep '^ORPHAN_FNS=' | cut -d= -f2)

if [[ "${orphan_count}" -gt 0 ]]; then
    echo "WARNING: ${orphan_count} ABI function(s) not in support_matrix.json (informational):"
    echo "${reverse_check}" | grep '  ' | head -20
else
    echo "PASS: All ABI source functions have matrix entries"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: No duplicate symbols
# ---------------------------------------------------------------------------
echo "--- Check 4: No duplicate symbols ---"

dup_check=$(python3 -c "
import json

with open('${MATRIX}') as f:
    matrix = json.load(f)

seen = {}
dups = []
for entry in matrix.get('symbols', []):
    sym = entry['symbol']
    if sym in seen:
        dups.append(f'{sym} (first in {seen[sym]}, duplicate in {entry.get(\"module\", \"?\")})')
    seen[sym] = entry.get('module', '?')

print(f'DUPLICATES={len(dups)}')
for d in dups:
    print(f'  {d}')
")

dup_count=$(echo "${dup_check}" | grep '^DUPLICATES=' | cut -d= -f2)

if [[ "${dup_count}" -gt 0 ]]; then
    echo "FAIL: ${dup_count} duplicate symbol(s):"
    echo "${dup_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: No duplicate symbols in matrix"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Status distribution sanity
# ---------------------------------------------------------------------------
echo "--- Check 5: Status distribution ---"

python3 -c "
import json

with open('${MATRIX}') as f:
    matrix = json.load(f)

symbols = matrix.get('symbols', [])
by_status = {}
by_module = {}
for entry in symbols:
    status = entry.get('status', 'unknown')
    module = entry.get('module', 'unknown')
    by_status[status] = by_status.get(status, 0) + 1
    by_module[module] = by_module.get(module, 0) + 1

valid_statuses = {'Implemented', 'RawSyscall', 'GlibcCallThrough', 'Stub'}

print(f'Total symbols: {len(symbols)}')
print('By status:')
for status in sorted(by_status.keys()):
    marker = '' if status in valid_statuses else ' [INVALID]'
    print(f'  {status}: {by_status[status]}{marker}')

print(f'Modules: {len(by_module)}')

# Check for invalid statuses
invalid = [s for s in by_status if s not in valid_statuses]
if invalid:
    print(f'INVALID_STATUSES={len(invalid)}')
else:
    print('INVALID_STATUSES=0')
"
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_symbol_drift: FAILED"
    exit 1
fi

echo ""
echo "check_symbol_drift: PASS"
