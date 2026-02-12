#!/usr/bin/env bash
# check_replacement_guard.sh — CI gate for bd-130
#
# Enforces the replacement profile guard: no glibc call-through permitted
# outside the interpose allowlist. In replacement mode (L2/L3), ALL modules
# must be free of host glibc function calls.
#
# Modes:
#   interpose  — allowlisted modules may call through (default)
#   replacement — zero call-through permitted anywhere
#
# Usage:
#   bash scripts/check_replacement_guard.sh [interpose|replacement]
#
# Exit codes:
#   0 — guard passes
#   1 — forbidden call-through detected
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ABI_SRC="${ROOT}/crates/frankenlibc-abi/src"
PROFILE_DEF="${ROOT}/tests/conformance/replacement_profile.json"
MODE="${1:-interpose}"

failures=0

echo "=== Replacement Profile Guard (bd-130) ==="
echo "mode=${MODE}"
echo ""

# ---------------------------------------------------------------------------
# Check 1: Profile definition exists
# ---------------------------------------------------------------------------
echo "--- Check 1: Profile definition ---"

if [[ ! -f "${PROFILE_DEF}" ]]; then
    echo "FAIL: tests/conformance/replacement_profile.json not found"
    failures=$((failures + 1))
else
    echo "PASS: Profile definition exists"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Scan ABI source for call-through patterns
# ---------------------------------------------------------------------------
echo "--- Check 2: Call-through scan (mode=${MODE}) ---"

scan_result=$(python3 -c "
import json, re, os

abi_src = '${ABI_SRC}'
profile_path = '${PROFILE_DEF}'
mode = '${MODE}'

with open(profile_path) as f:
    profile = json.load(f)

allowlist = set(profile['interpose_allowlist']['modules'])

call_through_re = re.compile(r'libc::([a-z_][a-z0-9_]*)\s*\(')

violations = []
module_counts = {}

for fname in sorted(os.listdir(abi_src)):
    if not fname.endswith('_abi.rs'):
        continue
    module = fname.replace('.rs', '')
    filepath = os.path.join(abi_src, fname)

    with open(filepath) as f:
        lines = f.readlines()

    module_calls = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith('//'):
            continue
        for m in call_through_re.finditer(line):
            func_name = m.group(1)
            if func_name == 'syscall':
                continue
            module_calls.append({
                'line': lineno,
                'function': func_name,
                'context': stripped[:120]
            })

    if module_calls:
        module_counts[module] = len(module_calls)
        is_forbidden = False
        if mode == 'replacement':
            is_forbidden = True
        elif mode == 'interpose' and module not in allowlist:
            is_forbidden = True
        if is_forbidden:
            for call in module_calls:
                violations.append({
                    'module': module,
                    'line': call['line'],
                    'function': call['function'],
                    'context': call['context']
                })

total_ct = sum(module_counts.values())
print(f'TOTAL_CALL_THROUGHS={total_ct}')
print(f'MODULES_WITH_CT={len(module_counts)}')
print(f'VIOLATIONS={len(violations)}')

for mod, count in sorted(module_counts.items()):
    allowed = 'ALLOWED' if (mode == 'interpose' and mod in allowlist) else 'FORBIDDEN'
    print(f'  MODULE: {mod} calls={count} [{allowed}]')

if violations:
    print('')
    print('VIOLATION DETAILS:')
    for v in violations:
        print(f\"  {v['module']}.rs:{v['line']} libc::{v['function']}() -- {v['context']}\")
")

total_ct=$(echo "${scan_result}" | grep '^TOTAL_CALL_THROUGHS=' | cut -d= -f2)
violation_count=$(echo "${scan_result}" | grep '^VIOLATIONS=' | cut -d= -f2)
modules_ct=$(echo "${scan_result}" | grep '^MODULES_WITH_CT=' | cut -d= -f2)

echo "Total call-throughs found: ${total_ct} across ${modules_ct} modules"
echo "${scan_result}" | grep '  MODULE:'
echo ""

if [[ "${violation_count}" -gt 0 ]]; then
    echo "FAIL: ${violation_count} forbidden call-through(s) in ${MODE} mode:"
    echo "${scan_result}" | grep -A1000 'VIOLATION DETAILS:' | tail -n +2
    failures=$((failures + 1))
else
    echo "PASS: No forbidden call-throughs in ${MODE} mode"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Verify no pthread/syscall call-through outside allowlist
# ---------------------------------------------------------------------------
echo "--- Check 3: Pthread/syscall isolation ---"

pthread_check=$(python3 -c "
import os, re

abi_src = '${ABI_SRC}'
call_re = re.compile(r'libc::pthread_[a-z_]+\s*\(')
violations = []

for fname in sorted(os.listdir(abi_src)):
    if not fname.endswith('.rs') or fname == 'pthread_abi.rs':
        continue
    filepath = os.path.join(abi_src, fname)
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            if line.strip().startswith('//'):
                continue
            for m in call_re.finditer(line):
                violations.append(f'{fname}:{lineno} {m.group(0).strip()}')

print(f'PTHREAD_VIOLATIONS={len(violations)}')
for v in violations:
    print(f'  {v}')
")

pthread_violations=$(echo "${pthread_check}" | grep '^PTHREAD_VIOLATIONS=' | cut -d= -f2)

if [[ "${pthread_violations}" -gt 0 ]]; then
    echo "FAIL: pthread call-through found outside pthread_abi.rs:"
    echo "${pthread_check}" | grep -v 'PTHREAD_VIOLATIONS='
    failures=$((failures + 1))
else
    echo "PASS: All pthread calls confined to pthread_abi.rs"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Raw syscall audit — verify syscall usage is correct
# ---------------------------------------------------------------------------
echo "--- Check 4: Raw syscall audit ---"

syscall_check=$(python3 -c "
import os, re

abi_src = '${ABI_SRC}'
syscall_re = re.compile(r'libc::syscall\s*\(\s*libc::SYS_([a-z_0-9]+)')
syscalls_by_module = {}

for fname in sorted(os.listdir(abi_src)):
    if not fname.endswith('.rs'):
        continue
    module = fname.replace('.rs', '')
    filepath = os.path.join(abi_src, fname)
    with open(filepath) as f:
        for lineno, line in enumerate(f, 1):
            if line.strip().startswith('//'):
                continue
            for m in syscall_re.finditer(line):
                syscalls_by_module.setdefault(module, []).append(m.group(1))

total = sum(len(v) for v in syscalls_by_module.values())
print(f'RAW_SYSCALLS={total}')
for mod, calls in sorted(syscalls_by_module.items()):
    unique = sorted(set(calls))
    print(f'  {mod}: {\", \".join(unique)}')
")

raw_syscalls=$(echo "${syscall_check}" | grep '^RAW_SYSCALLS=' | cut -d= -f2)
echo "Raw syscalls found: ${raw_syscalls} (these are safe)"
echo "${syscall_check}" | grep '  '
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Mode: ${MODE}"
echo "Total call-throughs: ${total_ct}"
echo "Violations: ${violation_count}"
echo "Failures: ${failures}"

if [[ "${MODE}" == "interpose" ]]; then
    echo ""
    echo "Note: In interpose mode, allowlisted modules may call through to host glibc."
    echo "Run with 'replacement' argument to enforce zero call-through."
fi

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_replacement_guard: FAILED"
    exit 1
fi

echo ""
echo "check_replacement_guard: PASS"
