#!/usr/bin/env bash
# check_c_fixture_suite.sh — CI gate for bd-3jh
#
# Validates that:
#   1. Fixture spec JSON exists and is valid.
#   2. All fixture source files exist and compile.
#   3. Fixture spec covers required acceptance symbols.
#   4. Covered modules reference valid support_matrix modules.
#   5. Summary statistics are consistent.
#   6. bd-15n.2 high-risk fixtures include traceability + strict/hardened expectations.
#
# This gate does NOT run fixtures under LD_PRELOAD (that's c_fixture_suite.sh).
# It validates the fixture suite structure and spec.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation errors found
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT}/tests/conformance/c_fixture_spec.json"
MATRIX="${ROOT}/support_matrix.json"

failures=0

echo "=== C Fixture Suite Gate (bd-3jh) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Spec exists and is valid
# ---------------------------------------------------------------------------
echo "--- Check 1: Fixture spec exists and is valid ---"

if [[ ! -f "${SPEC}" ]]; then
    echo "FAIL: tests/conformance/c_fixture_spec.json not found"
    echo ""
    echo "check_c_fixture_suite: FAILED"
    exit 1
fi

valid_check=$(python3 -c "
import json
try:
    with open('${SPEC}') as f:
        s = json.load(f)
    v = s.get('schema_version', 0)
    fixtures = s.get('fixtures', [])
    if v < 1:
        print('INVALID: schema_version < 1')
    elif not fixtures:
        print('INVALID: empty fixtures')
    else:
        total_tests = sum(f.get('tests', 0) for f in fixtures)
        print(f'VALID version={v} fixtures={len(fixtures)} tests={total_tests}')
except Exception as e:
    print(f'INVALID: {e}')
")

if [[ "${valid_check}" == INVALID* ]]; then
    echo "FAIL: ${valid_check}"
    failures=$((failures + 1))
else
    echo "PASS: ${valid_check}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: All fixture source files exist and compile
# ---------------------------------------------------------------------------
echo "--- Check 2: Fixture source files exist ---"

src_check=$(python3 -c "
import json, os

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
root = '${ROOT}'
for fixture in spec.get('fixtures', []):
    fid = fixture.get('id', '?')
    src = fixture.get('source', '')
    path = os.path.join(root, src)
    if not os.path.isfile(path):
        errors.append(f'{fid}: source not found: {src}')

print(f'SRC_ERRORS={len(errors)}')
print(f'FIXTURES={len(spec.get(\"fixtures\", []))}')
for e in errors:
    print(f'  {e}')
")

src_errs=$(echo "${src_check}" | grep '^SRC_ERRORS=' | cut -d= -f2)

if [[ "${src_errs}" -gt 0 ]]; then
    echo "FAIL: ${src_errs} source file error(s):"
    echo "${src_check}" | grep '  '
    failures=$((failures + 1))
else
    count=$(echo "${src_check}" | grep '^FIXTURES=' | cut -d= -f2)
    echo "PASS: All ${count} fixture source files exist"
fi

# Try to compile if cc is available
if command -v cc >/dev/null 2>&1; then
    compile_fails=0
    tmpdir=$(mktemp -d)
    for src in "${ROOT}"/tests/integration/fixture_*.c; do
        name="$(basename "${src}" .c)"
        flags=""
        if [[ "${name}" == fixture_pthread* ]]; then
            flags="-pthread"
        elif [[ "${name}" == "fixture_math" ]]; then
            flags="-lm"
        fi
        if ! cc -O2 -Wall -Wextra "${src}" -o "${tmpdir}/${name}" ${flags} 2>/dev/null; then
            echo "FAIL: ${name} does not compile"
            compile_fails=$((compile_fails + 1))
        fi
    done

    if [[ "${compile_fails}" -gt 0 ]]; then
        failures=$((failures + 1))
    else
        echo "PASS: All fixtures compile successfully"
    fi
else
    echo "SKIP: cc not found, cannot verify compilation"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Required acceptance symbols covered
# ---------------------------------------------------------------------------
echo "--- Check 3: Acceptance symbol coverage ---"

cov_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []

required = set(spec.get('coverage_summary', {}).get('required_by_acceptance', []))

covered = set()
for fixture in spec.get('fixtures', []):
    for sym in fixture.get('covered_symbols', []):
        covered.add(sym)

missing = required - covered
if missing:
    errors.append(f'Required symbols not covered by fixtures: {sorted(missing)}')

print(f'COV_ERRORS={len(errors)}')
print(f'REQUIRED={len(required)}')
print(f'COVERED={len(covered)}')
for e in errors:
    print(f'  {e}')
")

cov_errs=$(echo "${cov_check}" | grep '^COV_ERRORS=' | cut -d= -f2)

if [[ "${cov_errs}" -gt 0 ]]; then
    echo "FAIL: ${cov_errs} coverage error(s):"
    echo "${cov_check}" | grep '  '
    failures=$((failures + 1))
else
    req=$(echo "${cov_check}" | grep '^REQUIRED=' | cut -d= -f2)
    cov=$(echo "${cov_check}" | grep '^COVERED=' | cut -d= -f2)
    echo "PASS: ${req} required symbols covered (${cov} total)"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Covered modules valid
# ---------------------------------------------------------------------------
echo "--- Check 4: Module validity ---"

mod_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)
with open('${MATRIX}') as f:
    matrix = json.load(f)

errors = []
valid_modules = set(s.get('module', '') for s in matrix.get('symbols', []))

for fixture in spec.get('fixtures', []):
    fid = fixture.get('id', '?')
    for mod in fixture.get('covered_modules', []):
        if mod not in valid_modules:
            errors.append(f'{fid}: invalid module \"{mod}\"')

print(f'MOD_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

mod_errs=$(echo "${mod_check}" | grep '^MOD_ERRORS=' | cut -d= -f2)

if [[ "${mod_errs}" -gt 0 ]]; then
    echo "FAIL: ${mod_errs} module error(s):"
    echo "${mod_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: All covered modules valid in support_matrix"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Summary consistency
# ---------------------------------------------------------------------------
echo "--- Check 5: Summary consistency ---"

sum_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

errors = []
summary = spec.get('summary', {})
fixtures = spec.get('fixtures', [])

total_fixtures = len(fixtures)
total_tests = sum(f.get('tests', 0) for f in fixtures)
all_symbols = set()
all_modules = set()
for f in fixtures:
    for sym in f.get('covered_symbols', []):
        all_symbols.add(sym)
    for mod in f.get('covered_modules', []):
        all_modules.add(mod)

if summary.get('total_fixtures', 0) != total_fixtures:
    errors.append(f'total_fixtures: claimed={summary.get(\"total_fixtures\")} actual={total_fixtures}')
if summary.get('total_tests', 0) != total_tests:
    errors.append(f'total_tests: claimed={summary.get(\"total_tests\")} actual={total_tests}')
if summary.get('modules_covered', 0) != len(all_modules):
    errors.append(f'modules_covered: claimed={summary.get(\"modules_covered\")} actual={len(all_modules)}')
if summary.get('symbols_covered', 0) != len(all_symbols):
    errors.append(f'symbols_covered: claimed={summary.get(\"symbols_covered\")} actual={len(all_symbols)}')

# Check coverage_summary matches too
cs = spec.get('coverage_summary', {})
if cs.get('total_fixtures', 0) != total_fixtures:
    errors.append(f'coverage_summary.total_fixtures mismatch')
if cs.get('total_tests', 0) != total_tests:
    errors.append(f'coverage_summary.total_tests mismatch')

print(f'SUMMARY_ERRORS={len(errors)}')
print(f'Fixtures: {total_fixtures} | Tests: {total_tests} | Symbols: {len(all_symbols)} | Modules: {len(all_modules)}')
for e in errors:
    print(f'  {e}')
")

sum_errs=$(echo "${sum_check}" | grep '^SUMMARY_ERRORS=' | cut -d= -f2)

if [[ "${sum_errs}" -gt 0 ]]; then
    echo "FAIL: ${sum_errs} summary error(s):"
    echo "${sum_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: Summary statistics consistent"
fi
echo "${sum_check}" | grep -E '^Fixtures' || true
echo ""

# ---------------------------------------------------------------------------
# Check 6: bd-15n.2 traceability + mode expectations
# ---------------------------------------------------------------------------
echo "--- Check 6: bd-15n.2 metadata (traceability + strict/hardened expectations) ---"

trace_check=$(python3 -c "
import json

with open('${SPEC}') as f:
    spec = json.load(f)

required = {'fixture_ctype', 'fixture_math', 'fixture_socket'}
by_id = {f.get('id'): f for f in spec.get('fixtures', []) if isinstance(f, dict)}
errors = []

for fid in sorted(required):
    fixture = by_id.get(fid)
    if fixture is None:
        errors.append(f'missing fixture {fid}')
        continue

    traceability = fixture.get('spec_traceability')
    if not isinstance(traceability, dict):
        errors.append(f'{fid}: missing spec_traceability object')
    else:
        for key in ('posix', 'c11', 'internal'):
            refs = traceability.get(key)
            if not isinstance(refs, list) or not any(isinstance(x, str) and x.strip() for x in refs):
                errors.append(f'{fid}: spec_traceability.{key} must include at least one non-empty reference')

    mode_expectations = fixture.get('mode_expectations')
    if not isinstance(mode_expectations, dict):
        errors.append(f'{fid}: missing mode_expectations object')
    else:
        for mode in ('strict', 'hardened'):
            entry = mode_expectations.get(mode)
            if not isinstance(entry, dict):
                errors.append(f'{fid}: mode_expectations.{mode} missing')
                continue
            if entry.get('expected_exit') != 0:
                errors.append(f'{fid}: mode_expectations.{mode}.expected_exit must be 0')
            marker = entry.get('expected_stdout_contains')
            if not isinstance(marker, str) or not marker.strip():
                errors.append(f'{fid}: mode_expectations.{mode}.expected_stdout_contains missing')

print(f'TRACE_ERRORS={len(errors)}')
for e in errors:
    print(f'  {e}')
")

trace_errs=$(echo "${trace_check}" | grep '^TRACE_ERRORS=' | cut -d= -f2)
if [[ "${trace_errs}" -gt 0 ]]; then
    echo "FAIL: ${trace_errs} metadata error(s):"
    echo "${trace_check}" | grep '  '
    failures=$((failures + 1))
else
    echo "PASS: bd-15n.2 fixtures carry traceability + mode expectations"
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_c_fixture_suite: FAILED"
    exit 1
fi

echo ""
echo "check_c_fixture_suite: PASS"
