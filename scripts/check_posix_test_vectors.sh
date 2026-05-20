#!/usr/bin/env bash
# check_posix_test_vectors.sh — validate FrankenLibC against POSIX test vectors (bd-2tq.1)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="default"
if [[ $# -gt 1 ]]; then
    echo "usage: $0 [--validate-only]" >&2
    exit 2
fi
if [[ $# -eq 1 ]]; then
    if [[ "$1" != "--validate-only" ]]; then
        echo "usage: $0 [--validate-only]" >&2
        exit 2
    fi
    MODE="validate-only"
fi

VECTORS="${FRANKENLIBC_POSIX_TEST_VECTORS:-${ROOT}/tests/conformance/posix_test_vectors.v1.json}"
OUT_DIR="${FRANKENLIBC_POSIX_TEST_VECTORS_OUT_DIR:-${ROOT}/target/conformance/posix_vectors}"
RUN_ID="${FRANKENLIBC_POSIX_TEST_VECTORS_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
REPORT="${FRANKENLIBC_POSIX_TEST_VECTORS_REPORT:-${OUT_DIR}/${RUN_ID}_report.json}"
LOG="${FRANKENLIBC_POSIX_TEST_VECTORS_LOG:-${OUT_DIR}/${RUN_ID}_log.jsonl}"
mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

if [ ! -f "${VECTORS}" ]; then
    echo "FAIL: missing ${VECTORS}" >&2
    exit 1
fi

echo "=== POSIX test vector validation (bd-2tq.1) ==="
echo "vectors: ${VECTORS}"
echo "run_id: ${RUN_ID}"

# Validate JSON is well-formed
python3 - "${VECTORS}" "${REPORT}" "${LOG}" "${RUN_ID}" "${MODE}" <<'PY'
import json
import pathlib
import sys

vectors_path = pathlib.Path(sys.argv[1])
report_path = pathlib.Path(sys.argv[2])
log_path = pathlib.Path(sys.argv[3])
run_id = sys.argv[4]
mode = sys.argv[5]

with open(vectors_path) as f:
    d = json.load(f)

summary = d.get('coverage_summary', {})
family_map = d.get('families', {})
families = len(family_map)
functions = summary.get('functions_with_vectors', 0)
positive = summary.get('total_positive_vectors', 0)
boundary = summary.get('total_boundary_vectors', 0)
error = summary.get('total_error_vectors', 0)
undefined = summary.get('total_undefined_documented', 0)
total = positive + boundary + error
print(f'Families: {families}')
print(f'Functions with vectors: {functions}')
print(f'Total vectors: {total} (positive={positive}, boundary={boundary}, error={error})')

# Validate structure
issues = []
if d.get('schema_version') != '1.0':
    issues.append('schema_version: expected 1.0')
if d.get('spec_reference') != 'IEEE Std 1003.1-2017 (POSIX.1)':
    issues.append('spec_reference: expected IEEE Std 1003.1-2017 (POSIX.1)')
if not isinstance(family_map, dict) or not family_map:
    issues.append('families: must be a non-empty object')
if not isinstance(summary, dict):
    issues.append('coverage_summary: must be an object')

actual_functions = 0
actual_positive = 0
actual_boundary = 0
actual_error = 0
actual_undefined = 0

for fam_name, fam in family_map.items():
    if not isinstance(fam, dict) or not fam:
        issues.append(f'{fam_name}: family must be a non-empty object')
        continue
    for fn_name, fn_data in fam.items():
        if not isinstance(fn_data, dict):
            issues.append(f'{fam_name}/{fn_name}: function entry must be an object')
            continue
        actual_functions += 1
        if 'test_vectors' not in fn_data and 'error_conditions' not in fn_data:
            issues.append(f'{fam_name}/{fn_name}: missing test_vectors or error_conditions')
        if 'spec_section' not in fn_data:
            issues.append(f'{fam_name}/{fn_name}: missing spec_section')
        for vector in fn_data.get('test_vectors', []):
            category = vector.get('category') if isinstance(vector, dict) else None
            if category == 'positive':
                actual_positive += 1
            elif category == 'boundary':
                actual_boundary += 1
            elif category == 'error':
                actual_error += 1
            else:
                issues.append(f'{fam_name}/{fn_name}: vector has unknown category {category!r}')
        error_conditions = fn_data.get('error_conditions', [])
        if isinstance(error_conditions, list):
            actual_error += len(error_conditions)
        else:
            issues.append(f'{fam_name}/{fn_name}: error_conditions must be an array')
        undefined_behaviors = fn_data.get('undefined_behaviors', [])
        if isinstance(undefined_behaviors, list):
            actual_undefined += len(undefined_behaviors)
        else:
            issues.append(f'{fam_name}/{fn_name}: undefined_behaviors must be an array')

expected_summary = {
    'families_covered': families,
    'functions_with_vectors': actual_functions,
    'total_positive_vectors': actual_positive,
    'total_boundary_vectors': actual_boundary,
    'total_error_vectors': actual_error,
    'total_undefined_documented': actual_undefined,
}
for key, expected in expected_summary.items():
    actual = summary.get(key)
    if actual != expected:
        issues.append(f'coverage_summary.{key}: expected {expected}, got {actual!r}')

if issues:
    print(f'FAIL: {len(issues)} structural issues:')
    for iss in issues[:5]:
        print(f'  {iss}')
else:
    print('Structure: OK (all functions have vectors and spec_section)')

# Generate report
report = {
    'schema_version': 'v1',
    'report_schema': 'posix_test_vectors.report.v1',
    'bead': 'bd-2tq.1',
    'mode': mode,
    'run_id': run_id,
    'vectors_file': str(vectors_path),
    'summary': summary,
    'families': families,
    'functions': functions,
    'total_vectors': total,
    'structure_issues': len(issues),
    'structure_errors': issues,
    'outcome': 'pass' if not issues else 'fail',
    'failure_signature': 'none' if not issues else issues[0].split(':', 1)[0],
    'status': 'PASS' if not issues else 'FAIL'
}
report_path.parent.mkdir(parents=True, exist_ok=True)
with open(report_path, 'w') as f:
    json.dump(report, indent=2, fp=f)
log_entry = {
    'event': 'posix_test_vectors_validated' if not issues else 'posix_test_vectors_failed',
    'bead': 'bd-2tq.1',
    'mode': mode,
    'run_id': run_id,
    'outcome': report['outcome'],
    'failure_signature': report['failure_signature'],
    'vectors_file': str(vectors_path),
    'report': str(report_path),
}
with open(log_path, 'a') as f:
    print(json.dumps(log_entry, sort_keys=True), file=f)
print(f'Report: {report_path}')
print(f"check_posix_test_vectors: {report['status']}")
if issues:
    sys.exit(1)
PY

echo "=== done ==="
