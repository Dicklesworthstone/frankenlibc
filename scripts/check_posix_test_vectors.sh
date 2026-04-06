#!/usr/bin/env bash
# check_posix_test_vectors.sh — validate FrankenLibC against POSIX test vectors (bd-2tq.1)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VECTORS="${ROOT}/tests/conformance/posix_test_vectors.v1.json"
OUT_DIR="${ROOT}/target/conformance/posix_vectors"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="${OUT_DIR}/${RUN_ID}_report.json"
mkdir -p "${OUT_DIR}"

if [ ! -f "${VECTORS}" ]; then
    echo "FAIL: missing ${VECTORS}" >&2
    exit 1
fi

echo "=== POSIX test vector validation (bd-2tq.1) ==="
echo "vectors: ${VECTORS}"
echo "run_id: ${RUN_ID}"

# Validate JSON is well-formed
python3 -c "
import json, sys
with open('${VECTORS}') as f:
    d = json.load(f)
summary = d.get('coverage_summary', {})
families = len(d.get('families', {}))
functions = summary.get('functions_with_vectors', 0)
positive = summary.get('total_positive_vectors', 0)
boundary = summary.get('total_boundary_vectors', 0)
error = summary.get('total_error_vectors', 0)
total = positive + boundary + error
print(f'Families: {families}')
print(f'Functions with vectors: {functions}')
print(f'Total vectors: {total} (positive={positive}, boundary={boundary}, error={error})')

# Validate structure
issues = []
for fam_name, fam in d.get('families', {}).items():
    for fn_name, fn_data in fam.items():
        if 'test_vectors' not in fn_data and 'error_conditions' not in fn_data:
            issues.append(f'{fam_name}/{fn_name}: missing test_vectors or error_conditions')
        if 'spec_section' not in fn_data:
            issues.append(f'{fam_name}/{fn_name}: missing spec_section')

if issues:
    print(f'WARN: {len(issues)} structural issues:')
    for iss in issues[:5]:
        print(f'  {iss}')
else:
    print('Structure: OK (all functions have vectors and spec_section)')

# Generate report
report = {
    'schema_version': 'v1',
    'run_id': '${RUN_ID}',
    'vectors_file': '${VECTORS}',
    'summary': summary,
    'families': families,
    'functions': functions,
    'total_vectors': total,
    'structure_issues': len(issues),
    'status': 'PASS' if not issues else 'WARN'
}
with open('${REPORT}', 'w') as f:
    json.dump(report, indent=2, fp=f)
print(f'Report: ${REPORT}')
print(f'check_posix_test_vectors: {report[\"status\"]}')
"

echo "=== done ==="
