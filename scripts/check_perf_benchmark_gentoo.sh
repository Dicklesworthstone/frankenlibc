#!/usr/bin/env bash
# CI gate: Gentoo performance benchmarking artifact + test integrity (bd-2icq.9).
#
# Checks:
# 1. perf-benchmark.py exists and has valid Python syntax
# 2. Dry-run mode produces valid JSON output with correct schema
# 3. Output schema matches expected fields
# 4. Python unit tests pass
#
# Exit 0 on PASS, 1 on FAIL.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCHMARK_SCRIPT="${ROOT}/scripts/gentoo/perf-benchmark.py"
TEST_FILE="${ROOT}/tests/gentoo/test_perf_benchmark.py"

echo "=== Gentoo Performance Benchmark Gate (bd-2icq.9) ==="

fail() { echo "FAIL: $1"; exit 1; }

# 1. Script exists and has valid Python syntax
[[ -f "${BENCHMARK_SCRIPT}" ]] || fail "perf-benchmark.py not found at ${BENCHMARK_SCRIPT}"
python3 -c "import py_compile; py_compile.compile('${BENCHMARK_SCRIPT}', doraise=True)" \
  || fail "perf-benchmark.py has syntax errors"
echo "PASS: perf-benchmark.py syntax valid"

# 2. Dry-run produces valid JSON
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}" EXIT

python3 "${BENCHMARK_SCRIPT}" \
  --mode dry-run \
  --packages sys-apps/coreutils \
  --output "${TMPDIR}/results.json" \
  > /dev/null 2>&1 \
  || fail "dry-run mode failed"

[[ -f "${TMPDIR}/results.json" ]] || fail "dry-run did not produce output file"
echo "PASS: dry-run produces output"

# 3. Validate schema
python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/results.json'))
required = ['schema_version', 'bead', 'total_packages', 'successful', 'failed',
            'avg_build_overhead_percent', 'median_build_overhead_percent', 'packages']
missing = [k for k in required if k not in data]
if missing:
    print(f'Missing keys: {missing}', file=sys.stderr)
    sys.exit(1)
if data['schema_version'] != 'v1':
    print(f'Bad schema_version: {data[\"schema_version\"]}', file=sys.stderr)
    sys.exit(1)
if data['bead'] != 'bd-2icq.9':
    print(f'Bad bead: {data[\"bead\"]}', file=sys.stderr)
    sys.exit(1)
if data['total_packages'] < 1:
    print('No packages in results', file=sys.stderr)
    sys.exit(1)
" || fail "output schema validation failed"
echo "PASS: output schema valid"

# 4. Tier1 dry-run produces 5 results
python3 "${BENCHMARK_SCRIPT}" \
  --mode dry-run \
  --packages tier1 \
  --output "${TMPDIR}/tier1_results.json" \
  > /dev/null 2>&1 \
  || fail "tier1 dry-run failed"

python3 -c "
import json, sys
data = json.load(open('${TMPDIR}/tier1_results.json'))
if data['total_packages'] != 5:
    print(f'Expected 5 packages, got {data[\"total_packages\"]}', file=sys.stderr)
    sys.exit(1)
if data['successful'] != 5:
    print(f'Expected 5 successful, got {data[\"successful\"]}', file=sys.stderr)
    sys.exit(1)
# Verify each package has latency profile
for pkg in data['packages']:
    if 'latency_profile' not in pkg:
        print(f'Package {pkg[\"package\"]} missing latency_profile', file=sys.stderr)
        sys.exit(1)
" || fail "tier1 dry-run schema validation failed"
echo "PASS: tier1 dry-run produces valid 5-package results"

# 5. Python tests pass
if [[ -f "${TEST_FILE}" ]] && command -v python3 >/dev/null 2>&1; then
  python3 -m pytest "${TEST_FILE}" -q --tb=short 2>&1 | tail -5
  echo "PASS: test_perf_benchmark.py tests passed"
fi

echo ""
echo "PASS: Gentoo Performance Benchmark gate (bd-2icq.9) all checks passed"
