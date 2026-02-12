#!/usr/bin/env bash
# check_structured_logs.sh — CI gate for bd-144
#
# Validates:
# 1. Log schema definition (tests/conformance/log_schema.json) exists and is valid.
# 2. The structured_log module compiles and its unit tests pass.
# 3. Any JSONL log files found in test output conform to the schema.
#
# Exit codes:
#   0 — all checks pass
#   1 — validation failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCHEMA="${ROOT}/tests/conformance/log_schema.json"

failures=0

echo "=== Structured Logging Gate (bd-144) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Schema definition exists and is valid JSON
# ---------------------------------------------------------------------------
echo "--- Check 1: Log schema definition ---"

if [[ ! -f "${SCHEMA}" ]]; then
    echo "FAIL: log_schema.json not found at ${SCHEMA}"
    failures=$((failures + 1))
else
    if ! python3 -c "import json; json.load(open('${SCHEMA}'))" 2>/dev/null; then
        echo "FAIL: log_schema.json is not valid JSON"
        failures=$((failures + 1))
    else
        schema_ok=$(python3 -c "
import json
with open('${SCHEMA}') as f:
    s = json.load(f)
errors = []
for key in ['schema_version', 'required_fields', 'optional_fields', 'artifact_index_schema', 'examples']:
    if key not in s:
        errors.append(f'Missing key: {key}')
for field in ['timestamp', 'trace_id', 'level', 'event']:
    if field not in s.get('required_fields', {}):
        errors.append(f'Missing required field def: {field}')
if errors:
    for e in errors:
        print(f'ERROR: {e}')
    print(f'ERRORS={len(errors)}')
else:
    print('ERRORS=0')
")
        error_count=$(echo "${schema_ok}" | grep 'ERRORS=' | cut -d= -f2)
        if [[ "${error_count}" -gt 0 ]]; then
            echo "FAIL: Schema structure errors:"
            echo "${schema_ok}" | grep 'ERROR:'
            failures=$((failures + 1))
        else
            echo "PASS: Log schema definition is valid"
        fi
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Rust module compiles and tests pass
# ---------------------------------------------------------------------------
echo "--- Check 2: structured_log module tests ---"

if cargo test -p frankenlibc-harness --lib -- structured_log 2>&1 | tail -5 | grep -q "test result: ok"; then
    echo "PASS: structured_log unit tests pass"
else
    echo "FAIL: structured_log unit tests failed"
    failures=$((failures + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Validate any existing JSONL log files
# ---------------------------------------------------------------------------
echo "--- Check 3: Validate existing JSONL log files ---"

log_files=$(find "${ROOT}/tests" -name "*.jsonl" -type f 2>/dev/null || true)
log_count=0
log_errors=0

if [[ -z "${log_files}" ]]; then
    echo "INFO: No JSONL log files found in tests/ (expected for initial setup)"
else
    while IFS= read -r logfile; do
        log_count=$((log_count + 1))
        # Validate each line
        line_errors=$(python3 -c "
import json, sys
errors = 0
with open('${logfile}') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            print(f'  line {i}: invalid JSON: {e}')
            errors += 1
            continue
        for field in ['timestamp', 'trace_id', 'level', 'event']:
            if field not in obj:
                print(f'  line {i}: missing required field: {field}')
                errors += 1
print(f'LINE_ERRORS={errors}')
" 2>&1)
        file_errors=$(echo "${line_errors}" | grep 'LINE_ERRORS=' | cut -d= -f2)
        if [[ "${file_errors}" -gt 0 ]]; then
            echo "FAIL: ${logfile} has ${file_errors} validation error(s):"
            echo "${line_errors}" | grep -v 'LINE_ERRORS='
            log_errors=$((log_errors + file_errors))
        fi
    done <<< "${log_files}"

    if [[ "${log_errors}" -eq 0 ]]; then
        echo "PASS: ${log_count} JSONL log file(s) validated successfully"
    else
        failures=$((failures + 1))
    fi
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_structured_logs: FAILED"
    exit 1
fi

echo ""
echo "check_structured_logs: PASS"
