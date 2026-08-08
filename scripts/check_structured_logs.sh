#!/usr/bin/env bash
# check_structured_logs.sh — CI gate for bd-144
#
# Validates:
# 1. Log schema definition (tests/conformance/log_schema.json) exists and is valid (schema_version >= 2).
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
sv = s.get('schema_version', 0)
if not isinstance(sv, int):
    errors.append('schema_version must be an integer')
elif sv < 2:
    errors.append('schema_version must be >= 2')
for field in ['timestamp', 'trace_id', 'level', 'event']:
    if field not in s.get('required_fields', {}):
        errors.append(f'Missing required field def: {field}')
for field in ['decision_id', 'policy_id', 'evidence_seqno']:
    if field not in s.get('optional_fields', {}):
        errors.append(f'Missing optional field def: {field}')
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

# The minimum number of structured_log tests that must actually EXECUTE. libtest
# prints the very same "test result: ok." line for a filter that matched nothing
# ("0 passed; ...; 296 filtered out"), so a gate that greps for that string
# reports PASS having asserted nothing — the failure class that hid 293 tests for
# weeks (bd-r71n1b, bd-1l9rlp). Assert the positive fact instead: a passed count.
# Raise this when tests are added; never lower it to make a red gate green.
STRUCTURED_LOG_MIN_TESTS=15

# Verdict on one libtest run. Requires, in order: the runner exited 0 (a pipe to
# `tail` would have thrown that status away), a summary line exists at all, no
# failures, and at least ${2} tests actually passed.
# Args: <combined output> <min passed> <label>. Echoes a reason, returns 0/1.
assert_test_summary() {
    local output="$1" min_passed="$2" label="$3" runner_status="$4"
    local summary passed failed

    if [[ "${runner_status}" -ne 0 ]]; then
        echo "FAIL: ${label}: test runner exited ${runner_status} (build or test failure)"
        return 1
    fi
    summary="$(printf '%s\n' "${output}" | grep -m1 '^test result:' || true)"
    if [[ -z "${summary}" ]]; then
        echo "FAIL: ${label}: no 'test result:' summary line — nothing was executed"
        return 1
    fi
    passed="$(printf '%s\n' "${summary}" | sed -n 's/.*[^0-9]\([0-9][0-9]*\) passed.*/\1/p')"
    failed="$(printf '%s\n' "${summary}" | sed -n 's/.*[^0-9]\([0-9][0-9]*\) failed.*/\1/p')"
    [[ -z "${passed}" ]] && passed=0
    [[ -z "${failed}" ]] && failed=0

    if [[ "${failed}" -gt 0 ]]; then
        echo "FAIL: ${label}: ${failed} test(s) failed"
        return 1
    fi
    if [[ "${passed}" -lt "${min_passed}" ]]; then
        echo "FAIL: ${label}: only ${passed} test(s) executed, expected >= ${min_passed}"
        echo "      (${summary})"
        echo "      A zero or shrunken count means the tests were renamed, moved,"
        echo "      feature-gated out, or filtered to nothing — not that they passed."
        return 1
    fi
    echo "PASS: ${label}: ${passed} test(s) passed (>= ${min_passed} required)"
    return 0
}

# Self-test: prove the verdict function can actually go RED. Without this, a
# regression that made assert_test_summary permissive would be invisible — the
# happy path looks identical either way.
selftest_failures=0
_expect_verdict() {
    local want="$1" label="$2" out="$3" status="${4:-0}"
    if assert_test_summary "${out}" 1 "selftest/${label}" "${status}" >/dev/null 2>&1; then
        [[ "${want}" == "accept" ]] || { echo "FAIL: selftest ${label}: accepted, expected reject"; selftest_failures=$((selftest_failures + 1)); }
    else
        [[ "${want}" == "reject" ]] || { echo "FAIL: selftest ${label}: rejected, expected accept"; selftest_failures=$((selftest_failures + 1)); }
    fi
}
# The exact line libtest prints for a filter that matches nothing — measured on
# frankenlibc-abi/glibc_internal_abi_test with filter 'no_such_test_name_xyz'.
_expect_verdict reject zero-match-filter \
    'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 296 filtered out; finished in 0.00s'
_expect_verdict reject no-summary-line 'error: could not compile `frankenlibc-harness`'
_expect_verdict reject nonzero-exit \
    'test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' 101
_expect_verdict reject reported-failures \
    'test result: FAILED. 14 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out'
_expect_verdict accept real-pass \
    'test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 281 filtered out; finished in 0.01s'
if [[ "${selftest_failures}" -gt 0 ]]; then
    echo "FAIL: Check 2 self-test failed (${selftest_failures}) — the verdict logic is broken"
    failures=$((failures + 1))
else
    echo "INFO: Check 2 verdict self-test passed (5 cases: 4 reject, 1 accept)"
fi

# Capture output and the runner's OWN exit status; `set -o pipefail` is on, but
# assigning through $(...) and reading $? keeps the status explicit rather than
# depending on the pipeline shape.
set +e
test_output="$(cargo test -p frankenlibc-harness --lib -- structured_log 2>&1)"
test_status=$?
set -e

if ! assert_test_summary "${test_output}" "${STRUCTURED_LOG_MIN_TESTS}" "structured_log unit tests" "${test_status}"; then
    printf '%s\n' "${test_output}" | tail -15 | sed 's/^/      | /'
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
        base="$(basename "${logfile}")"
        if [[ "${logfile}" == *"/tests/gentoo/fixtures/sample_logs/"* && "${base}" == invalid_* ]]; then
            echo "INFO: Skipping negative fixture ${logfile}"
            continue
        fi

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
        if obj.get('event') == 'runtime_decision':
            for field in ['decision', 'symbol', 'span_id', 'decision_id']:
                if field not in obj or not str(obj.get(field, '')).strip():
                    print(f'  line {i}: runtime_decision event missing required field: {field}')
                    errors += 1
            if 'decision' not in obj:
                continue
            if 'decision_id' in obj and int(obj['decision_id']) == 0:
                print(f'  line {i}: runtime_decision decision_id must be non-zero')
                errors += 1
            if 'policy_id' in obj and int(obj['policy_id']) == 0:
                print(f'  line {i}: policy_id must be non-zero when present')
                errors += 1
            for field in ['controller_id', 'decision_action', 'risk_inputs']:
                if field not in obj:
                    print(f'  line {i}: runtime_decision event missing explainability field: {field}')
                    errors += 1
            if 'decision_action' in obj and obj['decision_action'] not in ['Allow', 'FullValidate', 'Repair', 'Deny']:
                print(f\"  line {i}: invalid decision_action: {obj['decision_action']}\")
                errors += 1
            if 'risk_inputs' in obj and not isinstance(obj['risk_inputs'], dict):
                print(f'  line {i}: risk_inputs must be an object')
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
