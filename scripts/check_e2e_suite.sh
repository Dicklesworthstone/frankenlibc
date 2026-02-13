#!/usr/bin/env bash
# check_e2e_suite.sh — CI gate for bd-2ez
#
# Validates:
# 1. e2e_suite.sh exists and is executable.
# 2. Manifest validator + manifest catalog file exist.
# 3. The suite can dry-run the scenario manifest catalog.
# 4. The suite can run at least the fault scenario (fastest).
# 5. Output JSONL conforms to the structured logging contract.
# 6. Artifact index is generated and valid.
# 7. strict/hardened mode-pair replay report is generated and valid.
#
# Note: Many E2E scenarios are expected to timeout/fail during the interpose
# phase of frankenlibc development. This gate verifies the *infrastructure*
# works, not that all programs pass. As more symbols are implemented, the
# pass rate will increase.
#
# Exit codes:
#   0 — infrastructure checks pass
#   1 — infrastructure failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

failures=0

echo "=== E2E Suite Gate (bd-2ez) ==="
echo ""

# ---------------------------------------------------------------------------
# Check 1: Suite script exists
# ---------------------------------------------------------------------------
echo "--- Check 1: E2E suite script exists ---"

if [[ ! -f "${ROOT}/scripts/e2e_suite.sh" ]]; then
    echo "FAIL: scripts/e2e_suite.sh not found"
    failures=$((failures + 1))
elif [[ ! -x "${ROOT}/scripts/e2e_suite.sh" ]]; then
    echo "FAIL: scripts/e2e_suite.sh is not executable"
    failures=$((failures + 1))
else
    echo "PASS: e2e_suite.sh exists and is executable"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 2: Manifest tooling exists
# ---------------------------------------------------------------------------
echo "--- Check 2: Manifest tooling ---"

if [[ ! -f "${ROOT}/scripts/validate_e2e_manifest.py" ]]; then
    echo "FAIL: scripts/validate_e2e_manifest.py not found"
    failures=$((failures + 1))
elif [[ ! -f "${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json" ]]; then
    echo "FAIL: tests/conformance/e2e_scenario_manifest.v1.json not found"
    failures=$((failures + 1))
elif ! python3 "${ROOT}/scripts/validate_e2e_manifest.py" validate --manifest "${ROOT}/tests/conformance/e2e_scenario_manifest.v1.json" >/dev/null 2>&1; then
    echo "FAIL: manifest validation failed"
    failures=$((failures + 1))
else
    echo "PASS: manifest validator + catalog present and valid"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 3: Dry-run manifest catalog
# ---------------------------------------------------------------------------
echo "--- Check 3: Manifest dry-run ---"

set +e
bash "${ROOT}/scripts/e2e_suite.sh" --dry-run-manifest fault strict >/dev/null 2>&1
dry_run_rc=$?
set -e

if [[ "${dry_run_rc}" -ne 0 ]]; then
    echo "FAIL: manifest dry-run failed (exit=${dry_run_rc})"
    failures=$((failures + 1))
else
    echo "PASS: manifest dry-run succeeded"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 4: Run a minimal scenario and verify infrastructure
# ---------------------------------------------------------------------------
echo "--- Check 4: Infrastructure smoke test ---"

# Run fault scenario only (fastest — just 3 cases per mode)
# Use short timeout to not block CI
export TIMEOUT_SECONDS=3
set +e
bash "${ROOT}/scripts/e2e_suite.sh" fault 2>/dev/null
suite_rc=$?
set -e

# Find the most recent run directory
latest_run=$(ls -td "${ROOT}"/target/e2e_suite/e2e-* 2>/dev/null | head -1)

if [[ -z "${latest_run}" ]]; then
    echo "FAIL: No E2E run directory generated"
    failures=$((failures + 1))
else
    echo "PASS: E2E suite ran and generated output at ${latest_run}"
fi
echo ""

# ---------------------------------------------------------------------------
# Check 5: Validate structured log output
# ---------------------------------------------------------------------------
echo "--- Check 5: Structured log validation ---"

if [[ -n "${latest_run}" && -f "${latest_run}/trace.jsonl" ]]; then
    log_check=$(python3 -c "
import json
errors = 0
lines = 0
with open('${latest_run}/trace.jsonl') as f:
    for i, line in enumerate(f, 1):
        line = line.strip()
        if not line:
            continue
        lines += 1
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
        tid = obj.get('trace_id', '')
        if '::' not in tid:
            print(f'  line {i}: trace_id missing :: separator: {tid}')
            errors += 1
        # Verify bead_id is set
        if 'bead_id' not in obj:
            print(f'  line {i}: missing bead_id')
            errors += 1
        event = obj.get('event', '')
        if event.startswith('case_') or event == 'manifest_case':
            for field in ['mode', 'scenario_id', 'expected_outcome', 'artifact_policy']:
                if field not in obj:
                    print(f'  line {i}: event {event} missing required field: {field}')
                    errors += 1
            if event.startswith('case_'):
                for field in ['replay_key', 'env_fingerprint']:
                    if field not in obj:
                        print(f'  line {i}: event {event} missing required field: {field}')
                        errors += 1
            if 'artifact_policy' in obj and not isinstance(obj['artifact_policy'], dict):
                print(f'  line {i}: artifact_policy must be object for event {event}')
                errors += 1
        if event == 'mode_pair_result':
            for field in ['scenario_id', 'mode_pair_result', 'drift_flags']:
                if field not in obj:
                    print(f'  line {i}: mode_pair_result missing required field: {field}')
                    errors += 1
            if 'drift_flags' in obj and not isinstance(obj['drift_flags'], list):
                print(f'  line {i}: drift_flags must be array for mode_pair_result')
                errors += 1
print(f'LINES={lines}')
print(f'ERRORS={errors}')
")
    log_lines=$(echo "${log_check}" | grep 'LINES=' | cut -d= -f2)
    log_errors=$(echo "${log_check}" | grep 'ERRORS=' | cut -d= -f2)

    if [[ "${log_errors}" -gt 0 ]]; then
        echo "FAIL: ${log_errors} JSONL validation error(s):"
        echo "${log_check}" | grep -v 'LINES=' | grep -v 'ERRORS='
        failures=$((failures + 1))
    elif [[ "${log_lines}" -lt 2 ]]; then
        echo "FAIL: Too few log lines (${log_lines}), expected at least suite_start + suite_end"
        failures=$((failures + 1))
    else
        echo "PASS: ${log_lines} structured log lines, all valid"
    fi
else
    echo "FAIL: trace.jsonl not found"
    failures=$((failures + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Check 6: Artifact index
# ---------------------------------------------------------------------------
echo "--- Check 6: Artifact index ---"

if [[ -n "${latest_run}" && -f "${latest_run}/artifact_index.json" ]]; then
    idx_check=$(python3 -c "
import json
with open('${latest_run}/artifact_index.json') as f:
    idx = json.load(f)
errors = []
for key in ['index_version', 'run_id', 'bead_id', 'generated_utc', 'artifacts']:
    if key not in idx:
        errors.append(f'Missing key: {key}')
if idx.get('index_version') != 1:
    errors.append(f'Expected index_version 1, got {idx.get(\"index_version\")}')
if idx.get('bead_id') != 'bd-2ez':
    errors.append(f'Expected bead_id bd-2ez, got {idx.get(\"bead_id\")}')
arts = idx.get('artifacts', [])
for a in arts:
    for field in ['path', 'kind', 'sha256']:
        if field not in a:
            errors.append(f'Artifact missing field: {field}')
if errors:
    for e in errors:
        print(f'INDEX_ERROR: {e}')
print(f'ARTIFACTS={len(arts)}')
print(f'INDEX_ERRORS={len(errors)}')
")
    idx_errors=$(echo "${idx_check}" | grep 'INDEX_ERRORS=' | cut -d= -f2)
    idx_artifacts=$(echo "${idx_check}" | grep 'ARTIFACTS=' | cut -d= -f2)

    if [[ "${idx_errors}" -gt 0 ]]; then
        echo "FAIL: Artifact index validation errors:"
        echo "${idx_check}" | grep 'INDEX_ERROR:'
        failures=$((failures + 1))
    else
        echo "PASS: Artifact index valid with ${idx_artifacts} entries"
    fi
else
    echo "FAIL: artifact_index.json not found"
    failures=$((failures + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Check 7: Mode pair report
# ---------------------------------------------------------------------------
echo "--- Check 7: Mode pair report ---"

if [[ -n "${latest_run}" && -f "${latest_run}/mode_pair_report.json" ]]; then
    pair_check=$(python3 -c "
import json
with open('${latest_run}/mode_pair_report.json') as f:
    report = json.load(f)
errors = []
for key in ['schema_version', 'run_id', 'pair_count', 'mismatch_count', 'pairs']:
    if key not in report:
        errors.append(f'Missing key: {key}')
if report.get('schema_version') != 'v1':
    errors.append(f'Expected schema_version v1, got {report.get(\"schema_version\")}')
if not isinstance(report.get('pairs', []), list):
    errors.append('pairs must be an array')
for pair in report.get('pairs', []):
    for field in ['scenario_id', 'mode_pair_result', 'drift_flags']:
        if field not in pair:
            errors.append(f'pair missing field: {field}')
if errors:
    for e in errors:
        print(f'PAIR_ERROR: {e}')
print(f'PAIR_ERRORS={len(errors)}')
")
    pair_errors=$(echo "${pair_check}" | grep 'PAIR_ERRORS=' | cut -d= -f2)
    if [[ "${pair_errors}" -gt 0 ]]; then
        echo "FAIL: Mode pair report validation errors:"
        echo "${pair_check}" | grep 'PAIR_ERROR:'
        failures=$((failures + 1))
    else
        echo "PASS: mode_pair_report.json is valid"
    fi
else
    echo "FAIL: mode_pair_report.json not found"
    failures=$((failures + 1))
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=== Summary ==="
echo "Failures: ${failures}"
echo "Note: E2E test case failures (timeouts) are expected during interpose phase."
echo "This gate validates the E2E *infrastructure*, not program pass rates."

if [[ "${failures}" -gt 0 ]]; then
    echo ""
    echo "check_e2e_suite: FAILED"
    exit 1
fi

echo ""
echo "check_e2e_suite: PASS"
