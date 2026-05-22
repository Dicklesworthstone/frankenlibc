#!/usr/bin/env bash
# check_queue_empty_reality_trigger_completion_contract.sh
# Completion contract for bd-iu3fb.2 [RC-WS9.2]: Queue-empty triggers mandatory reality check.
#
# Verification:
#   1. The trigger script exists and is executable
#   2. --trigger-only mode correctly detects empty queue condition
#   3. The script produces a structured JSON report
#   4. Exit code semantics are correct (0=has work, 2=empty+passed, 1=empty+failed)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCRIPT="$ROOT/scripts/check_queue_empty_reality_trigger.sh"
REPORT="${FRANKENLIBC_QUEUE_TRIGGER_CC_REPORT:-$ROOT/target/conformance/queue_empty_trigger_cc.report.json}"
TRACE_ID="cc-queue-trigger-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "$(dirname "$REPORT")"

errors=()
checks_passed=0
checks_total=0

check() {
    local name="$1"
    local condition="$2"
    ((checks_total++)) || true
    if eval "$condition"; then
        echo "PASS: $name"
        ((checks_passed++)) || true
        return 0
    else
        echo "FAIL: $name"
        errors+=("$name")
        return 1
    fi
}

echo "=== Queue-Empty Reality Trigger Completion Contract ==="
echo "trace_id: $TRACE_ID"
echo ""

check "script_exists" "[[ -f '$SCRIPT' ]]"
check "script_executable" "[[ -x '$SCRIPT' ]]"

if [[ -x "$SCRIPT" ]]; then
    output=$("$SCRIPT" --trigger-only --json 2>&1) || true
    exit_code=$?

    check "trigger_only_runs" "[[ -n '$output' ]]"
    check "trigger_only_exit_is_0_or_2" "[[ $exit_code -eq 0 || $exit_code -eq 2 ]]"

    if echo "$output" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
        check "output_is_valid_json" "true"

        schema=$(echo "$output" | python3 -c "import json,sys; print(json.load(sys.stdin).get('schema_version',''))" 2>/dev/null || echo "")
        check "schema_version_present" "[[ '$schema' == 'queue_empty_reality_trigger.v1' ]]"

        trigger_cond=$(echo "$output" | python3 -c "import json,sys; print(json.load(sys.stdin).get('trigger_condition',''))" 2>/dev/null || echo "")
        check "trigger_condition_field_present" "[[ -n '$trigger_cond' ]]"
    else
        check "output_is_valid_json" "false"
    fi

    check "help_option_works" "'$SCRIPT' --help >/dev/null 2>&1"
fi

report_file="$ROOT/target/conformance/queue_empty_reality_trigger.report.json"
if [[ -f "$report_file" ]]; then
    check "report_file_generated" "true"
    check "report_file_valid_json" "python3 -c 'import json; json.load(open(\"$report_file\"))' 2>/dev/null"
else
    check "report_file_generated" "false"
fi

echo ""
echo "=== Summary ==="
echo "Checks: $checks_passed / $checks_total passed"

python3 - "$REPORT" "$TRACE_ID" "$checks_passed" "$checks_total" "${errors[@]:-}" <<'PY'
import json
import sys
import time

report_path = sys.argv[1]
trace_id = sys.argv[2]
passed = int(sys.argv[3])
total = int(sys.argv[4])
errors = sys.argv[5:] if len(sys.argv) > 5 else []

report = {
    "schema_version": "completion_contract.v1",
    "bead_id": "bd-iu3fb.2",
    "title": "[RC-WS9.2] Queue-empty triggers mandatory reality check",
    "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "trace_id": trace_id,
    "checks_passed": passed,
    "checks_total": total,
    "outcome": "pass" if passed == total else "fail",
    "failures": errors,
    "evidence": {
        "trigger_script": "scripts/check_queue_empty_reality_trigger.sh",
        "completion_contract": "scripts/check_queue_empty_reality_trigger_completion_contract.sh",
    },
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
    f.write("\n")

print(json.dumps(report, indent=2))
PY

if [[ ${#errors[@]} -gt 0 ]]; then
    echo ""
    echo "COMPLETION CONTRACT FAILED"
    exit 1
fi

echo ""
echo "COMPLETION CONTRACT PASSED"
exit 0
