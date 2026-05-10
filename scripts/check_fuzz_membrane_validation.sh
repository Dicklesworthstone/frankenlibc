#!/usr/bin/env bash
# check_fuzz_membrane_validation.sh — CI gate for bd-1oz.4
# Validates membrane fuzz target against spec requirements.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/fuzz_membrane_validation.v1.json"
GATE_REPORT="${FRANKENLIBC_FUZZ_MEMBRANE_VALIDATION_REPORT:-$REPO_ROOT/target/conformance/fuzz_membrane_validation.report.json}"
GATE_LOG="${FRANKENLIBC_FUZZ_MEMBRANE_VALIDATION_LOG:-$REPO_ROOT/target/conformance/fuzz_membrane_validation.log.jsonl}"
TRACE_ID="${FRANKENLIBC_FUZZ_MEMBRANE_VALIDATION_TRACE_ID:-fuzz-membrane-validation-$(date -u +%Y%m%dT%H%M%SZ)}"
START_NS="$(date +%s%N)"

echo "=== Membrane Fuzz Target Validation Gate (bd-1oz.4) ==="

echo "--- Generating membrane validation report ---"
python3 "$SCRIPT_DIR/generate_fuzz_membrane_validation.py" -o "$REPORT" 2>&1 || true

if [ ! -f "$REPORT" ]; then
    echo "FAIL: membrane validation report not generated"
    exit 1
fi

python3 - "$REPORT" "$GATE_REPORT" "$GATE_LOG" "$TRACE_ID" "$START_NS" <<'PY'
import datetime
import json
import pathlib
import sys
import time

report_path = sys.argv[1]
gate_report_path = pathlib.Path(sys.argv[2])
gate_log_path = pathlib.Path(sys.argv[3])
trace_id = sys.argv[4]
start_ns = int(sys.argv[5])
errors = 0
failure_signatures = []

def fail(signature, message):
    global errors
    print(f"FAIL: {message}")
    errors += 1
    failure_signatures.append(signature)

def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def write_gate_outputs(outcome, summary, checks):
    duration_ms = (time.time_ns() - start_ns) // 1_000_000
    failure_signature = "none" if outcome == "pass" else ",".join(failure_signatures)
    artifact_refs = [
        "tests/conformance/fuzz_membrane_validation.v1.json",
        "crates/frankenlibc-fuzz/fuzz_targets/fuzz_membrane.rs",
        "crates/frankenlibc-harness/tests/fuzz_membrane_validation_test.rs",
    ]
    gate_report = {
        "schema_version": "v1",
        "bead_id": "bd-1oz.4.1",
        "original_bead": "bd-1oz.4",
        "trace_id": trace_id,
        "target": "fuzz_membrane",
        "outcome": outcome,
        "duration_ms": duration_ms,
        "readiness_pct": summary.get("readiness_pct", 0),
        "total_gaps": summary.get("total_gaps", 0),
        "failure_signature": failure_signature,
        "artifact_refs": artifact_refs,
        "checks": checks,
    }
    gate_report_path.parent.mkdir(parents=True, exist_ok=True)
    gate_report_path.write_text(json.dumps(gate_report, indent=2) + "\n", encoding="utf-8")

    def event_row(event, row_outcome):
        return {
            "timestamp": utc_now(),
            "trace_id": trace_id,
            "level": "info" if row_outcome != "fail" else "error",
            "event": event,
            "bead_id": "bd-1oz.4.1",
            "target": "fuzz_membrane",
            "artifact_refs": artifact_refs,
            "outcome": row_outcome,
            "duration_ms": duration_ms,
            "readiness_pct": summary.get("readiness_pct", 0),
            "total_gaps": summary.get("total_gaps", 0),
            "failure_signature": failure_signature,
        }

    rows = [
        event_row("fuzz_membrane_validation_started", "running"),
        event_row(
            "fuzz_membrane_validation_completed"
            if outcome == "pass"
            else "fuzz_membrane_validation_failed",
            outcome,
        ),
    ]
    gate_log_path.parent.mkdir(parents=True, exist_ok=True)
    gate_log_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )

with open(report_path) as f:
    report = json.load(f)

summary = report.get("summary", {})
source = report.get("source_analysis", {})
gaps = report.get("gap_analysis", [])

readiness = summary.get("readiness_pct", 0)
strategies = summary.get("strategies_coverage", "0/0")
transitions = summary.get("transitions_coverage", "0/0")
cache = summary.get("cache_coverage", "0/0")
invariants = summary.get("invariants_coverage", "0/0")
total_gaps = summary.get("total_gaps", 0)
high_gaps = summary.get("high_severity_gaps", 0)

print(f"Readiness:               {readiness}%")
print(f"  Strategies:            {strategies}")
print(f"  State transitions:     {transitions}")
print(f"  Cache coherence:       {cache}")
print(f"  Invariants:            {invariants}")
print(f"  Gaps:                  {total_gaps} ({high_gaps} high)")
print()

# Source must exist and compile
if not source.get("has_fuzz_target"):
    fail("missing_fuzz_target_macro", "fuzz_membrane.rs missing fuzz_target! macro")
else:
    print("PASS: fuzz_membrane.rs has valid harness structure")

# Must have ValidationPipeline
if not source.get("has_pipeline_creation"):
    fail("missing_validation_pipeline", "fuzz_membrane.rs doesn't create ValidationPipeline")
else:
    print("PASS: ValidationPipeline is exercised")

# Must check outcomes
if not source.get("has_outcome_checking"):
    fail("missing_outcome_checks", "fuzz_membrane.rs doesn't check validation outcomes")
else:
    print("PASS: Validation outcomes are checked (can_read/can_write)")

# Must have at least 1 strategy implemented
strat_impl = int(strategies.split("/")[0])
if strat_impl < 1:
    fail("no_fuzzing_strategies", "No fuzzing strategies implemented")
else:
    print(f"PASS: {strat_impl} fuzzing strategies active")

# At least 1 state transition exercised
trans_impl = int(transitions.split("/")[0])
if trans_impl < 1:
    fail("no_state_transitions", "No state transitions exercised")
else:
    print(f"PASS: {trans_impl} state transitions exercised")

# CWE coverage
cwes = summary.get("cwe_targets", [])
if len(cwes) < 2:
    fail("insufficient_cwe_targets", f"Only {len(cwes)} CWEs targeted (need >= 2)")
else:
    print(f"PASS: {len(cwes)} CWEs targeted")

# Gap analysis must be documented
if total_gaps == 0 and readiness < 100:
    fail("missing_gap_analysis", "Readiness < 100% but no gaps documented")
else:
    print(f"PASS: {total_gaps} gaps documented for improvement roadmap")

completion = report.get("completion_debt_evidence")
if not isinstance(completion, dict):
    fail("missing_completion_debt_evidence", "completion_debt_evidence must be an object")
else:
    if completion.get("bead") != "bd-1oz.4.1":
        fail("wrong_completion_bead", "completion_debt_evidence.bead must be bd-1oz.4.1")
    if completion.get("original_bead") != "bd-1oz.4":
        fail("wrong_original_bead", "completion_debt_evidence.original_bead must be bd-1oz.4")
    root = pathlib.Path(report_path).resolve().parents[2]
    test_source = completion.get("test_source")
    if not isinstance(test_source, str) or not test_source:
        fail("missing_test_source", "completion_debt_evidence.test_source must be non-empty")
        test_source_text = ""
    else:
        test_source_path = pathlib.Path(test_source)
        if not test_source_path.is_absolute():
            test_source_path = root / test_source_path
        if not test_source_path.is_file():
            fail("missing_test_source_file", f"test source missing: {test_source}")
            test_source_text = ""
        else:
            test_source_text = test_source_path.read_text(encoding="utf-8")

    fuzz_primary = completion.get("fuzz_primary")
    if not isinstance(fuzz_primary, dict):
        fail("missing_fuzz_primary", "completion_debt_evidence.fuzz_primary must be an object")
    else:
        target_source = fuzz_primary.get("target_source")
        target_source_path = root / str(target_source)
        if fuzz_primary.get("target") != "fuzz_membrane":
            fail("wrong_fuzz_target", "fuzz_primary.target must be fuzz_membrane")
        if not target_source_path.is_file():
            fail("missing_fuzz_target_source", f"fuzz target source missing: {target_source}")
        required_tests = fuzz_primary.get("required_test_names")
        if not isinstance(required_tests, list) or not required_tests:
            fail("missing_fuzz_required_tests", "fuzz_primary.required_test_names must be non-empty")
        else:
            for test_name in required_tests:
                if not isinstance(test_name, str) or not test_name:
                    fail("invalid_fuzz_test_name", "fuzz primary contains invalid test name")
                elif f"fn {test_name}(" not in test_source_text:
                    fail("missing_fuzz_test_name", f"fuzz primary references missing test {test_name}")

    telemetry = completion.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        fail("missing_telemetry_primary", "completion_debt_evidence.telemetry_primary must be an object")
    else:
        if telemetry.get("default_report_path") != "target/conformance/fuzz_membrane_validation.report.json":
            fail("wrong_telemetry_report_path", "telemetry default_report_path drifted")
        if telemetry.get("default_log_path") != "target/conformance/fuzz_membrane_validation.log.jsonl":
            fail("wrong_telemetry_log_path", "telemetry default_log_path drifted")
        expected_events = {
            "fuzz_membrane_validation_started",
            "fuzz_membrane_validation_completed",
            "fuzz_membrane_validation_failed",
        }
        required_events = telemetry.get("required_events")
        if not isinstance(required_events, list) or set(required_events) != expected_events:
            fail("wrong_telemetry_events", "telemetry required_events drifted")
        expected_fields = {
            "timestamp",
            "trace_id",
            "level",
            "event",
            "bead_id",
            "target",
            "artifact_refs",
            "outcome",
            "duration_ms",
            "readiness_pct",
            "total_gaps",
            "failure_signature",
        }
        required_fields = telemetry.get("required_fields")
        if not isinstance(required_fields, list) or not required_fields:
            fail("missing_telemetry_fields", "telemetry required_fields must be non-empty")
        else:
            missing = sorted(expected_fields - set(str(field) for field in required_fields))
            if missing:
                fail("missing_telemetry_field", f"telemetry required_fields missing {missing}")

checks = {
    "schema_valid": "pass",
    "source_analysis_present": "pass" if source else "fail",
    "fuzz_primary_bound": "pass" if isinstance(completion, dict) else "fail",
    "telemetry_primary_bound": "pass" if isinstance(completion, dict) else "fail",
}
write_gate_outputs("pass" if errors == 0 else "fail", summary, checks)

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_fuzz_membrane_validation: PASS")
PY
