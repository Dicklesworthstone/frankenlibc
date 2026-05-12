#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CHANGEPOINT_COMPLETION_CONTRACT:-$ROOT/tests/conformance/changepoint_drift_policy_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CHANGEPOINT_COMPLETION_OUT_DIR:-$ROOT/target/conformance/changepoint_drift_policy_completion_contract}"
REPORT="${FRANKENLIBC_CHANGEPOINT_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_CHANGEPOINT_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"
GATE_STDOUT="${FRANKENLIBC_CHANGEPOINT_COMPLETION_GATE_STDOUT:-$OUT_DIR/gate_stdout.txt}"
GATE_STDERR="${FRANKENLIBC_CHANGEPOINT_COMPLETION_GATE_STDERR:-$OUT_DIR/gate_stderr.txt}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GATE_STDOUT")" "$(dirname "$GATE_STDERR")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$GATE_STDOUT" "$GATE_STDERR" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import time
from typing import Any

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
gate_stdout_path = pathlib.Path(sys.argv[5])
gate_stderr_path = pathlib.Path(sys.argv[6])
start_ns = time.time_ns()

EXPECTED_SCHEMA = "changepoint_drift_policy_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "changepoint_drift_policy_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-3tc"
EXPECTED_COMPLETION_BEAD = "bd-3tc.1"
EXPECTED_SOURCE_IDS = {
    "changepoint_module",
    "runtime_math_mod",
    "policy_artifact",
    "gate_script",
    "harness_test",
    "statistical_kernel_contract",
    "completion_checker",
    "completion_harness",
}
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "changepoint_drift.source_artifacts_validated",
    "changepoint_drift.unit_bindings_validated",
    "changepoint_drift.e2e_gate_replayed",
    "changepoint_drift.telemetry_validated",
    "changepoint_drift.completion_contract_validated",
    "changepoint_drift.completion_contract_failed",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "original_bead",
    "completion_debt_bead",
    "source_commit",
    "status",
    "failure_signature",
    "source_count",
    "implementation_ref_count",
    "inline_unit_test_count",
    "harness_test_count",
    "policy_summary",
    "gate_stdout",
    "artifact_refs",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "original_bead",
    "completion_debt_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "failure_signature",
}
EXPECTED_POLICY_SUMMARY = {
    "bocpd_parameters": 8,
    "bocpd_states": 4,
    "routing_policies": 4,
    "upstream_feeds": 2,
    "downstream_consumers": 3,
    "false_positive_targets": 3,
    "unit_tests": 9,
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        return "unknown"


def load_json(path: pathlib.Path, context: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return data


def string_set(value: Any, context: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        errors.append(f"{context} must be a non-empty string array")
        return set()
    return set(value)


def append_event(event: str, status: str, details: dict[str, Any] | None = None) -> None:
    details = details or {}
    failure_signature = "none" if status == "pass" else "changepoint_drift_policy_completion_contract_invalid"
    events.append(
        {
            "timestamp": now_utc(),
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::changepoint-drift::{event}::{status}",
            "original_bead": EXPECTED_ORIGINAL_BEAD,
            "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
            "event": event,
            "status": status,
            "mode": "strict",
            "api_family": "runtime_math",
            "symbol": "changepoint",
            "decision_path": "changepoint_drift_policy::completion_contract::validate",
            "healing_action": None,
            "errno": 0 if status == "pass" else 22,
            "latency_ns": time.time_ns() - start_ns,
            "artifact_refs": [
                rel(contract_path),
                rel(report_path),
                rel(log_path),
                rel(gate_stdout_path),
                rel(gate_stderr_path),
            ],
            "failure_signature": failure_signature,
            "details": details,
        }
    )


def validate_file_line_ref(ref: Any, context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} must be a file:line string")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_no - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def source_artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = contract.get("source_artifacts")
    if not isinstance(sources, list):
        errors.append("source_artifacts must be an array")
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            errors.append("source_artifacts entry missing id")
            continue
        by_id[source_id] = source
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"source_artifacts.{source_id}.path must be non-empty")
            continue
        path = root / path_text
        if not path.is_file():
            errors.append(f"source artifact missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in source.get("required_needles", []):
            if not isinstance(needle, str) or not needle:
                errors.append(f"source_artifacts.{source_id}.required_needles contains invalid needle")
            elif needle not in text:
                errors.append(f"{path_text} missing required needle: {needle}")
    declared = set(by_id)
    if declared != EXPECTED_SOURCE_IDS:
        errors.append(f"source artifact ids drifted: declared={sorted(declared)} expected={sorted(EXPECTED_SOURCE_IDS)}")
    if not errors:
        append_event("changepoint_drift.source_artifacts_validated", "pass", {"source_count": len(by_id)})
    return by_id


def source_text(sources: dict[str, dict[str, Any]], source_id: str) -> str:
    path_text = sources.get(source_id, {}).get("path")
    if not isinstance(path_text, str):
        return ""
    path = root / path_text
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def validate_unit(contract: dict[str, Any], sources: dict[str, dict[str, Any]]) -> tuple[int, int, dict[str, Any]]:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("unit_primary must be an object")
        return 0, 0, {}
    if unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary.missing_item_id must be tests.unit.primary")
    module_text = source_text(sources, "changepoint_module")
    harness_text = source_text(sources, "harness_test")
    inline_tests = string_set(unit.get("required_inline_unit_tests"), "unit_primary.required_inline_unit_tests")
    harness_tests = string_set(unit.get("required_harness_tests"), "unit_primary.required_harness_tests")
    if len(inline_tests) < int(unit.get("minimum_inline_unit_tests", 0)):
        errors.append("inline unit test count is below minimum")
    for test_name in inline_tests:
        if f"fn {test_name}(" not in module_text:
            errors.append(f"missing changepoint inline unit test: {test_name}")
    for test_name in harness_tests:
        if f"fn {test_name}(" not in harness_text:
            errors.append(f"missing changepoint harness test: {test_name}")

    policy = load_json(root / "tests/conformance/changepoint_drift_policy.json", "changepoint policy")
    summary = policy.get("summary", {}) if isinstance(policy.get("summary"), dict) else {}
    required_summary = unit.get("required_policy_summary")
    if not isinstance(required_summary, dict):
        errors.append("unit_primary.required_policy_summary must be an object")
    else:
        for key, expected in EXPECTED_POLICY_SUMMARY.items():
            if required_summary.get(key) != expected:
                errors.append(f"unit_primary.required_policy_summary.{key} must be {expected}")
            if summary.get(key) != expected:
                errors.append(f"policy summary {key} drifted: {summary.get(key)} != {expected}")
    if not errors:
        append_event(
            "changepoint_drift.unit_bindings_validated",
            "pass",
            {
                "inline_unit_test_count": len(inline_tests),
                "harness_test_count": len(harness_tests),
                "policy_summary": summary,
            },
        )
    return len(inline_tests), len(harness_tests), summary


def replay_gate(contract: dict[str, Any]) -> None:
    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be an object")
        return
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
    gate_script = e2e.get("gate_script")
    if gate_script != "scripts/check_changepoint_drift.sh":
        errors.append("e2e_primary.gate_script must be scripts/check_changepoint_drift.sh")
    result = subprocess.run(
        ["bash", "scripts/check_changepoint_drift.sh"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    gate_stdout_path.write_text(result.stdout, encoding="utf-8")
    gate_stderr_path.write_text(result.stderr, encoding="utf-8")
    if result.returncode != 0:
        errors.append(f"check_changepoint_drift.sh failed with status {result.returncode}: {result.stderr[-2000:]}")
        return
    stdout_needles = string_set(e2e.get("required_gate_stdout"), "e2e_primary.required_gate_stdout")
    for needle in stdout_needles:
        if needle not in result.stdout:
            errors.append(f"gate stdout missing required text: {needle}")
    if not errors:
        append_event(
            "changepoint_drift.e2e_gate_replayed",
            "pass",
            {"gate_stdout": rel(gate_stdout_path), "gate_stderr": rel(gate_stderr_path)},
        )


def validate_telemetry(contract: dict[str, Any]) -> int:
    telemetry = contract.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_primary must be an object")
        return 0
    if telemetry.get("missing_item_id") != "telemetry.primary":
        errors.append("telemetry_primary.missing_item_id must be telemetry.primary")
    completion_events = string_set(telemetry.get("required_completion_events"), "telemetry_primary.required_completion_events")
    missing_events = sorted(REQUIRED_EVENTS - completion_events)
    if missing_events:
        errors.append(f"completion events missing {missing_events}")
    report_fields = string_set(telemetry.get("required_report_fields"), "telemetry_primary.required_report_fields")
    missing_report = sorted(REQUIRED_REPORT_FIELDS - report_fields)
    if missing_report:
        errors.append(f"report fields missing {missing_report}")
    log_fields = string_set(telemetry.get("required_log_fields"), "telemetry_primary.required_log_fields")
    missing_log = sorted(REQUIRED_LOG_FIELDS - log_fields)
    if missing_log:
        errors.append(f"log fields missing {missing_log}")
    if not errors:
        append_event("changepoint_drift.telemetry_validated", "pass", {"completion_event_count": len(completion_events)})
    return len(completion_events)


contract = load_json(contract_path, "completion contract")
if contract:
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        errors.append(f"schema_version must be {EXPECTED_SCHEMA}")
    if contract.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
        errors.append(f"original_bead must be {EXPECTED_ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != EXPECTED_COMPLETION_BEAD:
        errors.append(f"completion_debt_bead must be {EXPECTED_COMPLETION_BEAD}")
    completion = contract.get("completion_debt_evidence")
    if not isinstance(completion, dict):
        errors.append("completion_debt_evidence must be an object")
    else:
        missing_items = string_set(completion.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed")
        if missing_items != EXPECTED_MISSING_ITEMS:
            errors.append(f"completion debt missing items drifted: {sorted(missing_items)}")
        threshold = completion.get("next_audit_score_threshold")
        if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
            errors.append("completion_debt_evidence.next_audit_score_threshold must be 800..1000")
    refs = contract.get("implementation_refs")
    if not isinstance(refs, list) or not refs:
        errors.append("implementation_refs must be a non-empty array")
    else:
        for index, ref in enumerate(refs):
            validate_file_line_ref(ref, f"implementation_refs[{index}]")

sources = source_artifact_map(contract) if contract else {}
inline_unit_test_count, harness_test_count, policy_summary = validate_unit(contract, sources) if contract else (0, 0, {})
if not errors:
    replay_gate(contract)
completion_event_count = validate_telemetry(contract) if contract else 0

status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else "changepoint_drift_policy_completion_contract_invalid"
if status == "pass":
    append_event("changepoint_drift.completion_contract_validated", "pass", {"contract": rel(contract_path)})
else:
    append_event("changepoint_drift.completion_contract_failed", "fail", {"errors": errors[:20]})

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": status,
    "failure_signature": failure_signature,
    "generated_at_utc": now_utc(),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "contract": rel(contract_path),
    "source_count": len(sources),
    "implementation_ref_count": len(contract.get("implementation_refs", [])) if isinstance(contract.get("implementation_refs"), list) else 0,
    "inline_unit_test_count": inline_unit_test_count,
    "harness_test_count": harness_test_count,
    "completion_event_count": completion_event_count,
    "policy_summary": policy_summary,
    "gate_stdout": rel(gate_stdout_path),
    "gate_stderr": rel(gate_stderr_path),
    "errors": errors,
    "artifact_refs": [
        rel(contract_path),
        rel(report_path),
        rel(log_path),
        rel(gate_stdout_path),
        rel(gate_stderr_path),
    ],
}
missing_report_keys = sorted(REQUIRED_REPORT_FIELDS - set(report))
if missing_report_keys:
    errors.append(f"internal report missing keys {missing_report_keys}")
    report["status"] = "fail"
    report["failure_signature"] = "changepoint_drift_policy_completion_contract_invalid"
    report["errors"] = errors

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "changepoint_drift_policy_completion_contract: PASS "
    f"sources={len(sources)} inline_unit_tests={inline_unit_test_count} "
    f"harness_tests={harness_test_count} events={len(events)}"
)
PY
