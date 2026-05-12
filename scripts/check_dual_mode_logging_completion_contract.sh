#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_CONTRACT:-$ROOT/tests/conformance/dual_mode_logging_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_REPORT:-$OUT_DIR/dual_mode_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_DUAL_MODE_LOGGING_COMPLETION_LOG:-$OUT_DIR/dual_mode_logging_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "dual_mode_logging_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "dual_mode_logging_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-oai.6"
COMPLETION_BEAD = "bd-oai.6.1"
TRACE_ID = "bd-oai-6-1-dual-mode-logging-completion-v1"
PASS_EVENT = "dual_mode_logging_completion_contract_validated"
FAIL_EVENT = "dual_mode_logging_completion_contract_failed"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "telemetry.primary": "telemetry",
}
REQUIRED_SOURCE_KEYS = {
    "runtime_policy",
    "runtime_math",
    "runtime_mode_startup_contract",
    "runtime_mode_startup_checker",
    "runtime_mode_startup_harness",
    "runtime_mode_evidence_contract",
    "runtime_mode_evidence_harness",
    "runtime_math_logging_contract",
    "runtime_math_logging_checker",
    "runtime_math_logging_harness",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_LEVELS = {"trace", "debug", "info", "warn", "error"}
REQUIRED_EVENTS = {
    "runtime_mode_startup_selection",
    "runtime_mode_switch_attempt",
    "runtime_mode_dispatch",
    "runtime_decision",
    "runtime_evidence_emitted",
    "runtime_calibration",
    "runtime_snapshot",
    "runtime_snapshot_field_out_of_range",
}
REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "decision_id",
    "level",
    "event",
    "controller_id",
    "decision_path",
    "mode",
    "api_family",
    "symbol",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
}
REQUIRED_CHECKER_EVENTS = {
    "dual_mode_logging_source_bound",
    "dual_mode_logging_unit_bound",
    "dual_mode_logging_e2e_bound",
    "dual_mode_logging_telemetry_bound",
    PASS_EVENT,
    FAIL_EVENT,
}
BASE_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "status",
    "source_commit",
    "original_bead",
    "completion_debt_bead",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []
log_rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


COMMIT = source_commit()


def err(signature: str, message: str, **details: Any) -> None:
    detail = " ".join(f"{key}={value!r}" for key, value in sorted(details.items()))
    errors.append(f"{signature}: {message}" + (f" ({detail})" if detail else ""))


def require(condition: bool, signature: str, message: str, **details: Any) -> None:
    if not condition:
        err(signature, message, **details)


def event(name: str, status: str, artifact_refs: list[str], **extra: Any) -> None:
    row = {
        "timestamp": utc_now(),
        "trace_id": TRACE_ID,
        "event": name,
        "status": status,
        "source_commit": COMMIT,
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "artifact_refs": artifact_refs,
        "failure_signature": "none" if status == "pass" else "contract_validation_failed",
    }
    row.update(extra)
    log_rows.append(row)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err("json_invalid", f"{label} is not valid JSON", path=rel(path), error=str(exc))
        return {}
    if not isinstance(value, dict):
        err("json_shape", f"{label} must be a JSON object", path=rel(path))
        return {}
    return value


def string_set(value: Any, context: str, *, allow_empty: bool = False) -> set[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err("array_shape", f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err("array_item_shape", f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        err("source_path_missing", f"{context} path is missing", path=path_text)
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err("source_unreadable", f"{context} path is unreadable", path=path_text, error=str(exc))
        return ""


def file_line_ref_exists(ref: str) -> bool:
    if not isinstance(ref, str) or ":" not in ref:
        err("file_line_ref_malformed", "file-line reference must contain ':'", ref=ref)
        return False
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err("file_line_ref_malformed", "file-line reference line must be an integer", ref=ref)
        return False
    path = ROOT / path_text
    if line_no <= 0 or not path.is_file():
        err("file_line_ref_missing", "file-line reference path missing or line not positive", ref=ref)
        return False
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        err("file_line_ref_missing", "file-line reference line exceeds file length", ref=ref)
        return False
    return True


def validate_sources(contract: dict[str, Any]) -> dict[str, str]:
    artifacts = contract.get("source_artifacts")
    anchors = contract.get("source_anchors")
    if not isinstance(artifacts, dict):
        err("source_artifacts_shape", "source_artifacts must be an object")
        return {}
    if not isinstance(anchors, dict):
        err("source_anchors_shape", "source_anchors must be an object")
        return {}
    require(
        set(artifacts) == REQUIRED_SOURCE_KEYS,
        "source_artifact_key_drift",
        "source artifact key set drifted",
        actual=sorted(artifacts),
        expected=sorted(REQUIRED_SOURCE_KEYS),
    )
    paths: dict[str, str] = {}
    for key, value in artifacts.items():
        if not isinstance(value, str) or not value:
            err("source_artifact_value", f"source_artifacts.{key} must be a non-empty path")
            continue
        paths[key] = value
        text = read_text(value, f"source_artifacts.{key}")
        required = string_set(anchors.get(key, []), f"source_anchors.{key}", allow_empty=True)
        missing = sorted(anchor for anchor in required if anchor not in text)
        if missing:
            err("source_anchor_missing", f"{key} is missing required anchors", missing=missing)
        event(
            "dual_mode_logging_source_bound",
            "pass" if text and not missing else "fail",
            [value],
            source_key=key,
            anchor_count=len(required),
            missing_anchor_count=len(missing),
        )
    return paths


def validate_file_refs(contract: dict[str, Any]) -> int:
    refs = string_set(contract.get("implementation_refs"), "implementation_refs")
    for ref in refs:
        file_line_ref_exists(ref)
    return len(refs)


def validate_missing_items(contract: dict[str, Any]) -> tuple[int, int, int]:
    bindings = contract.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings_shape", "missing_item_bindings must be a non-empty array")
        return (0, 0, 0)
    observed: dict[str, str] = {}
    test_ref_count = 0
    command_count = 0
    evidence_count = 0
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            err("missing_item_shape", f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("id")
        kind = binding.get("kind")
        if not isinstance(item_id, str) or not item_id:
            err("missing_item_id", f"missing_item_bindings[{index}].id missing")
            continue
        if not isinstance(kind, str) or not kind:
            err("missing_item_kind", f"missing_item_bindings[{item_id}].kind missing")
            continue
        observed[item_id] = kind
        evidence = string_set(binding.get("evidence"), f"missing_item_bindings.{item_id}.evidence")
        refs = string_set(binding.get("required_test_refs"), f"missing_item_bindings.{item_id}.required_test_refs")
        commands = string_set(binding.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
        evidence_count += len(evidence)
        test_ref_count += len(refs)
        command_count += len(commands)
        for ref in evidence:
            if ":" in ref:
                file_line_ref_exists(ref)
            else:
                require((ROOT / ref).is_file(), "evidence_path_missing", "evidence path must exist", ref=ref)
        for command in commands:
            if "cargo" in command:
                require("rch exec --" in command, "cargo_not_rch", "cargo validations must use rch", command=command)
                require("CARGO_TARGET_DIR=" in command, "target_dir_missing", "rch cargo validations must name CARGO_TARGET_DIR", command=command)
    require(
        observed == EXPECTED_MISSING_ITEMS,
        "missing_item_set_drift",
        "completion debt missing item set drifted",
        actual=observed,
        expected=EXPECTED_MISSING_ITEMS,
    )
    return (evidence_count, test_ref_count, command_count)


def validate_logging_contract(contract: dict[str, Any]) -> tuple[int, int, int]:
    logging = contract.get("logging_contract")
    if not isinstance(logging, dict):
        err("logging_contract_shape", "logging_contract must be an object")
        return (0, 0, 0)
    levels = string_set(logging.get("required_levels"), "logging_contract.required_levels")
    events = string_set(logging.get("required_events"), "logging_contract.required_events")
    fields = string_set(logging.get("required_fields"), "logging_contract.required_fields")
    require(REQUIRED_LEVELS <= levels, "logging_level_missing", "required logging levels missing", missing=sorted(REQUIRED_LEVELS - levels))
    require(REQUIRED_EVENTS <= events, "logging_event_missing", "required logging events missing", missing=sorted(REQUIRED_EVENTS - events))
    require(REQUIRED_FIELDS <= fields, "logging_field_missing", "required logging fields missing", missing=sorted(REQUIRED_FIELDS - fields))
    policy = logging.get("required_mode_policy")
    require(isinstance(policy, dict), "mode_policy_shape", "required_mode_policy must be an object")
    if isinstance(policy, dict):
        require(policy.get("env_key") == "FRANKENLIBC_MODE", "mode_policy_env", "mode policy must bind FRANKENLIBC_MODE")
        require(policy.get("default_mode") == "strict", "mode_policy_default", "mode policy default must be strict")
        require(policy.get("immutable_after_startup") is True, "mode_policy_immutability", "mode policy immutability must be explicit")
        require(policy.get("switch_attempt_event") == "runtime_mode_switch_attempt", "mode_policy_switch_event", "mode switch event drifted")
    snapshot = logging.get("required_snapshot_policy")
    require(isinstance(snapshot, dict), "snapshot_policy_shape", "required_snapshot_policy must be an object")
    if isinstance(snapshot, dict):
        require(snapshot.get("capture_timing_field") == "snapshot_capture_latency_ns", "snapshot_policy_timing", "snapshot timing field drifted")
        require(snapshot.get("field_count_field") == "snapshot_validated_field_count", "snapshot_policy_field_count", "snapshot field-count field drifted")
        require(snapshot.get("range_violation_event") == "runtime_snapshot_field_out_of_range", "snapshot_policy_range_event", "snapshot range event drifted")
    prefixes = string_set(logging.get("required_trace_prefixes"), "logging_contract.required_trace_prefixes")
    require(
        {"runtime_policy::mode::", "runtime_math::dispatch::", "runtime_math::decision::", "runtime_math::evidence::"} <= prefixes,
        "trace_prefix_missing",
        "required trace prefixes missing",
    )
    return (len(levels), len(events), len(fields))


def validate_test_refs(contract: dict[str, Any], sources: dict[str, str]) -> int:
    source_blobs = {key: read_text(path, f"source_artifacts.{key}") for key, path in sources.items()}
    refs: set[str] = set()
    for binding in contract.get("missing_item_bindings", []):
        if isinstance(binding, dict):
            refs |= string_set(binding.get("required_test_refs"), f"required_test_refs.{binding.get('id', 'unknown')}")
    for test_name in sorted(refs):
        needle = f"fn {test_name}"
        if not any(needle in blob for blob in source_blobs.values()):
            err("test_ref_missing", "required test ref missing from source artifacts", test_name=test_name)
    return len(refs)


def validate_telemetry(contract: dict[str, Any]) -> tuple[int, int]:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract_shape", "telemetry_contract must be an object")
        return (0, 0)
    require(
        telemetry.get("report_schema_version") == EXPECTED_REPORT_SCHEMA,
        "telemetry_report_schema",
        "telemetry report schema drifted",
        actual=telemetry.get("report_schema_version"),
    )
    report_fields = string_set(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields")
    log_fields = string_set(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
    checker_events = string_set(telemetry.get("required_checker_events"), "telemetry_contract.required_checker_events")
    require({"schema_version", "status", "source_commit", "summary", "errors", "artifacts"} <= report_fields, "report_field_missing", "report fields missing")
    require(BASE_LOG_FIELDS <= log_fields, "log_field_missing", "log fields missing", missing=sorted(BASE_LOG_FIELDS - log_fields))
    require(REQUIRED_CHECKER_EVENTS <= checker_events, "checker_event_missing", "checker events missing", missing=sorted(REQUIRED_CHECKER_EVENTS - checker_events))
    failures = string_set(telemetry.get("failure_signatures"), "telemetry_contract.failure_signatures")
    require({"source_anchor_missing", "logging_event_missing", "cargo_not_rch"} <= failures, "failure_signature_missing", "failure signatures missing")
    return (len(report_fields), len(log_fields))


contract = load_json(CONTRACT, "contract")
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead", "unexpected original_bead", actual=contract.get("original_bead"))
require(contract.get("completion_debt_bead") == COMPLETION_BEAD, "completion_bead", "unexpected completion_debt_bead", actual=contract.get("completion_debt_bead"))

sources = validate_sources(contract)
ref_count = validate_file_refs(contract)
evidence_count, test_ref_count, command_count = validate_missing_items(contract)
level_count, event_count, field_count = validate_logging_contract(contract)
resolved_test_refs = validate_test_refs(contract, sources)
report_field_count, log_field_count = validate_telemetry(contract)

summary = {
    "source_artifact_count": len(sources),
    "implementation_ref_count": ref_count,
    "missing_item_count": len(EXPECTED_MISSING_ITEMS),
    "evidence_ref_count": evidence_count,
    "test_ref_count": test_ref_count,
    "resolved_test_ref_count": resolved_test_refs,
    "command_count": command_count,
    "logging_level_count": level_count,
    "logging_event_count": event_count,
    "logging_field_count": field_count,
    "report_field_count": report_field_count,
    "log_field_count": log_field_count,
}

event("dual_mode_logging_unit_bound", "pass" if not errors else "fail", [rel(CONTRACT)], test_ref_count=test_ref_count)
event("dual_mode_logging_e2e_bound", "pass" if not errors else "fail", [rel(CONTRACT)], command_count=command_count)
event("dual_mode_logging_telemetry_bound", "pass" if not errors else "fail", [rel(CONTRACT)], log_field_count=log_field_count)
event(PASS_EVENT if not errors else FAIL_EVENT, "pass" if not errors else "fail", [rel(CONTRACT), rel(REPORT), rel(LOG)], **summary)

status = "pass" if not errors else "fail"
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "source_commit": COMMIT,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": summary,
    "errors": errors,
    "artifacts": {
        "contract": rel(CONTRACT),
        "report": rel(REPORT),
        "log": rel(LOG),
    },
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in log_rows) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL dual-mode logging completion contract primary_failure={errors[0]}", file=os.sys.stderr)
    raise SystemExit(1)

print(
    "PASS dual-mode logging completion contract "
    f"sources={len(sources)} events={event_count} fields={field_count} tests={resolved_test_refs}"
)
PY
