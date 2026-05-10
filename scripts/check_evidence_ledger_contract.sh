#!/usr/bin/env bash
# Gate for bd-28tf.1: evidence ledger JSONL/OTLP completion-debt contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_EVIDENCE_LEDGER_CONTRACT:-$ROOT/tests/conformance/evidence_ledger_contract.v1.json}"
REPORT="${FRANKENLIBC_EVIDENCE_LEDGER_REPORT:-$ROOT/target/conformance/evidence_ledger_contract.report.json}"
LOG="${FRANKENLIBC_EVIDENCE_LEDGER_LOG:-$ROOT/target/conformance/evidence_ledger_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" <<'PY'
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
start_ns = time.time_ns()

BEAD_ID = "bd-28tf"
COMPLETION_BEAD_ID = "bd-28tf.1"
EXPECTED_SCHEMA = "evidence_ledger_contract.v1"
EXPECTED_MANIFEST = "evidence-ledger-contract"
COMPLETION_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
JSONL_FIELDS = {
    "timestamp",
    "evidence_seqno",
    "trace_id",
    "decision_id",
    "policy_id",
    "schema_version",
    "category",
    "level",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "outcome",
    "healing_action",
    "errno",
    "latency_ns",
    "details",
    "artifact_refs",
    "redaction_policy",
}
OTLP_LOG_ATTRIBUTES = {
    "frankenlibc.trace_id",
    "frankenlibc.evidence_seqno",
    "frankenlibc.decision_id",
    "frankenlibc.policy_id",
    "frankenlibc.schema_version",
    "frankenlibc.category",
    "frankenlibc.level",
    "frankenlibc.mode",
    "frankenlibc.api_family",
    "frankenlibc.symbol",
    "frankenlibc.decision_path",
    "frankenlibc.outcome",
    "frankenlibc.healing_action",
    "frankenlibc.errno",
    "frankenlibc.latency_ns",
    "frankenlibc.details",
    "frankenlibc.artifact_refs",
    "frankenlibc.redaction_policy",
}
TELEMETRY_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "bead_id",
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


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def load_contract(errors: list[str]) -> dict[str, Any]:
    try:
        data = json.loads(contract_path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(contract_path)}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append("contract must be a JSON object")
        return {}
    return data


def string_list(value: dict[str, Any], key: str, errors: list[str], context: str) -> list[str]:
    item = value.get(key)
    if not isinstance(item, list) or not item or not all(isinstance(part, str) and part for part in item):
        errors.append(f"{context}.{key} must be a non-empty string array")
        return []
    return list(item)


def validate_file_line_ref(ref: Any, errors: list[str], context: str) -> None:
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
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references a blank line: {ref}")


def validate_completion(contract: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    completion = contract.get("completion_debt_evidence")
    if not isinstance(completion, dict):
        errors.append("completion_debt_evidence must be an object")
        return {}
    if completion.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if completion.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = completion.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 700 or threshold > 1000:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be 700..1000")

    test_source = completion.get("test_source")
    test_source_text = ""
    if not isinstance(test_source, str) or not test_source:
        errors.append("completion_debt_evidence.test_source must be non-empty")
    else:
        test_source_path = root / test_source
        if not test_source_path.is_file():
            errors.append(f"completion_debt_evidence.test_source missing: {test_source}")
        else:
            test_source_text = test_source_path.read_text(encoding="utf-8")

    impl_refs = completion.get("implementation_refs")
    if not isinstance(impl_refs, list) or not impl_refs:
        errors.append("completion_debt_evidence.implementation_refs must be non-empty")
    else:
        for index, ref in enumerate(impl_refs):
            validate_file_line_ref(ref, errors, f"completion_debt_evidence.implementation_refs[{index}]")

    for section_name, missing_item_id in COMPLETION_SECTIONS.items():
        section = completion.get(section_name)
        if not isinstance(section, dict):
            errors.append(f"completion_debt_evidence.{section_name} must be an object")
            continue
        if section.get("missing_item_id") != missing_item_id:
            errors.append(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item_id}")
        section_threshold = section.get("next_audit_score_threshold", threshold)
        if not isinstance(section_threshold, int) or section_threshold < 700 or section_threshold > 1000:
            errors.append(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be 700..1000")
        required_tests = section.get("required_test_names")
        if not isinstance(required_tests, list) or not required_tests:
            errors.append(f"completion_debt_evidence.{section_name}.required_test_names must be non-empty")
            continue
        for test_name in required_tests:
            if not isinstance(test_name, str) or not test_name:
                errors.append(f"completion_debt_evidence.{section_name} contains invalid test name")
            elif f"fn {test_name}(" not in test_source_text:
                errors.append(f"completion_debt_evidence.{section_name} references missing test {test_name}")

    return completion


def validate_contract(contract: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        errors.append(f"schema_version must be {EXPECTED_SCHEMA}")
    if contract.get("manifest_id") != EXPECTED_MANIFEST:
        errors.append(f"manifest_id must be {EXPECTED_MANIFEST}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")

    for source in string_list(contract, "source_modules", errors, "contract"):
        if not (root / source).is_file():
            errors.append(f"source module missing: {source}")

    jsonl = contract.get("jsonl_contract")
    if not isinstance(jsonl, dict):
        errors.append("jsonl_contract must be an object")
    else:
        missing = sorted(JSONL_FIELDS - set(string_list(jsonl, "required_fields", errors, "jsonl_contract")))
        if missing:
            errors.append(f"jsonl_contract.required_fields missing {missing}")
        for category in [
            "metrics_snapshot",
            "healing_action",
            "validation_decision",
            "conformance_result",
            "runtime_math_decision",
        ]:
            if category not in set(string_list(jsonl, "required_categories", errors, "jsonl_contract")):
                errors.append(f"jsonl_contract.required_categories missing {category}")

    otlp = contract.get("otlp_contract")
    if not isinstance(otlp, dict):
        errors.append("otlp_contract must be an object")
    else:
        if otlp.get("schema") != "logs/v1":
            errors.append("otlp_contract.schema must be logs/v1")
        missing = sorted(OTLP_LOG_ATTRIBUTES - set(string_list(otlp, "required_log_attributes", errors, "otlp_contract")))
        if missing:
            errors.append(f"otlp_contract.required_log_attributes missing {missing}")
        resources = set(string_list(otlp, "required_resource_attributes", errors, "otlp_contract"))
        for key in ["service.name", "telemetry.sdk.name", "frankenlibc.schema_version", "frankenlibc.redaction_policy"]:
            if key not in resources:
                errors.append(f"otlp_contract.required_resource_attributes missing {key}")

    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
    else:
        missing = sorted(TELEMETRY_LOG_FIELDS - set(string_list(telemetry, "required_log_fields", errors, "telemetry_contract")))
        if missing:
            errors.append(f"telemetry_contract.required_log_fields missing {missing}")
        events = set(string_list(telemetry, "required_events", errors, "telemetry_contract"))
        if {"evidence_ledger_contract_validated", "evidence_ledger_contract_failed"} - events:
            errors.append("telemetry_contract.required_events drifted")

    redaction = contract.get("privacy_redaction_policy")
    if not isinstance(redaction, dict):
        errors.append("privacy_redaction_policy must be an object")
    else:
        if redaction.get("default_policy") != "redact_pointers":
            errors.append("privacy_redaction_policy.default_policy must be redact_pointers")
        policies = set(string_list(redaction, "accepted_policies", errors, "privacy_redaction_policy"))
        if {"none", "redact_pointers", "full"} - policies:
            errors.append("privacy_redaction_policy.accepted_policies drifted")

    return validate_completion(contract, errors)


errors: list[str] = []
contract = load_contract(errors)
completion = validate_contract(contract, errors)
duration_ns = time.time_ns() - start_ns
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else "evidence_ledger_contract_invalid"
event = "evidence_ledger_contract_validated" if not errors else "evidence_ledger_contract_failed"

report = {
    "schema_version": "evidence_ledger_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": completion.get("bead", ""),
    "status": status,
    "failure_signature": failure_signature,
    "generated_at_utc": now_utc(),
    "source_commit": git_head(),
    "contract": rel(contract_path),
    "completion_debt_evidence": completion,
    "summary": {
        "jsonl_required_field_count": len(contract.get("jsonl_contract", {}).get("required_fields", []))
        if isinstance(contract.get("jsonl_contract"), dict)
        else 0,
        "otlp_required_log_attribute_count": len(contract.get("otlp_contract", {}).get("required_log_attributes", []))
        if isinstance(contract.get("otlp_contract"), dict)
        else 0,
        "completion_debt_sections": sorted(COMPLETION_SECTIONS),
        "next_audit_score_threshold": completion.get("next_audit_score_threshold"),
    },
    "errors": errors,
    "artifact_refs": [
        rel(contract_path),
        rel(report_path),
        rel(log_path),
    ],
}

log_row = {
    "timestamp": now_utc(),
    "trace_id": f"{COMPLETION_BEAD_ID}::evidence-ledger-contract::{status}",
    "bead_id": BEAD_ID,
    "completion_debt_bead": completion.get("bead", ""),
    "event": event,
    "status": status,
    "mode": "strict",
    "api_family": "membrane",
    "symbol": "evidence_ledger",
    "decision_path": "evidence_ledger::contract::validate",
    "healing_action": None,
    "errno": 0 if not errors else 22,
    "latency_ns": duration_ns,
    "artifact_refs": report["artifact_refs"],
    "failure_signature": failure_signature,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if not errors else 1)
PY
