#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_CONTRACT:-$ROOT/tests/conformance/runtime_math_admission_ci_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_REPORT:-$OUT_DIR/runtime_math_admission_ci_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MATH_ADMISSION_CI_COMPLETION_LOG:-$OUT_DIR/runtime_math_admission_ci_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "runtime_math_admission_ci_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_admission_ci_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-3ot.3"
COMPLETION_BEAD = "bd-3ot.3.1"

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def source_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def validate_sources(manifest: dict[str, Any]) -> tuple[dict[str, str], dict[str, dict[str, Any]]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}, {}

    texts: dict[str, str] = {}
    loaded: dict[str, dict[str, Any]] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        path = ROOT / path_value
        require(path.exists(), f"source artifact missing: {artifact_id}: {path_value}")
        if path.suffix in {".sh", ".py", ".rs"}:
            texts[artifact_id] = source_text(path_value, artifact_id)
        if path.suffix == ".json":
            loaded[artifact_id] = load_json(path, artifact_id)
    return texts, loaded


def validate_admission_report(manifest: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    expected = manifest.get("required_source_contract", {}).get("admission_report", {})
    if not isinstance(expected, dict):
        err("required_source_contract.admission_report must be an object")
        expected = {}

    require(report.get("schema_version") == "v1", "admission report schema_version must be v1")
    require(report.get("status") == expected.get("status"), "admission report status drifted")
    summary = report.get("summary", {}) if isinstance(report.get("summary"), dict) else {}
    for field in ["total_modules", "admitted", "retired", "blocked", "errors", "warnings"]:
        require(summary.get(field) == expected.get(field), f"admission summary {field} drifted")

    policies = set(as_string_list(report.get("policies_enforced"), "admission_report.policies_enforced"))
    for policy in as_string_list(expected.get("policies_enforced"), "required admission policies"):
        require(policy in policies, f"admission policy missing: {policy}")

    artifacts = report.get("artifacts_emitted", {}) if isinstance(report.get("artifacts_emitted"), dict) else {}
    for artifact in as_string_list(expected.get("required_artifacts_emitted"), "required artifacts emitted"):
        require(artifact in artifacts, f"admission report missing emitted artifact {artifact}")

    integrity = report.get("artifact_integrity", {}) if isinstance(report.get("artifact_integrity"), dict) else {}
    for entry_name in as_string_list(expected.get("required_integrity_entries"), "required integrity entries"):
        entry = integrity.get(entry_name)
        require(isinstance(entry, dict), f"artifact_integrity missing {entry_name}")
        if isinstance(entry, dict):
            sha = entry.get("sha256")
            require(isinstance(sha, str) and len(sha) == 64 and all(c in "0123456789abcdefABCDEF" for c in sha), f"artifact_integrity.{entry_name}.sha256 invalid")
            require(isinstance(entry.get("size_bytes"), int) and entry.get("size_bytes", 0) > 0, f"artifact_integrity.{entry_name}.size_bytes invalid")

    ledger = report.get("admission_ledger", [])
    if not isinstance(ledger, list) or not ledger:
        err("admission_ledger must be a non-empty array")
        ledger = []
    require(len(ledger) == summary.get("total_modules"), "admission ledger length must match total_modules")
    for entry in ledger:
        if not isinstance(entry, dict):
            err("admission ledger entries must be objects")
            continue
        for key in ["module", "tier", "ablation_decision", "admission_status"]:
            require(key in entry, f"admission ledger entry missing {key}")
        if entry.get("tier") == "production_core":
            require(entry.get("admission_status") == "ADMITTED", f"production core module not admitted: {entry.get('module')}")
        if entry.get("tier") == "research":
            require(entry.get("admission_status") == "RETIRED", f"research module not retired: {entry.get('module')}")

    return {
        "total_modules": summary.get("total_modules", 0),
        "admitted": summary.get("admitted", 0),
        "retired": summary.get("retired", 0),
        "blocked": summary.get("blocked", 0),
        "policy_count": len(policies),
        "ledger_entries": len(ledger),
    }


def validate_supporting_artifacts(manifest: dict[str, Any], loaded: dict[str, dict[str, Any]]) -> dict[str, Any]:
    required = manifest.get("required_source_contract", {})
    if not isinstance(required, dict):
        required = {}

    controller = loaded.get("controller_manifest", {})
    controller_summary = controller.get("summary", {}) if isinstance(controller.get("summary"), dict) else {}
    expected_controller = required.get("controller_manifest_summary", {}) if isinstance(required.get("controller_manifest_summary"), dict) else {}
    for field, expected_value in expected_controller.items():
        require(controller_summary.get(field) == expected_value, f"controller manifest summary {field} drifted")
    controllers = controller.get("controllers", [])
    require(isinstance(controllers, list) and len(controllers) == expected_controller.get("total_entries"), "controller manifest controllers length drifted")

    production = loaded.get("production_manifest", {})
    expected_production = required.get("production_manifest", {}) if isinstance(required.get("production_manifest"), dict) else {}
    production_modules = production.get("production_modules", [])
    research_only = production.get("research_only_modules", [])
    require(isinstance(production_modules, list) and len(production_modules) == expected_production.get("production_modules"), "production manifest production_modules count drifted")
    require(isinstance(research_only, list) and len(research_only) == expected_production.get("research_only_modules"), "production manifest research_only_modules count drifted")

    value = loaded.get("math_value_proof", {})
    value_summary = value.get("summary", {}) if isinstance(value.get("summary"), dict) else {}
    expected_value = required.get("math_value_proof", {}) if isinstance(required.get("math_value_proof"), dict) else {}
    for field, expected in expected_value.items():
        require(value_summary.get(field) == expected, f"math value proof summary {field} drifted")

    retirement = loaded.get("math_retirement_policy", {})
    retirement_summary = retirement.get("summary", {}) if isinstance(retirement.get("summary"), dict) else {}
    expected_retirement = required.get("math_retirement_policy", {}) if isinstance(required.get("math_retirement_policy"), dict) else {}
    for field, expected in expected_retirement.items():
        require(retirement_summary.get(field) == expected, f"math retirement summary {field} drifted")

    return {
        "controller_entries": len(controllers) if isinstance(controllers, list) else 0,
        "production_modules": len(production_modules) if isinstance(production_modules, list) else 0,
        "research_only_modules": len(research_only) if isinstance(research_only, list) else 0,
        "value_assessed": value_summary.get("total_modules_assessed", 0),
        "retirement_policy_status": retirement_summary.get("policy_status", "unknown"),
    }


def validate_ci_wiring(manifest: dict[str, Any], texts: dict[str, str]) -> dict[str, Any]:
    required = manifest.get("required_source_contract", {})
    if not isinstance(required, dict):
        required = {}
    ci = texts.get("ci_script", "")
    epic = texts.get("epic_closure_checker", "")
    ci_markers = as_string_list(required.get("ci_markers"), "required_source_contract.ci_markers")
    for marker in ci_markers:
        require(marker in ci, f"CI marker missing: {marker}")
    epic_markers = as_string_list(required.get("epic_closure_markers"), "required_source_contract.epic_closure_markers")
    for marker in epic_markers:
        require(marker in epic, f"epic closure marker missing: {marker}")
    return {"ci_markers": len(ci_markers), "epic_markers": len(epic_markers)}


def validate_missing_item_bindings(manifest: dict[str, Any]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        bindings = []
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    for required_id in ["tests.unit.primary", "tests.e2e.primary"]:
        require(required_id in ids, f"missing item binding {required_id}")

    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        binding_id = str(binding.get("id", "?"))
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{binding_id}.required_commands")
        as_string_list(binding.get("required_test_refs"), f"missing_item_bindings.{binding_id}.required_test_refs")
        if binding_id == "tests.unit.primary":
            require(any("rch exec -- cargo test" in command for command in commands), "unit binding must reference rch cargo test")
            require(any("runtime_math_admission_gate_test" in command for command in commands), "unit binding must reference runtime_math_admission_gate_test")
        if binding_id == "tests.e2e.primary":
            require(any("check_runtime_math_admission.sh" in command for command in commands), "e2e binding must reference admission checker")
            require(any("check_runtime_math_epic_closure.sh" in command for command in commands), "e2e binding must reference epic closure checker")
    return {"binding_count": len(bindings), "binding_ids": sorted(str(item) for item in ids)}


def validate_test_sources(manifest: dict[str, Any]) -> dict[str, Any]:
    sources = manifest.get("completion_debt_evidence", {}).get("test_sources", {})
    if not isinstance(sources, dict) or not sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return {"test_source_count": 0, "required_test_refs": 0}
    refs = 0
    for source_id, source in sources.items():
        if not isinstance(source, dict):
            err(f"test source {source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"test source {source_id} must include path")
            continue
        text = source_text(path_text, source_id)
        for test_ref in as_string_list(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            refs += 1
            require(test_ref in text, f"test source {source_id} missing required test ref {test_ref}")
    return {"test_source_count": len(sources), "required_test_refs": refs}


def validate_telemetry(manifest: dict[str, Any], report_events: list[dict[str, Any]]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    emitted = {str(event.get("event")) for event in report_events}
    for event_name in sorted(required_events):
        require(event_name in emitted, f"telemetry event missing: {event_name}")
    required_fields = as_string_list(telemetry.get("required_fields"), "telemetry_contract.required_fields")
    for event_row in report_events:
        for field in required_fields:
            require(field in event_row, f"telemetry event {event_row.get('event')} missing field {field}")
    return {"required_events": len(required_events), "required_fields": len(required_fields)}


def event(name: str, status: str, outcome: str, artifact_refs: list[str], **extra: Any) -> dict[str, Any]:
    payload = {
        "event": name,
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": outcome,
        "artifact_refs": artifact_refs,
    }
    payload.update(extra)
    return payload


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

texts, loaded = validate_sources(manifest)
admission_summary = validate_admission_report(manifest, loaded.get("admission_report", {}))
supporting_summary = validate_supporting_artifacts(manifest, loaded)
ci_summary = validate_ci_wiring(manifest, texts)
binding_summary = validate_missing_item_bindings(manifest)
test_summary = validate_test_sources(manifest)

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    "tests/runtime_math/admission_gate_report.v1.json",
    "tests/runtime_math/controller_manifest.v1.json",
    "target/conformance/runtime_math_admission_gate.log.jsonl",
]
events = [
    event(
        "runtime_math_admission_ci_completion_summary",
        "pass",
        "admission_report_checked",
        artifact_refs,
        admission=admission_summary,
        supporting=supporting_summary,
    ),
    event(
        "runtime_math_admission_ci_bindings",
        "pass",
        "unit_e2e_bound",
        artifact_refs,
        ci=ci_summary,
        bindings=binding_summary,
        tests=test_summary,
    ),
    event(
        "runtime_math_admission_ci_completion_contract_pass",
        "pass",
        "ready_for_closeout",
        artifact_refs,
        checked_at_unix=int(time.time()),
    ),
]
telemetry_summary = validate_telemetry(manifest, events)

status = "fail" if errors else "pass"
if status == "fail":
    events = [
        event(
            "runtime_math_admission_ci_completion_contract_fail",
            "fail",
            "contract_rejected",
            artifact_refs,
            error_count=len(errors),
        )
    ]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "errors": errors,
    "admission_summary": admission_summary,
    "supporting_summary": supporting_summary,
    "ci_summary": ci_summary,
    "binding_summary": binding_summary,
    "test_summary": test_summary,
    "telemetry_summary": telemetry_summary,
    "events": events,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    print(f"runtime_math_admission_ci_completion_contract: FAIL errors={len(errors)}")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "runtime_math_admission_ci_completion_contract: PASS "
    f"modules={admission_summary['total_modules']} "
    f"admitted={admission_summary['admitted']} "
    f"retired={admission_summary['retired']} "
    f"policies={admission_summary['policy_count']} "
    f"bindings={binding_summary['binding_count']}"
)
PY
