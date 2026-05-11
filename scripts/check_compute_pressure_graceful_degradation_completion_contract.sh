#!/usr/bin/env bash
# check_compute_pressure_graceful_degradation_completion_contract.sh - bd-w2c3.7.4 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT_PATH="${FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_CONTRACT:-${ROOT}/tests/conformance/compute_pressure_graceful_degradation_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT_PATH="${FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_REPORT:-${OUT_DIR}/compute_pressure_graceful_degradation_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_COMPUTE_PRESSURE_GRACEFUL_DEGRADATION_LOG:-${OUT_DIR}/compute_pressure_graceful_degradation_completion_contract.log.jsonl}"

mkdir -p "$(dirname "${REPORT_PATH}")" "$(dirname "${LOG_PATH}")"

export FLC_ROOT="${ROOT}"
export FLC_CONTRACT_PATH="${CONTRACT_PATH}"
export FLC_REPORT_PATH="${REPORT_PATH}"
export FLC_LOG_PATH="${LOG_PATH}"

python3 - <<'PY'
from __future__ import annotations

import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

root = Path(os.environ["FLC_ROOT"])
contract_path = Path(os.environ["FLC_CONTRACT_PATH"])
report_path = Path(os.environ["FLC_REPORT_PATH"])
log_path = Path(os.environ["FLC_LOG_PATH"])
ts = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

EXPECTED_SCHEMA = "compute_pressure_graceful_degradation_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "compute_pressure_graceful_degradation_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.7"
COMPLETION_BEAD = "bd-w2c3.7.4"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_REGIMES = {"Nominal", "Pressured", "Overloaded", "Recovery"}
EXPECTED_MODES = {"strict", "hardened"}
EXPECTED_RING_IDS = {
    "runtime_math.decision_card_ring",
    "runtime_math.evidence_symbol_ring",
    "structured_log.event_ring",
    "stdio.evidence_row_ring",
    "membrane.validation_log_ring",
}
REQUIRED_BACKPRESSURE_POLICY_FLAGS = [
    "fail_closed_when_ring_path_unaccounted",
    "fail_closed_when_seqno_non_monotone",
    "fail_closed_when_loss_count_field_missing",
    "fail_closed_when_max_epoch_field_missing",
    "fail_closed_when_redaction_cardinality_unbounded",
    "fail_closed_when_serialization_non_deterministic_post_overwrite",
    "fail_closed_when_loss_evidence_kind_undocumented",
    "fail_closed_when_source_commit_stale",
]

errors: list[str] = []
events: list[dict[str, Any]] = []


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = source_commit()


def add_error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        add_error(message)


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(f"{label} is not valid JSON: {path}: {exc}")
        return {}


def rel_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"path must stay under workspace root: {value}")
    return root / path


def rel(value: Path) -> str:
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(value)


def string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        add_error(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            add_error(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def check_file_line_ref(file_line_ref: str) -> None:
    if ":" not in file_line_ref:
        add_error(f"implementation ref missing line separator: {file_line_ref}")
        return
    path_text, line_text = file_line_ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        add_error(f"implementation ref has invalid line: {file_line_ref}")
        return
    try:
        path = rel_path(path_text)
    except ValueError as exc:
        add_error(str(exc))
        return
    if not path.is_file():
        add_error(f"implementation ref path missing: {file_line_ref}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no < 1 or line_no > len(lines) or not lines[line_no - 1].strip():
        add_error(f"implementation ref does not point to a non-empty line: {file_line_ref}")


def fn_exists(path: Path, name: str) -> bool:
    return f"fn {name}" in path.read_text(encoding="utf-8")


def load_artifacts(evidence: dict[str, Any]) -> tuple[dict[str, Path], dict[str, str], dict[str, Any]]:
    artifacts = evidence.get("artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        add_error("completion_debt_evidence.artifacts must be a non-empty object")
        return {}, {}, {}
    paths: dict[str, Path] = {}
    texts: dict[str, str] = {}
    jsons: dict[str, Any] = {}
    for name, raw_path in artifacts.items():
        if not isinstance(raw_path, str) or not raw_path:
            add_error(f"artifact {name} path must be a non-empty string")
            continue
        try:
            path = rel_path(raw_path)
        except ValueError as exc:
            add_error(str(exc))
            continue
        paths[name] = path
        if not path.is_file():
            add_error(f"artifact {name} missing: {raw_path}")
            continue
        if path.suffix in {".rs", ".sh", ".py", ".md"}:
            texts[name] = path.read_text(encoding="utf-8")
        if path.suffix == ".json":
            jsons[name] = load_json(path, name)
    return paths, texts, jsons


def validate_top_level(contract: dict[str, Any]) -> dict[str, Any]:
    require(contract.get("schema") == EXPECTED_SCHEMA, f"schema must be {EXPECTED_SCHEMA}")
    require(contract.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
    require(
        contract.get("completion_debt_bead") == COMPLETION_BEAD,
        f"completion_debt_bead must be {COMPLETION_BEAD}",
    )
    require(int(contract.get("next_audit_score_threshold", 0)) >= 800, "next_audit_score_threshold must be >= 800")
    evidence = contract.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        add_error("completion_debt_evidence must be an object")
        return {}
    missing_items = set(string_list(evidence.get("missing_items"), "completion_debt_evidence.missing_items"))
    require(missing_items == EXPECTED_MISSING_ITEMS, f"missing_items must be exactly {sorted(EXPECTED_MISSING_ITEMS)}")
    for ref in string_list(evidence.get("implementation_refs"), "completion_debt_evidence.implementation_refs"):
        check_file_line_ref(ref)
    return evidence


def validate_pressure(evidence: dict[str, Any], texts: dict[str, str], jsons: dict[str, Any]) -> dict[str, Any]:
    spec = evidence.get("pressure_sensing", {})
    if not isinstance(spec, dict):
        add_error("pressure_sensing must be an object")
        return {}
    contract_regimes = set(string_list(spec.get("required_regimes"), "pressure_sensing.required_regimes"))
    contract_modes = set(string_list(spec.get("required_modes"), "pressure_sensing.required_modes"))
    require(contract_regimes == EXPECTED_REGIMES, f"pressure_sensing.required_regimes must be exactly {sorted(EXPECTED_REGIMES)}")
    require(contract_modes == EXPECTED_MODES, f"pressure_sensing.required_modes must be exactly {sorted(EXPECTED_MODES)}")

    scenarios = jsons.get("pressure_sensing_scenarios", {})
    require(scenarios.get("schema_version") == "v1", "pressure scenarios schema_version must be v1")
    require(scenarios.get("bead") == spec.get("scenario_bead"), "pressure scenarios bead drifted")
    scenario_rows = scenarios.get("scenarios", [])
    require(isinstance(scenario_rows, list) and len(scenario_rows) >= int(spec.get("minimum_scenario_count", 0)), "pressure scenarios count below contract")
    actual_ids = {str(row.get("id")) for row in scenario_rows if isinstance(row, dict)}
    for scenario_id in string_list(spec.get("required_scenario_ids"), "pressure_sensing.required_scenario_ids"):
        require(scenario_id in actual_ids, f"pressure scenario missing required id {scenario_id}")
    summary = scenarios.get("summary", {}) if isinstance(scenarios.get("summary"), dict) else {}
    actual_regimes = set(string_list(summary.get("regimes_tested"), "pressure scenarios summary.regimes_tested"))
    require(actual_regimes == EXPECTED_REGIMES, "pressure scenarios must cover nominal/pressured/overloaded/recovery")

    thresholds = scenarios.get("thresholds", {}) if isinstance(scenarios.get("thresholds"), dict) else {}
    expected_thresholds = spec.get("thresholds", {}) if isinstance(spec.get("thresholds"), dict) else {}
    for field, expected in expected_thresholds.items():
        require(thresholds.get(field) == expected, f"pressure threshold {field} drifted")
    require(
        thresholds.get("pressured_exit", 0) < thresholds.get("pressured_enter", 0) < thresholds.get("overloaded_enter", 0),
        "pressure threshold ordering invalid",
    )
    require(
        thresholds.get("pressured_exit", 0) < thresholds.get("overloaded_exit", 0) < thresholds.get("overloaded_enter", 0),
        "overload exit threshold ordering invalid",
    )

    fixture = jsons.get("pressure_sensing_fixture", {})
    require(fixture.get("family") == spec.get("fixture_family"), "pressure fixture family drifted")
    require(fixture.get("version") == spec.get("fixture_version"), "pressure fixture version drifted")
    fixture_cases = fixture.get("cases", [])
    require(isinstance(fixture_cases, list) and len(fixture_cases) >= int(spec.get("minimum_fixture_cases", 0)), "pressure fixture case count below contract")
    case_names = {str(row.get("name")) for row in fixture_cases if isinstance(row, dict)}
    modes = {str(row.get("mode")) for row in fixture_cases if isinstance(row, dict)}
    require(EXPECTED_MODES.issubset(modes), "pressure fixture must include strict and hardened cases")
    for case_name in string_list(spec.get("required_case_names"), "pressure_sensing.required_case_names"):
        require(case_name in case_names, f"pressure fixture missing required case {case_name}")

    snippets = evidence.get("source_snippets", {})
    if isinstance(snippets, dict):
        for source_name in ["pressure_sensor_source", "runtime_math_source", "pressure_sensing_script"]:
            source_text = texts.get(source_name, "")
            for snippet in string_list(snippets.get(source_name), f"source_snippets.{source_name}"):
                require(snippet in source_text, f"{source_name} missing snippet {snippet}")

    script = texts.get("pressure_sensing_script", "")
    for field in string_list(spec.get("tooling_contract_fields"), "pressure_sensing.tooling_contract_fields"):
        require(field in script, f"pressure_sensing_script missing tooling contract field {field}")

    return {
        "scenario_count": len(scenario_rows) if isinstance(scenario_rows, list) else 0,
        "fixture_cases": len(fixture_cases) if isinstance(fixture_cases, list) else 0,
        "required_regimes": sorted(contract_regimes),
        "required_modes": sorted(contract_modes),
    }


def validate_family_degradation(evidence: dict[str, Any], texts: dict[str, str], jsons: dict[str, Any]) -> dict[str, Any]:
    spec = evidence.get("family_degradation", {})
    if not isinstance(spec, dict):
        add_error("family_degradation must be an object")
        return {}
    family = jsons.get("family_degradation_contract", {})
    require(family.get("schema") == "family_degradation_policy_completion_contract.v1", "family degradation schema drifted")
    require(family.get("bead") == spec.get("contract_bead"), "family degradation bead drifted")
    require(family.get("completion_debt_bead") == spec.get("completion_debt_bead"), "family degradation completion debt bead drifted")
    family_evidence = family.get("completion_debt_evidence", {}) if isinstance(family.get("completion_debt_evidence"), dict) else {}
    missing_items = set(string_list(family_evidence.get("missing_items"), "family degradation missing_items"))
    require({"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}.issubset(missing_items), "family degradation contract must bind unit/e2e/telemetry")
    telemetry = family_evidence.get("telemetry_primary", {}) if isinstance(family_evidence.get("telemetry_primary"), dict) else {}
    actual_events = set(string_list(telemetry.get("required_events"), "family_degradation.telemetry.required_events"))
    actual_fields = set(string_list(telemetry.get("required_fields"), "family_degradation.telemetry.required_fields"))
    for event in string_list(spec.get("required_events"), "family_degradation.required_events"):
        require(event in actual_events, f"family degradation telemetry missing event {event}")
    for field in string_list(spec.get("required_fields"), "family_degradation.required_fields"):
        require(field in actual_fields, f"family degradation telemetry missing field {field}")

    guard = family_evidence.get("policy_table_guard", {}) if isinstance(family_evidence.get("policy_table_guard"), dict) else {}
    require(
        guard.get("hardened_overload_action") == "Repair(ReturnSafeDefault)",
        "family degradation hardened overload action drifted",
    )
    require(guard.get("strict_overload_action") == "Deny", "family degradation strict overload action drifted")

    snippets = evidence.get("source_snippets", {})
    if isinstance(snippets, dict):
        source_text = texts.get("family_degradation_script", "")
        for snippet in string_list(snippets.get("family_degradation_script"), "source_snippets.family_degradation_script"):
            require(snippet in source_text, f"family_degradation_script missing snippet {snippet}")

    for section_name in ["unit_primary", "e2e_primary"]:
        section = family_evidence.get(section_name, {}) if isinstance(family_evidence.get(section_name), dict) else {}
        for command in string_list(section.get("required_commands"), f"family_degradation.{section_name}.required_commands"):
            if "cargo " in command:
                require("rch exec" in command, f"family degradation cargo command must offload through rch: {command}")
    return {
        "required_event_count": len(actual_events),
        "required_field_count": len(actual_fields),
        "overload_policy": spec.get("required_overload_policy"),
    }


def validate_backpressure(evidence: dict[str, Any], jsons: dict[str, Any]) -> dict[str, Any]:
    spec = evidence.get("backpressure", {})
    if not isinstance(spec, dict):
        add_error("backpressure must be an object")
        return {}
    contract_ring_ids = set(string_list(spec.get("required_ring_ids"), "backpressure.required_ring_ids"))
    require(contract_ring_ids == EXPECTED_RING_IDS, f"backpressure.required_ring_ids must be exactly {sorted(EXPECTED_RING_IDS)}")

    manifest = jsons.get("evidence_ring_backpressure_contract", {})
    require(manifest.get("manifest_id") == spec.get("manifest_id"), "backpressure manifest_id drifted")
    require(manifest.get("bead") == spec.get("source_bead"), "backpressure source bead drifted")
    ring_paths = manifest.get("ring_paths", [])
    require(isinstance(ring_paths, list) and len(ring_paths) == len(EXPECTED_RING_IDS), "backpressure ring path count drifted")
    actual_ring_ids = {str(row.get("ring_id")) for row in ring_paths if isinstance(row, dict)}
    require(actual_ring_ids == EXPECTED_RING_IDS, "backpressure ring ids drifted")
    required_fields = set(string_list(spec.get("required_ring_path_fields"), "backpressure.required_ring_path_fields"))
    for row in ring_paths if isinstance(ring_paths, list) else []:
        if not isinstance(row, dict):
            add_error("backpressure ring path rows must be objects")
            continue
        for field in required_fields:
            require(field in row, f"backpressure ring path {row.get('ring_id')} missing {field}")
        require(row.get("expected_loss_semantics") == "overwrite_oldest", f"backpressure ring path {row.get('ring_id')} must use overwrite_oldest")
        require(row.get("monotone_seqno_required") is True, f"backpressure ring path {row.get('ring_id')} must require monotone seqno")
        require(row.get("deterministic_serialization_after_overwrite") is True, f"backpressure ring path {row.get('ring_id')} must require deterministic serialization")

    stress = manifest.get("stress_profile", {}) if isinstance(manifest.get("stress_profile"), dict) else {}
    require(stress.get("drive_to_capacity_multiple") == spec.get("stress_drive_to_capacity_multiple"), "backpressure stress drive multiple drifted")
    require(set(string_list(stress.get("modes"), "backpressure stress modes")) == EXPECTED_MODES, "backpressure stress modes must cover strict+hardened")
    require(stress.get("deterministic_seed_required") is spec.get("deterministic_seed_required"), "backpressure deterministic seed requirement drifted")

    policy = manifest.get("policy", {}) if isinstance(manifest.get("policy"), dict) else {}
    for flag in REQUIRED_BACKPRESSURE_POLICY_FLAGS:
        require(policy.get(flag) is True, f"backpressure policy flag {flag} must be true")

    kinds = manifest.get("loss_evidence_kinds", [])
    fail_closed = [row for row in kinds if isinstance(row, dict) and row.get("fail_closed") is True]
    require(len(fail_closed) == spec.get("fail_closed_kinds_count"), "backpressure fail-closed kind count drifted")

    return {
        "ring_path_count": len(ring_paths) if isinstance(ring_paths, list) else 0,
        "fail_closed_kinds_count": len(fail_closed),
        "drive_to_capacity_multiple": stress.get("drive_to_capacity_multiple"),
    }


def validate_bindings(evidence: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    test_sources = evidence.get("test_sources", {})
    if not isinstance(test_sources, dict) or not test_sources:
        add_error("test_sources must be a non-empty object")
        return {}
    source_paths: dict[str, Path] = {}
    for source_name, path_text in test_sources.items():
        if not isinstance(path_text, str):
            add_error(f"test source {source_name} must be a string path")
            continue
        try:
            source_paths[source_name] = rel_path(path_text)
        except ValueError as exc:
            add_error(str(exc))
    source_paths.update(paths)

    seen_refs = 0
    for section_name, expected_missing_id in [
        ("unit_primary", "tests.unit.primary"),
        ("e2e_primary", "tests.e2e.primary"),
    ]:
        section = evidence.get(section_name, {})
        if not isinstance(section, dict):
            add_error(f"{section_name} must be an object")
            continue
        require(section.get("missing_item_id") == expected_missing_id, f"{section_name}.missing_item_id mismatch")
        for ref in section.get("required_test_refs", []):
            if not isinstance(ref, dict):
                add_error(f"{section_name}.required_test_refs entries must be objects")
                continue
            source = str(ref.get("source", ""))
            name = str(ref.get("name", ""))
            path = source_paths.get(source)
            if path is None:
                add_error(f"{section_name} references unknown source {source}")
                continue
            require(path.is_file(), f"{section_name} test source missing: {source}")
            require(fn_exists(path, name), f"{section_name} source {source} missing test function {name}")
            seen_refs += 1
        for command in string_list(section.get("required_commands"), f"{section_name}.required_commands"):
            needs_rch = "cargo " in command or "check_pressure_sensing.sh" in command
            if needs_rch:
                require(command.startswith("rch exec -- "), f"command must offload through rch: {command}")
        if section_name == "e2e_primary":
            for script_command in string_list(section.get("required_scripts"), "e2e_primary.required_scripts"):
                needs_rch = "check_pressure_sensing.sh" in script_command
                if needs_rch:
                    require(script_command.startswith("rch exec -- "), f"pressure sensing e2e script must run through rch: {script_command}")
                script_path_text = script_command
                if script_command.startswith("rch exec -- "):
                    parts = script_command.split()
                    script_path_text = next((part for part in parts if part.startswith("scripts/")), "")
                elif script_command.startswith("bash "):
                    script_path_text = script_command.split()[1]
                if script_path_text:
                    try:
                        require(rel_path(script_path_text).is_file(), f"required e2e script missing: {script_path_text}")
                    except ValueError as exc:
                        add_error(str(exc))
    return {"test_ref_count": seen_refs}


def make_event(name: str, status: str, *, outcome: str, artifact_refs: list[str], details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "trace_id": f"{COMPLETION_BEAD}:{name}",
        "event": name,
        "status": status,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": SOURCE_COMMIT,
        "mode": "hardened",
        "api_family": "runtime_math",
        "symbol": "runtime_math::compute_pressure_degradation",
        "decision_path": "pressure_sensor+family_degradation_policy+evidence_backpressure",
        "healing_action": "ReturnSafeDefault" if status == "pass" else "None",
        "errno": 0 if status == "pass" else 1,
        "latency_ns": 0,
        "overload_state": "overloaded",
        "degradation_active": status == "pass",
        "overload_policy": "overloaded_safe_fallback" if status == "pass" else "contract_failed",
        "artifact_refs": artifact_refs,
        "failure_signature": "none" if status == "pass" else "compute_pressure_graceful_degradation_contract_failed",
        "details": details or {},
    }


def validate_telemetry_contract(evidence: dict[str, Any], generated_events: list[dict[str, Any]]) -> dict[str, Any]:
    telemetry = evidence.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        add_error("telemetry_contract must be an object")
        telemetry = {}
    require(telemetry.get("report_schema") == EXPECTED_REPORT_SCHEMA, "telemetry report schema drifted")
    required_events = set(string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    required_fields = set(string_list(telemetry.get("required_fields"), "telemetry_contract.required_fields"))
    emitted = {str(row.get("event")) for row in generated_events}
    for event_name in required_events:
        require(event_name in emitted, f"telemetry event missing: {event_name}")
    for row in generated_events:
        missing = required_fields - set(row)
        require(not missing, f"telemetry event {row.get('event')} missing fields {sorted(missing)}")
    return {"required_event_count": len(required_events), "required_field_count": len(required_fields)}


contract = load_json(contract_path, "completion contract")
if not isinstance(contract, dict):
    contract = {}
evidence = validate_top_level(contract)
paths, texts, jsons = load_artifacts(evidence)
pressure_summary = validate_pressure(evidence, texts, jsons)
family_summary = validate_family_degradation(evidence, texts, jsons)
backpressure_summary = validate_backpressure(evidence, jsons)
binding_summary = validate_bindings(evidence, paths)

artifact_refs = [
    rel(contract_path),
    rel(report_path),
    rel(log_path),
    "tests/conformance/fixtures/pressure_sensing.json",
    "tests/conformance/pressure_sensing_scenarios.v1.json",
    "tests/conformance/family_degradation_policy_completion_contract.v1.json",
    "tests/conformance/evidence_ring_backpressure_stress_contract.v1.json",
]

status = "pass" if not errors else "fail"
events.extend(
    [
        make_event(
            "compute_pressure_graceful_degradation_sources_validated",
            status,
            outcome="source_artifacts_checked",
            artifact_refs=artifact_refs,
            details={"pressure": pressure_summary, "family_degradation": family_summary},
        ),
        make_event(
            "compute_pressure_graceful_degradation_unit_bindings_validated",
            status,
            outcome="unit_bindings_checked",
            artifact_refs=artifact_refs,
            details=binding_summary,
        ),
        make_event(
            "compute_pressure_graceful_degradation_e2e_bindings_validated",
            status,
            outcome="e2e_bindings_checked",
            artifact_refs=artifact_refs,
            details={"family_degradation": family_summary},
        ),
        make_event(
            "compute_pressure_graceful_degradation_backpressure_validated",
            status,
            outcome="backpressure_loss_accounting_checked",
            artifact_refs=artifact_refs,
            details=backpressure_summary,
        ),
        make_event(
            "compute_pressure_graceful_degradation_completion_contract_validated",
            status,
            outcome="completion_contract_checked",
            artifact_refs=artifact_refs,
            details={"error_count": len(errors)},
        ),
    ]
)
telemetry_summary = validate_telemetry_contract(evidence, events)
status = "pass" if not errors else "fail"
for row in events:
    row["status"] = status
    row["errno"] = 0 if status == "pass" else 1
    row["healing_action"] = "ReturnSafeDefault" if status == "pass" else "None"
    row["degradation_active"] = status == "pass"
    row["overload_policy"] = "overloaded_safe_fallback" if status == "pass" else "contract_failed"
    row["failure_signature"] = "none" if status == "pass" else "compute_pressure_graceful_degradation_contract_failed"

report = {
    "schema": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "generated_at": ts,
    "source_commit": SOURCE_COMMIT,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "pressure": pressure_summary,
        "family_degradation": family_summary,
        "backpressure": backpressure_summary,
        "bindings": binding_summary,
        "telemetry": telemetry_summary,
    },
    "events": events,
    "errors": errors,
    "artifacts": {
        "contract": rel(contract_path),
        "report_json": rel(report_path),
        "log_jsonl": rel(log_path),
    },
}

log_path.parent.mkdir(parents=True, exist_ok=True)
with log_path.open("w", encoding="utf-8") as handle:
    for row in events:
        handle.write(json.dumps(row, sort_keys=True))
        handle.write("\n")
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(
        f"FAIL: compute pressure graceful degradation completion contract errors={len(errors)} "
        f"report={rel(report_path)}"
    )
    raise SystemExit(1)

print(
    "PASS: compute pressure graceful degradation completion contract "
    f"(scenarios={pressure_summary.get('scenario_count')}, "
    f"ring_paths={backpressure_summary.get('ring_path_count')}, "
    f"report={rel(report_path)})"
)
PY
