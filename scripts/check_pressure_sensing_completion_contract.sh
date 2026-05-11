#!/usr/bin/env bash
# check_pressure_sensing_completion_contract.sh - bd-w2c3.7.1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT_PATH="${FRANKENLIBC_PRESSURE_SENSING_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/pressure_sensing_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PRESSURE_SENSING_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT_PATH="${FRANKENLIBC_PRESSURE_SENSING_COMPLETION_REPORT:-${OUT_DIR}/pressure_sensing_completion_contract.report.json}"
LOG_PATH="${FRANKENLIBC_PRESSURE_SENSING_COMPLETION_LOG:-${OUT_DIR}/pressure_sensing_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "pressure_sensing_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "pressure_sensing_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.7.1"
COMPLETION_BEAD = "bd-w2c3.7.1.1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_MODES = {"strict", "hardened"}
EXPECTED_REGIMES = {"Nominal", "Pressured", "Overloaded", "Recovery"}

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


def fn_exists(path: Path, name: str) -> bool:
    return f"fn {name}" in path.read_text(encoding="utf-8")


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


def validate_state_machine(evidence: dict[str, Any], texts: dict[str, str], jsons: dict[str, Any]) -> dict[str, Any]:
    spec = evidence.get("pressure_state_machine", {})
    if not isinstance(spec, dict):
        add_error("pressure_state_machine must be an object")
        return {}
    require(set(string_list(spec.get("required_modes"), "pressure_state_machine.required_modes")) == EXPECTED_MODES, "pressure_state_machine.required_modes must be strict+hardened")
    require(set(string_list(spec.get("required_regimes"), "pressure_state_machine.required_regimes")) == EXPECTED_REGIMES, "pressure_state_machine.required_regimes must be all four regimes")

    source = texts.get("pressure_sensor_source", "")
    for snippet in string_list(spec.get("source_snippets"), "pressure_state_machine.source_snippets"):
        require(snippet in source, f"pressure_sensor_source missing snippet {snippet}")

    scenarios = jsons.get("pressure_sensing_scenarios", {})
    require(scenarios.get("schema_version") == spec.get("scenario_schema_version"), "pressure scenarios schema_version drifted")
    require(scenarios.get("bead") == spec.get("scenario_bead"), "pressure scenarios bead drifted")
    scenario_rows = scenarios.get("scenarios", [])
    require(isinstance(scenario_rows, list) and len(scenario_rows) >= int(spec.get("minimum_scenario_count", 0)), "pressure scenario count below contract")
    scenario_ids = {str(row.get("id")) for row in scenario_rows if isinstance(row, dict)}
    for scenario_id in string_list(spec.get("required_scenario_ids"), "pressure_state_machine.required_scenario_ids"):
        require(scenario_id in scenario_ids, f"pressure scenario missing id {scenario_id}")
    summary = scenarios.get("summary", {}) if isinstance(scenarios.get("summary"), dict) else {}
    require(set(string_list(summary.get("regimes_tested"), "pressure scenarios summary.regimes_tested")) == EXPECTED_REGIMES, "pressure scenarios regime coverage drifted")
    actual_properties = set(string_list(summary.get("properties_validated"), "pressure scenarios summary.properties_validated"))
    for item in string_list(spec.get("required_properties"), "pressure_state_machine.required_properties"):
        require(item in actual_properties, f"pressure scenarios missing property {item}")

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
        "overload threshold ordering invalid",
    )

    fixture = jsons.get("pressure_sensing_fixture", {})
    require(fixture.get("family") == spec.get("fixture_family"), "pressure fixture family drifted")
    require(fixture.get("version") == spec.get("fixture_version"), "pressure fixture version drifted")
    fixture_cases = fixture.get("cases", [])
    require(isinstance(fixture_cases, list) and len(fixture_cases) >= int(spec.get("minimum_fixture_cases", 0)), "pressure fixture case count below contract")
    case_names = {str(row.get("name")) for row in fixture_cases if isinstance(row, dict)}
    modes = {str(row.get("mode")) for row in fixture_cases if isinstance(row, dict)}
    require(EXPECTED_MODES.issubset(modes), "pressure fixture must cover strict and hardened modes")
    for case_name in string_list(spec.get("required_case_names"), "pressure_state_machine.required_case_names"):
        require(case_name in case_names, f"pressure fixture missing case {case_name}")
    for row in fixture_cases if isinstance(fixture_cases, list) else []:
        if isinstance(row, dict):
            require("expected_output" in row, f"pressure fixture case missing expected_output: {row.get('name')}")
            require("spec_section" in row, f"pressure fixture case missing spec_section: {row.get('name')}")

    return {
        "scenario_count": len(scenario_rows) if isinstance(scenario_rows, list) else 0,
        "fixture_cases": len(fixture_cases) if isinstance(fixture_cases, list) else 0,
        "regimes": sorted(EXPECTED_REGIMES),
        "modes": sorted(EXPECTED_MODES),
    }


def validate_gate(evidence: dict[str, Any], texts: dict[str, str]) -> dict[str, Any]:
    spec = evidence.get("gate_contract", {})
    if not isinstance(spec, dict):
        add_error("gate_contract must be an object")
        return {}
    script = texts.get("pressure_sensing_script", "")
    for snippet in string_list(spec.get("script_snippets"), "gate_contract.script_snippets"):
        require(snippet in script, f"pressure_sensing_script missing snippet {snippet}")
    for key in string_list(spec.get("report_required_keys"), "gate_contract.report_required_keys"):
        require(key in script, f"pressure_sensing_script does not materialize report key {key}")
    for field in string_list(spec.get("log_required_fields"), "gate_contract.log_required_fields"):
        require(field in script, f"pressure_sensing_script does not materialize log field {field}")
    for field in string_list(spec.get("tooling_contract_fields"), "gate_contract.tooling_contract_fields"):
        require(field in script, f"pressure_sensing_script missing tooling field {field}")
    require(str(spec.get("required_event")) in script, "pressure_sensing_script missing required log event")
    require(str(spec.get("required_api_family")) in script, "pressure_sensing_script missing required api_family")
    return {
        "report_required_keys": len(spec.get("report_required_keys", [])),
        "log_required_fields": len(spec.get("log_required_fields", [])),
        "tooling_contract_fields": len(spec.get("tooling_contract_fields", [])),
    }


def validate_bindings(evidence: dict[str, Any]) -> dict[str, Any]:
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
            if "cargo " in command:
                require(command.startswith("rch exec -- "), f"cargo command must offload through rch: {command}")
        if section_name == "e2e_primary":
            for script_command in string_list(section.get("required_scripts"), "e2e_primary.required_scripts"):
                if "check_pressure_sensing.sh" in script_command:
                    require(script_command.startswith("rch exec -- "), f"pressure sensing e2e script must run through rch: {script_command}")
                script_path_text = ""
                if script_command.startswith("rch exec -- "):
                    script_path_text = next((part for part in script_command.split() if part.startswith("scripts/")), "")
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
        "api_family": "pressure_sensing",
        "symbol": "pressure_sensing::PressureSensor::observe",
        "decision_path": "pressure_sensor::observe+tooling_contract+structured_log",
        "healing_action": "None",
        "errno": 0 if status == "pass" else 1,
        "latency_ns": 0,
        "overload_state": "overloaded",
        "degradation_active": status == "pass",
        "artifact_refs": artifact_refs,
        "failure_signature": "none" if status == "pass" else "pressure_sensing_completion_contract_failed",
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
_, texts, jsons = load_artifacts(evidence)
state_summary = validate_state_machine(evidence, texts, jsons)
gate_summary = validate_gate(evidence, texts)
binding_summary = validate_bindings(evidence)

artifact_refs = [
    rel(contract_path),
    rel(report_path),
    rel(log_path),
    "crates/frankenlibc-membrane/src/pressure_sensor.rs",
    "tests/conformance/fixtures/pressure_sensing.json",
    "tests/conformance/pressure_sensing_scenarios.v1.json",
    "scripts/check_pressure_sensing.sh",
]
status = "pass" if not errors else "fail"
events.extend(
    [
        make_event(
            "pressure_sensing_completion_sources_validated",
            status,
            outcome="state_machine_fixture_and_script_checked",
            artifact_refs=artifact_refs,
            details={"state_machine": state_summary, "gate": gate_summary},
        ),
        make_event(
            "pressure_sensing_completion_unit_bindings_validated",
            status,
            outcome="unit_bindings_checked",
            artifact_refs=artifact_refs,
            details=binding_summary,
        ),
        make_event(
            "pressure_sensing_completion_e2e_bindings_validated",
            status,
            outcome="e2e_bindings_checked",
            artifact_refs=artifact_refs,
            details=gate_summary,
        ),
        make_event(
            "pressure_sensing_completion_contract_validated",
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
    row["degradation_active"] = status == "pass"
    row["failure_signature"] = "none" if status == "pass" else "pressure_sensing_completion_contract_failed"

report = {
    "schema": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "generated_at": ts,
    "source_commit": SOURCE_COMMIT,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "state_machine": state_summary,
        "gate": gate_summary,
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
    print(f"FAIL: pressure sensing completion contract errors={len(errors)} report={rel(report_path)}")
    raise SystemExit(1)

print(
    "PASS: pressure sensing completion contract "
    f"(scenarios={state_summary.get('scenario_count')}, "
    f"fixture_cases={state_summary.get('fixture_cases')}, "
    f"report={rel(report_path)})"
)
PY
