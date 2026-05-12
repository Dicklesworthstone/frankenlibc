#!/usr/bin/env bash
# Validate bd-wud.1 mode semantics matrix completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MODE_SEMANTICS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/mode_semantics_matrix_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MODE_SEMANTICS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/mode_semantics_matrix_completion}"
REPORT="${FRANKENLIBC_MODE_SEMANTICS_COMPLETION_REPORT:-${OUT_DIR}/mode_semantics_matrix_completion_contract.report.json}"
LOG="${FRANKENLIBC_MODE_SEMANTICS_COMPLETION_LOG:-${OUT_DIR}/mode_semantics_matrix_completion_contract.events.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import stat
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

SCHEMA = "mode_semantics_matrix_completion_contract.v1"
REPORT_SCHEMA = "mode_semantics_matrix_completion_contract.report.v1"
LOG_SCHEMA = "mode_semantics_matrix_completion_contract.log.v1"
ORIGINAL_BEAD = "bd-wud"
COMPLETION_BEAD = "bd-wud.1"
EXPECTED_MISSING = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
REQUIRED_SOURCE_IDS = {
    "mode_semantics_matrix",
    "mode_semantics_gate",
    "mode_semantics_harness",
    "verification_matrix_record",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_TESTS = {
    "matrix_exists_and_valid",
    "all_families_have_required_fields",
    "family_modules_exist_in_abi_source",
    "heals_call_sites_match_source",
    "behaviors_have_matching_scenarios",
    "summary_consistent_with_entries",
    "gate_script_exists_and_executable",
    "no_duplicate_families",
    "check_mode_semantics.sh",
    "checker_accepts_contract_and_emits_telemetry",
}
REQUIRED_COMMANDS = {
    "bash scripts/check_mode_semantics.sh",
    "bash scripts/check_mode_semantics_matrix_completion_contract.sh",
    "rch exec -- cargo test -p frankenlibc-harness --test mode_semantics_test -- --nocapture",
    "rch exec -- cargo test -p frankenlibc-harness --test mode_semantics_matrix_completion_contract_test -- --nocapture",
    "rch exec -- cargo clippy -p frankenlibc-harness --test mode_semantics_matrix_completion_contract_test -- -D warnings",
}
REQUIRED_EVENTS = {
    "mode_semantics_matrix.source_artifacts_validated",
    "mode_semantics_matrix.matrix_expectations_validated",
    "mode_semantics_matrix.unit_binding_validated",
    "mode_semantics_matrix.e2e_binding_validated",
    "mode_semantics_matrix.telemetry_binding_validated",
    "mode_semantics_matrix.completion_contract_validated",
    "mode_semantics_matrix.completion_contract_failed",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_count = 0
implementation_ref_count = 0
test_binding_count = 0
binding_count = 0
family_count = 0
total_heals_call_sites = 0


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def string_array(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": LOG_SCHEMA,
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_file_line_ref(value: Any, label: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        error(f"{label} must be file:line")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        error(f"{label} must be file:line")
        return
    path = ROOT / path_text
    if not path.is_file():
        error(f"{label} references missing file: {value}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        error(f"{label} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        error(f"{label} references blank line: {value}")


def validate_sources(contract: dict[str, Any]) -> None:
    global source_count
    sources = contract.get("source_artifacts")
    if not isinstance(sources, list):
        error("source_artifacts must be an array")
        return
    ids: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            error(f"source_artifacts[{index}] must be an object")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            error(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        ids.add(source_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"source artifact {source_id} path must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            error(f"source artifact {source_id} missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in string_array(source.get("required_needles"), f"{source_id}.required_needles"):
            if needle not in text:
                error(f"source artifact {source_id} missing required needle: {needle}")
        if source_id == "mode_semantics_gate" and not (path.stat().st_mode & stat.S_IXUSR):
            error("scripts/check_mode_semantics.sh must be executable")
        if source_id == "completion_checker" and not (path.stat().st_mode & stat.S_IXUSR):
            error("scripts/check_mode_semantics_matrix_completion_contract.sh must be executable")
    missing = REQUIRED_SOURCE_IDS - ids
    extra = ids - REQUIRED_SOURCE_IDS
    if missing:
        error(f"source_artifacts missing required ids: {sorted(missing)}")
    if extra:
        error(f"source_artifacts contains unexpected ids: {sorted(extra)}")
    source_count = len(ids)
    append_event(
        "mode_semantics_matrix.source_artifacts_validated",
        "pass" if not errors else "fail",
        {"source_count": source_count},
    )


def validate_matrix_expectations(contract: dict[str, Any]) -> None:
    global family_count, total_heals_call_sites
    expectations = contract.get("matrix_expectations", {})
    require(isinstance(expectations, dict), "matrix_expectations must be object")
    matrix = load_json(ROOT / "tests/conformance/mode_semantics_matrix.json", "mode semantics matrix")
    if not isinstance(matrix, dict):
        return
    require(matrix.get("schema_version") == expectations.get("schema_version"), "matrix schema_version drifted")
    require(matrix.get("bead") == expectations.get("bead") == ORIGINAL_BEAD, "matrix bead drifted")
    require(matrix.get("env_variable") == expectations.get("env_variable") == "FRANKENLIBC_MODE", "matrix env_variable drifted")
    modes = matrix.get("modes", {})
    expected_modes = set(string_array(expectations.get("modes"), "matrix_expectations.modes"))
    require(set(modes.keys()) == expected_modes, "matrix modes drifted")
    require(modes.get("strict", {}).get("heals_enabled") is False, "strict mode must not enable heals")
    require(modes.get("hardened", {}).get("heals_enabled") is True, "hardened mode must enable heals")
    families = matrix.get("families", [])
    require(isinstance(families, list) and families, "matrix families must be non-empty array")
    summary = matrix.get("summary", {})
    require(isinstance(summary, dict), "matrix summary must be object")
    family_count = len(families) if isinstance(families, list) else 0
    families_with_healing = 0
    total_heals_call_sites = 0
    family_names: set[str] = set()
    for index, family in enumerate(families if isinstance(families, list) else []):
        if not isinstance(family, dict):
            error(f"matrix families[{index}] must be object")
            continue
        name = family.get("family")
        module = family.get("module")
        if not isinstance(name, str) or not name:
            error(f"matrix families[{index}] missing family name")
        elif name in family_names:
            error(f"matrix duplicate family: {name}")
        else:
            family_names.add(name)
        if not isinstance(module, str) or not (ROOT / "crates/frankenlibc-abi/src" / f"{module}.rs").is_file():
            error(f"matrix family {name or index} references missing ABI module {module}")
        symbols = family.get("symbols")
        if not isinstance(symbols, list) or not symbols:
            error(f"matrix family {name or index} symbols must be non-empty")
        strict = family.get("strict_behavior")
        hardened = family.get("hardened_behavior")
        if not isinstance(strict, dict) or not strict:
            error(f"matrix family {name or index} strict_behavior must be non-empty object")
        if not isinstance(hardened, dict) or not hardened:
            error(f"matrix family {name or index} hardened_behavior must be non-empty object")
        if isinstance(strict, dict) and isinstance(hardened, dict):
            missing = set(strict.keys()) - set(hardened.keys())
            if missing:
                error(f"matrix family {name or index} hardened_behavior missing strict scenarios: {sorted(missing)}")
        heals = family.get("heals_call_sites")
        if not isinstance(heals, int) or heals < 0:
            error(f"matrix family {name or index} heals_call_sites must be non-negative int")
            heals = 0
        if heals > 0:
            families_with_healing += 1
        total_heals_call_sites += heals
    require(family_count == expectations.get("total_families"), "matrix total_families expectation drifted")
    require(summary.get("total_families") == family_count, "matrix summary total_families mismatch")
    require(families_with_healing == expectations.get("families_with_healing"), "matrix families_with_healing expectation drifted")
    require(summary.get("families_with_healing") == families_with_healing, "matrix summary families_with_healing mismatch")
    require(total_heals_call_sites == expectations.get("total_heals_call_sites"), "matrix total_heals_call_sites expectation drifted")
    require(summary.get("total_heals_call_sites") == total_heals_call_sites, "matrix summary total_heals_call_sites mismatch")
    append_event(
        "mode_semantics_matrix.matrix_expectations_validated",
        "pass" if not errors else "fail",
        {
            "family_count": family_count,
            "families_with_healing": families_with_healing,
            "total_heals_call_sites": total_heals_call_sites,
        },
    )


def run_base_gate() -> None:
    gate = ROOT / "scripts/check_mode_semantics.sh"
    proc = subprocess.run(
        ["bash", str(gate)],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0 or "check_mode_semantics: PASS" not in proc.stdout:
        error(
            "base mode semantics gate failed: "
            f"status={proc.returncode} stdout={proc.stdout[-1000:]} stderr={proc.stderr[-1000:]}"
        )


def validate_contract(contract: dict[str, Any]) -> None:
    global implementation_ref_count, test_binding_count, binding_count
    require(contract.get("schema_version") == SCHEMA, "schema_version drifted")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead drifted")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead drifted")
    audit = contract.get("audit_reference", {})
    require(isinstance(audit, dict), "audit_reference must be object")
    require(audit.get("score_before") == 470, "audit_reference.score_before drifted")
    require(audit.get("score_threshold") == 800, "audit_reference.score_threshold must be 800")
    evidence = contract.get("completion_debt_evidence", {})
    require(isinstance(evidence, dict), "completion_debt_evidence must be object")
    missing_items = set(string_array(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
    if missing_items != EXPECTED_MISSING:
        error(f"missing_items_closed drifted: {sorted(missing_items)}")
    refs = string_array(contract.get("implementation_refs"), "implementation_refs")
    implementation_ref_count = len(refs)
    for index, reference in enumerate(refs):
        validate_file_line_ref(reference, f"implementation_refs[{index}]")
    bindings = contract.get("completion_bindings")
    if not isinstance(bindings, list):
        error("completion_bindings must be array")
        return
    binding_count = len(bindings)
    seen_missing: set[str] = set()
    tests: set[str] = set()
    commands: set[str] = set()
    events_required: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            error(f"completion_bindings[{index}] must be object")
            continue
        missing_item = binding.get("missing_item_id")
        if not isinstance(missing_item, str) or not missing_item:
            error(f"completion_bindings[{index}].missing_item_id must be non-empty string")
        else:
            seen_missing.add(missing_item)
        for row in binding.get("required_test_refs", []):
            if isinstance(row, dict) and isinstance(row.get("name"), str):
                tests.add(row["name"])
        commands.update(string_array(binding.get("required_commands"), f"completion_bindings[{index}].required_commands"))
        events_required.update(string_array(binding.get("required_completion_events"), f"completion_bindings[{index}].required_completion_events"))
        event_name = {
            "tests.unit.primary": "mode_semantics_matrix.unit_binding_validated",
            "tests.e2e.primary": "mode_semantics_matrix.e2e_binding_validated",
            "telemetry.primary": "mode_semantics_matrix.telemetry_binding_validated",
        }.get(str(missing_item))
        if event_name:
            append_event(event_name, "pass" if not errors else "fail", {"missing_item_id": missing_item})
    test_binding_count = len(tests)
    if seen_missing != EXPECTED_MISSING:
        error(f"completion_bindings missing items drifted: {sorted(seen_missing)}")
    if not REQUIRED_TESTS.issubset(tests):
        error(f"completion_bindings required_test_refs missing {sorted(REQUIRED_TESTS - tests)}")
    if not REQUIRED_COMMANDS.issubset(commands):
        error(f"completion_bindings required_commands missing {sorted(REQUIRED_COMMANDS - commands)}")
    if not REQUIRED_EVENTS.issubset(events_required):
        error(f"completion_bindings required_completion_events missing {sorted(REQUIRED_EVENTS - events_required)}")


def write_outputs(contract: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    event = (
        "mode_semantics_matrix.completion_contract_failed"
        if errors
        else "mode_semantics_matrix.completion_contract_validated"
    )
    append_event(event, status, {"error_count": len(errors)})
    evidence = contract.get("completion_debt_evidence", {}) if isinstance(contract, dict) else {}
    report = {
        "schema_version": REPORT_SCHEMA,
        "timestamp": utc_now(),
        "event": event,
        "status": status,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": SOURCE_COMMIT,
        "missing_items_bound": sorted(evidence.get("missing_items_closed", []))
        if isinstance(evidence, dict)
        else [],
        "source_count": source_count,
        "implementation_ref_count": implementation_ref_count,
        "test_binding_count": test_binding_count,
        "binding_count": binding_count,
        "family_count": family_count,
        "total_heals_call_sites": total_heals_call_sites,
        "artifact_refs": [rel(CONTRACT), rel(LOG)],
        "failure_signature": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in events) + "\n", encoding="utf-8")


contract_data = load_json(CONTRACT, "completion contract")
if not isinstance(contract_data, dict):
    contract_data = {}
validate_sources(contract_data)
validate_matrix_expectations(contract_data)
run_base_gate()
validate_contract(contract_data)
write_outputs(contract_data)

if errors:
    print("FAIL mode semantics matrix completion contract")
    for item in errors:
        print(f"- {item}")
    sys.exit(1)

print(
    "PASS mode semantics matrix completion contract "
    f"sources={source_count} bindings={binding_count} families={family_count} events={len(events)}"
)
PY
