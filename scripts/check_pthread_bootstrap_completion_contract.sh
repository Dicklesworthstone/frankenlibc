#!/usr/bin/env bash
# Validate bd-yos.1 pthread bootstrap completion-contract evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${1:-${ROOT}/tests/conformance/pthread_bootstrap_completion_contract.v1.json}"
OUT_DIR="${2:-${ROOT}/target/conformance}"
REPORT="${OUT_DIR}/pthread_bootstrap_completion_contract.report.json"
LOG="${OUT_DIR}/pthread_bootstrap_completion_contract.log.jsonl"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()

EXPECTED_SCHEMA = "pthread_bootstrap_completion_contract.v1"
EXPECTED_MANIFEST = "bd-yos.1-pthread-bootstrap-completion-contract"
EXPECTED_BEAD = "bd-yos"
EXPECTED_COMPLETION_BEAD = "bd-yos.1"
EXPECTED_SOURCE_KEYS = {
    "pthread_abi",
    "abi_lifecycle_test",
    "harness_conformance_test",
    "pthread_fixture",
    "stress_scenarios",
    "stress_gate",
    "stress_artifacts_test",
    "nochange_proof",
    "completion_checker",
    "completion_test",
}
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
EXPECTED_SYMBOLS = {"pthread_create", "pthread_join", "pthread_detach"}
EXPECTED_BEHAVIORS = {
    "create_join_return_value",
    "detach_consumes_handle",
    "join_consumes_handle",
    "self_join_edeadlk",
    "unknown_thread_esrch",
    "fixture_create_join_detach_distribution",
    "strict_hardened_stress_artifact",
    "host_thread_handoff_tid_publication",
}
EXPECTED_STRESS_SCENARIOS = {
    "fanout_fanin_single",
    "create_join_churn",
    "mixed_detach_join",
    "c_fixture_pthread_common_adversarial",
}
EXPECTED_STRESS_MODES = {"strict", "hardened"}
EXPECTED_TELEMETRY_EVENTS = {
    "pthread_bootstrap.source_artifacts_validated",
    "pthread_bootstrap.implementation_refs_validated",
    "pthread_bootstrap.test_refs_validated",
    "pthread_bootstrap.stress_catalog_validated",
    "pthread_bootstrap.completion_contract_validated",
    "pthread_bootstrap.completion_contract_failed",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "required_symbols",
    "required_behaviors",
    "test_refs",
    "stress_scenarios",
    "artifact_refs",
    "failure_signature",
}
EXPECTED_UNIT_REFS = {
    ("abi_lifecycle_test", "pthread_create_join_roundtrip_uses_default_host_routing"),
    ("abi_lifecycle_test", "pthread_join_and_detach_unknown_thread_are_esrch"),
    ("abi_lifecycle_test", "pthread_detach_makes_subsequent_join_fail_with_esrch"),
    ("abi_lifecycle_test", "pthread_join_then_reuse_handle_is_esrch"),
    ("abi_lifecycle_test", "pthread_self_join_is_rejected_with_edeadlk"),
}
EXPECTED_E2E_REFS = {
    ("harness_conformance_test", "pthread_thread_covers_create"),
    ("harness_conformance_test", "pthread_thread_covers_join"),
    ("harness_conformance_test", "pthread_thread_covers_detach"),
    ("harness_conformance_test", "pthread_thread_function_distribution"),
    ("harness_conformance_test", "pthread_thread_error_codes_valid"),
    ("stress_artifacts_test", "thread_stress_gate_emits_valid_bd1f35_artifacts"),
}
EXPECTED_TELEMETRY_REFS = {
    ("completion_test", "checker_validates_contract_and_emits_report_log"),
    ("completion_test", "checker_rejects_missing_required_symbol"),
    ("completion_test", "checker_rejects_missing_unit_ref"),
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, context: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{context} JSON load failed: {exc}")
        return {}


def read_text(path: pathlib.Path, context: str) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} read failed: {exc}")
        return ""


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        err(f"{context} must be a non-empty string array")
        return []
    return list(value)


def artifact_path(value: Any, context: str) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty path")
        return None
    path = (ROOT / value).resolve()
    if path != ROOT and ROOT not in path.parents:
        err(f"{context} escapes workspace: {value}")
        return None
    if not path.is_file():
        err(f"{context} missing file: {value}")
        return None
    return path


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events.append(
        {
            "schema_version": "pthread_bootstrap_completion_contract.log.v1",
            "timestamp": now,
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
            "bead_id": EXPECTED_BEAD,
            "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
            "original_bead": EXPECTED_BEAD,
            "status": status,
            "source_commit": git_head(),
            "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS),
            "required_symbols": sorted(EXPECTED_SYMBOLS),
            "required_behaviors": sorted(EXPECTED_BEHAVIORS),
            "test_refs": details.get("test_refs", []),
            "stress_scenarios": details.get("stress_scenarios", []),
            "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
            "failure_signature": "none" if status == "pass" else "pthread_bootstrap_completion_contract_failed",
            "details": details,
        }
    )


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be file:line")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} has invalid line: {value}")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} missing file: {value}")
        return
    line_no = int(line_text)
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no > len(lines):
        err(f"{context} line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        err(f"{context} points to blank line: {value}")


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = manifest.get("source_artifacts")
    if not isinstance(source_artifacts, dict):
        err("source_artifacts must be an object")
        source_artifacts = {}
    missing = EXPECTED_SOURCE_KEYS - set(source_artifacts)
    extra = set(source_artifacts) - EXPECTED_SOURCE_KEYS
    require(not missing, f"source_artifacts missing keys: {sorted(missing)}")
    require(not extra, f"source_artifacts unexpected keys: {sorted(extra)}")
    paths: dict[str, pathlib.Path] = {}
    for key in sorted(EXPECTED_SOURCE_KEYS):
        path = artifact_path(source_artifacts.get(key), f"source_artifacts.{key}")
        if path is not None:
            paths[key] = path
    append_event(
        "pthread_bootstrap.source_artifacts_validated",
        "fail" if missing or extra else "pass",
        {"artifact_count": len(paths), "keys": sorted(paths)},
    )
    return paths


def validate_manifest_shape(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead mismatch")
    require(manifest.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead mismatch")

    completion = manifest.get("completion_debt", {})
    if not isinstance(completion, dict):
        err("completion_debt must be an object")
        completion = {}
    require(completion.get("original_bead") == EXPECTED_BEAD, "completion_debt.original_bead mismatch")
    require(
        set(string_list(completion.get("missing_items_closed"), "completion_debt.missing_items_closed"))
        == EXPECTED_MISSING_ITEMS,
        "completion_debt.missing_items_closed mismatch",
    )
    threshold = completion.get("next_audit_score_threshold")
    require(isinstance(threshold, int) and 800 <= threshold <= 1000, "next_audit_score_threshold must be 800..1000")

    surface = manifest.get("pthread_bootstrap_surface", {})
    if not isinstance(surface, dict):
        err("pthread_bootstrap_surface must be an object")
        surface = {}
    symbols = set(string_list(surface.get("required_symbols"), "pthread_bootstrap_surface.required_symbols"))
    behaviors = set(string_list(surface.get("required_behaviors"), "pthread_bootstrap_surface.required_behaviors"))
    require(symbols == EXPECTED_SYMBOLS, f"required_symbols mismatch: {sorted(symbols)}")
    require(behaviors == EXPECTED_BEHAVIORS, f"required_behaviors mismatch: {sorted(behaviors)}")

    stress = surface.get("stress_support", {})
    if not isinstance(stress, dict):
        err("pthread_bootstrap_surface.stress_support must be an object")
        stress = {}
    require(stress.get("artifact") == "stress_scenarios", "stress_support.artifact mismatch")
    require(stress.get("source_bead") == "bd-1f35", "stress_support.source_bead mismatch")
    require(
        set(string_list(stress.get("required_scenarios"), "stress_support.required_scenarios"))
        == EXPECTED_STRESS_SCENARIOS,
        "stress_support.required_scenarios mismatch",
    )
    require(
        set(string_list(stress.get("required_modes"), "stress_support.required_modes"))
        == EXPECTED_STRESS_MODES,
        "stress_support.required_modes mismatch",
    )


def validate_implementation_refs(evidence: dict[str, Any]) -> list[str]:
    refs = evidence.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 9:
        err("completion_debt_evidence.implementation_refs must contain at least 9 refs")
        return []
    out: list[str] = []
    for index, ref in enumerate(refs):
        validate_file_line_ref(ref, f"implementation_refs[{index}]")
        if isinstance(ref, str):
            out.append(ref)
    append_event(
        "pthread_bootstrap.implementation_refs_validated",
        "pass",
        {"implementation_ref_count": len(out)},
    )
    return out


def validate_ref_section(
    section: dict[str, Any],
    section_name: str,
    expected_missing_item: str,
    expected_refs: set[tuple[str, str]],
    sources: dict[str, pathlib.Path],
) -> list[dict[str, str]]:
    require(section.get("missing_item_id") == expected_missing_item, f"{section_name}.missing_item_id mismatch")
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"{section_name}.required_test_refs must be non-empty")
        refs = []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"{section_name}.required_test_refs[{index}] must be an object")
            continue
        artifact = ref.get("artifact")
        name = ref.get("name")
        if not isinstance(artifact, str) or artifact not in sources:
            err(f"{section_name}.required_test_refs[{index}].artifact is unknown: {artifact}")
            continue
        if not isinstance(name, str) or not name:
            err(f"{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        key = (artifact, name)
        if key in seen:
            err(f"{section_name} duplicate test ref {artifact}::{name}")
        seen.add(key)
        text = read_text(sources[artifact], f"{artifact}")
        if f"fn {name}" not in text:
            err(f"{section_name} missing test function {artifact}::{name}")
        normalized.append({"artifact": artifact, "name": name})
    missing = expected_refs - seen
    require(not missing, f"{section_name} missing required refs: {sorted(missing)}")

    commands = section.get("required_commands", [])
    if section_name != "telemetry_primary":
        for command in string_list(commands, f"{section_name}.required_commands"):
            if "cargo " in command:
                require(command.startswith("rch exec --"), f"{section_name} has non-rch cargo command: {command}")
    return normalized


def validate_stress_catalog(sources: dict[str, pathlib.Path]) -> list[str]:
    path = sources.get("stress_scenarios")
    if path is None:
        return []
    catalog = load_json(path, "stress_scenarios")
    scenarios = {
        item.get("id")
        for item in catalog.get("scenarios", [])
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
    require(EXPECTED_STRESS_SCENARIOS.issubset(scenarios), f"stress catalog missing scenarios: {sorted(EXPECTED_STRESS_SCENARIOS - scenarios)}")
    summary = catalog.get("summary", {})
    if isinstance(summary, dict):
        require(summary.get("mode_count") == 2, "stress catalog summary.mode_count must be 2")
        require(summary.get("scenario_count") >= 4, "stress catalog summary.scenario_count must be >= 4")
    else:
        err("stress catalog summary must be an object")
    append_event(
        "pthread_bootstrap.stress_catalog_validated",
        "pass",
        {"stress_scenarios": sorted(scenarios)},
    )
    return sorted(scenarios)


manifest = load_json(CONTRACT, "contract")
if not isinstance(manifest, dict):
    manifest = {}
    err("contract root must be an object")

validate_manifest_shape(manifest)
sources = validate_source_artifacts(manifest)
evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    evidence = {}
    err("completion_debt_evidence must be an object")

implementation_refs = validate_implementation_refs(evidence)
unit_refs = validate_ref_section(
    evidence.get("unit_primary", {}) if isinstance(evidence.get("unit_primary"), dict) else {},
    "unit_primary",
    "tests.unit.primary",
    EXPECTED_UNIT_REFS,
    sources,
)
e2e_refs = validate_ref_section(
    evidence.get("e2e_primary", {}) if isinstance(evidence.get("e2e_primary"), dict) else {},
    "e2e_primary",
    "tests.e2e.primary",
    EXPECTED_E2E_REFS,
    sources,
)
telemetry = evidence.get("telemetry_primary", {}) if isinstance(evidence.get("telemetry_primary"), dict) else {}
telemetry_refs = validate_ref_section(
    telemetry,
    "telemetry_primary",
    "telemetry.primary",
    EXPECTED_TELEMETRY_REFS,
    sources,
)

required_events = set(string_list(telemetry.get("required_events"), "telemetry_primary.required_events")) if isinstance(telemetry, dict) else set()
required_fields = set(string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields")) if isinstance(telemetry, dict) else set()
require(required_events == EXPECTED_TELEMETRY_EVENTS, f"telemetry events mismatch: {sorted(required_events)}")
require(required_fields == EXPECTED_TELEMETRY_FIELDS, f"telemetry fields mismatch: {sorted(required_fields)}")
require(
    telemetry.get("default_report_path") == "target/conformance/pthread_bootstrap_completion_contract.report.json",
    "telemetry_primary.default_report_path mismatch",
)
require(
    telemetry.get("default_log_path") == "target/conformance/pthread_bootstrap_completion_contract.log.jsonl",
    "telemetry_primary.default_log_path mismatch",
)

all_refs = unit_refs + e2e_refs + telemetry_refs
append_event(
    "pthread_bootstrap.test_refs_validated",
    "pass",
    {"test_refs": all_refs, "unit_count": len(unit_refs), "e2e_count": len(e2e_refs), "telemetry_count": len(telemetry_refs)},
)
stress_scenarios = validate_stress_catalog(sources)

status = "fail" if errors else "pass"
append_event(
    "pthread_bootstrap.completion_contract_validated" if status == "pass" else "pthread_bootstrap.completion_contract_failed",
    status,
    {"error_count": len(errors), "test_refs": all_refs, "stress_scenarios": stress_scenarios},
)

report = {
    "schema_version": "pthread_bootstrap_completion_contract.report.v1",
    "status": status,
    "bead_id": EXPECTED_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "original_bead": EXPECTED_BEAD,
    "source_commit": git_head(),
    "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS),
    "required_symbols": sorted(EXPECTED_SYMBOLS),
    "required_behaviors": sorted(EXPECTED_BEHAVIORS),
    "source_artifacts": {key: rel(path) for key, path in sorted(sources.items())},
    "implementation_refs": implementation_refs,
    "unit_refs": unit_refs,
    "e2e_refs": e2e_refs,
    "telemetry_refs": telemetry_refs,
    "stress_scenarios": stress_scenarios,
    "required_events": sorted(required_events),
    "required_fields": sorted(required_fields),
    "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")

if errors:
    print("FAIL pthread bootstrap completion contract")
    for message in errors:
        print(f"- {message}")
    raise SystemExit(1)

print(
    "PASS pthread bootstrap completion contract "
    f"sources={len(sources)} unit_refs={len(unit_refs)} e2e_refs={len(e2e_refs)} "
    f"telemetry_refs={len(telemetry_refs)} stress_scenarios={len(stress_scenarios)} events={len(events)}"
)
PY
