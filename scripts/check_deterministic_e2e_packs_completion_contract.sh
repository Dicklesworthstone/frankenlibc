#!/usr/bin/env bash
# check_deterministic_e2e_packs_completion_contract.sh - bd-w2c3.9.2.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_DETERMINISTIC_E2E_PACKS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/deterministic_e2e_packs_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_DETERMINISTIC_E2E_PACKS_COMPLETION_OUT_DIR:-$ROOT/target/conformance/deterministic_e2e_packs_completion_contract}"
REPORT="${FRANKENLIBC_DETERMINISTIC_E2E_PACKS_COMPLETION_REPORT:-$OUT_DIR/deterministic_e2e_packs_completion_contract.report.json}"
LOG="${FRANKENLIBC_DETERMINISTIC_E2E_PACKS_COMPLETION_LOG:-$OUT_DIR/deterministic_e2e_packs_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "deterministic_e2e_packs_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "deterministic_e2e_packs_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.9.2"
COMPLETION_BEAD = "bd-w2c3.9.2.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
}
EXPECTED_EVENTS = {
    "deterministic_e2e_unit_bound",
    "deterministic_e2e_pack_bound",
    "deterministic_e2e_replay_bound",
    "deterministic_e2e_conformance_bound",
    "deterministic_e2e_security_bound",
    "deterministic_e2e_completion_contract_validated",
}
EVENT_BY_MISSING_ITEM = {
    "tests.unit.primary": "deterministic_e2e_unit_bound",
    "tests.e2e.primary": "deterministic_e2e_pack_bound",
    "tests.conformance.primary": "deterministic_e2e_conformance_bound",
}
REQUIRED_CLASSES = {"smoke", "stress", "fault", "stability"}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_COMPONENTS = {
    "replay_key_controller",
    "strict_hardened_pair_comparator",
    "checker_fail_closed_validation",
    "strict_hardened_runtime_evidence",
}
REQUIRED_DECISIONS = {"Allow", "FullValidate", "Repair", "Deny"}
REQUIRED_SECURITY_MARKERS = {
    "redacted_required_field",
    "decision_mismatch",
    "strict_hardened_e2e_real_network_required",
    "strict_hardened_e2e_destructive_operation",
    "strict_hardened_e2e_strict_repair_not_allowed",
}
FORBIDDEN_COMMAND_SUBSTRINGS = {
    "git reset --hard",
    "git clean -fd",
    "rm -rf",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def strings(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def repo_path(value: Any, context: str, *, must_be_file: bool = False) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {value}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


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


def read_text(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


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


def collect_strings(value: Any) -> set[str]:
    found: set[str] = set()
    if isinstance(value, str):
        found.add(value)
    elif isinstance(value, list):
        for item in value:
            found.update(collect_strings(item))
    elif isinstance(value, dict):
        for key, item in value.items():
            found.add(str(key))
            found.update(collect_strings(item))
    return found


def function_exists(source_text: str, name: str) -> bool:
    return (
        f"fn {name}(" in source_text
        or f"fn {name}<" in source_text
        or f"def {name}(" in source_text
    )


def artifact_bead_value(artifact: dict[str, Any], key: str) -> str | None:
    value = artifact.get(key)
    if isinstance(value, str):
        return value
    evidence = artifact.get("completion_debt_evidence")
    if isinstance(evidence, dict) and isinstance(evidence.get(key), str):
        return evidence.get(key)
    if key == "bead" and isinstance(evidence, dict) and isinstance(evidence.get("original_bead"), str):
        return evidence.get("original_bead")
    return None


def validate_command(command: Any, context: str) -> None:
    if not isinstance(command, str) or not command:
        err(f"{context} command must be a non-empty string")
        return
    for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS:
        if forbidden in command:
            err(f"{context} command contains forbidden substring {forbidden!r}: {command}")
    if "cargo " in command and "rch exec" not in command:
        err(f"{context} cargo validation must be rch-backed: {command}")


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    raw = manifest.get("source_artifacts", {})
    if not isinstance(raw, dict) or not raw:
        err("source_artifacts must be a non-empty object")
        return {}
    artifacts: dict[str, str] = {}
    for key, value in raw.items():
        if repo_path(value, f"source_artifacts.{key}", must_be_file=True) is not None and isinstance(value, str):
            artifacts[str(key)] = value
    return artifacts


def validate_impl_refs(manifest: dict[str, Any]) -> int:
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 14:
        err("implementation_refs must include at least 14 concrete source anchors")
        return 0
    checked = 0
    cache: dict[str, list[str]] = {}
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        path = repo_path(path_text, f"implementation_refs[{index}].path", must_be_file=True)
        if path is None:
            continue
        if not isinstance(line, int) or line <= 0:
            err(f"implementation_refs[{index}].line must be a positive integer")
            continue
        if not isinstance(anchor, str) or not anchor:
            err(f"implementation_refs[{index}].anchor must be non-empty")
            continue
        lines = cache.setdefault(str(path), path.read_text(encoding="utf-8").splitlines())
        if line > len(lines):
            err(f"implementation_refs[{index}] line outside file: {path_text}:{line}")
            continue
        text = lines[line - 1]
        if not text.strip():
            err(f"implementation_refs[{index}] points at blank line: {path_text}:{line}")
            continue
        if anchor not in text:
            err(f"implementation_refs[{index}] missing anchor {anchor!r} at {path_text}:{line}")
            continue
        checked += 1
    return checked


def validate_test_refs(binding_id: str, refs: Any, artifacts: dict[str, str]) -> list[str]:
    if not isinstance(refs, list) or not refs:
        err(f"binding {binding_id} required_test_refs must be non-empty")
        return []
    cache: dict[str, str] = {}
    found: list[str] = []
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"binding {binding_id} required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or source not in artifacts:
            err(f"binding {binding_id} references unknown test source {source!r}")
            continue
        if not isinstance(name, str) or not name:
            err(f"binding {binding_id} test ref name must be non-empty")
            continue
        text = cache.setdefault(source, read_text(artifacts[source], f"test source {source}"))
        if not function_exists(text, name):
            err(f"binding {binding_id} references missing test {source}::{name}")
            continue
        found.append(f"{source}::{name}")
    return found


def validate_evidence_bindings(manifest: dict[str, Any], artifacts: dict[str, str]) -> tuple[dict[str, dict[str, Any]], int]:
    raw = manifest.get("evidence_bindings")
    if not isinstance(raw, list) or not raw:
        err("evidence_bindings must be a non-empty array")
        return {}, 0
    bindings: dict[str, dict[str, Any]] = {}
    test_ref_count = 0
    for index, binding in enumerate(raw):
        if not isinstance(binding, dict):
            err(f"evidence_bindings[{index}] must be an object")
            continue
        binding_id = binding.get("binding_id")
        if not isinstance(binding_id, str) or not binding_id:
            err(f"evidence_bindings[{index}].binding_id must be non-empty")
            continue
        if binding_id in bindings:
            err(f"duplicate evidence binding id: {binding_id}")
        artifact_key = binding.get("artifact_key")
        if not isinstance(artifact_key, str) or artifact_key not in artifacts:
            err(f"binding {binding_id} artifact_key must name a source artifact")
            continue
        artifact = load_json(ROOT / artifacts[artifact_key], f"binding {binding_id} artifact")
        identity_field = binding.get("identity_field")
        identity_value = binding.get("identity_value")
        require(
            isinstance(identity_field, str) and artifact.get(identity_field) == identity_value,
            f"binding {binding_id} identity mismatch",
        )
        expected_bead = binding.get("expected_bead")
        if isinstance(expected_bead, str):
            require(
                artifact_bead_value(artifact, "bead") == expected_bead,
                f"binding {binding_id} bead mismatch",
            )
        expected_completion = binding.get("expected_completion_debt_bead")
        if isinstance(expected_completion, str):
            require(
                artifact_bead_value(artifact, "completion_debt_bead") == expected_completion,
                f"binding {binding_id} completion debt bead mismatch",
            )
        covers = set(strings(binding.get("covers"), f"binding {binding_id}.covers"))
        require(bool(covers), f"binding {binding_id} must cover at least one missing item")
        require(covers <= EXPECTED_MISSING_ITEMS, f"binding {binding_id} covers unknown items {sorted(covers - EXPECTED_MISSING_ITEMS)}")
        for key in strings(binding.get("required_artifact_keys"), f"binding {binding_id}.required_artifact_keys"):
            require(key in artifacts, f"binding {binding_id} required artifact key not declared: {key}")
        test_ref_count += len(validate_test_refs(binding_id, binding.get("required_test_refs"), artifacts))
        for command_index, command in enumerate(strings(binding.get("required_commands"), f"binding {binding_id}.required_commands")):
            validate_command(command, f"binding {binding_id}.required_commands[{command_index}]")
        binding["_covers_set"] = covers
        bindings[binding_id] = binding
    return bindings, test_ref_count


def validate_completion_coverage(manifest: dict[str, Any], bindings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    raw = manifest.get("completion_coverage")
    if not isinstance(raw, list) or not raw:
        err("completion_coverage must be a non-empty array")
        return {"coverage_count": 0, "binding_count": 0}
    seen: set[str] = set()
    all_binding_ids: set[str] = set()
    for index, coverage in enumerate(raw):
        if not isinstance(coverage, dict):
            err(f"completion_coverage[{index}] must be an object")
            continue
        missing_item = coverage.get("missing_item_id")
        if not isinstance(missing_item, str):
            err(f"completion_coverage[{index}].missing_item_id must be a string")
            continue
        seen.add(missing_item)
        require(coverage.get("status") == "covered", f"{missing_item} status must be covered")
        binding_ids = strings(coverage.get("binding_ids"), f"coverage {missing_item}.binding_ids")
        if missing_item == "tests.conformance.primary":
            required = {"runtime_evidence_replay_gate", "strict_hardened_runtime_evidence_e2e"}
            require(
                required <= set(binding_ids),
                "tests.conformance.primary must be bound by runtime and strict/hardened evidence",
            )
        if missing_item == "tests.e2e.primary":
            require(
                "replay_pair_comparator" in binding_ids and "strict_hardened_runtime_evidence_e2e" in binding_ids,
                "tests.e2e.primary must include replay pair and strict/hardened bindings",
            )
        for binding_id in binding_ids:
            all_binding_ids.add(binding_id)
            binding = bindings.get(binding_id)
            if not isinstance(binding, dict):
                err(f"coverage {missing_item} references unknown binding {binding_id}")
                continue
            covers = binding.get("_covers_set", set())
            require(missing_item in covers, f"coverage {missing_item} references binding {binding_id} that does not cover it")
        for command_index, command in enumerate(strings(coverage.get("validation_commands"), f"coverage {missing_item}.validation_commands")):
            validate_command(command, f"coverage {missing_item}.validation_commands[{command_index}]")
    require(seen == EXPECTED_MISSING_ITEMS, f"completion_coverage must cover {sorted(EXPECTED_MISSING_ITEMS)}")
    return {"coverage_count": len(raw), "binding_count": len(all_binding_ids)}


def validate_pack_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("deterministic_pack_contract")
    if not isinstance(contract, dict):
        err("deterministic_pack_contract must be an object")
        return {}
    classes = set(strings(contract.get("required_manifest_classes"), "deterministic_pack_contract.required_manifest_classes"))
    modes = set(strings(contract.get("required_modes"), "deterministic_pack_contract.required_modes"))
    components = set(strings(contract.get("required_replay_components"), "deterministic_pack_contract.required_replay_components"))
    decisions = set(strings(contract.get("required_runtime_decisions"), "deterministic_pack_contract.required_runtime_decisions"))
    security_markers = set(strings(contract.get("security_evidence_markers"), "deterministic_pack_contract.security_evidence_markers"))
    require(classes == REQUIRED_CLASSES, f"deterministic_pack_contract.required_manifest_classes mismatch: {sorted(classes)}")
    require(modes == REQUIRED_MODES, f"deterministic_pack_contract.required_modes mismatch: {sorted(modes)}")
    require(components == REQUIRED_COMPONENTS, f"deterministic_pack_contract.required_replay_components mismatch: {sorted(components)}")
    require(decisions == REQUIRED_DECISIONS, f"deterministic_pack_contract.required_runtime_decisions mismatch: {sorted(decisions)}")
    require(REQUIRED_SECURITY_MARKERS <= security_markers, f"security markers missing {sorted(REQUIRED_SECURITY_MARKERS - security_markers)}")

    manifest_path = ROOT / artifacts.get("e2e_manifest", "")
    e2e_manifest = load_json(manifest_path, "e2e scenario manifest")
    scenarios = e2e_manifest.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        err("e2e scenario manifest scenarios must be non-empty")
        scenarios = []
    class_counts = {klass: 0 for klass in REQUIRED_CLASSES}
    seed_key = contract.get("required_replay_seed_key")
    required_env = set(strings(contract.get("required_replay_env_keys"), "deterministic_pack_contract.required_replay_env_keys"))
    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            err(f"e2e scenario manifest scenarios[{index}] must be an object")
            continue
        klass = scenario.get("class")
        if isinstance(klass, str) and klass in class_counts:
            class_counts[klass] += 1
        expectations = scenario.get("mode_expectations")
        if isinstance(expectations, dict):
            require(REQUIRED_MODES <= set(expectations), f"scenario {scenario.get('id')} missing strict/hardened mode expectations")
        else:
            err(f"scenario {scenario.get('id')} mode_expectations must be an object")
        replay = scenario.get("replay")
        if isinstance(replay, dict):
            require(replay.get("seed_key") == seed_key, f"scenario {scenario.get('id')} replay seed_key mismatch")
            env_keys = set(strings(replay.get("env_keys"), f"scenario {scenario.get('id')}.replay.env_keys"))
            require(required_env <= env_keys, f"scenario {scenario.get('id')} replay env keys missing {sorted(required_env - env_keys)}")
            require(isinstance(replay.get("deterministic_inputs"), str) and replay.get("deterministic_inputs"), f"scenario {scenario.get('id')} deterministic_inputs missing")
        else:
            err(f"scenario {scenario.get('id')} replay must be an object")
    minimums = contract.get("class_minimums")
    if not isinstance(minimums, dict):
        err("deterministic_pack_contract.class_minimums must be an object")
        minimums = {}
    for klass in REQUIRED_CLASSES:
        minimum = minimums.get(klass)
        require(isinstance(minimum, int) and class_counts.get(klass, 0) >= minimum, f"class {klass} below minimum {minimum}: {class_counts.get(klass, 0)}")

    replay_contract = load_json(ROOT / artifacts.get("replay_pair_contract", ""), "replay pair contract")
    source_contract = replay_contract.get("source_contract")
    component_rows = source_contract.get("components") if isinstance(source_contract, dict) else None
    if isinstance(component_rows, list):
        component_names = {
            str(item.get("name"))
            for item in component_rows
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
    else:
        err("replay pair source_contract.components must be an array")
        component_names = set()
    require(REQUIRED_COMPONENTS <= component_names, f"replay pair components missing {sorted(REQUIRED_COMPONENTS - component_names)}")

    runtime_gate = load_json(ROOT / artifacts.get("runtime_replay_gate", ""), "runtime replay gate")
    claim_policy = runtime_gate.get("claim_policy")
    if not isinstance(claim_policy, dict):
        err("runtime replay gate claim_policy must be an object")
        claim_policy = {}
    runtime_decisions = set(strings(claim_policy.get("required_decisions"), "runtime replay required_decisions"))
    runtime_modes = set(strings(claim_policy.get("required_modes"), "runtime replay required_modes"))
    require(runtime_decisions == REQUIRED_DECISIONS, f"runtime replay decisions mismatch: {sorted(runtime_decisions)}")
    require(runtime_modes == REQUIRED_MODES, f"runtime replay modes mismatch: {sorted(runtime_modes)}")
    runtime_strings = collect_strings(runtime_gate)
    require({"redacted_required_field", "decision_mismatch"} <= runtime_strings, "runtime replay security negative cases missing")
    replay_records = runtime_gate.get("replay_records")
    if not isinstance(replay_records, list) or len(replay_records) < len(REQUIRED_DECISIONS):
        err("runtime replay records must cover all required decisions")
    else:
        record_decisions = {str(record.get("expected_decision")) for record in replay_records if isinstance(record, dict)}
        record_modes = {str(record.get("runtime_mode")) for record in replay_records if isinstance(record, dict)}
        require(REQUIRED_DECISIONS <= record_decisions, f"runtime replay record decisions missing {sorted(REQUIRED_DECISIONS - record_decisions)}")
        require(REQUIRED_MODES <= record_modes, f"runtime replay record modes missing {sorted(REQUIRED_MODES - record_modes)}")

    strict_gate = load_json(ROOT / artifacts.get("strict_hardened_gate", ""), "strict/hardened gate")
    strict_modes = set(strings(strict_gate.get("required_modes"), "strict_hardened_gate.required_modes"))
    require(strict_modes == REQUIRED_MODES, f"strict/hardened modes mismatch: {sorted(strict_modes)}")
    strict_strings = collect_strings(strict_gate)
    require(REQUIRED_SECURITY_MARKERS <= strict_strings | runtime_strings, f"security markers missing from gates {sorted(REQUIRED_SECURITY_MARKERS - (strict_strings | runtime_strings))}")
    operation_safety = strict_gate.get("operation_safety")
    if isinstance(operation_safety, dict):
        require(operation_safety.get("destructive_system_operation") is False, "strict/hardened top-level operation_safety must forbid destructive operations")
    else:
        err("strict/hardened gate operation_safety must be an object")
    strict_scenarios = strict_gate.get("scenarios")
    if isinstance(strict_scenarios, list):
        scenario_modes = {str(row.get("runtime_mode")) for row in strict_scenarios if isinstance(row, dict)}
        require(REQUIRED_MODES <= scenario_modes, f"strict/hardened scenarios missing modes {sorted(REQUIRED_MODES - scenario_modes)}")
        for row in strict_scenarios:
            if not isinstance(row, dict):
                continue
            safety = row.get("operation_safety")
            if isinstance(safety, dict):
                require(safety.get("real_network_required") is False, f"scenario {row.get('scenario_id')} requires real network")
                require(safety.get("destructive_system_operation") is False, f"scenario {row.get('scenario_id')} requires destructive operation")
    else:
        err("strict/hardened gate scenarios must be an array")

    return {
        "class_counts": class_counts,
        "manifest_class_count": len(classes),
        "replay_component_count": len(component_names),
        "runtime_decision_count": len(runtime_decisions),
        "security_marker_count": len(security_markers),
        "classes": sorted(classes),
        "components": sorted(components),
        "modes": sorted(modes),
        "decisions": sorted(decisions),
        "security_markers": sorted(security_markers),
    }


def validate_telemetry_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return {"required_events": 0, "required_fields": 0, "fields": []}
    require(telemetry.get("report_schema") == EXPECTED_REPORT_SCHEMA, "telemetry_contract.report_schema mismatch")
    required_events = set(strings(telemetry.get("required_events"), "telemetry_contract.required_events"))
    require(required_events == EXPECTED_EVENTS, f"telemetry events must be {sorted(EXPECTED_EVENTS)}")
    required_fields = set(strings(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    required_core = {
        "timestamp",
        "trace_id",
        "event",
        "status",
        "artifact_refs",
        "failure_signature",
        "scenario_classes",
        "replay_components",
        "runtime_modes",
        "runtime_decisions",
        "security_markers",
    }
    require(required_core <= required_fields, f"telemetry required fields missing {sorted(required_core - required_fields)}")
    return {"required_events": len(required_events), "required_fields": len(required_fields), "fields": sorted(required_fields)}


def append_event(
    event: str,
    missing_items: list[str],
    binding_ids: list[str],
    artifact_refs: list[str],
    validation_commands: list[str],
    pack_summary: dict[str, Any],
    status: str = "pass",
) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}::deterministic-e2e-packs::{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "evidence_binding_ids": binding_ids,
            "missing_item_ids": missing_items,
            "artifact_refs": artifact_refs,
            "validation_commands": validation_commands,
            "source_commit": git_head(),
            "scenario_classes": pack_summary.get("classes", []),
            "replay_components": pack_summary.get("components", []),
            "runtime_modes": pack_summary.get("modes", []),
            "runtime_decisions": pack_summary.get("decisions", []),
            "security_markers": pack_summary.get("security_markers", []),
            "failure_signature": "none" if status == "pass" else "deterministic_e2e_packs_completion_contract_failed",
        }
    )


def emit_success_events(manifest: dict[str, Any], artifacts: dict[str, str], pack_summary: dict[str, Any]) -> None:
    for coverage in manifest.get("completion_coverage", []):
        if not isinstance(coverage, dict):
            continue
        missing_item = coverage.get("missing_item_id")
        event = EVENT_BY_MISSING_ITEM.get(str(missing_item))
        if event is None:
            continue
        binding_ids = [str(item) for item in coverage.get("binding_ids", []) if isinstance(item, str)]
        artifact_refs = []
        for binding in manifest.get("evidence_bindings", []):
            if isinstance(binding, dict) and binding.get("binding_id") in binding_ids:
                key = binding.get("artifact_key")
                if isinstance(key, str) and key in artifacts:
                    artifact_refs.append(artifacts[key])
        append_event(
            event,
            [str(missing_item)],
            binding_ids,
            sorted(set(artifact_refs)),
            [str(item) for item in coverage.get("validation_commands", []) if isinstance(item, str)],
            pack_summary,
        )
    append_event(
        "deterministic_e2e_replay_bound",
        ["tests.unit.primary", "tests.e2e.primary"],
        ["replay_pair_comparator", "runtime_evidence_replay_gate"],
        [artifacts[key] for key in ("replay_pair_contract", "runtime_replay_gate") if key in artifacts],
        ["bash scripts/check_replay_engine_pair_comparator_completion_contract.sh", "bash scripts/check_runtime_evidence_replay_gate.sh"],
        pack_summary,
    )
    append_event(
        "deterministic_e2e_security_bound",
        ["tests.e2e.primary", "tests.conformance.primary"],
        ["runtime_evidence_replay_gate", "strict_hardened_runtime_evidence_e2e"],
        [artifacts[key] for key in ("runtime_replay_gate", "strict_hardened_gate") if key in artifacts],
        ["bash scripts/check_runtime_evidence_replay_gate.sh", "bash scripts/check_strict_hardened_evidence_e2e.sh"],
        pack_summary,
    )
    append_event(
        "deterministic_e2e_completion_contract_validated",
        sorted(EXPECTED_MISSING_ITEMS),
        sorted(
            str(binding.get("binding_id"))
            for binding in manifest.get("evidence_bindings", [])
            if isinstance(binding, dict) and isinstance(binding.get("binding_id"), str)
        ),
        sorted(artifacts.values()),
        ["bash scripts/check_deterministic_e2e_packs_completion_contract.sh"],
        pack_summary,
    )


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
audit = manifest.get("audit", {})
if not isinstance(audit, dict):
    err("audit must be an object")
    audit = {}
require(set(strings(audit.get("missing_items"), "audit.missing_items")) == EXPECTED_MISSING_ITEMS, "audit.missing_items mismatch")
require(int(audit.get("next_audit_score_threshold", 0)) >= 800, "audit.next_audit_score_threshold must be >= 800")

artifacts = validate_source_artifacts(manifest)
impl_ref_count = validate_impl_refs(manifest)
bindings, test_ref_count = validate_evidence_bindings(manifest, artifacts)
coverage_summary = validate_completion_coverage(manifest, bindings)
pack_summary = validate_pack_contract(manifest, artifacts)
telemetry_summary = validate_telemetry_contract(manifest)

if not errors:
    emit_success_events(manifest, artifacts, pack_summary)

required_fields = set(telemetry_summary.get("fields", []))
for row in events:
    missing = required_fields - set(row)
    if missing:
        err(f"generated telemetry row {row.get('event')} missing fields {sorted(missing)}")
emitted_events = {str(row.get("event")) for row in events}
if not errors:
    require(emitted_events == EXPECTED_EVENTS, f"generated telemetry events mismatch: {sorted(emitted_events)}")

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": "fail" if errors else "pass",
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "artifact_count": len(artifacts),
        "binding_count": len(bindings),
        "implementation_ref_count": impl_ref_count,
        "coverage_count": coverage_summary.get("coverage_count", 0),
        "test_ref_count": test_ref_count,
        "manifest_class_count": pack_summary.get("manifest_class_count", 0),
        "replay_component_count": pack_summary.get("replay_component_count", 0),
        "runtime_decision_count": pack_summary.get("runtime_decision_count", 0),
        "security_marker_count": pack_summary.get("security_marker_count", 0),
        "required_event_count": telemetry_summary.get("required_events", 0),
        "error_count": len(errors),
    },
    "coverage_summary": coverage_summary,
    "pack_summary": pack_summary,
    "errors": errors,
}

write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("deterministic_e2e_packs_completion_contract: FAIL")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "deterministic_e2e_packs_completion_contract: "
    f"PASS validated {len(bindings)} bindings, {impl_ref_count} refs, "
    f"{coverage_summary.get('coverage_count', 0)} coverage items"
)
PY
