#!/usr/bin/env bash
# check_strict_hardened_semantic_closure_completion_contract.sh - bd-w2c3.3.4 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_CONTRACT:-$ROOT/tests/conformance/strict_hardened_semantic_closure_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_OUT_DIR:-$ROOT/target/conformance/strict_hardened_semantic_closure_completion_contract}"
REPORT="${FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_REPORT:-$OUT_DIR/strict_hardened_semantic_closure_completion_contract.report.json}"
LOG="${FRANKENLIBC_STRICT_HARDENED_SEMANTIC_CLOSURE_LOG:-$OUT_DIR/strict_hardened_semantic_closure_completion_contract.log.jsonl}"
RUNTIME_MODE_REPORT="$OUT_DIR/runtime_mode_evidence_logging_coverage.report.json"
RUNTIME_MODE_LOG="$OUT_DIR/runtime_mode_evidence_logging_coverage.log.jsonl"
STRICT_E2E_REPORT="$OUT_DIR/strict_hardened_evidence_e2e.report.json"
STRICT_E2E_LOG="$OUT_DIR/strict_hardened_evidence_e2e.log.jsonl"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
RUNTIME_MODE_REPORT="$RUNTIME_MODE_REPORT" \
RUNTIME_MODE_LOG="$RUNTIME_MODE_LOG" \
STRICT_E2E_REPORT="$STRICT_E2E_REPORT" \
STRICT_E2E_LOG="$STRICT_E2E_LOG" \
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
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
RUNTIME_MODE_REPORT = pathlib.Path(os.environ["RUNTIME_MODE_REPORT"])
RUNTIME_MODE_LOG = pathlib.Path(os.environ["RUNTIME_MODE_LOG"])
STRICT_E2E_REPORT = pathlib.Path(os.environ["STRICT_E2E_REPORT"])
STRICT_E2E_LOG = pathlib.Path(os.environ["STRICT_E2E_LOG"])

EXPECTED_SCHEMA = "strict_hardened_semantic_closure_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "strict_hardened_semantic_closure_completion_contract.report.v1"
SOURCE_BEAD = "bd-w2c3.3"
COMPLETION_BEAD = "bd-w2c3.3.4"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
EXPECTED_EVENTS = [
    "strict_hardened_contract_validated",
    "strict_hardened_source_truth_validated",
    "strict_hardened_source_gates_replayed",
    "strict_hardened_completion_summary",
]

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_outputs: dict[str, dict[str, Any]] = {}


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return []
    rows: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label}:{index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label}:{index} must be a JSON object")
            continue
        rows.append(row)
    return rows


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


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


def text_for(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def strings(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
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


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "strict_hardened_completion_failed",
            "details": details,
        }
    )


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def run_gate(label: str, command: list[str], env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=merged,
        check=False,
    )
    source_gate_outputs[label] = {
        "command": " ".join(command),
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }
    if proc.returncode != 0:
        err(f"{label} failed with exit={proc.returncode}: stdout={proc.stdout[:1200]!r} stderr={proc.stderr[:1200]!r}")


def validate_impl_refs(manifest: dict[str, Any]) -> None:
    cache: dict[str, str] = {}
    refs = manifest.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 30:
        err("implementation_refs must include at least 30 concrete source anchors")
        return
    seen: set[str] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"implementation_refs[{index}] must be an object")
            continue
        kind = ref.get("kind")
        path_text = ref.get("path")
        line = ref.get("line")
        anchor = ref.get("anchor")
        if not isinstance(kind, str) or not kind:
            err(f"implementation_refs[{index}].kind must be a non-empty string")
        else:
            seen.add(kind)
        if not isinstance(path_text, str) or not path_text:
            err(f"implementation_refs[{index}].path must be a non-empty string")
            continue
        text = cache.setdefault(path_text, text_for(path_text, f"implementation_refs.{kind}"))
        lines = text.splitlines()
        if not isinstance(line, int) or line <= 0:
            err(f"{path_text} ref line must be a positive integer")
        elif line > len(lines) or not lines[line - 1].strip():
            err(f"{path_text}:{line} does not point to a non-empty line")
        if not isinstance(anchor, str) or not anchor:
            err(f"{path_text}:{line} missing anchor")
        elif anchor not in text:
            err(f"{path_text} missing anchor {anchor!r}")
    required_kinds = {
        "mode_semantics_schema",
        "hardened_matrix_summary",
        "mode_contract_env",
        "strict_hardened_e2e_scenarios",
        "runtime_mode_evidence_policy",
        "semantic_inventory_summary",
        "semantic_drift_gate",
        "strict_refinement_unit",
        "hardened_safety_unit",
    }
    missing = required_kinds - seen
    if missing:
        err(f"implementation_refs missing required kinds: {sorted(missing)}")


def validate_manifest(manifest: dict[str, Any]) -> dict[str, str]:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
    require(manifest.get("original_bead") == SOURCE_BEAD, f"original_bead must be {SOURCE_BEAD}")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
    audit = manifest.get("audit", {})
    if not isinstance(audit, dict):
        err("audit must be an object")
        audit = {}
    require(set(strings(audit.get("missing_items"), "audit.missing_items")) == EXPECTED_MISSING_ITEMS, "audit.missing_items must bind unit+e2e primary items")
    require(audit.get("next_audit_score_threshold", 0) >= 800, "next audit score threshold must be at least 800")

    source_artifacts_raw = manifest.get("source_artifacts", {})
    if not isinstance(source_artifacts_raw, dict) or not source_artifacts_raw:
        err("source_artifacts must be a non-empty object")
        source_artifacts_raw = {}
    source_artifacts: dict[str, str] = {}
    for key, value in source_artifacts_raw.items():
        path = repo_path(value, f"source_artifacts.{key}", must_be_file=True)
        if path is not None and isinstance(value, str):
            source_artifacts[key] = value

    validate_impl_refs(manifest)

    test_sources = manifest.get("test_sources", {})
    if not isinstance(test_sources, dict) or not test_sources:
        err("test_sources must be a non-empty object")
        test_sources = {}
    for source_id, source in test_sources.items():
        if not isinstance(source, dict):
            err(f"test_sources.{source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str):
            err(f"test_sources.{source_id}.path must be a string")
            continue
        text = text_for(path_text, f"test_sources.{source_id}")
        for name in strings(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            require(f"fn {name}" in text or name in text, f"test_sources.{source_id} missing test ref {name}")

    coverage = manifest.get("completion_coverage")
    if not isinstance(coverage, list) or len(coverage) != 2:
        err("completion_coverage must contain exactly unit and e2e sections")
    else:
        covered = {section.get("missing_item_id") for section in coverage if isinstance(section, dict)}
        require(covered == EXPECTED_MISSING_ITEMS, f"completion_coverage item mismatch: {covered!r}")
        for section in coverage:
            if not isinstance(section, dict):
                continue
            require(section.get("status") == "covered", "completion_coverage sections must be covered")
            for command in strings(section.get("validation_commands"), f"completion_coverage.{section.get('missing_item_id')}.validation_commands"):
                if "cargo " in command:
                    require(command.startswith("rch exec -- "), f"cargo validation command must use rch: {command}")

    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    require(set(strings(telemetry.get("required_events"), "telemetry_contract.required_events")) == set(EXPECTED_EVENTS), "telemetry_contract.required_events mismatch")

    append_event(
        "strict_hardened_contract_validated",
        "pass" if not errors else "fail",
        [rel(CONTRACT)],
        {"source_artifact_count": len(source_artifacts), "implementation_ref_count": len(manifest.get("implementation_refs", [])) if isinstance(manifest.get("implementation_refs"), list) else 0},
    )
    return source_artifacts


def validate_source_truth(manifest: dict[str, Any], source_artifacts: dict[str, str]) -> dict[str, Any]:
    truth = manifest.get("required_source_truth", {})
    if not isinstance(truth, dict):
        err("required_source_truth must be an object")
        truth = {}

    summary: dict[str, Any] = {}

    mode_semantics = load_json(ROOT / source_artifacts.get("mode_semantics_matrix", ""), "mode_semantics_matrix")
    expected = truth.get("mode_semantics", {}) if isinstance(truth.get("mode_semantics"), dict) else {}
    modes = mode_semantics.get("modes", {})
    families = mode_semantics.get("families", [])
    mode_summary = mode_semantics.get("summary", {})
    require(mode_semantics.get("schema_version", 0) >= expected.get("schema_version_min", 1), "mode semantics schema_version too low")
    require(set(modes.keys()) >= set(expected.get("required_modes", [])), "mode semantics missing strict/hardened modes")
    require(isinstance(families, list) and len(families) == expected.get("total_families"), "mode semantics family count drift")
    require(mode_summary.get("total_families") == expected.get("total_families"), "mode semantics summary.total_families drift")
    require(mode_summary.get("families_with_healing") == expected.get("families_with_healing"), "mode semantics families_with_healing drift")
    require(mode_summary.get("total_heals_call_sites") == expected.get("total_heals_call_sites"), "mode semantics total_heals_call_sites drift")
    for family in families if isinstance(families, list) else []:
        if not isinstance(family, dict):
            err("mode semantics families entries must be objects")
            continue
        for key in ["family", "module", "symbols", "strict_behavior", "hardened_behavior"]:
            require(key in family, f"mode semantics family missing {key}")
    summary["mode_semantics_families"] = len(families) if isinstance(families, list) else 0

    hardened = load_json(ROOT / source_artifacts.get("hardened_repair_deny_matrix", ""), "hardened_repair_deny_matrix")
    expected = truth.get("hardened_repair_deny_matrix", {}) if isinstance(truth.get("hardened_repair_deny_matrix"), dict) else {}
    h_summary = hardened.get("summary", {})
    entries = hardened.get("entries", [])
    classes = hardened.get("invalid_input_classes", [])
    require(hardened.get("schema_version") == expected.get("schema_version"), "hardened matrix schema_version drift")
    require(h_summary.get("entry_count") == expected.get("entry_count"), "hardened matrix entry_count drift")
    require(h_summary.get("covered_invalid_input_classes") == expected.get("covered_invalid_input_classes"), "hardened matrix covered class count drift")
    require(h_summary.get("repair_entries") == expected.get("repair_entries"), "hardened matrix repair_entries drift")
    require(h_summary.get("deny_entries") == expected.get("deny_entries"), "hardened matrix deny_entries drift")
    require(len(hardened.get("claimed_api_families", [])) >= expected.get("min_claimed_api_families", 0), "hardened matrix claimed family count drift")
    require(len(entries) == len(classes) == expected.get("entry_count"), "hardened matrix class/entry count mismatch")
    require(set(expected.get("required_healing_actions", [])) <= set(hardened.get("known_healing_actions", [])), "hardened matrix missing required healing actions")
    policy_ids: set[str] = set()
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            err("hardened matrix entries must be objects")
            continue
        policy_id = entry.get("policy_id")
        require(isinstance(policy_id, str) and policy_id.startswith("tsm."), f"hardened matrix invalid policy_id {policy_id!r}")
        require(policy_id not in policy_ids, f"hardened matrix duplicate policy_id {policy_id!r}")
        if isinstance(policy_id, str):
            policy_ids.add(policy_id)
        require(
            entry.get("decision_path") in {"Repair", "Deny"},
            f"hardened matrix invalid decision_path {entry.get('decision_path')!r}",
        )
    summary["hardened_matrix_entries"] = len(entries) if isinstance(entries, list) else 0

    mode_lock = load_json(ROOT / source_artifacts.get("mode_contract_lock", ""), "mode_contract_lock")
    expected = truth.get("mode_contract_lock", {}) if isinstance(truth.get("mode_contract_lock"), dict) else {}
    env_contract = mode_lock.get("env_contract", {})
    require(env_contract.get("env_key") == expected.get("env_key"), "mode contract env_key drift")
    require(env_contract.get("allowed_values") == expected.get("allowed_values"), "mode contract allowed_values drift")
    require(env_contract.get("default_value") == expected.get("default_value"), "mode contract default_value drift")
    require(env_contract.get("unknown_value_behavior") == expected.get("unknown_value_behavior"), "mode contract unknown_value_behavior drift")
    require(expected.get("mutability_fragment", "") in str(env_contract.get("mutability", "")), "mode contract mutability drift")
    provenance = mode_lock.get("required_provenance_fields", [])
    require(set(expected.get("required_provenance_fields", [])) <= set(provenance), "mode contract missing provenance fields")
    require(len(mode_lock.get("startup_reentrant_test_anchors", [])) == expected.get("startup_reentrant_anchor_count"), "mode contract startup anchor count drift")
    summary["mode_contract_provenance_fields"] = len(provenance) if isinstance(provenance, list) else 0

    strict_e2e = load_json(ROOT / source_artifacts.get("strict_hardened_evidence_e2e", ""), "strict_hardened_evidence_e2e")
    expected = truth.get("strict_hardened_e2e", {}) if isinstance(truth.get("strict_hardened_e2e"), dict) else {}
    scenarios = strict_e2e.get("scenarios", [])
    require(strict_e2e.get("schema_version") == expected.get("schema_version"), "strict/hardened e2e schema_version drift")
    require(strict_e2e.get("required_modes") == expected.get("required_modes"), "strict/hardened e2e required_modes drift")
    require(strict_e2e.get("required_api_families") == expected.get("required_api_families"), "strict/hardened e2e required_api_families drift")
    require(len(scenarios) == expected.get("scenario_count"), "strict/hardened e2e scenario_count drift")
    require(len(strict_e2e.get("negative_scenario_cases", [])) == expected.get("negative_case_count"), "strict/hardened e2e negative_case_count drift")
    require(set(expected.get("required_log_fields", [])) <= set(strict_e2e.get("required_log_fields", [])), "strict/hardened e2e missing log fields")
    scenario_modes = {
        (scenario.get("api_family"), scenario.get("runtime_mode"))
        for scenario in scenarios
        if isinstance(scenario, dict)
    }
    for family in expected.get("required_api_families", []):
        for mode in expected.get("required_modes", []):
            require((family, mode) in scenario_modes, f"strict/hardened e2e missing {family}/{mode} scenario")
    summary["strict_hardened_e2e_scenarios"] = len(scenarios) if isinstance(scenarios, list) else 0

    runtime = load_json(ROOT / source_artifacts.get("runtime_mode_evidence_logging", ""), "runtime_mode_evidence_logging")
    expected = truth.get("runtime_mode_evidence_logging", {}) if isinstance(truth.get("runtime_mode_evidence_logging"), dict) else {}
    runtime_summary = runtime.get("summary", {})
    coverage_policy = runtime.get("coverage_policy", {})
    require(runtime.get("schema_version") == expected.get("schema_version"), "runtime mode evidence schema_version drift")
    require(runtime.get("canonical_command") == expected.get("canonical_command"), "runtime mode evidence canonical_command drift")
    require(runtime_summary.get("coverage_row_count") == expected.get("coverage_rows"), "runtime mode evidence coverage_rows drift")
    require(runtime_summary.get("startup_evidence_row_count") == expected.get("startup_evidence_rows"), "runtime mode evidence startup rows drift")
    require(coverage_policy.get("allowed_modes") == expected.get("allowed_modes"), "runtime mode evidence allowed_modes drift")
    require(coverage_policy.get("ambient_tz_dependency_allowed") is expected.get("ambient_tz_dependency_allowed"), "runtime mode evidence ambient TZ policy drift")
    require(coverage_policy.get("subprocess_rows_must_override_inherited_mode") is expected.get("subprocess_rows_must_override_inherited_mode"), "runtime mode evidence subprocess override policy drift")
    summary["runtime_mode_evidence_rows"] = runtime_summary.get("coverage_row_count")

    inventory = load_json(ROOT / source_artifacts.get("semantic_contract_inventory", ""), "semantic_contract_inventory")
    expected = truth.get("semantic_contract_inventory", {}) if isinstance(truth.get("semantic_contract_inventory"), dict) else {}
    inv_summary = inventory.get("summary", {})
    require(inventory.get("schema_version") == expected.get("schema_version"), "semantic inventory schema_version drift")
    require(inv_summary.get("entry_count") == expected.get("entry_count"), "semantic inventory entry_count drift")
    require(inv_summary.get("seed_overlay_covered") == expected.get("seed_overlay_covered"), "semantic inventory seed coverage drift")
    require(set(expected.get("required_semantic_classes", [])) <= set(inv_summary.get("by_semantic_class", {}).keys()), "semantic inventory class coverage drift")
    require(expected.get("blocked_claim_fragment", "") in str(inv_summary.get("blocked_claim", "")), "semantic inventory blocked claim text drift")
    summary["semantic_inventory_entries"] = inv_summary.get("entry_count")

    drift = load_json(ROOT / source_artifacts.get("semantic_contract_drift_scan", ""), "semantic_contract_drift_scan")
    require(drift.get("schema_version") == truth.get("semantic_contract_drift", {}).get("schema_version"), "semantic drift schema_version drift")

    append_event(
        "strict_hardened_source_truth_validated",
        "pass" if not errors else "fail",
        [source_artifacts.get("mode_semantics_matrix", ""), source_artifacts.get("hardened_repair_deny_matrix", ""), source_artifacts.get("strict_hardened_evidence_e2e", "")],
        summary,
    )
    return summary


def replay_source_gates(source_artifacts: dict[str, str]) -> dict[str, Any]:
    run_gate("mode_semantics", ["bash", "scripts/check_mode_semantics.sh"])
    run_gate("hardened_repair_deny_matrix", ["bash", "scripts/check_hardened_repair_deny_matrix.sh"])
    run_gate("mode_contract_lock", ["bash", "scripts/check_mode_contract_lock.sh"])
    run_gate(
        "runtime_mode_evidence_logging",
        ["bash", "scripts/check_runtime_mode_evidence_logging_coverage.sh", "--validate-only"],
        {
            "RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_REPORT": str(RUNTIME_MODE_REPORT),
            "RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_LOG": str(RUNTIME_MODE_LOG),
        },
    )
    run_gate(
        "strict_hardened_evidence_e2e",
        ["bash", "scripts/check_strict_hardened_evidence_e2e.sh"],
        {
            "FRANKENLIBC_STRICT_HARDENED_E2E_OUT_DIR": str(OUT_DIR),
            "FRANKENLIBC_STRICT_HARDENED_E2E_REPORT": str(STRICT_E2E_REPORT),
            "FRANKENLIBC_STRICT_HARDENED_E2E_LOG": str(STRICT_E2E_LOG),
        },
    )
    run_gate("semantic_contract_inventory", ["bash", "scripts/check_semantic_contract_inventory.sh"])
    run_gate("semantic_contract_drift", ["bash", "scripts/check_semantic_contract_drift.sh"])

    runtime_report = load_json(RUNTIME_MODE_REPORT, "runtime_mode_evidence_logging report")
    runtime_log = load_jsonl(RUNTIME_MODE_LOG, "runtime_mode_evidence_logging log")
    e2e_report = load_json(STRICT_E2E_REPORT, "strict_hardened_evidence_e2e report")
    e2e_log = load_jsonl(STRICT_E2E_LOG, "strict_hardened_evidence_e2e log")
    hardened_report = load_json(ROOT / "target/conformance/hardened_repair_deny_matrix.report.json", "hardened repair/deny report")
    mode_lock_report = load_json(ROOT / "target/conformance/mode_contract_lock.report.json", "mode contract lock report")
    inventory_report = load_json(ROOT / "target/conformance/semantic_contract_inventory.report.json", "semantic inventory report")
    drift_report = load_json(ROOT / "target/conformance/semantic_contract_drift_scan.report.json", "semantic drift report")

    require(e2e_report.get("status") == "pass", "strict/hardened e2e source report must pass")
    require(e2e_report.get("summary", {}).get("scenario_count") == 10, "strict/hardened e2e report scenario_count drift")
    require(e2e_report.get("summary", {}).get("structured_log_rows") == 16, "strict/hardened e2e structured log row drift")
    require(len(e2e_log) == 16, "strict/hardened e2e log row count drift")
    require(runtime_report.get("summary", {}).get("coverage_rows") == 7, "runtime evidence report row count drift")
    require(len(runtime_log) == 1, "runtime evidence completion log should emit one summary row")
    require(hardened_report.get("summary", {}).get("entry_count") == 15, "hardened source report entry_count drift")
    require(mode_lock_report.get("summary", {}).get("required_provenance_fields") == 12, "mode lock source report provenance count drift")
    require(inventory_report.get("status") == "pass", "semantic inventory source report must pass")
    require(drift_report.get("status") == "pass", "semantic drift source report must pass")
    require(not drift_report.get("newly_found_drift"), "semantic drift source report found new drift")

    details = {
        "runtime_mode_log_rows": len(runtime_log),
        "strict_hardened_e2e_log_rows": len(e2e_log),
        "source_gate_count": len(source_gate_outputs),
        "semantic_inventory_entries": inventory_report.get("entry_count"),
        "semantic_drift_untracked_contracts": drift_report.get("summary", {}).get("untracked_contract_annotation_count"),
    }
    append_event(
        "strict_hardened_source_gates_replayed",
        "pass" if not errors else "fail",
        [
            rel(RUNTIME_MODE_REPORT),
            rel(RUNTIME_MODE_LOG),
            rel(STRICT_E2E_REPORT),
            rel(STRICT_E2E_LOG),
            "target/conformance/hardened_repair_deny_matrix.report.json",
            "target/conformance/mode_contract_lock.report.json",
            "target/conformance/semantic_contract_inventory.report.json",
            "target/conformance/semantic_contract_drift_scan.report.json",
        ],
        details,
    )
    return details


manifest = load_json(CONTRACT, "completion contract")
source_artifacts = validate_manifest(manifest)
source_truth_summary = validate_source_truth(manifest, source_artifacts)
gate_summary = replay_source_gates(source_artifacts)

summary = {
    **source_truth_summary,
    **gate_summary,
    "required_events": len(EXPECTED_EVENTS),
    "validation_status": "pass" if not errors else "fail",
}
append_event(
    "strict_hardened_completion_summary",
    "pass" if not errors else "fail",
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    summary,
)

status = "pass" if not errors else "fail"
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": SOURCE_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": git_head(),
    "summary": summary,
    "source_gate_outputs": source_gate_outputs,
    "events": events,
    "errors": errors,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("check_strict_hardened_semantic_closure_completion_contract: FAIL")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)

print("check_strict_hardened_semantic_closure_completion_contract: PASS")
print(f"Report: {rel(REPORT)}")
print(f"Log: {rel(LOG)}")
PY
