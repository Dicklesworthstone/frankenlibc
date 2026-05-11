#!/usr/bin/env bash
# check_runtime_math_branch_diversity_snapshot_completion_contract.sh - bd-5vr.7.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_CONTRACT:-$ROOT/tests/conformance/runtime_math_branch_diversity_snapshot_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_REPORT:-$OUT_DIR/runtime_math_branch_diversity_snapshot_completion_contract.report.json}"
LOG="${FRANKENLIBC_BRANCH_SNAPSHOT_COMPLETION_LOG:-$OUT_DIR/runtime_math_branch_diversity_snapshot_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "runtime_math_branch_diversity_snapshot_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_math_branch_diversity_snapshot_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-5vr.7.1-runtime-math-branch-diversity-snapshot-completion-contract"
ORIGINAL_BEAD = "bd-5vr.7"
COMPLETION_BEAD = "bd-5vr.7.1"
TRACE_ID = "bd-5vr.7.1::runtime-math-branch-diversity-snapshot::v1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "tests.golden.primary"}
REQUIRED_UNIT_TEST_NAMES = {
    "manifest_binds_branch_diversity_snapshot_completion_items",
    "checker_validates_branch_diversity_snapshot_contract_and_emits_report_log",
    "checker_rejects_missing_branch_diversity_binding",
    "checker_rejects_missing_golden_binding",
    "checker_rejects_non_rch_cargo_command",
}
REQUIRED_E2E_TEST_NAMES = {
    "e2e_branch_diversity_healthy_with_balanced_family_mix",
    "e2e_branch_diversity_violation_with_single_family_dominance",
    "e2e_branch_diversity_near_violation_at_boundary",
    "e2e_snapshot_captures_schema_version_and_core_fields",
    "e2e_snapshot_deterministic_replay_produces_identical_snapshots",
    "e2e_snapshot_strict_vs_hardened_mode_independence",
    "e2e_independent_kernels_produce_consistent_results_under_concurrent_scenario",
    "e2e_kernel_isolation_divergent_inputs_produce_independent_state",
    "e2e_framework_trait_evaluate_calibrate_snapshot_cycle",
    "e2e_framework_decision_cards_export_contains_all_decisions",
}
REQUIRED_GOLDEN_TEST_NAMES = {
    "e2e_snapshot_serialization_contains_all_core_fields",
    "e2e_snapshot_golden_replay_field_stability",
    "runtime_math_kernel_snapshot_golden_checksum_matches_manifest",
    "checker_rejects_golden_hash_drift",
}
PASS_EVENTS = {
    "runtime_math_branch_snapshot_unit_bindings_verified",
    "runtime_math_branch_snapshot_e2e_bindings_verified",
    "runtime_math_branch_snapshot_golden_verified",
    "runtime_math_branch_snapshot_completion_contract_pass",
}
FAIL_EVENT = "runtime_math_branch_snapshot_completion_contract_fail"

errors: list[str] = []
events: list[dict[str, Any]] = []


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


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


SOURCE_COMMIT = git_head()


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


def artifact_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    return full


def source_text(path_text: Any, context: str) -> str:
    path = artifact_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{TRACE_ID}:{event}:{len(events) + 1:03d}",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "source_commit": SOURCE_COMMIT,
            "status": status,
            "outcome": "pass" if status == "pass" else "fail",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "runtime_math_branch_snapshot_completion_contract_failed",
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        artifact_path(path_text, f"source_artifacts.{artifact_id}")
        if isinstance(path_text, str):
            out[str(artifact_id)] = path_text
    return out


def validate_test_refs(
    section: dict[str, Any],
    section_name: str,
    sources: dict[str, str],
    required_names: set[str],
) -> list[str]:
    found: list[str] = []
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"{section_name}.required_test_refs must be a non-empty array")
        return found
    source_cache = {
        source_id: source_text(path, f"test_source.{source_id}")
        for source_id, path in sources.items()
    }
    for index, ref_obj in enumerate(refs):
        if not isinstance(ref_obj, dict):
            err(f"{section_name}.required_test_refs[{index}] must be an object")
            continue
        source_id = ref_obj.get("source")
        name = ref_obj.get("name")
        if not isinstance(source_id, str) or source_id not in source_cache:
            err(f"{section_name}.required_test_refs[{index}] references unknown source {source_id!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
            err(f"{section_name}.required_test_refs[{index}] missing test {source_id}::{name}")
            continue
        found.append(f"{source_id}::{name}")
    found_names = {item.split("::", 1)[1] for item in found if "::" in item}
    missing_required = sorted(required_names - found_names)
    if missing_required:
        err(f"{section_name}.required_test_refs missing required bindings {missing_required}")
    for command in section.get("required_commands", []):
        if not isinstance(command, str):
            err(f"{section_name}.required_commands entries must be strings")
            continue
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"{section_name} cargo command must be rch-backed: {command}")
    return found


def validate_contract(manifest: dict[str, Any], artifacts: dict[str, str]) -> dict[str, Any]:
    contract = manifest.get("required_runtime_math_branch_snapshot_contract", {})
    if not isinstance(contract, dict):
        err("required_runtime_math_branch_snapshot_contract must be an object")
        contract = {}

    e2e_text = source_text(artifacts.get("dual_mode_e2e_test"), "source_artifacts.dual_mode_e2e_test")
    runtime_text = source_text(artifacts.get("runtime_math_mod"), "source_artifacts.runtime_math_mod")
    determinism_text = source_text(
        artifacts.get("runtime_math_determinism_test"),
        "source_artifacts.runtime_math_determinism_test",
    )

    require(
        contract.get("scenario_id") == "bd-5vr.7-runtime-math-branch-diversity-snapshot-e2e",
        "scenario_id mismatch",
    )
    modes = set(as_string_list(contract.get("required_modes"), "required_modes"))
    require(modes == {"strict", "hardened"}, "required_modes must be exactly strict+hardened")

    branch = contract.get("branch_diversity", {})
    if not isinstance(branch, dict):
        err("branch_diversity contract must be an object")
        branch = {}
    require(int(branch.get("minimum_active_families", 0)) >= 3, "branch diversity must require at least 3 active families")
    require(int(branch.get("healthy_dominant_share_max_ppm", 0)) == 350000, "healthy dominant share threshold must be 350000 ppm")
    require(int(branch.get("near_violation_min_ppm", 0)) == 350000, "near violation threshold must be 350000 ppm")
    require(int(branch.get("violation_min_ppm", 0)) == 400000, "violation threshold must be 400000 ppm")
    require(int(branch.get("single_family_violation_ppm", 0)) == 1000000, "single-family violation must be 1000000 ppm")
    states = set(as_string_list(branch.get("required_states"), "branch_diversity.required_states"))
    require(states == {"Healthy", "NearViolation", "Violation"}, "branch required_states mismatch")
    for token in as_string_list(branch.get("required_source_tokens"), "branch_diversity.required_source_tokens"):
        require(token in e2e_text, f"branch-diversity source missing token {token!r}")

    snapshot = contract.get("snapshot_capture", {})
    if not isinstance(snapshot, dict):
        err("snapshot_capture contract must be an object")
        snapshot = {}
    require(int(snapshot.get("snapshot_schema_version", 0)) == 2, "snapshot schema version must be 2")
    require("pub const RUNTIME_KERNEL_SNAPSHOT_SCHEMA_VERSION: u32 = 2;" in runtime_text, "runtime snapshot schema constant must remain 2")
    require(int(snapshot.get("minimum_snapshot_tests", 0)) >= 5, "snapshot contract must require at least 5 snapshot tests")
    require(int(snapshot.get("minimum_snapshot_fields", 0)) >= 16, "snapshot contract must require core field coverage")
    for token in as_string_list(snapshot.get("required_source_tokens"), "snapshot_capture.required_source_tokens"):
        require(token in e2e_text or token in runtime_text, f"snapshot source missing token {token!r}")

    multi = contract.get("multi_kernel_interaction", {})
    if not isinstance(multi, dict):
        err("multi_kernel_interaction contract must be an object")
        multi = {}
    require(int(multi.get("minimum_decision_steps", 0)) >= 128, "multi-kernel interaction must preserve 128-step scenario")
    for token in as_string_list(multi.get("required_source_tokens"), "multi_kernel_interaction.required_source_tokens"):
        require(token in e2e_text, f"multi-kernel source missing token {token!r}")

    golden = contract.get("golden_snapshot", {})
    if not isinstance(golden, dict):
        err("golden_snapshot contract must be an object")
        golden = {}
    golden_path = artifact_path(artifacts.get("kernel_snapshot_golden"), "source_artifacts.kernel_snapshot_golden")
    sha_path = artifact_path(artifacts.get("kernel_snapshot_sha256s"), "source_artifacts.kernel_snapshot_sha256s")
    expected_sha = golden.get("expected_sha256")
    require(isinstance(expected_sha, str) and len(expected_sha) == 64, "golden expected_sha256 must be a 64-char digest")
    actual_sha = sha256_file(golden_path) if golden_path is not None else ""
    require(actual_sha == expected_sha, "golden snapshot hash drift")
    if sha_path is not None and isinstance(expected_sha, str):
        sha_text = sha_path.read_text(encoding="utf-8")
        require(f"{expected_sha}  {golden.get('expected_filename')}" in sha_text, "sha256 manifest missing expected golden snapshot row")
    golden_json = load_json(golden_path, "kernel snapshot golden") if golden_path is not None else {}
    require(golden_json.get("version") == "v1", "golden snapshot version must be v1")
    require(golden_json.get("scenario", {}).get("id") == golden.get("expected_scenario"), "golden snapshot scenario mismatch")
    require(golden_json.get("scenario", {}).get("seed") == golden.get("expected_seed"), "golden snapshot seed mismatch")
    require(golden_json.get("scenario", {}).get("steps") == golden.get("expected_steps"), "golden snapshot steps mismatch")
    for mode in as_string_list(golden.get("required_modes"), "golden_snapshot.required_modes"):
        require(isinstance(golden_json.get(mode), dict), f"golden snapshot missing mode {mode}")
    for token in as_string_list(golden.get("required_source_tokens"), "golden_snapshot.required_source_tokens"):
        require(token in e2e_text or token in determinism_text, f"golden source missing token {token!r}")

    return {
        "scenario_id": contract.get("scenario_id"),
        "required_modes": sorted(modes),
        "branch_states": sorted(states),
        "snapshot_schema_version": snapshot.get("snapshot_schema_version"),
        "golden_sha256": expected_sha,
        "golden_actual_sha256": actual_sha,
        "golden_filename": golden.get("expected_filename"),
    }


def write_outputs(
    manifest: dict[str, Any],
    status: str,
    branch_summary: dict[str, Any],
    unit_refs: list[str],
    e2e_refs: list[str],
    golden_refs: list[str],
) -> None:
    telemetry = manifest.get("telemetry_contract", {}) if isinstance(manifest, dict) else {}
    required_events = set(as_string_list(telemetry.get("required_events", []), "telemetry_contract.required_events", allow_empty=True))
    forbidden_pass_events = set(as_string_list(telemetry.get("forbidden_pass_events", []), "telemetry_contract.forbidden_pass_events", allow_empty=True))
    observed_events = {event["event"] for event in events}
    if status == "pass":
        missing_events = sorted(required_events - observed_events)
        if missing_events:
            err(f"required telemetry events missing {missing_events}")
            status = "fail"
        forbidden = sorted(forbidden_pass_events & observed_events)
        if forbidden:
            err(f"forbidden pass telemetry events observed {forbidden}")
            status = "fail"
    if status == "fail" and FAIL_EVENT not in observed_events:
        append_event(FAIL_EVENT, "fail", [rel(CONTRACT)], {"errors": errors.copy()})

    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "manifest_id": manifest.get("manifest_id"),
        "source_bead": manifest.get("original_bead"),
        "completion_debt_bead": manifest.get("completion_debt_bead"),
        "status": status,
        "unit_bindings": unit_refs,
        "e2e_bindings": e2e_refs,
        "golden_bindings": golden_refs,
        "branch_snapshot_contract": branch_summary,
        "events": [event["event"] for event in events],
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

    required_report_fields = set(as_string_list(telemetry.get("required_report_fields", []), "telemetry_contract.required_report_fields", allow_empty=True))
    missing_report_fields = sorted(field for field in required_report_fields if field not in report)
    if missing_report_fields:
        errors.append(f"report missing required fields {missing_report_fields}")
        report["status"] = "fail"
        report["errors"] = errors
        REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

artifacts = validate_source_artifacts(manifest)
evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
missing_items = set(as_string_list(evidence.get("missing_items_closed"), "completion_debt_evidence.missing_items_closed"))
require(missing_items == REQUIRED_MISSING_ITEMS, "missing_items_closed must close exactly unit/e2e/golden")

unit_section = evidence.get("unit_primary", {})
if not isinstance(unit_section, dict):
    err("completion_debt_evidence.unit_primary must be an object")
    unit_section = {}
e2e_section = evidence.get("e2e_primary", {})
if not isinstance(e2e_section, dict):
    err("completion_debt_evidence.e2e_primary must be an object")
    e2e_section = {}
golden_section = evidence.get("golden_primary", {})
if not isinstance(golden_section, dict):
    err("completion_debt_evidence.golden_primary must be an object")
    golden_section = {}

unit_refs = validate_test_refs(unit_section, "unit_primary", artifacts, REQUIRED_UNIT_TEST_NAMES)
append_event(
    "runtime_math_branch_snapshot_unit_bindings_verified",
    "pass" if not errors else "fail",
    [rel(artifacts.get("completion_harness_test", ""))],
    {"unit_refs": unit_refs},
)

e2e_refs = validate_test_refs(e2e_section, "e2e_primary", artifacts, REQUIRED_E2E_TEST_NAMES)
append_event(
    "runtime_math_branch_snapshot_e2e_bindings_verified",
    "pass" if not errors else "fail",
    [rel(artifacts.get("dual_mode_e2e_test", "")), rel(artifacts.get("branch_diversity_spec", ""))],
    {"e2e_refs": e2e_refs},
)

golden_refs = validate_test_refs(golden_section, "golden_primary", artifacts, REQUIRED_GOLDEN_TEST_NAMES)
branch_summary = validate_contract(manifest, artifacts)
append_event(
    "runtime_math_branch_snapshot_golden_verified",
    "pass" if not errors else "fail",
    [rel(artifacts.get("kernel_snapshot_golden", "")), rel(artifacts.get("kernel_snapshot_sha256s", ""))],
    {"golden_refs": golden_refs, "golden_sha256": branch_summary.get("golden_sha256")},
)

if not errors:
    append_event(
        "runtime_math_branch_snapshot_completion_contract_pass",
        "pass",
        [rel(CONTRACT)],
        {"e2e_bindings": len(e2e_refs), "golden_bindings": len(golden_refs)},
    )

status = "fail" if errors else "pass"
write_outputs(manifest, status, branch_summary, unit_refs, e2e_refs, golden_refs)

if errors:
    print(f"FAIL runtime math branch/snapshot completion contract: {len(errors)} error(s)")
    for message in errors:
        print(f"- {message}")
    raise SystemExit(1)

print(
    "PASS runtime math branch/snapshot completion contract "
    f"e2e={len(e2e_refs)} golden={len(golden_refs)}"
)
PY
