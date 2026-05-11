#!/usr/bin/env bash
# check_real_world_application_testing_completion_contract.sh - bd-33xi.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REAL_WORLD_COMPLETION_CONTRACT:-$ROOT/tests/conformance/real_world_application_testing_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_REAL_WORLD_COMPLETION_REPORT:-$ROOT/target/conformance/real_world_application_testing_completion_contract.report.json}"
LOG="${FRANKENLIBC_REAL_WORLD_COMPLETION_LOG:-$ROOT/target/conformance/real_world_application_testing_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

COMPLETION_BEAD = "bd-33xi.1"
ORIGINAL_BEAD = "bd-33xi"
EXPECTED_SCHEMA = "real_world_application_testing_completion_contract.v1"
EXPECTED_MANIFEST = "bd-33xi.1-real-world-application-testing-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "integration_primary": "tests.integration.primary",
    "e2e_primary": "tests.e2e.primary",
}
TIER1 = {"bash", "coreutils", "python3", "curl", "git"}
TIER2 = {"nginx", "postgresql", "redis-server", "nodejs", "go-programs"}
REQUIRED_SCENARIOS = {
    "basic_functionality",
    "long_running_operation",
    "high_load_stress",
    "error_condition_handling",
    "graceful_shutdown",
}
VALIDATION_DIMENSIONS = {
    "functional_correctness",
    "performance_budget",
    "stability_no_crash_or_hang",
    "memory_bounded_overhead",
}
REQUIRED_MODES = {"strict", "hardened"}
EXPECTED_EVENTS = {
    "real_world_application_testing_completion_contract_validated",
    "real_world_application_testing_completion_contract_failed",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "mode",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "source_commit",
    "target_dir",
    "failure_signature",
    "artifact_refs",
    "outcome",
}

errors: list[str] = []


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


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


def as_string_set(value: Any, context: str) -> set[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty string array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    if len(result) != len(value):
        err(f"{context} must not contain duplicates")
    return result


def validate_repo_file(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        path = validate_repo_file(path_text, f"test_sources.{key}")
        if path is not None and path.is_file():
            texts[str(key)] = path.read_text(encoding="utf-8")
        elif path is not None:
            err(f"test_sources.{key} must reference a file")
    return texts


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        text = texts.get(source)
        if text is None:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] references unknown source {source}")
            continue
        if f"fn {name}" not in text:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] references missing test {source}::{name}")
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        normalized.append({"source": source, "name": name})
    return normalized


def load_source_workloads(path_text: str) -> dict[str, dict[str, Any]]:
    source = load_json(ROOT / path_text, "workload_matrix")
    workloads = source.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        err("workload_matrix.workloads must be non-empty")
        return {}
    by_binary: dict[str, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for workload in workloads:
        if not isinstance(workload, dict):
            err("workload_matrix.workloads entries must be objects")
            continue
        binary = workload.get("binary")
        wid = workload.get("id")
        if isinstance(binary, str):
            by_binary[binary] = workload
        if isinstance(wid, str):
            by_id[wid] = workload
    return {"by_binary": by_binary, "by_id": by_id}


def load_acceptance_workloads(path_text: str) -> dict[str, dict[str, Any]]:
    source = load_json(ROOT / path_text, "user_workload_acceptance_matrix")
    workloads = source.get("workloads")
    if not isinstance(workloads, list) or not workloads:
        err("user_workload_acceptance_matrix.workloads must be non-empty")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for workload in workloads:
        if isinstance(workload, dict) and isinstance(workload.get("id"), str):
            result[workload["id"]] = workload
    return result


manifest = load_json(CONTRACT, "completion contract")
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != COMPLETION_BEAD:
    err(f"bead must be {COMPLETION_BEAD}")
if manifest.get("original_bead") != ORIGINAL_BEAD:
    err(f"original_bead must be {ORIGINAL_BEAD}")

source_artifacts = manifest.get("source_artifacts")
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
for key, path_text in source_artifacts.items():
    validate_repo_file(path_text, f"source_artifacts.{key}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    err("completion_debt_evidence must be an object")
    completion = {}

threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

bindings = completion.get("missing_item_bindings")
if not isinstance(bindings, list) or len(bindings) != len(EXPECTED_MISSING_ITEMS):
    err("completion_debt_evidence.missing_item_bindings must bind every expected missing item")
else:
    seen_bindings: dict[str, str] = {}
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            err(f"missing_item_bindings[{index}] must be an object")
            continue
        missing_item = binding.get("missing_item_id")
        section = binding.get("evidence_section")
        if not isinstance(missing_item, str) or not isinstance(section, str):
            err(f"missing_item_bindings[{index}] must include missing_item_id and evidence_section")
            continue
        seen_bindings[section] = missing_item
    if seen_bindings != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_bindings mismatch: {seen_bindings}")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 20:
    err("completion_debt_evidence.implementation_refs must contain at least 20 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(completion.get("test_sources"))
test_ref_summary: dict[str, list[dict[str, str]]] = {}
for section, missing_item in EXPECTED_MISSING_ITEMS.items():
    value = completion.get(section)
    if not isinstance(value, dict):
        err(f"completion_debt_evidence.{section} must be an object")
        continue
    if value.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section}.missing_item_id must be {missing_item}")
    test_ref_summary[section] = validate_test_refs(value, section, texts)
    commands = value.get("required_commands")
    if not isinstance(commands, list) or not commands:
        err(f"completion_debt_evidence.{section}.required_commands must be non-empty")

contract = completion.get("real_world_contract")
if not isinstance(contract, dict):
    err("completion_debt_evidence.real_world_contract must be an object")
    contract = {}

if as_string_set(contract.get("required_tier1_applications"), "required_tier1_applications") != TIER1:
    err("required_tier1_applications must match original bd-33xi Tier 1 apps")
if as_string_set(contract.get("required_tier2_applications"), "required_tier2_applications") != TIER2:
    err("required_tier2_applications must match original bd-33xi Tier 2 apps")
if as_string_set(contract.get("required_scenarios"), "required_scenarios") != REQUIRED_SCENARIOS:
    err("required_scenarios must match original bd-33xi scenario set")
if as_string_set(contract.get("validation_dimensions"), "validation_dimensions") != VALIDATION_DIMENSIONS:
    err("validation_dimensions must match original bd-33xi validation dimensions")
if as_string_set(contract.get("required_runtime_modes"), "required_runtime_modes") != REQUIRED_MODES:
    err("required_runtime_modes must be strict+hardened")

policy = contract.get("claim_policy")
if not isinstance(policy, dict):
    err("real_world_contract.claim_policy must be an object")
    policy = {}
if policy.get("tier1_must_be_evidence_bound") is not True:
    err("claim_policy.tier1_must_be_evidence_bound must be true")
if policy.get("tier2_missing_source_rows_must_be_claim_blocked") is not True:
    err("claim_policy.tier2_missing_source_rows_must_be_claim_blocked must be true")
if policy.get("missing_evidence_result") != "claim_blocked_gap":
    err("claim_policy.missing_evidence_result must be claim_blocked_gap")
if policy.get("blocked_gap_failure_signature") != "source_matrix_gap":
    err("claim_policy.blocked_gap_failure_signature must be source_matrix_gap")

workload_path = source_artifacts.get("workload_matrix", "tests/conformance/workload_matrix.json")
acceptance_path = source_artifacts.get(
    "user_workload_acceptance_matrix",
    "tests/conformance/user_workload_acceptance_matrix.v1.json",
)
source_workloads = load_source_workloads(str(workload_path))
source_by_binary = source_workloads.get("by_binary", {})
source_by_id = source_workloads.get("by_id", {})
acceptance_by_id = load_acceptance_workloads(str(acceptance_path))

rows = contract.get("application_rows")
if not isinstance(rows, list) or len(rows) != len(TIER1 | TIER2):
    err("real_world_contract.application_rows must include exactly the original 10 applications")
    rows = []

row_ids: set[str] = set()
evidence_bound_apps: list[str] = []
claim_blocked_apps: list[str] = []
for index, row in enumerate(rows):
    if not isinstance(row, dict):
        err(f"application_rows[{index}] must be an object")
        continue
    app = row.get("application_id")
    tier = row.get("tier")
    if not isinstance(app, str) or not app:
        err(f"application_rows[{index}].application_id must be non-empty")
        continue
    if app in row_ids:
        err(f"application_rows duplicate application_id {app}")
    row_ids.add(app)
    expected_tier = "tier1" if app in TIER1 else "tier2" if app in TIER2 else None
    if expected_tier is None:
        err(f"application_rows[{index}] has unexpected application_id {app}")
    elif tier != expected_tier:
        err(f"{app}: tier must be {expected_tier}")

    if as_string_set(row.get("runtime_modes"), f"{app}.runtime_modes") != REQUIRED_MODES:
        err(f"{app}: runtime_modes must be strict+hardened")
    if as_string_set(row.get("scenarios"), f"{app}.scenarios") != REQUIRED_SCENARIOS:
        err(f"{app}: scenarios must cover every original scenario")
    if as_string_set(row.get("validation_dimensions"), f"{app}.validation_dimensions") != VALIDATION_DIMENSIONS:
        err(f"{app}: validation_dimensions must cover every original validation dimension")

    artifact_refs = row.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs:
        err(f"{app}: artifact_refs must be non-empty")
    else:
        for ref_index, ref in enumerate(artifact_refs):
            if not isinstance(ref, str) or not ref:
                err(f"{app}: artifact_refs[{ref_index}] must be a non-empty string")
                continue
            if not ref.startswith("target/") and not (ROOT / ref).exists():
                err(f"{app}: artifact_refs[{ref_index}] missing: {ref}")

    status = row.get("claim_status")
    if status == "evidence_bound":
        evidence_bound_apps.append(app)
        binary = row.get("workload_matrix_binary")
        wid = row.get("workload_matrix_id")
        if not isinstance(binary, str) or not isinstance(wid, str):
            err(f"{app}: evidence_bound rows must include workload_matrix_binary and workload_matrix_id")
            continue
        if binary not in source_by_binary:
            err(f"{app}: workload_matrix_binary {binary} is not present in workload_matrix")
        source_row = source_by_id.get(wid)
        if not source_row or source_row.get("binary") != binary:
            err(f"{app}: workload_matrix_id {wid} does not resolve to binary {binary}")
        if row.get("failure_signature") != "none":
            err(f"{app}: evidence_bound rows must use failure_signature=none")
        if row.get("support_claimed") is not True:
            err(f"{app}: evidence_bound rows must set support_claimed=true")
    elif status == "claim_blocked_gap":
        claim_blocked_apps.append(app)
        if app in TIER1:
            err(f"{app}: Tier 1 applications may not be claim_blocked_gap")
        if row.get("failure_signature") != "source_matrix_gap":
            err(f"{app}: claim_blocked_gap rows must use failure_signature=source_matrix_gap")
        if row.get("support_claimed") is not False:
            err(f"{app}: claim_blocked_gap rows must set support_claimed=false")
        if not row.get("source_matrix_gap_reason"):
            err(f"{app}: claim_blocked_gap rows must include source_matrix_gap_reason")
        proxy = row.get("proxy_workload_id")
        if not isinstance(proxy, str) or proxy not in acceptance_by_id:
            err(f"{app}: claim_blocked_gap rows must reference an existing proxy_workload_id")
    else:
        err(f"{app}: claim_status must be evidence_bound or claim_blocked_gap")

if row_ids != (TIER1 | TIER2):
    err(f"application_rows application set mismatch: {sorted(row_ids)}")

telemetry = completion.get("telemetry_primary")
if not isinstance(telemetry, dict):
    err("completion_debt_evidence.telemetry_primary must be an object")
    telemetry = {}
if as_string_set(telemetry.get("required_events"), "telemetry_primary.required_events") != EXPECTED_EVENTS:
    err("telemetry_primary.required_events mismatch")
if as_string_set(telemetry.get("required_fields"), "telemetry_primary.required_fields") != EXPECTED_TELEMETRY_FIELDS:
    err("telemetry_primary.required_fields mismatch")

source_commit = git_head()
artifact_refs = [
    rel(CONTRACT),
    "tests/conformance/workload_matrix.json",
    "tests/conformance/user_workload_acceptance_matrix.v1.json",
    "scripts/ld_preload_smoke.sh",
    "scripts/e2e_suite.sh",
]
status = "fail" if errors else "pass"
report = {
    "schema_version": "real_world_application_testing_completion_contract.report.v1",
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "missing_items": sorted(EXPECTED_MISSING_ITEMS.values()),
    "tier1_applications": sorted(TIER1),
    "tier2_applications": sorted(TIER2),
    "evidence_bound_applications": sorted(evidence_bound_apps),
    "claim_blocked_applications": sorted(claim_blocked_apps),
    "scenario_count": len(REQUIRED_SCENARIOS),
    "validation_dimension_count": len(VALIDATION_DIMENSIONS),
    "test_ref_summary": test_ref_summary,
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_row = {
    "timestamp": now_utc(),
    "trace_id": f"{COMPLETION_BEAD}::real_world_application_testing_completion::{status}",
    "level": "error" if errors else "info",
    "event": "real_world_application_testing_completion_contract_failed"
    if errors
    else "real_world_application_testing_completion_contract_validated",
    "bead_id": COMPLETION_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "mode": "strict",
    "runtime_mode": "strict",
    "replacement_level": "L0",
    "api_family": "real-world-application-testing",
    "symbol": "bd-33xi",
    "oracle_kind": "completion_contract",
    "expected": {
        "tier1": sorted(TIER1),
        "tier2": sorted(TIER2),
        "scenarios": sorted(REQUIRED_SCENARIOS),
        "validation_dimensions": sorted(VALIDATION_DIMENSIONS),
    },
    "actual": {
        "evidence_bound_applications": sorted(evidence_bound_apps),
        "claim_blocked_applications": sorted(claim_blocked_apps),
        "errors": errors,
    },
    "errno": 0,
    "decision_path": "contract->source_artifacts->missing_items->application_tiers->telemetry",
    "healing_action": "None",
    "latency_ns": 1,
    "source_commit": source_commit,
    "target_dir": rel(REPORT.parent),
    "failure_signature": "none" if not errors else "real_world_application_testing_completion_contract_failed",
    "artifact_refs": artifact_refs + [rel(REPORT)],
    "outcome": status,
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    for message in errors:
        print(f"real_world_application_testing_completion_contract: {message}", file=sys.stderr)
    sys.exit(1)

print(
    "real_world_application_testing_completion_contract: pass "
    f"tier1={len(TIER1)} tier2={len(TIER2)} "
    f"evidence_bound={len(evidence_bound_apps)} claim_blocked={len(claim_blocked_apps)}"
)
PY
