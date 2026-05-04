#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${USER_WORKLOAD_VERTICAL_SLICE_MANIFEST:-$ROOT/tests/conformance/user_workload_vertical_slice.v1.json}"
REPORT="${USER_WORKLOAD_VERTICAL_SLICE_REPORT:-$ROOT/target/conformance/user_workload_vertical_slice.report.json}"
LOG="${USER_WORKLOAD_VERTICAL_SLICE_LOG:-$ROOT/target/conformance/user_workload_vertical_slice.log.jsonl}"
INDEX="${USER_WORKLOAD_VERTICAL_SLICE_INDEX:-$ROOT/target/conformance/user_workload_vertical_slice.artifact_index.json}"

python3 - "$ROOT" "$MANIFEST" "$REPORT" "$LOG" "$INDEX" <<'PY'
import json
import os
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
index_path = Path(sys.argv[5])

errors = []
failure_signatures = []

REQUIRED_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "scenario_id",
    "workload_id",
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
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
}


def fail(message, signature):
    errors.append(message)
    failure_signatures.append(signature)


def load_json(path, signature):
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except Exception as exc:
        fail(f"{path}: {exc}", signature)
        return None


def rel(path):
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def repo_path(path_text):
    return root / path_text


def exists_file(path_text, signature):
    path = repo_path(path_text)
    if not path.is_file():
        fail(f"required file is missing: {path_text}", signature)
        return False
    return True


def executable_or_file(path_text, signature):
    path = repo_path(path_text)
    if not path.is_file():
        fail(f"required command is missing: {path_text}", signature)
        return False
    return True


def current_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


manifest = load_json(manifest_path, "vertical_slice_manifest_unreadable")
if manifest is None:
    sys.exit(1)

if manifest.get("schema_version") != "v1" or manifest.get("bead") != "bd-bp8fl.10.6":
    fail("manifest must declare schema_version=v1 and bead=bd-bp8fl.10.6", "vertical_slice_bad_manifest")

selected = manifest.get("selected_workload")
if not isinstance(selected, dict):
    fail("selected_workload must be an object", "vertical_slice_missing_workload")
    selected = {}

if not selected.get("id"):
    fail("selected_workload.id is required", "vertical_slice_missing_workload")

if not selected.get("why_real_user_decision"):
    fail("selected_workload must record why this is a real user decision", "vertical_slice_missing_rationale")

matrix_path = repo_path(selected.get("source_artifact", ""))
matrix = load_json(matrix_path, "vertical_slice_missing_workload") if selected.get("source_artifact") else None
selected_row = None
if matrix:
    for row in matrix.get("workloads", []):
        if row.get("id") == selected.get("id"):
            selected_row = row
            break
    if selected_row is None:
        fail(f"selected workload {selected.get('id')} not found in workload matrix", "vertical_slice_missing_workload")

if selected_row:
    expected_domains = set(selected.get("expected_coverage_domains", []))
    actual_domains = set(selected_row.get("coverage_domains", []))
    if selected.get("expected_primary_domain") != selected_row.get("primary_domain"):
        fail("selected workload primary_domain does not match matrix row", "vertical_slice_workload_mismatch")
    if not expected_domains.issubset(actual_domains):
        fail("selected workload coverage domains do not match matrix row", "vertical_slice_workload_mismatch")
    if set(selected.get("expected_runtime_modes", [])) != set(selected_row.get("runtime_modes", [])):
        fail("selected workload runtime modes do not match matrix row", "vertical_slice_workload_mismatch")
    if set(selected.get("expected_replacement_levels", [])) != set(selected_row.get("replacement_levels", [])):
        fail("selected workload replacement levels do not match matrix row", "vertical_slice_workload_mismatch")

required_fields = set(manifest.get("required_log_fields", []))
missing_log_fields = sorted(REQUIRED_LOG_FIELDS - required_fields)
if missing_log_fields:
    fail(f"required_log_fields missing {missing_log_fields}", "vertical_slice_log_contract_missing")

source_commit = current_commit()
freshness = manifest.get("freshness_policy", {})
expected_commit = freshness.get("source_commit")
if expected_commit not in {"current", source_commit}:
    fail(
        f"freshness_policy.source_commit={expected_commit!r} is not current {source_commit}",
        freshness.get("stale_failure_signature", "vertical_slice_stale_source_commit"),
    )

expected_decision = manifest.get("expected_current_decision", {})
if expected_decision.get("status") in {"claim_blocked", "skipped", "unsupported"} and expected_decision.get("support_claimed") is True:
    fail(
        "expected_current_decision cannot claim support for a blocked/skipped/unsupported status",
        freshness.get("contradictory_failure_signature", "vertical_slice_contradictory_claim"),
    )

for input_path in manifest.get("source_of_truth_inputs", []):
    exists_file(input_path, "vertical_slice_missing_source_of_truth")

smoke_suite_path = root / "tests/conformance/real_program_smoke_suite.v1.json"
smoke_suite = load_json(smoke_suite_path, "vertical_slice_missing_smoke_case")
smoke_cases = {}
failure_bundle_policy = {}
if smoke_suite:
    smoke_cases = {case.get("case_id"): case for case in smoke_suite.get("cases", [])}
    failure_bundle_policy = smoke_suite.get("failure_bundle_policy", {})
    actions = failure_bundle_policy.get("next_safe_actions", {})
    symbol_action = actions.get("symbol_missing", {})
    if symbol_action.get("bead") != "bd-bp8fl.10.6":
        fail("symbol_missing next_safe_action must route to bd-bp8fl.10.6", "vertical_slice_failure_bundle_policy")

replay_bindings = manifest.get("replay_bindings", [])
if len(replay_bindings) < 2:
    fail("replay_bindings must include direct and isolated paths", "vertical_slice_replay_paths_missing")

path_kinds = {binding.get("path_kind") for binding in replay_bindings}
if not {"direct", "isolated"}.issubset(path_kinds):
    fail("replay_bindings must include both direct and isolated path_kind values", "vertical_slice_replay_paths_missing")

for binding in replay_bindings:
    executable_or_file(binding.get("script", ""), "vertical_slice_missing_replay_script")
    source_artifact = binding.get("source_artifact")
    if source_artifact:
        exists_file(source_artifact, "vertical_slice_missing_smoke_case")
    case = smoke_cases.get(binding.get("case_id"))
    if case is None:
        fail(f"smoke case missing: {binding.get('case_id')}", "vertical_slice_missing_smoke_case")
        continue
    for key in ["runtime_mode", "replacement_level", "oracle_kind"]:
        if binding.get(key) != case.get(key):
            fail(f"{binding.get('case_id')}: {key} mismatch", "vertical_slice_smoke_case_mismatch")
    if binding.get("smoke_workload_id") != case.get("workload_id"):
        fail(f"{binding.get('case_id')}: workload_id mismatch", "vertical_slice_smoke_case_mismatch")

for fixture in manifest.get("fixture_evidence", []):
    exists_file(fixture.get("manifest", ""), "vertical_slice_missing_fixture_gate")
    executable_or_file(fixture.get("checker", ""), "vertical_slice_missing_fixture_gate")

for gate in manifest.get("claim_gates", []):
    exists_file(gate.get("artifact", ""), "vertical_slice_missing_claim_gate")
    executable_or_file(gate.get("command", ""), "vertical_slice_missing_claim_gate")
    if not gate.get("blocks_missing_or_stale"):
        fail(f"{gate.get('id')}: claim gate must fail closed on missing/stale evidence", "vertical_slice_claim_gate_not_blocking")

negative_ids = {case.get("id") for case in manifest.get("negative_tests", [])}
for required in {
    "missing_selected_workload",
    "stale_source_commit",
    "contradictory_claim",
    "missing_smoke_case",
}:
    if required not in negative_ids:
        fail(f"negative_tests missing {required}", "vertical_slice_negative_coverage_missing")

artifact_index_spec = manifest.get("artifact_index", {})
required_kinds = set(artifact_index_spec.get("must_include_kinds", []))
artifacts = [
    {
        "kind": "manifest",
        "path": rel(manifest_path),
        "source_bead": "bd-bp8fl.10.6",
    },
    {
        "kind": "report",
        "path": rel(report_path),
        "source_bead": "bd-bp8fl.10.6",
    },
    {
        "kind": "log",
        "path": rel(log_path),
        "source_bead": "bd-bp8fl.10.6",
    },
    {
        "kind": "workload_matrix",
        "path": selected.get("source_artifact", ""),
        "source_bead": selected.get("source_bead", "bd-bp8fl.10.1"),
    },
    {
        "kind": "smoke_suite",
        "path": "tests/conformance/real_program_smoke_suite.v1.json",
        "source_bead": "bd-bp8fl.10.2",
    },
    {
        "kind": "failure_bundle_policy",
        "path": "tests/conformance/real_program_smoke_suite.v1.json",
        "source_bead": "bd-bp8fl.10.3",
    },
]
for gate in manifest.get("claim_gates", []):
    artifacts.append(
        {
            "kind": "claim_gate" if gate.get("id") != "compatibility_report" else "compatibility_report",
            "path": gate.get("artifact", ""),
            "source_bead": gate.get("source_bead"),
        }
    )
for fixture in manifest.get("fixture_evidence", []):
    artifacts.append(
        {
            "kind": "fixture_gate",
            "path": fixture.get("manifest", ""),
            "source_bead": fixture.get("source_bead"),
        }
    )

present_kinds = {artifact.get("kind") for artifact in artifacts}
missing_kinds = sorted(required_kinds - present_kinds)
if missing_kinds:
    fail(f"artifact index missing kinds {missing_kinds}", "vertical_slice_artifact_index_missing_kind")

index = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.10.6",
    "source_commit": source_commit,
    "artifacts": artifacts,
}

log_rows = []
for binding in replay_bindings:
    log_rows.append(
        {
            "trace_id": f"bd-bp8fl.10.6::{binding.get('id')}",
            "bead_id": "bd-bp8fl.10.6",
            "scenario_id": binding.get("case_id"),
            "workload_id": selected.get("id"),
            "runtime_mode": binding.get("runtime_mode"),
            "replacement_level": binding.get("replacement_level"),
            "api_family": selected.get("expected_primary_domain"),
            "symbol": ",".join(selected.get("representative_symbols", [])[:4]),
            "oracle_kind": binding.get("oracle_kind"),
            "expected": binding.get("expected_status"),
            "actual": expected_decision.get("status"),
            "errno": None,
            "decision_path": [
                "workload_matrix",
                "smoke_suite",
                "failure_bundle",
                "compatibility_report",
                "claim_gate",
            ],
            "healing_action": "none",
            "latency_ns": 0,
            "artifact_refs": [
                selected.get("source_artifact"),
                binding.get("source_artifact"),
                artifact_index_spec.get("path"),
            ],
            "source_commit": source_commit,
            "target_dir": "target/conformance",
            "failure_signature": expected_decision.get("failure_signature", "none"),
        }
    )

report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.10.6",
    "status": "pass" if not errors else "fail",
    "errors": errors,
    "failure_signatures": sorted(set(failure_signatures)),
    "selected_workload_id": selected.get("id"),
    "selected_smoke_workload_ids": sorted({binding.get("smoke_workload_id") for binding in replay_bindings}),
    "source_commit": source_commit,
    "replay_binding_count": len(replay_bindings),
    "fixture_gate_count": len(manifest.get("fixture_evidence", [])),
    "claim_gate_count": len(manifest.get("claim_gates", [])),
    "negative_test_count": len(manifest.get("negative_tests", [])),
    "artifact_index": rel(index_path),
    "artifact_index_kinds": sorted(present_kinds),
    "expected_current_decision": expected_decision,
    "benchmark_policy": manifest.get("benchmark_policy", {}),
    "log_path": rel(log_path),
}

report_path.parent.mkdir(parents=True, exist_ok=True)
log_path.parent.mkdir(parents=True, exist_ok=True)
index_path.parent.mkdir(parents=True, exist_ok=True)

with index_path.open("w", encoding="utf-8") as handle:
    json.dump(index, handle, indent=2, sort_keys=True)
    handle.write("\n")

with report_path.open("w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")

with log_path.open("w", encoding="utf-8") as handle:
    for row in log_rows:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, indent=2, sort_keys=True))

if errors:
    sys.exit(1)
PY
