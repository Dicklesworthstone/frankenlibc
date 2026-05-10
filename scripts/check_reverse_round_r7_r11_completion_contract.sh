#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RR_R7_R11_COMPLETION_CONTRACT:-$ROOT/tests/conformance/reverse_round_r7_r11_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_RR_R7_R11_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_RR_R7_R11_COMPLETION_REPORT:-$OUT_DIR/reverse_round_r7_r11_completion_contract.report.json}"
LOG="${FRANKENLIBC_RR_R7_R11_COMPLETION_LOG:-$OUT_DIR/reverse_round_r7_r11_completion_contract.log.jsonl}"

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
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "reverse_round_r7_r11_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "reverse_round_r7_r11_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-2a2.1"
COMPLETION_BEAD = "bd-2a2.1.1"
PASS_EVENT = "reverse_round_r7_r11_completion_contract_pass"
FAIL_EVENT = "reverse_round_r7_r11_completion_contract_fail"
REQUIRED_SOURCE_ARTIFACTS = {
    "reverse_round_generator",
    "reverse_round_report",
    "reverse_round_gate",
    "reverse_round_harness",
    "reverse_round_plan",
    "runtime_math_epic_gate",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_ROUNDS = {"R7", "R8", "R9", "R10", "R11"}
REQUIRED_SOURCE_TEST_REFS = {
    "contracts_schema_complete",
    "contracts_all_modules_exist",
    "contracts_all_invariants_specified",
    "contracts_branch_diversity",
    "contracts_legacy_surfaces_anchored",
    "contracts_r7_r11_verification_hooks_capture_all_declared_paths",
    "contracts_report_generates_successfully",
    "gate_script_emits_report_and_structured_log",
    "contracts_reproducible",
    "reverse_round_plan_doc_sections_include_execution_contracts",
}
REQUIRED_COMPLETION_TEST_REFS = {
    "manifest_binds_unit_and_e2e_completion_evidence",
    "checker_validates_reverse_round_r7_r11_completion_contract",
    "checker_emits_completion_report_and_jsonl",
    "checker_rejects_missing_round_binding",
    "checker_rejects_missing_source_test_ref",
    "checker_rejects_unimplemented_telemetry_event",
}
REQUIRED_TELEMETRY_EVENTS = {
    "reverse_round_r7_r11_completion_summary",
    "reverse_round_r7_r11_round_bindings",
    "reverse_round_r7_r11_source_bindings",
    "reverse_round_r7_r11_test_bindings",
    PASS_EVENT,
    FAIL_EVENT,
}
PASS_LOG_EVENTS = [
    "reverse_round_r7_r11_completion_summary",
    "reverse_round_r7_r11_round_bindings",
    "reverse_round_r7_r11_source_bindings",
    "reverse_round_r7_r11_test_bindings",
    PASS_EVENT,
]

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


def read_text(path_text: str, label: str) -> str:
    try:
        return (ROOT / path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


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


def require_set(value: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def require_text(path_text: str, needles: list[str], context: str) -> None:
    source = read_text(path_text, context)
    for needle in needles:
        require(needle in source, f"{context} missing text {needle!r}")


def collect_hook_paths(round_data: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    hooks = round_data.get("verification_strategy", [])
    if not isinstance(hooks, list):
        err("round verification_strategy must be an array")
        return paths
    for hook in hooks:
        if not isinstance(hook, dict):
            err("verification_strategy entries must be objects")
            continue
        path = hook.get("path")
        if isinstance(path, str) and path:
            paths.add(path)
            require(hook.get("path_exists") is True, f"verification hook path must exist: {path}")
        hook_paths = hook.get("paths", [])
        if isinstance(hook_paths, list):
            for entry in hook_paths:
                if not isinstance(entry, dict):
                    err("verification_strategy paths entries must be objects")
                    continue
                nested_path = entry.get("path")
                if isinstance(nested_path, str) and nested_path:
                    paths.add(nested_path)
                    require(entry.get("path_exists") is True, f"verification nested path must exist: {nested_path}")
    return paths


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
missing_sources = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
if missing_sources:
    err(f"source_artifacts missing {','.join(missing_sources)}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

rr_contract = evidence.get("required_reverse_round_contract", {})
if not isinstance(rr_contract, dict):
    err("completion_debt_evidence.required_reverse_round_contract must be an object")
    rr_contract = {}

required_rounds = rr_contract.get("required_rounds", {})
if not isinstance(required_rounds, dict):
    err("required_reverse_round_contract.required_rounds must be an object")
    required_rounds = {}
missing_rounds = sorted(REQUIRED_ROUNDS - set(required_rounds))
if missing_rounds:
    err(f"required_reverse_round_contract.required_rounds missing {','.join(missing_rounds)}")

require_set(
    rr_contract.get("required_gate_log_fields"),
    {"trace_id", "mode", "api_family", "symbol", "decision_path", "healing_action", "errno", "latency_ns", "artifact_refs"},
    "required_reverse_round_contract.required_gate_log_fields",
)
require_set(
    rr_contract.get("required_cross_round_integrations"),
    {"loader_allocator", "loader_resolver", "loader_time64_bridge"},
    "required_reverse_round_contract.required_cross_round_integrations",
)
require_set(
    rr_contract.get("required_milestones"),
    {"bootstrap_surface", "loader_temporal_policy_surface"},
    "required_reverse_round_contract.required_milestones",
)

telemetry_events = set(as_string_list(evidence.get("telemetry_events"), "completion_debt_evidence.telemetry_events"))
missing_events = sorted(REQUIRED_TELEMETRY_EVENTS - telemetry_events)
if missing_events:
    err(f"completion_debt_evidence.telemetry_events missing {','.join(missing_events)}")
unknown_events = sorted(telemetry_events - REQUIRED_TELEMETRY_EVENTS)
if unknown_events:
    err(f"completion_debt_evidence.telemetry_events has unsupported event(s) {','.join(unknown_events)}")

for impl_ref in evidence.get("implementation_refs", []):
    if not isinstance(impl_ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = impl_ref.get("path")
    needles = impl_ref.get("required_text")
    if not isinstance(path_text, str):
        err("implementation_refs entry missing path")
        continue
    require((ROOT / path_text).exists(), f"implementation ref path missing: {path_text}")
    require_text(path_text, as_string_list(needles, f"implementation_refs.{impl_ref.get('id', path_text)}.required_text"), f"implementation ref {path_text}")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    err("completion_debt_evidence.test_sources must be an object")
    test_sources = {}
source_tests = test_sources.get("reverse_round_harness", {})
completion_tests = test_sources.get("completion_harness_test", {})
if not isinstance(source_tests, dict):
    err("test_sources.reverse_round_harness must be an object")
    source_tests = {}
if not isinstance(completion_tests, dict):
    err("test_sources.completion_harness_test must be an object")
    completion_tests = {}
require_set(source_tests.get("required_test_refs"), REQUIRED_SOURCE_TEST_REFS, "test_sources.reverse_round_harness.required_test_refs")
require_set(completion_tests.get("required_test_refs"), REQUIRED_COMPLETION_TEST_REFS, "test_sources.completion_harness_test.required_test_refs")

report_path = source_artifacts.get("reverse_round_report")
rr_report = load_json(ROOT / str(report_path), "reverse_round_report") if isinstance(report_path, str) else {}
require(rr_report.get("schema_version") == rr_contract.get("report_schema_version"), "reverse-round report schema_version mismatch")
require(rr_report.get("bead") == rr_contract.get("bead"), "reverse-round report bead mismatch")
require(isinstance(rr_report.get("report_hash"), str) and rr_report.get("report_hash"), "reverse-round report_hash missing")

summary = rr_report.get("summary", {})
if not isinstance(summary, dict):
    err("reverse-round summary must be an object")
    summary = {}
expected_summary = rr_contract.get("summary", {})
if not isinstance(expected_summary, dict):
    err("required_reverse_round_contract.summary must be an object")
    expected_summary = {}
for field, expected in expected_summary.items():
    require(summary.get(field) == expected, f"reverse-round summary.{field} mismatch")

round_results = rr_report.get("round_results", {})
if not isinstance(round_results, dict):
    err("reverse-round round_results must be an object")
    round_results = {}
missing_report_rounds = sorted(REQUIRED_ROUNDS - set(round_results))
if missing_report_rounds:
    err(f"reverse-round report missing rounds {','.join(missing_report_rounds)}")

for round_id in sorted(REQUIRED_ROUNDS):
    expected_round = required_rounds.get(round_id, {})
    actual_round = round_results.get(round_id, {})
    if not isinstance(expected_round, dict):
        err(f"required_rounds.{round_id} must be an object")
        expected_round = {}
    if not isinstance(actual_round, dict):
        err(f"round_results.{round_id} must be an object")
        actual_round = {}
    require(actual_round.get("name") == expected_round.get("name"), f"{round_id} name mismatch")
    expected_surfaces = set(as_string_list(expected_round.get("legacy_surfaces"), f"required_rounds.{round_id}.legacy_surfaces"))
    actual_surfaces = set(as_string_list(actual_round.get("legacy_surfaces"), f"round_results.{round_id}.legacy_surfaces"))
    missing_surfaces = sorted(expected_surfaces - actual_surfaces)
    if missing_surfaces:
        err(f"{round_id} missing legacy_surfaces {','.join(missing_surfaces)}")
    expected_families = set(as_string_list(expected_round.get("math_families"), f"required_rounds.{round_id}.math_families"))
    families = actual_round.get("math_families", {})
    if not isinstance(families, dict):
        err(f"round_results.{round_id}.math_families must be an object")
        families = {}
    missing_families = sorted(expected_families - set(families))
    if missing_families:
        err(f"{round_id} missing math_families {','.join(missing_families)}")
    for family_id in expected_families & set(families):
        family = families.get(family_id)
        if isinstance(family, dict):
            require(family.get("module_exists") is True, f"{round_id}.{family_id} module_exists must be true")
            require(isinstance(family.get("invariant"), str) and family.get("invariant"), f"{round_id}.{family_id} invariant missing")
        else:
            err(f"{round_id}.{family_id} family entry must be an object")
    branch = actual_round.get("branch_diversity", {})
    if not isinstance(branch, dict):
        err(f"round_results.{round_id}.branch_diversity must be an object")
        branch = {}
    require(int(branch.get("class_count", 0)) >= 3, f"{round_id} branch_diversity.class_count must be >= 3")
    require(branch.get("passes_diversity") is True, f"{round_id} branch diversity must pass")
    require(len(actual_round.get("implementation_plan", [])) >= 3, f"{round_id} implementation_plan must have at least 3 entries")
    hook_paths = collect_hook_paths(actual_round)
    expected_paths = set(as_string_list(expected_round.get("verification_paths"), f"required_rounds.{round_id}.verification_paths"))
    missing_paths = sorted(expected_paths - hook_paths)
    if missing_paths:
        err(f"{round_id} missing verification_paths {','.join(missing_paths)}")

cross_round = rr_report.get("cross_round_integrations", {})
if not isinstance(cross_round, dict):
    err("reverse-round cross_round_integrations must be an object")
    cross_round = {}
for integration_id in as_string_list(rr_contract.get("required_cross_round_integrations"), "required_cross_round_integrations"):
    integration = cross_round.get(integration_id)
    if not isinstance(integration, dict):
        err(f"cross_round_integrations missing {integration_id}")
        continue
    require(integration.get("passes_integration") is True, f"cross-round integration {integration_id} must pass")

milestones = rr_report.get("milestone_branch_diversity", {})
if not isinstance(milestones, dict):
    err("reverse-round milestone_branch_diversity must be an object")
    milestones = {}
for milestone_id in as_string_list(rr_contract.get("required_milestones"), "required_milestones"):
    milestone = milestones.get(milestone_id)
    if not isinstance(milestone, dict):
        err(f"milestone_branch_diversity missing {milestone_id}")
        continue
    require(milestone.get("passes_milestone") is True, f"milestone {milestone_id} must pass")

gate_text = read_text(str(source_artifacts.get("reverse_round_gate", "")), "reverse_round_gate")
for field in as_string_list(rr_contract.get("required_gate_log_fields"), "required_gate_log_fields"):
    require(field in gate_text, f"reverse_round_gate missing log field {field}")

missing_bindings = manifest.get("missing_item_bindings", [])
if not isinstance(missing_bindings, list):
    err("missing_item_bindings must be an array")
    missing_bindings = []
binding_by_id = {item.get("id"): item for item in missing_bindings if isinstance(item, dict)}
unit_binding = binding_by_id.get("tests.unit.primary")
e2e_binding = binding_by_id.get("tests.e2e.primary")
if not isinstance(unit_binding, dict):
    err("missing_item_bindings missing tests.unit.primary")
    unit_binding = {}
if not isinstance(e2e_binding, dict):
    err("missing_item_bindings missing tests.e2e.primary")
    e2e_binding = {}
require(unit_binding.get("kind") == "unit", "tests.unit.primary kind must be unit")
require(e2e_binding.get("kind") == "e2e", "tests.e2e.primary kind must be e2e")
require_set(unit_binding.get("required_test_refs"), REQUIRED_COMPLETION_TEST_REFS | {
    "contracts_schema_complete",
    "contracts_all_modules_exist",
    "contracts_all_invariants_specified",
    "contracts_branch_diversity",
    "contracts_legacy_surfaces_anchored",
    "contracts_r7_r11_verification_hooks_capture_all_declared_paths",
}, "tests.unit.primary.required_test_refs")
require_set(e2e_binding.get("required_test_refs"), {
    "contracts_report_generates_successfully",
    "gate_script_emits_report_and_structured_log",
    "contracts_reproducible",
    "reverse_round_plan_doc_sections_include_execution_contracts",
    "checker_validates_reverse_round_r7_r11_completion_contract",
}, "tests.e2e.primary.required_test_refs")

source_commit = git_head()
status = "fail" if errors else "pass"
failure_signature = "validation_errors" if errors else "none"
event_names = PASS_LOG_EVENTS if not errors else [
    "reverse_round_r7_r11_completion_summary",
    FAIL_EVENT,
]
artifact_refs = {
    key: value
    for key, value in sorted(source_artifacts.items())
    if isinstance(value, str)
}
test_refs = sorted(REQUIRED_SOURCE_TEST_REFS | REQUIRED_COMPLETION_TEST_REFS)
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

rows = []
for event in event_names:
    rows.append(
        {
            "timestamp": timestamp,
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": "pass" if not errors else "fail",
            "source_commit": source_commit,
            "schema_version": EXPECTED_REPORT_SCHEMA,
            "artifact_refs": artifact_refs,
            "test_refs": test_refs,
            "round_ids": sorted(REQUIRED_ROUNDS),
            "failure_signature": failure_signature,
        }
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "generated_at_utc": timestamp,
    "source_commit": source_commit,
    "status": status,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "summary": {
        "bound_rounds": len(REQUIRED_ROUNDS),
        "rounds_verified": summary.get("rounds_verified"),
        "modules_found": summary.get("modules_found"),
        "modules_missing": summary.get("modules_missing"),
        "invariants_specified": summary.get("invariants_specified"),
        "invariants_total": summary.get("invariants_total"),
        "math_class_count": summary.get("math_class_count"),
        "cross_round_checks_passing": summary.get("cross_round_checks_passing"),
        "cross_round_checks_total": summary.get("cross_round_checks_total"),
        "milestones_diverse": summary.get("milestones_diverse"),
        "milestones_verified": summary.get("milestones_verified"),
        "source_artifacts": len(artifact_refs),
        "test_refs": len(test_refs),
        "errors": len(errors),
    },
    "events": event_names,
    "artifact_refs": artifact_refs,
    "test_refs": test_refs,
    "round_ids": sorted(REQUIRED_ROUNDS),
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

if errors:
    print("FAIL: reverse-round R7-R11 completion contract failed")
    for message in errors:
        print(f"  - {message}")
    sys.exit(1)

print("PASS: reverse-round R7-R11 completion contract validated 5 rounds")
PY
