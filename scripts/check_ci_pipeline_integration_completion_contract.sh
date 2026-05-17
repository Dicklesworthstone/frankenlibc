#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CI_PIPELINE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/ci_pipeline_integration_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CI_PIPELINE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_CI_PIPELINE_COMPLETION_REPORT:-$OUT_DIR/ci_pipeline_integration_completion_contract.report.json}"
LOG="${FRANKENLIBC_CI_PIPELINE_COMPLETION_LOG:-$OUT_DIR/ci_pipeline_integration_completion_contract.log.jsonl}"

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
import re
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "ci_pipeline_integration_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "ci_pipeline_integration_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-3f6f"
COMPLETION_BEAD = "bd-3f6f.1"

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


def source_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def validate_sources(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}

    texts: dict[str, str] = {}
    for artifact_id, path_value in artifacts.items():
        if not isinstance(path_value, str) or not path_value:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        path = ROOT / path_value
        require(path.exists(), f"source artifact missing: {artifact_id}: {path_value}")
        if path.suffix in {".sh", ".yml", ".yaml", ".rs", ".py"} or path.name == "ci.yml":
            texts[artifact_id] = source_text(path_value, artifact_id)
    return texts


def validate_workflow(manifest: dict[str, Any], workflow: str) -> dict[str, Any]:
    required = manifest.get("required_source_contract", {})
    if not isinstance(required, dict):
        err("required_source_contract must be an object")
        required = {}

    jobs = as_string_list(required.get("workflow_jobs"), "required_source_contract.workflow_jobs")
    for job in jobs:
        require(
            re.search(rf"(?m)^  {re.escape(job)}:\s*$", workflow) is not None,
            f"workflow job missing: {job}",
        )

    markers = as_string_list(required.get("workflow_markers"), "required_source_contract.workflow_markers")
    for marker in markers:
        require(marker in workflow, f"workflow marker missing: {marker}")

    targets = as_string_list(required.get("fuzz_targets"), "required_source_contract.fuzz_targets")
    for target in targets:
        require(target in workflow, f"fuzz target missing from workflow: {target}")
    require("FUZZ_RUNS_PER_TARGET:-1000000" in workflow, "workflow missing 1,000,000 fuzz run budget default")
    require("FUZZ_TIMEOUT_SECONDS:-1800" in workflow, "workflow missing fuzz timeout budget default")

    upload_names = as_string_list(required.get("artifact_upload_names"), "required_source_contract.artifact_upload_names")
    for upload_name in upload_names:
        require(upload_name in workflow, f"artifact upload missing: {upload_name}")
    require(workflow.count("uses: actions/upload-artifact@v4") >= len(upload_names), "workflow must use upload-artifact for every artifact lane")
    require(workflow.count("if: always()") >= len(upload_names), "artifact uploads must be guarded with if: always()")

    artifact_markers = as_string_list(required.get("artifact_path_markers"), "required_source_contract.artifact_path_markers")
    for marker in artifact_markers:
        require(marker in workflow, f"artifact path marker missing: {marker}")

    return {
        "workflow_jobs": len(jobs),
        "workflow_markers": len(markers),
        "fuzz_targets": len(targets),
        "artifact_uploads": len(upload_names),
        "artifact_paths": len(artifact_markers),
    }


def validate_ci_script(manifest: dict[str, Any], ci_script: str) -> dict[str, Any]:
    required = manifest.get("required_source_contract", {})
    if not isinstance(required, dict):
        required = {}
    markers = as_string_list(required.get("ci_script_markers"), "required_source_contract.ci_script_markers")
    for marker in markers:
        require(marker in ci_script, f"ci script marker missing: {marker}")
    require("FRANKENLIBC_EXTENDED_GATES" in ci_script, "ci.sh must keep extended gate switch")
    require("FRANKENLIBC_FORCE_LOCAL_BENCHMARK_GATE" in ci_script, "ci.sh must keep deterministic benchmark fallback switch")
    require("run_remote_cargo()" in ci_script, "ci.sh must define run_remote_cargo wrapper")
    require("RCH_REQUIRE_REMOTE=1" in ci_script, "ci.sh cargo wrapper must require remote RCH")
    require("rch exec -- env" in ci_script, "ci.sh cargo wrapper must launch through rch exec -- env")
    require("CARGO_TARGET_DIR=" in ci_script, "ci.sh cargo wrapper must isolate CARGO_TARGET_DIR")
    require(
        "bash scripts/check_ci_rch_cargo_policy.sh --validate-only" in ci_script,
        "ci.sh must run ci RCH cargo policy checker before cargo-backed gates",
    )
    for subcommand in ("check", "clippy", "test", "build"):
        require(
            f"run_remote_cargo {subcommand}" in ci_script,
            f"ci.sh must route cargo {subcommand} through run_remote_cargo",
        )
    return {"ci_script_markers": len(markers)}


def validate_missing_item_bindings(manifest: dict[str, Any]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        bindings = []
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    required_ids = {
        "tests.unit.primary",
        "tests.e2e.primary",
        "tests.fuzz.primary",
        "tests.golden.primary",
        "tests.conformance.primary",
    }
    for required_id in sorted(required_ids):
        require(required_id in ids, f"missing item binding {required_id}")

    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        binding_id = str(binding.get("id", "?"))
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{binding_id}.required_commands")
        as_string_list(binding.get("required_test_refs"), f"missing_item_bindings.{binding_id}.required_test_refs")
        if binding_id == "tests.unit.primary":
            require(any("rch exec -- cargo test" in command for command in commands), "unit binding must reference rch cargo test")
        if binding_id == "tests.e2e.primary":
            require(any("scripts/ci.sh" in command for command in commands), "e2e binding must reference scripts/ci.sh")
            require(any("ld_preload_smoke" in command for command in commands), "e2e binding must reference ld_preload smoke")
        if binding_id == "tests.fuzz.primary":
            require(any("cargo fuzz run" in command for command in commands), "fuzz binding must reference cargo fuzz run")
            require(any("check_fuzz_phase2_targets" in command for command in commands), "fuzz binding must reference phase2 gate")
        if binding_id == "tests.golden.primary":
            require(any("conformance_golden_gate" in command for command in commands), "golden binding must reference conformance golden gate")
            require(any("snapshot_gate" in command for command in commands), "golden binding must reference snapshot gate")
        if binding_id == "tests.conformance.primary":
            require(any("check_symbol_fixture_coverage" in command for command in commands), "conformance binding must reference symbol fixture coverage")
    return {"binding_count": len(bindings), "binding_ids": sorted(str(item) for item in ids)}


def validate_test_sources(manifest: dict[str, Any]) -> dict[str, Any]:
    sources = manifest.get("completion_debt_evidence", {}).get("test_sources", {})
    if not isinstance(sources, dict) or not sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return {"test_source_count": 0, "required_test_refs": 0}
    required_count = 0
    for source_id, source in sources.items():
        if not isinstance(source, dict):
            err(f"test source {source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"test source {source_id} must include path")
            continue
        text = source_text(path_text, source_id)
        for test_ref in as_string_list(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            required_count += 1
            require(test_ref in text, f"test source {source_id} missing required test ref {test_ref}")
    return {"test_source_count": len(sources), "required_test_refs": required_count}


def validate_source_summaries(manifest: dict[str, Any]) -> dict[str, Any]:
    summaries = manifest.get("completion_debt_evidence", {}).get("expected_source_summaries", {})
    if not isinstance(summaries, dict):
        err("completion_debt_evidence.expected_source_summaries must be an object")
        summaries = {}
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict):
        artifacts = {}

    phase1 = load_json(ROOT / str(artifacts.get("fuzz_phase1_report", "")), "fuzz phase1 report")
    phase1_summary = phase1.get("summary", {}) if isinstance(phase1.get("summary"), dict) else {}
    phase1_expected = summaries.get("fuzz_phase1", {}) if isinstance(summaries.get("fuzz_phase1"), dict) else {}
    for field, json_field in [
        ("min_total_targets", "total_targets"),
        ("min_functional_targets", "functional_targets"),
        ("min_smoke_viable_targets", "smoke_viable_targets"),
        ("min_symbols_covered", "total_symbols_covered"),
    ]:
        require(
            int(phase1_summary.get(json_field, 0)) >= int(phase1_expected.get(field, 0)),
            f"fuzz_phase1 {json_field} below contract minimum",
        )

    phase2 = load_json(ROOT / str(artifacts.get("fuzz_phase2_report", "")), "fuzz phase2 report")
    phase2_summary = phase2.get("summary", {}) if isinstance(phase2.get("summary"), dict) else {}
    phase2_expected = summaries.get("fuzz_phase2", {}) if isinstance(summaries.get("fuzz_phase2"), dict) else {}
    for field, json_field in [
        ("min_total_targets", "total_targets"),
        ("min_functional_targets", "functional_targets"),
        ("min_smoke_viable_targets", "smoke_viable_targets"),
        ("min_symbols_covered", "total_symbols_covered"),
    ]:
        require(
            int(phase2_summary.get(json_field, 0)) >= int(phase2_expected.get(field, 0)),
            f"fuzz_phase2 {json_field} below contract minimum",
        )
    coverage = phase2.get("coverage_summary", {}) if isinstance(phase2.get("coverage_summary"), dict) else {}
    families = set(as_string_list(coverage.get("transition_families"), "fuzz_phase2.coverage_summary.transition_families"))
    for family in as_string_list(phase2_expected.get("required_transition_families"), "fuzz_phase2.required_transition_families"):
        require(family in families, f"fuzz_phase2 missing transition family {family}")
    policy = phase2.get("nightly_policy", {}) if isinstance(phase2.get("nightly_policy"), dict) else {}
    require(
        int(policy.get("runs_per_target", 0)) >= int(phase2_expected.get("min_runs_per_target", 0)),
        "fuzz_phase2 nightly_policy.runs_per_target below contract minimum",
    )

    golden = load_json(ROOT / str(artifacts.get("golden_fixture_report", "")), "golden fixture report")
    golden_summary = golden.get("summary", {}) if isinstance(golden.get("summary"), dict) else {}
    golden_expected = summaries.get("golden_fixture", {}) if isinstance(summaries.get("golden_fixture"), dict) else {}
    require(int(golden_summary.get("total", 0)) >= int(golden_expected.get("min_total", 0)), "golden fixture total below contract minimum")
    require(int(golden_summary.get("failed", -1)) == int(golden_expected.get("required_failed", 0)), "golden fixture failed count violates contract")

    matrix = load_json(ROOT / str(artifacts.get("conformance_matrix", "")), "conformance matrix")
    matrix_summary = matrix.get("summary", {}) if isinstance(matrix.get("summary"), dict) else {}
    matrix_expected = summaries.get("conformance_matrix", {}) if isinstance(summaries.get("conformance_matrix"), dict) else {}
    require(int(matrix_summary.get("total_cases", 0)) >= int(matrix_expected.get("min_total_cases", 0)), "conformance matrix total_cases below contract minimum")
    require(int(matrix_summary.get("failed", -1)) == int(matrix_expected.get("required_failed", 0)), "conformance matrix failed count violates contract")
    require(int(matrix_summary.get("errors", -1)) == int(matrix_expected.get("required_errors", 0)), "conformance matrix error count violates contract")

    return {
        "phase1_targets": int(phase1_summary.get("total_targets", 0)),
        "phase2_targets": int(phase2_summary.get("total_targets", 0)),
        "golden_total": int(golden_summary.get("total", 0)),
        "conformance_total_cases": int(matrix_summary.get("total_cases", 0)),
    }


def validate_telemetry(manifest: dict[str, Any], report_events: list[dict[str, Any]]) -> dict[str, Any]:
    telemetry = manifest.get("telemetry_contract", {})
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        telemetry = {}
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    emitted = {str(event.get("event")) for event in report_events}
    for event in sorted(required_events):
        require(event in emitted, f"telemetry event missing: {event}")
    required_fields = as_string_list(telemetry.get("required_fields"), "telemetry_contract.required_fields")
    for event in report_events:
        for field in required_fields:
            require(field in event, f"telemetry event {event.get('event')} missing field {field}")
    return {"required_events": len(required_events), "required_fields": len(required_fields)}


def event(name: str, status: str, outcome: str, artifact_refs: list[str], **extra: Any) -> dict[str, Any]:
    payload = {
        "event": name,
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": outcome,
        "artifact_refs": artifact_refs,
    }
    payload.update(extra)
    return payload


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

texts = validate_sources(manifest)
workflow_summary = validate_workflow(manifest, texts.get("workflow", ""))
ci_summary = validate_ci_script(manifest, texts.get("ci_script", ""))
binding_summary = validate_missing_item_bindings(manifest)
test_summary = validate_test_sources(manifest)
source_summary = validate_source_summaries(manifest)

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    ".github/workflows/ci.yml",
    "scripts/ci.sh",
]
events = [
    event(
        "ci_pipeline_completion_summary",
        "pass",
        "completion_contract_checked",
        artifact_refs,
        workflow=workflow_summary,
        ci_script=ci_summary,
        source_summaries=source_summary,
    ),
    event(
        "ci_pipeline_lane_bindings",
        "pass",
        "missing_items_bound",
        artifact_refs,
        bindings=binding_summary,
        tests=test_summary,
    ),
    event(
        "ci_pipeline_completion_contract_pass",
        "pass",
        "ready_for_closeout",
        artifact_refs,
        checked_at_unix=int(time.time()),
    ),
]
telemetry_summary = validate_telemetry(manifest, events)

status = "fail" if errors else "pass"
if status == "fail":
    events = [
        event(
            "ci_pipeline_completion_contract_fail",
            "fail",
            "contract_rejected",
            artifact_refs,
            error_count=len(errors),
        )
    ]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": status,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "errors": errors,
    "workflow_summary": workflow_summary,
    "ci_script_summary": ci_summary,
    "binding_summary": binding_summary,
    "test_summary": test_summary,
    "source_summary": source_summary,
    "telemetry_summary": telemetry_summary,
    "events": events,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")

if errors:
    print(f"ci_pipeline_integration_completion_contract: FAIL errors={len(errors)}")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "ci_pipeline_integration_completion_contract: PASS "
    f"jobs={workflow_summary['workflow_jobs']} "
    f"fuzz_targets={workflow_summary['fuzz_targets']} "
    f"bindings={binding_summary['binding_count']} "
    f"conformance_cases={source_summary['conformance_total_cases']}"
)
PY
