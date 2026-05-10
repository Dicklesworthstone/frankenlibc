#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_HOT_PATH_PROFILE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/hot_path_profile_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_HOT_PATH_PROFILE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_HOT_PATH_PROFILE_COMPLETION_REPORT:-$OUT_DIR/hot_path_profile_completion_contract.report.json}"
LOG="${FRANKENLIBC_HOT_PATH_PROFILE_COMPLETION_LOG:-$OUT_DIR/hot_path_profile_completion_contract.log.jsonl}"

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
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "hot_path_profile_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "hot_path_profile_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-30o.1"
COMPLETION_BEAD = "bd-30o.1.1"

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


def run_checker(path_text: str, label: str) -> None:
    proc = subprocess.run(
        ["bash", path_text],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err(
            f"{label} failed: exit={proc.returncode} "
            f"stdout={proc.stdout[:1200]!r} stderr={proc.stderr[:1200]!r}"
        )


def numeric_summary(value: dict[str, Any], field: str) -> float | None:
    actual = value.get(field)
    if isinstance(actual, (int, float)):
        return float(actual)
    err(f"summary field {field} must be numeric")
    return None


def validate_profile_artifact_contract(spec: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    artifacts = spec.get("profile_artifacts", {})
    if not isinstance(artifacts, dict):
        err("perf_baseline_spec.profile_artifacts must be an object")
        artifacts = {}

    required_files = set(as_string_list(required.get("required_profile_run_files"), "required_profile_run_files"))
    actual_files = set(as_string_list(artifacts.get("required_files"), "profile_artifacts.required_files"))
    for item in sorted(required_files):
        require(item in actual_files, f"profile_artifacts.required_files missing {item}")

    required_per_target = set(
        as_string_list(required.get("required_per_target_patterns"), "required_per_target_patterns")
    )
    actual_per_target = set(
        as_string_list(artifacts.get("per_target_required"), "profile_artifacts.per_target_required")
    )
    for item in sorted(required_per_target):
        require(item in actual_per_target, f"profile_artifacts.per_target_required missing {item}")

    structured = artifacts.get("structured_reports", {})
    if not isinstance(structured, dict):
        err("profile_artifacts.structured_reports must be an object")
        structured = {}
    profile_fields = set(
        as_string_list(
            structured.get("profile_report_v1", {}).get("required_fields")
            if isinstance(structured.get("profile_report_v1"), dict)
            else None,
            "profile_report_v1.required_fields",
        )
    )
    hotspot_fields = set(
        as_string_list(
            structured.get("hotspot_opportunity_matrix_v1", {}).get("required_fields")
            if isinstance(structured.get("hotspot_opportunity_matrix_v1"), dict)
            else None,
            "hotspot_opportunity_matrix_v1.required_fields",
        )
    )
    for item in as_string_list(required.get("required_profile_report_fields"), "required_profile_report_fields"):
        require(item in profile_fields, f"profile_report_v1.required_fields missing {item}")
    for item in as_string_list(required.get("required_hotspot_matrix_fields"), "required_hotspot_matrix_fields"):
        require(item in hotspot_fields, f"hotspot_opportunity_matrix_v1.required_fields missing {item}")

    return {
        "required_file_count": len(actual_files),
        "per_target_pattern_count": len(actual_per_target),
        "profile_report_field_count": len(profile_fields),
        "hotspot_matrix_field_count": len(hotspot_fields),
    }


def validate_perf_baseline_summary(spec: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    summary = spec.get("summary", {})
    if not isinstance(summary, dict):
        err("perf_baseline_spec.summary must be an object")
        summary = {}
    expected = required.get("perf_baseline_summary_exact", {})
    if not isinstance(expected, dict):
        err("required_source_contract.perf_baseline_summary_exact must be an object")
        expected = {}
    for field, expected_value in expected.items():
        require(
            summary.get(field) == expected_value,
            f"perf_baseline_spec.summary.{field}: expected={expected_value!r} actual={summary.get(field)!r}",
        )

    modes = set()
    suites = spec.get("benchmark_suites", {}).get("suites", [])
    if not isinstance(suites, list):
        err("perf_baseline_spec.benchmark_suites.suites must be an array")
        suites = []
    for suite in suites:
        if not isinstance(suite, dict):
            err("benchmark suite entries must be objects")
            continue
        suite_modes = suite.get("modes", [])
        if not isinstance(suite_modes, list) or not suite_modes:
            err(f"benchmark suite {suite.get('id', '?')} missing modes")
            continue
        modes.update(str(mode) for mode in suite_modes if isinstance(mode, str))

    for mode in as_string_list(required.get("required_modes"), "required_modes"):
        require(mode in modes, f"perf baseline suites missing required mode {mode}")

    return {
        "total_suites": summary.get("total_suites"),
        "total_benchmarks": summary.get("total_benchmarks"),
        "modes": sorted(modes),
        "profile_required_files": summary.get("profile_required_files"),
    }


def validate_opportunity_matrix(matrix: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    scoring = matrix.get("scoring", {})
    if not isinstance(scoring, dict):
        err("opportunity_matrix.scoring must be an object")
        scoring = {}
    dimensions = scoring.get("dimensions", {})
    if not isinstance(dimensions, dict):
        err("opportunity_matrix.scoring.dimensions must be an object")
        dimensions = {}
    for dim in as_string_list(required.get("required_opportunity_dimensions"), "required_opportunity_dimensions"):
        require(dim in dimensions, f"opportunity matrix missing scoring dimension {dim}")

    entries = matrix.get("entries", [])
    if not isinstance(entries, list) or not entries:
        err("opportunity_matrix.entries must be non-empty")
        entries = []
    threshold = scoring.get("threshold")
    require(isinstance(threshold, (int, float)), "opportunity_matrix.scoring.threshold must be numeric")
    for entry in entries:
        if not isinstance(entry, dict):
            err("opportunity matrix entries must be objects")
            continue
        entry_id = entry.get("id", "?")
        for field in [
            "id",
            "title",
            "impact",
            "confidence",
            "effort",
            "score",
            "status",
            "golden_output_verification",
            "rollback_instructions",
            "attribution_metadata",
        ]:
            require(field in entry, f"opportunity entry {entry_id} missing {field}")
        score = entry.get("score")
        status = entry.get("status")
        if status in {"eligible", "in_progress"} and isinstance(threshold, (int, float)):
            require(
                isinstance(score, (int, float)) and score >= threshold,
                f"opportunity entry {entry_id} status={status} below threshold",
            )

    return {"entry_count": len(entries), "threshold": threshold}


def validate_hot_path_report(report: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    require(report.get("schema_version") == "v1", "hot_path_profile_report.schema_version must be v1")
    require(report.get("bead") == "bd-bp8fl.8.3", "hot_path_profile_report bead must be bd-bp8fl.8.3")

    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        err("hot_path_profile_report.summary must be an object")
        summary = {}
    min_contract = required.get("required_profile_summary_min", {})
    if not isinstance(min_contract, dict):
        err("required_profile_summary_min must be an object")
        min_contract = {}
    for field, minimum in min_contract.items():
        if field == "optimization_seed_count":
            actual = len(report.get("optimization_beads_to_create", [])) if isinstance(report.get("optimization_beads_to_create"), list) else 0
        else:
            actual = numeric_summary(summary, field)
        if isinstance(actual, (int, float)):
            require(actual >= minimum, f"hot path report {field}: need >= {minimum}, got {actual}")

    families = set(as_string_list(summary.get("families"), "hot_path_profile_report.summary.families"))
    for family in as_string_list(required.get("required_profile_families"), "required_profile_families"):
        require(family in families, f"hot path report missing required family {family}")

    records = report.get("profile_records", [])
    if not isinstance(records, list) or not records:
        err("hot_path_profile_report.profile_records must be non-empty")
        records = []
    required_profile_fields = set(as_string_list(report.get("required_profile_fields"), "required_profile_fields"))
    required_log_fields = set(as_string_list(report.get("required_log_fields"), "required_log_fields"))

    last_score = float("inf")
    seen: set[str] = set()
    has_strict = False
    has_hardened = False
    has_membrane_validate = False
    for record in records:
        if not isinstance(record, dict):
            err("profile_records entries must be objects")
            continue
        profile_id = record.get("profile_id")
        require(isinstance(profile_id, str) and bool(profile_id), "profile record missing profile_id")
        if isinstance(profile_id, str):
            require(profile_id not in seen, f"duplicate profile_id {profile_id}")
            seen.add(profile_id)
        missing = required_profile_fields - set(record)
        require(not missing, f"profile record {profile_id} missing fields {sorted(missing)}")
        score = record.get("hotness_score")
        if isinstance(score, (int, float)):
            require(score <= last_score, f"profile records not sorted by hotness_score at {profile_id}")
            last_score = float(score)
        else:
            err(f"profile record {profile_id} hotness_score must be numeric")
        mode = record.get("runtime_mode")
        has_strict = has_strict or mode == "strict"
        has_hardened = has_hardened or mode == "hardened"
        require(mode in {"strict", "hardened"}, f"profile record {profile_id} has invalid runtime_mode")
        if record.get("api_family") == "membrane" and str(record.get("symbol", "")).startswith("validate_"):
            has_membrane_validate = True
        require(isinstance(record.get("baseline_artifact"), dict), f"profile record {profile_id} missing baseline_artifact object")
        require(bool(record.get("parity_proof_refs")), f"profile record {profile_id} missing parity proof refs")
        require(bool(record.get("artifact_refs")), f"profile record {profile_id} missing artifact refs")

    require(has_strict, "profile records missing strict runtime mode")
    require(has_hardened, "profile records missing hardened runtime mode")
    require(has_membrane_validate, "profile records missing membrane validate_* hot paths")

    return {
        "profile_record_count": len(records),
        "families": sorted(families),
        "required_profile_field_count": len(required_profile_fields),
        "required_log_field_count": len(required_log_fields),
        "optimization_seed_count": len(report.get("optimization_beads_to_create", []))
        if isinstance(report.get("optimization_beads_to_create"), list)
        else 0,
    }


def validate_test_sources(manifest: dict[str, Any]) -> None:
    sources = manifest.get("completion_debt_evidence", {}).get("test_sources", {})
    if not isinstance(sources, dict) or not sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return
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
            require(
                f"fn {test_ref}" in text or test_ref in text,
                f"test source {source_id} missing required test ref {test_ref}",
            )


def validate_missing_item_bindings(manifest: dict[str, Any]) -> dict[str, Any]:
    bindings = manifest.get("missing_item_bindings", [])
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        bindings = []
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    for required_id in ["tests.unit.primary", "tests.e2e.primary", "telemetry.primary"]:
        require(required_id in ids, f"missing item binding {required_id}")
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        binding_id = binding.get("id", "?")
        as_string_list(binding.get("required_test_refs"), f"missing_item_bindings.{binding_id}.required_test_refs")
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{binding_id}.required_commands")
        if binding_id in {"tests.unit.primary", "tests.e2e.primary"}:
            require(any("rch exec -- cargo test" in cmd or cmd.startswith("bash scripts/") for cmd in commands), f"{binding_id} missing executable proof command")
    return {"binding_count": len(bindings), "binding_ids": sorted(str(item) for item in ids)}


def validate_telemetry_contract(manifest: dict[str, Any], report_doc: dict[str, Any], events: list[dict[str, Any]]) -> None:
    contract = manifest.get("telemetry_contract", {})
    if not isinstance(contract, dict):
        err("telemetry_contract must be an object")
        return
    for field in as_string_list(contract.get("required_report_fields"), "telemetry_contract.required_report_fields"):
        require(field in report_doc, f"telemetry report missing field {field}")
    required_log_fields = set(as_string_list(contract.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    required_events = set(as_string_list(contract.get("required_events"), "telemetry_contract.required_events"))
    actual_events = {event.get("event") for event in events}
    for event_name in sorted(required_events):
        require(event_name in actual_events, f"telemetry event missing: {event_name}")
    for event in events:
        missing = required_log_fields - set(event)
        require(not missing, f"telemetry event {event.get('event')} missing fields {sorted(missing)}")


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
for artifact_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{artifact_id} must be a non-empty string")
        continue
    if not (ROOT / path_text).exists():
        err(f"source artifact {artifact_id} missing: {path_text}")

for ref in manifest.get("completion_debt_evidence", {}).get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} is missing path")
        continue
    text = source_text(path_text, ref.get("id", "implementation_ref"))
    for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id')}.required_text"):
        require(needle in text, f"implementation ref {ref.get('id')} missing required text {needle!r} in {path_text}")

validate_test_sources(manifest)
missing_item_summary = validate_missing_item_bindings(manifest)

required = manifest.get("required_source_contract", {})
if not isinstance(required, dict):
    err("required_source_contract must be an object")
    required = {}

perf_spec = load_json(ROOT / str(source_artifacts.get("perf_baseline_spec", "")), "perf_baseline_spec")
opportunity_matrix = load_json(ROOT / str(source_artifacts.get("opportunity_matrix", "")), "opportunity_matrix")
hot_path_report = load_json(ROOT / str(source_artifacts.get("hot_path_profile_report", "")), "hot_path_profile_report")

perf_summary = validate_perf_baseline_summary(perf_spec, required)
profile_artifacts = validate_profile_artifact_contract(perf_spec, required)
opportunity_summary = validate_opportunity_matrix(opportunity_matrix, required)
profile_report_summary = validate_hot_path_report(hot_path_report, required)

run_checker(str(source_artifacts.get("perf_baseline_checker", "")), "perf baseline source checker")
run_checker(str(source_artifacts.get("opportunity_matrix_checker", "")), "opportunity matrix source checker")
run_checker(str(source_artifacts.get("hot_path_profile_report_checker", "")), "hot path profile report source checker")

events = [
    {
        "event": "hot_path_profile_completion_summary",
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "pass",
        "outcome": "profile_artifact_contract_validated",
        "profile_record_count": profile_report_summary.get("profile_record_count"),
        "opportunity_entry_count": opportunity_summary.get("entry_count"),
    },
    {
        "event": "hot_path_profile_gate_bindings",
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "pass",
        "outcome": "unit_e2e_telemetry_bindings_present",
        "binding_count": missing_item_summary.get("binding_count"),
    },
    {
        "event": "hot_path_profile_completion_contract_pass",
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "pass",
        "outcome": "completion_contract_passed",
        "timestamp_unix": int(time.time()),
    },
]

report_doc = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": "pass" if not errors else "fail",
    "summary": perf_summary,
    "profile_artifacts": profile_artifacts,
    "opportunity_matrix": opportunity_summary,
    "profile_report_summary": profile_report_summary,
    "missing_item_bindings": missing_item_summary,
    "events": events,
    "errors": errors,
}

validate_telemetry_contract(manifest, report_doc, events)
report_doc["status"] = "pass" if not errors else "fail"
for event in events:
    event["status"] = report_doc["status"]

REPORT.write_text(json.dumps(report_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if errors:
    for message in errors:
        print(f"FAIL: {message}")
    raise SystemExit(1)

print("Hot path profile completion contract: PASS")
print(f"profile_records={profile_report_summary.get('profile_record_count')}")
print(f"opportunity_entries={opportunity_summary.get('entry_count')}")
print(f"profile_run_files={profile_artifacts.get('required_file_count')}")
PY
