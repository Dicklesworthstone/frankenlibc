#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PERF_BASELINE_SUITE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/perf_baseline_suite_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PERF_BASELINE_SUITE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_PERF_BASELINE_SUITE_COMPLETION_REPORT:-$OUT_DIR/perf_baseline_suite_completion_contract.report.json}"
LOG="${FRANKENLIBC_PERF_BASELINE_SUITE_COMPLETION_LOG:-$OUT_DIR/perf_baseline_suite_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "perf_baseline_suite_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "perf_baseline_suite_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-2wp"
COMPLETION_BEAD = "bd-2wp.1"

errors: list[str] = []


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


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def source_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def suite_map(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    suites = spec.get("benchmark_suites", {}).get("suites", [])
    if not isinstance(suites, list):
        err("perf_baseline_spec.benchmark_suites.suites must be an array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for suite in suites:
        if not isinstance(suite, dict):
            err("perf_baseline_spec suite entries must be objects")
            continue
        suite_id = suite.get("id")
        if not isinstance(suite_id, str) or not suite_id:
            err("perf_baseline_spec suite is missing id")
            continue
        if suite_id in result:
            err(f"duplicate suite id in perf_baseline_spec: {suite_id}")
        result[suite_id] = suite
    return result


def mode_list(suite: dict[str, Any], suite_id: str) -> list[str]:
    return as_string_list(suite.get("modes"), f"benchmark_suites.{suite_id}.modes")


def benchmark_names(suite: dict[str, Any], suite_id: str) -> list[str]:
    benches = suite.get("benchmarks")
    if not isinstance(benches, list) or not benches:
        err(f"benchmark_suites.{suite_id}.benchmarks must be a non-empty array")
        return []
    names: list[str] = []
    for index, bench in enumerate(benches):
        if not isinstance(bench, dict):
            err(f"benchmark_suites.{suite_id}.benchmarks[{index}] must be an object")
            continue
        name = bench.get("name")
        description = bench.get("description")
        if not isinstance(name, str) or not name:
            err(f"benchmark_suites.{suite_id}.benchmarks[{index}].name must be non-empty")
            continue
        if not isinstance(description, str) or not description:
            err(f"benchmark_suites.{suite_id}.{name}.description must be non-empty")
        names.append(name)
    return names


def compute_summary(spec: dict[str, Any], baseline: dict[str, Any], required_modes: set[str]) -> dict[str, Any]:
    suites = suite_map(spec)
    total_benchmarks = 0
    enforced_suites = 0
    planned_suites = 0
    modes_seen: set[str] = set()
    baseline_slots = 0
    present_baseline_slots = 0
    enforced_slots = 0
    present_enforced_slots = 0
    missing_baselines: list[str] = []

    baseline_p50 = baseline.get("baseline_p50_ns_op", {})
    if not isinstance(baseline_p50, dict):
        err("perf_baseline.baseline_p50_ns_op must be an object")
        baseline_p50 = {}

    for suite_id, suite in suites.items():
        crate_name = suite.get("crate")
        command = suite.get("command")
        output_prefix = suite.get("output_prefix")
        criterion_config = suite.get("criterion_config")
        enforced = bool(suite.get("enforced_in_gate", False))

        if not isinstance(crate_name, str) or not crate_name:
            err(f"benchmark_suites.{suite_id}.crate must be non-empty")
        elif not (ROOT / "crates" / crate_name).is_dir():
            err(f"benchmark_suites.{suite_id}.crate does not exist: crates/{crate_name}")

        if not isinstance(command, str) or "cargo bench" not in command or "--bench" not in command:
            err(f"benchmark_suites.{suite_id}.command must include cargo bench and --bench")

        if not isinstance(output_prefix, str) or not output_prefix.endswith("_BENCH"):
            err(f"benchmark_suites.{suite_id}.output_prefix must be a structured *_BENCH marker")

        if not isinstance(criterion_config, dict):
            err(f"benchmark_suites.{suite_id}.criterion_config must be an object")
        else:
            for field in ["sample_size", "measurement_time_secs", "warm_up_time_ms"]:
                if not isinstance(criterion_config.get(field), int):
                    err(f"benchmark_suites.{suite_id}.criterion_config.{field} must be an integer")

        suite_modes = mode_list(suite, suite_id)
        bench_names = benchmark_names(suite, suite_id)
        total_benchmarks += len(bench_names)
        if enforced:
            enforced_suites += 1
        else:
            planned_suites += 1

        for mode in suite_modes:
            modes_seen.add(mode)
            if mode not in required_modes:
                err(f"benchmark_suites.{suite_id}.modes contains unexpected mode {mode}")
            for bench_name in bench_names:
                baseline_slots += 1
                if enforced:
                    enforced_slots += 1
                value = (
                    baseline_p50.get(suite_id, {})
                    if isinstance(baseline_p50.get(suite_id, {}), dict)
                    else {}
                )
                mode_values = value.get(mode, {}) if isinstance(value.get(mode, {}), dict) else {}
                actual = mode_values.get(bench_name)
                if isinstance(actual, (int, float)) and actual >= 0:
                    present_baseline_slots += 1
                    if enforced:
                        present_enforced_slots += 1
                else:
                    missing_baselines.append(f"{suite_id}/{mode}/{bench_name}")

    if missing_baselines:
        err("missing baseline_p50 slots: " + ", ".join(missing_baselines[:12]))

    pct = spec.get("percentile_targets", {}).get("captured_percentiles", [])
    regen = spec.get("regeneration", {})
    profile_required_files = spec.get("profile_artifacts", {}).get("required_files", [])

    return {
        "total_suites": len(suites),
        "total_benchmarks": total_benchmarks,
        "enforced_suites": enforced_suites,
        "planned_suites": planned_suites,
        "modes": len(modes_seen),
        "captured_percentiles": len(pct) if isinstance(pct, list) else 0,
        "regeneration_steps": len(regen.get("command_sequence", [])) if isinstance(regen, dict) else 0,
        "prerequisite_checks": len(regen.get("prerequisites", [])) if isinstance(regen, dict) else 0,
        "profile_required_files": len(profile_required_files) if isinstance(profile_required_files, list) else 0,
        "baseline_p50_slots": baseline_slots,
        "present_baseline_p50_slots": present_baseline_slots,
        "enforced_baseline_p50_slots": enforced_slots,
        "present_enforced_baseline_p50_slots": present_enforced_slots,
        "baseline_slot_fill_pct": round((present_baseline_slots / baseline_slots) * 100.0, 3) if baseline_slots else 0.0,
        "enforced_baseline_slot_fill_pct": round((present_enforced_slots / enforced_slots) * 100.0, 3) if enforced_slots else 0.0,
    }


def run_source_checker(source_checker: str) -> None:
    proc = subprocess.run(
        ["bash", source_checker],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err(
            "source perf baseline checker failed: "
            f"exit={proc.returncode} stdout={proc.stdout[:1000]!r} stderr={proc.stderr[:1000]!r}"
        )


manifest = load_json(CONTRACT, "contract")

require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(
    manifest.get("completion_debt_bead") == COMPLETION_BEAD,
    f"completion_debt_bead must be {COMPLETION_BEAD}",
)

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

texts: dict[str, str] = {}
for artifact_id, path_text in source_artifacts.items():
    if isinstance(path_text, str) and path_text.endswith((".json", ".sh", ".rs", ".md")):
        texts[artifact_id] = source_text(path_text, artifact_id)

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

test_sources = manifest.get("completion_debt_evidence", {}).get("test_sources", {})
all_test_text = ""
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
else:
    for source_id, source in test_sources.items():
        if not isinstance(source, dict):
            err(f"test source {source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"test source {source_id} must include path")
            continue
        text = source_text(path_text, source_id)
        all_test_text += text + "\n"
        for test_ref in as_string_list(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            require(
                f"fn {test_ref}" in text or test_ref in text,
                f"test source {source_id} missing required test ref {test_ref}",
            )

required = manifest.get("required_source_contract", {})
if not isinstance(required, dict):
    err("required_source_contract must be an object")
    required = {}

required_modes = set(as_string_list(required.get("required_modes"), "required_source_contract.required_modes"))
spec = load_json(ROOT / str(source_artifacts.get("perf_baseline_spec", "")), "perf_baseline_spec")
baseline = load_json(ROOT / str(source_artifacts.get("perf_baseline", "")), "perf_baseline")
summary = compute_summary(spec, baseline, required_modes)

spec_summary = spec.get("summary", {})
if isinstance(spec_summary, dict):
    for field in [
        "total_suites",
        "total_benchmarks",
        "enforced_suites",
        "planned_suites",
        "modes",
        "captured_percentiles",
        "regeneration_steps",
        "prerequisite_checks",
        "profile_required_files",
    ]:
        require(spec_summary.get(field) == summary.get(field), f"spec.summary.{field} mismatch")

for field, expected in required.get("summary_exact", {}).items():
    require(summary.get(field) == expected, f"summary.{field} expected {expected!r}, got {summary.get(field)!r}")

for field, minimum in required.get("summary_min", {}).items():
    value = summary.get(field)
    require(
        isinstance(value, (int, float)) and value >= minimum,
        f"summary.{field} expected >= {minimum!r}, got {value!r}",
    )

suites = suite_map(spec)
suite_ids = set(suites)
for suite_id in as_string_list(required.get("required_suites"), "required_source_contract.required_suites"):
    require(suite_id in suite_ids, f"required suite missing from perf_baseline_spec: {suite_id}")

enforced_ids = {sid for sid, suite in suites.items() if suite.get("enforced_in_gate") is True}
for suite_id in as_string_list(required.get("required_enforced_suites"), "required_source_contract.required_enforced_suites"):
    require(suite_id in enforced_ids, f"required enforced suite missing: {suite_id}")

prefixes = {
    suite.get("output_prefix")
    for suite in suites.values()
    if isinstance(suite.get("output_prefix"), str)
}
for prefix in as_string_list(required.get("required_output_prefixes"), "required_source_contract.required_output_prefixes"):
    require(prefix in prefixes, f"required output prefix missing: {prefix}")

cross_refs = spec.get("cross_references", {})
if not isinstance(cross_refs, dict):
    err("perf_baseline_spec.cross_references must be an object")
    cross_refs = {}
for ref_id in as_string_list(required.get("required_cross_references"), "required_source_contract.required_cross_references"):
    require(ref_id in cross_refs, f"required cross reference missing: {ref_id}")

dashboard = load_json(ROOT / str(source_artifacts.get("dashboard_report", "")), "dashboard_report")
dashboard_rows = {
    row.get("row_id")
    for row in dashboard.get("rows", [])
    if isinstance(row, dict) and isinstance(row.get("row_id"), str)
}
for row_id in as_string_list(required.get("required_dashboard_rows"), "required_source_contract.required_dashboard_rows"):
    require(row_id in dashboard_rows, f"dashboard missing required perf baseline row {row_id}")

source_checker = source_artifacts.get("source_checker")
if isinstance(source_checker, str) and source_checker:
    run_source_checker(source_checker)
else:
    err("source_checker artifact path is missing")

gate_features = {
    "baseline_validation": "source_checker" in source_artifacts and not errors,
    "criterion_regression_gate": "cargo bench" in texts.get("perf_gate", ""),
    "rch_wrapped_gate": "rch exec -- env" in texts.get("benchmark_gate", ""),
    "load_guard": "should_skip_overloaded" in texts.get("perf_gate", ""),
    "injection_support": "FRANKENLIBC_PERF_INJECT_RESULTS" in texts.get("perf_gate", ""),
    "structured_event_log": "EVENT_LOG_PATH" in texts.get("perf_gate", "") and "benchmark_result" in texts.get("perf_gate", ""),
    "structured_report": "REPORT_PATH" in texts.get("perf_gate", "") and "write_report" in texts.get("perf_gate", ""),
}
for feature in as_string_list(required.get("required_gate_features"), "required_source_contract.required_gate_features"):
    require(gate_features.get(feature) is True, f"required gate feature missing or false: {feature}")

for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    for test_ref in as_string_list(item.get("required_test_refs"), f"missing_item_bindings.{item.get('id')}.required_test_refs"):
        require(test_ref in all_test_text, f"missing item {item.get('id')} lacks test ref {test_ref}")
    for command in as_string_list(item.get("required_commands"), f"missing_item_bindings.{item.get('id')}.required_commands"):
        require("cargo " not in command or "rch exec -- cargo " in command, f"required command must use rch: {command}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}

status = "pass" if not errors else "fail"
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
events = [
    {
        "timestamp": timestamp,
        "event": "perf_baseline_suite_completion_summary",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "summary",
        "total_suites": summary.get("total_suites"),
        "total_benchmarks": summary.get("total_benchmarks"),
        "enforced_suites": summary.get("enforced_suites"),
        "baseline_slot_fill_pct": summary.get("baseline_slot_fill_pct"),
        "enforced_baseline_slot_fill_pct": summary.get("enforced_baseline_slot_fill_pct"),
    },
    {
        "timestamp": timestamp,
        "event": "perf_baseline_suite_gate_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "gate_bindings",
        "gate_features": gate_features,
        "dashboard_row_count": len(required.get("required_dashboard_rows", [])),
    },
    {
        "timestamp": timestamp,
        "event": "perf_baseline_suite_completion_contract_pass",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "pass" if status == "pass" else "fail",
    },
]

event_names = {event["event"] for event in events}
for event_name in as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"):
    require(event_name in event_names, f"required telemetry event {event_name} was not emitted")

for event in events:
    for field in as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"):
        require(field in event, f"telemetry event {event.get('event')} missing field {field}")

if errors:
    status = "fail"
    for event in events:
        event["status"] = status
        if event["event"] == "perf_baseline_suite_completion_contract_pass":
            event["outcome"] = "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "summary": summary,
    "gate_features": gate_features,
    "dashboard_row_count": len(required.get("required_dashboard_rows", [])),
    "events": [event["event"] for event in events],
    "errors": errors,
}

for field in as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields"):
    if field not in report:
        err(f"completion report missing required field {field}")

if errors:
    status = "fail"
    report["status"] = status
    report["errors"] = errors
    for event in events:
        event["status"] = status
        if event["event"] == "perf_baseline_suite_completion_contract_pass":
            event["outcome"] = "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if errors:
    print(f"FAIL: perf baseline suite completion contract ({len(errors)} errors, report={rel(REPORT)})")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: perf baseline suite completion contract "
    f"(suites={summary.get('total_suites')}, "
    f"benchmarks={summary.get('total_benchmarks')}, "
    f"baseline_fill={summary.get('baseline_slot_fill_pct')}, "
    f"report={rel(REPORT)})"
)
PY
