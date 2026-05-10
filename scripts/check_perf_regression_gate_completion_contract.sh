#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_PERF_REGRESSION_GATE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/perf_regression_gate_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_PERF_REGRESSION_GATE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_PERF_REGRESSION_GATE_COMPLETION_REPORT:-$OUT_DIR/perf_regression_gate_completion_contract.report.json}"
LOG="${FRANKENLIBC_PERF_REGRESSION_GATE_COMPLETION_LOG:-$OUT_DIR/perf_regression_gate_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "perf_regression_gate_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "perf_regression_gate_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-30o.3"
COMPLETION_BEAD = "bd-30o.3.1"

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


def validate_policy(policy: dict[str, Any], baseline: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    require(policy.get("schema_version") == 1, "attribution policy schema_version must be 1")
    supersedes = as_string_list(policy.get("supersedes"), "attribution_policy.supersedes")
    require(ORIGINAL_BEAD in supersedes, f"attribution policy must supersede {ORIGINAL_BEAD}")

    for section in as_string_list(required.get("required_policy_sections"), "required_policy_sections"):
        require(isinstance(policy.get(section), dict), f"attribution policy missing section {section}")

    expected_summary = required.get("policy_summary_exact", {})
    if not isinstance(expected_summary, dict):
        err("required_source_contract.policy_summary_exact must be an object")
        expected_summary = {}
    summary = policy.get("summary", {})
    if not isinstance(summary, dict):
        err("attribution policy summary must be an object")
        summary = {}
    for field, expected in expected_summary.items():
        require(summary.get(field) == expected, f"summary.{field}: expected={expected!r} actual={summary.get(field)!r}")

    attribution = policy.get("attribution", {})
    if not isinstance(attribution, dict):
        err("attribution section must be an object")
        attribution = {}
    classes = set(as_string_list(attribution.get("regression_classes"), "attribution.regression_classes"))
    for cls in as_string_list(required.get("required_regression_classes"), "required_regression_classes"):
        require(cls in classes, f"missing regression class {cls}")

    suspects = attribution.get("suspect_component_map", {})
    if not isinstance(suspects, dict):
        err("attribution.suspect_component_map must be an object")
        suspects = {}
    for benchmark_id in as_string_list(required.get("required_mapped_benchmark_ids"), "required_mapped_benchmark_ids"):
        require(benchmark_id in suspects, f"suspect_component_map missing required benchmark {benchmark_id}")

    baseline_ids: set[str] = set()
    p50 = baseline.get("baseline_p50_ns_op", {})
    if not isinstance(p50, dict):
        err("perf_baseline.baseline_p50_ns_op must be an object")
        p50 = {}
    for suite, modes in p50.items():
        if not isinstance(modes, dict):
            continue
        for benches in modes.values():
            if not isinstance(benches, dict):
                continue
            for bench in benches:
                baseline_ids.add(f"{suite}/{bench}")
    missing = sorted(benchmark_id for benchmark_id in baseline_ids if benchmark_id not in suspects)
    require(not missing, "suspect_component_map missing baseline benchmark ids: " + ", ".join(missing[:12]))

    log_fields = set(as_string_list(policy.get("logging_contract", {}).get("required_fields") if isinstance(policy.get("logging_contract"), dict) else None, "logging_contract.required_fields"))
    for field in as_string_list(required.get("required_log_fields"), "required_log_fields"):
        require(field in log_fields, f"logging_contract.required_fields missing {field}")

    auto = policy.get("auto_throttle_policy", {})
    if not isinstance(auto, dict):
        err("auto_throttle_policy must be an object")
        auto = {}
    auto_log_fields = set(as_string_list(auto.get("required_log_fields"), "auto_throttle_policy.required_log_fields"))
    for field in as_string_list(required.get("required_auto_throttle_log_fields"), "required_auto_throttle_log_fields"):
        require(field in auto_log_fields, f"auto_throttle_policy.required_log_fields missing {field}")
    auto_report_fields = set(as_string_list(auto.get("required_report_fields"), "auto_throttle_policy.required_report_fields"))
    for field in as_string_list(required.get("required_auto_throttle_report_fields"), "required_auto_throttle_report_fields"):
        require(field in auto_report_fields, f"auto_throttle_policy.required_report_fields missing {field}")
    scenario = auto.get("scenario", {})
    if not isinstance(scenario, dict):
        err("auto_throttle_policy.scenario must be an object")
        scenario = {}
    require(scenario.get("scenario") == "overloaded", "auto_throttle_policy scenario must be overloaded")

    intentional = policy.get("intentional_regression_scenario", {})
    if not isinstance(intentional, dict):
        err("intentional_regression_scenario must be an object")
        intentional = {}
    require(intentional.get("scenario") == "regression", "intentional_regression_scenario scenario must be regression")
    require(intentional.get("required_detected_benchmark") == "runtime_math/decide", "intentional regression must detect runtime_math/decide")

    return {
        "mapped_benchmarks": len(suspects),
        "baseline_benchmark_ids": len(baseline_ids),
        "regression_classes": len(classes),
        "required_log_fields": len(log_fields),
        "auto_throttle_log_fields": len(auto_log_fields),
        "auto_throttle_report_fields": len(auto_report_fields),
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
            require(f"fn {test_ref}" in text or test_ref in text, f"test source {source_id} missing required test ref {test_ref}")


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
        commands = as_string_list(binding.get("required_commands"), f"missing_item_bindings.{binding_id}.required_commands")
        as_string_list(binding.get("required_test_refs"), f"missing_item_bindings.{binding_id}.required_test_refs")
        if binding_id == "tests.unit.primary":
            require(any("rch exec -- cargo test" in command for command in commands), "unit binding must reference rch cargo test")
        if binding_id == "tests.e2e.primary":
            require(any("check_perf_regression_gate.sh" in command for command in commands), "e2e binding must reference perf regression gate checker")
        if binding_id == "telemetry.primary":
            require(any("jq -s empty" in command for command in commands), "telemetry binding must validate JSONL")
    return {"binding_count": len(bindings), "binding_ids": sorted(str(item) for item in ids)}


def validate_gate_features(texts: dict[str, str], required: dict[str, Any]) -> dict[str, bool]:
    perf_gate = texts.get("perf_gate", "")
    checker = texts.get("gate_checker", "")
    scenario = texts.get("scenario_script", "")
    wrapper = texts.get("benchmark_gate_wrapper", "")
    ci = texts.get("ci_script", "")
    features = {
        "policy_mapping": "resolve_suspect_component" in perf_gate and "suspect_component_map" in checker,
        "structured_event_log": "EVENT_LOG_PATH" in perf_gate and "emit_regression_event" in perf_gate,
        "structured_report": "REPORT_PATH" in perf_gate and "write_report" in perf_gate,
        "injected_regression_replay": "FRANKENLIBC_PERF_INJECT_RESULTS" in perf_gate and "--scenario regression" in scenario,
        "auto_throttle_replay": "emit_throttle_event" in perf_gate and "--scenario overloaded" in scenario,
        "rch_wrapper": "rch exec -- env" in wrapper and "bash scripts/perf_gate.sh" in wrapper,
        "ci_extended_gate": "scripts/check_perf_regression_gate.sh" in ci,
    }
    for feature in as_string_list(required.get("required_gate_features"), "required_gate_features"):
        require(features.get(feature) is True, f"missing gate feature {feature}")
    return features


def validate_telemetry_contract(manifest: dict[str, Any], report_doc: dict[str, Any], events: list[dict[str, Any]]) -> None:
    contract = manifest.get("telemetry_contract", {})
    if not isinstance(contract, dict):
        err("telemetry_contract must be an object")
        return
    for field in as_string_list(contract.get("required_report_fields"), "telemetry_contract.required_report_fields"):
        require(field in report_doc, f"telemetry report missing field {field}")
    required_log_fields = set(as_string_list(contract.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    actual_events = {event.get("event") for event in events}
    for event_name in as_string_list(contract.get("required_events"), "telemetry_contract.required_events"):
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

texts: dict[str, str] = {}
for artifact_id, path_text in source_artifacts.items():
    if isinstance(path_text, str) and path_text.endswith((".json", ".sh", ".rs")):
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

validate_test_sources(manifest)
missing_item_summary = validate_missing_item_bindings(manifest)

required = manifest.get("required_source_contract", {})
if not isinstance(required, dict):
    err("required_source_contract must be an object")
    required = {}

policy = load_json(ROOT / str(source_artifacts.get("attribution_policy", "")), "attribution_policy")
baseline = load_json(ROOT / str(source_artifacts.get("perf_baseline", "")), "perf_baseline")
policy_summary = validate_policy(policy, baseline, required)
gate_features = validate_gate_features(texts, required)

run_checker(str(source_artifacts.get("gate_checker", "")), "perf regression gate checker")

events = [
    {
        "event": "perf_regression_gate_completion_summary",
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "pass",
        "outcome": "policy_threshold_attribution_contract_validated",
        "mapped_benchmarks": policy_summary.get("mapped_benchmarks"),
    },
    {
        "event": "perf_regression_gate_e2e_bindings",
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": "pass",
        "outcome": "intentional_regression_and_auto_throttle_e2e_bound",
        "binding_count": missing_item_summary.get("binding_count"),
    },
    {
        "event": "perf_regression_gate_completion_contract_pass",
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
    "policy_summary": policy_summary,
    "gate_features": gate_features,
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

print("Perf regression gate completion contract: PASS")
print(f"mapped_benchmarks={policy_summary.get('mapped_benchmarks')}")
print(f"baseline_benchmark_ids={policy_summary.get('baseline_benchmark_ids')}")
print(f"gate_features={sum(1 for value in gate_features.values() if value)}")
PY
