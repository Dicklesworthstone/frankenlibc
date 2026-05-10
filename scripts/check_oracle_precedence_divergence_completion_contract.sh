#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_ORACLE_PRECEDENCE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/oracle_precedence_divergence_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_ORACLE_PRECEDENCE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_ORACLE_PRECEDENCE_COMPLETION_REPORT:-$OUT_DIR/oracle_precedence_divergence_completion_contract.report.json}"
LOG="${FRANKENLIBC_ORACLE_PRECEDENCE_COMPLETION_LOG:-$OUT_DIR/oracle_precedence_divergence_completion_contract.log.jsonl}"

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
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "oracle_precedence_divergence_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "oracle_precedence_divergence_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-bp8fl.1.6"
COMPLETION_BEAD = "bd-bp8fl.1.6.1"

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


def json_lines(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return []
    records: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except Exception as exc:
            err(f"{label}:{index} is not valid JSON: {exc}")
            continue
        if not isinstance(value, dict):
            err(f"{label}:{index} must be a JSON object")
            continue
        records.append(value)
    return records


def compute_summary(artifact: dict[str, Any]) -> dict[str, Any]:
    oracles = artifact.get("oracle_kinds", [])
    classes = artifact.get("divergence_classifications", [])
    rules = artifact.get("decision_rules", [])
    mappings = artifact.get("semantic_class_mappings", [])
    scenarios = artifact.get("scenarios", [])
    replay_cases = artifact.get("replay_cases", [])
    negative_precedence_tests = artifact.get("negative_precedence_tests", [])

    by_divergence: Counter[str] = Counter()
    by_primary: Counter[str] = Counter()
    negative_claim_tests = 0
    for scenario in scenarios if isinstance(scenarios, list) else []:
        if not isinstance(scenario, dict):
            continue
        divergence = scenario.get("divergence_class")
        primary = scenario.get("primary_oracle")
        if isinstance(divergence, str):
            by_divergence[divergence] += 1
        if isinstance(primary, str):
            by_primary[primary] += 1
        negatives = scenario.get("negative_claim_tests", [])
        if isinstance(negatives, list):
            negative_claim_tests += len(negatives)

    mapped = sorted(
        row.get("semantic_class")
        for row in mappings
        if isinstance(row, dict) and isinstance(row.get("semantic_class"), str)
    )
    return {
        "oracle_kind_count": len(oracles) if isinstance(oracles, list) else 0,
        "divergence_class_count": len(classes) if isinstance(classes, list) else 0,
        "decision_rule_count": len(rules) if isinstance(rules, list) else 0,
        "semantic_class_mapping_count": len(mappings) if isinstance(mappings, list) else 0,
        "scenario_count": len(scenarios) if isinstance(scenarios, list) else 0,
        "replay_case_count": len(replay_cases) if isinstance(replay_cases, list) else 0,
        "negative_claim_test_count": negative_claim_tests,
        "negative_precedence_test_count": (
            len(negative_precedence_tests) if isinstance(negative_precedence_tests, list) else 0
        ),
        "by_divergence_class": dict(sorted(by_divergence.items())),
        "by_primary_oracle": dict(sorted(by_primary.items())),
        "semantic_classes_mapped": mapped,
    }


def run_source_checker(source_checker: str) -> dict[str, Any]:
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
            "source oracle precedence checker failed: "
            f"exit={proc.returncode} stdout={proc.stdout[:1200]!r} stderr={proc.stderr[:1200]!r}"
        )
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, dict):
            return parsed
        err("source oracle precedence checker stdout must be a JSON object")
    except Exception as exc:
        err(f"source oracle precedence checker stdout was not JSON: {exc}")
    return {}


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

texts: dict[str, str] = {}
for artifact_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{artifact_id} must be a non-empty string")
        continue
    path = ROOT / path_text
    if not path.exists():
        err(f"source artifact {artifact_id} missing: {path_text}")
        continue
    if path_text.endswith((".json", ".sh", ".rs", ".md")):
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

artifact_path = ROOT / str(source_artifacts.get("oracle_precedence_manifest", ""))
artifact = load_json(artifact_path, "oracle_precedence_manifest")
require(artifact.get("schema_version") == "v1", "oracle manifest schema_version must be v1")
require(artifact.get("bead") == ORIGINAL_BEAD, f"oracle manifest bead must be {ORIGINAL_BEAD}")

summary = compute_summary(artifact)
manifest_summary = artifact.get("summary", {})
require(manifest_summary == summary, "oracle manifest summary must match computed contents")
for field, expected in required.get("summary_exact", {}).items():
    require(summary.get(field) == expected, f"summary.{field} expected {expected!r}, got {summary.get(field)!r}")

oracle_ids = {
    row.get("id")
    for row in artifact.get("oracle_kinds", [])
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}
for oracle in as_string_list(required.get("required_oracles"), "required_source_contract.required_oracles"):
    require(oracle in oracle_ids, f"required oracle missing: {oracle}")

class_ids = {
    row.get("id")
    for row in artifact.get("divergence_classifications", [])
    if isinstance(row, dict) and isinstance(row.get("id"), str)
}
for class_id in as_string_list(required.get("required_divergence_classes"), "required_source_contract.required_divergence_classes"):
    require(class_id in class_ids, f"required divergence class missing: {class_id}")

observable_fields = set(as_string_list(artifact.get("observable_fields"), "oracle_manifest.observable_fields"))
for field in as_string_list(required.get("required_observable_fields"), "required_source_contract.required_observable_fields"):
    require(field in observable_fields, f"required observable field missing: {field}")

replay_kinds = {
    row.get("replay_kind")
    for row in artifact.get("replay_cases", [])
    if isinstance(row, dict) and isinstance(row.get("replay_kind"), str)
}
for replay_kind in as_string_list(required.get("required_replay_kinds"), "required_source_contract.required_replay_kinds"):
    require(replay_kind in replay_kinds, f"required replay kind missing: {replay_kind}")

inputs = artifact.get("inputs", {})
if not isinstance(inputs, dict):
    err("oracle manifest inputs must be an object")
    inputs = {}
for artifact_id in as_string_list(required.get("required_input_artifacts"), "required_source_contract.required_input_artifacts"):
    input_path = inputs.get(artifact_id)
    require(isinstance(input_path, str) and bool(input_path), f"required input artifact missing: {artifact_id}")
    if isinstance(input_path, str):
        require((ROOT / input_path).exists(), f"required input artifact path missing: {input_path}")

source_checker = source_artifacts.get("source_checker")
source_report = {}
if isinstance(source_checker, str) and source_checker:
    source_report = run_source_checker(source_checker)
else:
    err("source_checker artifact path is missing")

source_report_path = ROOT / "target/conformance/oracle_precedence_divergence.report.json"
source_log_path = ROOT / "target/conformance/oracle_precedence_divergence.log.jsonl"
if source_report_path.exists():
    disk_report = load_json(source_report_path, "source_gate_report")
    if disk_report:
        source_report = disk_report

checks = source_report.get("checks", {}) if isinstance(source_report, dict) else {}
if not isinstance(checks, dict):
    err("source gate report checks must be an object")
    checks = {}
for field in as_string_list(required.get("required_source_report_fields"), "required_source_contract.required_source_report_fields"):
    require(field in source_report, f"source gate report missing field {field}")
for check in as_string_list(required.get("required_source_checks"), "required_source_contract.required_source_checks"):
    require(checks.get(check) == "pass", f"source gate check did not pass: {check}")
require(source_report.get("status") == "pass", "source gate report status must be pass")

source_events = json_lines(source_log_path, "source_gate_log")
if source_events:
    source_event = source_events[0]
    for field in as_string_list(required.get("required_structured_log_fields"), "required_source_contract.required_structured_log_fields"):
        require(field in source_event, f"source gate log missing field {field}")
    require(source_event.get("status") == "pass", "source gate log status must be pass")

for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    for test_ref in as_string_list(item.get("required_test_refs"), f"missing_item_bindings.{item_id}.required_test_refs"):
        require(test_ref in all_test_text, f"missing item {item_id} lacks test ref {test_ref}")
    for command in as_string_list(item.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands"):
        require("cargo " not in command or "rch exec -- cargo " in command, f"required command must use rch: {command}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
events = [
    {
        "timestamp": timestamp,
        "event": "oracle_precedence_completion_summary",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "summary",
        "oracle_kind_count": summary.get("oracle_kind_count"),
        "divergence_class_count": summary.get("divergence_class_count"),
        "scenario_count": summary.get("scenario_count"),
        "replay_case_count": summary.get("replay_case_count"),
    },
    {
        "timestamp": timestamp,
        "event": "oracle_precedence_source_gate_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "source_gate",
        "source_gate_report": rel(source_report_path),
        "source_gate_log": rel(source_log_path),
        "source_check_count": len(checks),
    },
    {
        "timestamp": timestamp,
        "event": "oracle_precedence_completion_contract_pass",
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

status = "pass" if not errors else "fail"
for event in events:
    event["status"] = status
    if event["event"] == "oracle_precedence_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "summary": summary,
    "source_gate_report": rel(source_report_path),
    "checks": checks,
    "events": [event["event"] for event in events],
    "errors": errors,
}

for field in as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields"):
    if field not in report:
        err(f"completion report missing required field {field}")

status = "pass" if not errors else "fail"
report["status"] = status
report["errors"] = errors
for event in events:
    event["status"] = status
    if event["event"] == "oracle_precedence_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if errors:
    print(f"FAIL: oracle precedence completion contract ({len(errors)} errors, report={rel(REPORT)})")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: oracle precedence completion contract "
    f"(oracles={summary.get('oracle_kind_count')}, "
    f"classes={summary.get('divergence_class_count')}, "
    f"scenarios={summary.get('scenario_count')}, "
    f"report={rel(REPORT)})"
)
PY
