#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/feature_parity_gap_groups_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_REPORT:-$OUT_DIR/feature_parity_gap_groups_completion_contract.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_GAP_GROUPS_COMPLETION_LOG:-$OUT_DIR/feature_parity_gap_groups_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "feature_parity_gap_groups_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "feature_parity_gap_groups_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-bp8fl.3.1"
COMPLETION_BEAD = "bd-bp8fl.3.1.1"

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


def compute_summary(groups: dict[str, Any], ledger: dict[str, Any]) -> dict[str, Any]:
    batches = groups.get("batches", [])
    gaps = ledger.get("gaps", [])
    batch_gap_ids: list[str] = []
    for batch in batches if isinstance(batches, list) else []:
        if not isinstance(batch, dict):
            continue
        gap_ids = batch.get("gap_ids", [])
        if isinstance(gap_ids, list):
            batch_gap_ids.extend(str(gap_id) for gap_id in gap_ids if isinstance(gap_id, str))

    ledger_ids = [gap.get("gap_id") for gap in gaps if isinstance(gap, dict) and isinstance(gap.get("gap_id"), str)]
    ledger_set = set(ledger_ids)
    batched_set = set(batch_gap_ids)
    duplicate_count = sum(1 for count in Counter(batch_gap_ids).values() if count > 1)
    section_counts: Counter[str] = Counter()
    for gap in gaps if isinstance(gaps, list) else []:
        if isinstance(gap, dict):
            section_counts[str(gap.get("section") or "machine_delta")] += 1
    return {
        "ledger_gap_count": len(ledger_ids),
        "batch_count": len(batches) if isinstance(batches, list) else 0,
        "batched_gap_count": len(batch_gap_ids),
        "duplicate_gap_count": duplicate_count,
        "unbatched_gap_count": len(ledger_set - batched_set),
        "extra_gap_count": len(batched_set - ledger_set),
        "by_feature_parity_section": dict(section_counts),
    }


def run_source_checker(
    source_checker: str,
    source_report_path: pathlib.Path,
    source_log_path: pathlib.Path,
    source_regenerated_path: pathlib.Path,
) -> dict[str, Any]:
    env = os.environ.copy()
    env["FRANKENLIBC_FEATURE_PARITY_GAP_GROUP_REPORT"] = str(source_report_path)
    env["FRANKENLIBC_FEATURE_PARITY_GAP_GROUP_LOG"] = str(source_log_path)
    env["FRANKENLIBC_FEATURE_PARITY_GAP_REGENERATED"] = str(source_regenerated_path)
    proc = subprocess.run(
        ["bash", source_checker],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        err(
            "source feature parity gap groups checker failed: "
            f"exit={proc.returncode} stdout={proc.stdout[:1200]!r} stderr={proc.stderr[:1200]!r}"
        )
    try:
        parsed = json.loads(proc.stdout)
        if isinstance(parsed, dict):
            return parsed
        err("source feature parity gap groups checker stdout must be a JSON object")
    except Exception as exc:
        err(f"source feature parity gap groups checker stdout was not JSON: {exc}")
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

groups = load_json(ROOT / str(source_artifacts.get("gap_groups", "")), "feature_parity_gap_groups")
ledger = load_json(ROOT / str(source_artifacts.get("gap_ledger", "")), "feature_parity_gap_ledger")
require(groups.get("schema_version") == "v1", "gap groups schema_version must be v1")
require(groups.get("bead") == ORIGINAL_BEAD, f"gap groups bead must be {ORIGINAL_BEAD}")

summary = compute_summary(groups, ledger)
artifact_summary = groups.get("summary", {})
if isinstance(artifact_summary, dict):
    for field in ["ledger_gap_count", "batch_count", "batched_gap_count", "duplicate_gap_count", "unbatched_gap_count", "by_feature_parity_section"]:
        require(artifact_summary.get(field) == summary.get(field), f"gap groups summary.{field} mismatch")
else:
    err("gap groups summary must be an object")

for field, expected in required.get("summary_exact", {}).items():
    require(summary.get(field) == expected, f"summary.{field} expected {expected!r}, got {summary.get(field)!r}")
for section in as_string_list(required.get("required_sections"), "required_source_contract.required_sections"):
    require(section in summary.get("by_feature_parity_section", {}), f"required section missing: {section}")

batches = groups.get("batches", [])
batch_ids = {
    batch.get("batch_id")
    for batch in batches
    if isinstance(batch, dict) and isinstance(batch.get("batch_id"), str)
}
for batch_id in as_string_list(required.get("required_batches"), "required_source_contract.required_batches"):
    require(batch_id in batch_ids, f"required batch missing: {batch_id}")

for axis in as_string_list(required.get("required_grouping_axes"), "required_source_contract.required_grouping_axes"):
    require(axis in groups.get("required_grouping_axes", []), f"required grouping axis missing: {axis}")
for field in as_string_list(required.get("required_log_fields"), "required_source_contract.required_log_fields"):
    require(field in groups.get("required_log_fields", []), f"required source log field missing: {field}")

outputs = groups.get("generated_outputs", {})
if not isinstance(outputs, dict):
    err("generated_outputs must be an object")
    outputs = {}
for output_id in as_string_list(required.get("required_generated_outputs"), "required_source_contract.required_generated_outputs"):
    require(output_id in outputs, f"required generated output missing: {output_id}")

source_report_path = REPORT.parent / "feature_parity_gap_groups.source.report.json"
source_log_path = REPORT.parent / "feature_parity_gap_groups.source.log.jsonl"
source_regenerated_path = REPORT.parent / "feature_parity_gap_groups.source.regenerated.v1.json"

source_checker = source_artifacts.get("source_checker")
source_report = {}
if isinstance(source_checker, str) and source_checker:
    source_report = run_source_checker(
        source_checker,
        source_report_path,
        source_log_path,
        source_regenerated_path,
    )
else:
    err("source_checker artifact path is missing")

if source_report_path.exists():
    disk_report = load_json(source_report_path, "source_gate_report")
    if disk_report:
        source_report = disk_report

checks = source_report.get("checks", {}) if isinstance(source_report, dict) else {}
if not isinstance(checks, dict):
    err("source gate report checks must be an object")
    checks = {}
for field in as_string_list(required.get("required_report_fields"), "required_source_contract.required_report_fields"):
    require(field in source_report, f"source gate report missing field {field}")
for check in as_string_list(required.get("required_source_checks"), "required_source_contract.required_source_checks"):
    require(checks.get(check) == "pass", f"source gate check did not pass: {check}")
require(source_report.get("status") == "pass", "source gate report status must be pass")

source_events = json_lines(source_log_path, "source_gate_log")
expected_source_log_rows = summary.get("batch_count", 0) + summary.get("ledger_gap_count", 0) + 1
require(len(source_events) == expected_source_log_rows, f"source log row count expected {expected_source_log_rows}, got {len(source_events)}")
for event in source_events[: min(len(source_events), 12)]:
    for field in as_string_list(required.get("required_log_fields"), "required_source_contract.required_log_fields"):
        require(field in event, f"source gate log missing field {field}")

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
        "event": "feature_parity_gap_groups_completion_summary",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "summary",
        "ledger_gap_count": summary.get("ledger_gap_count"),
        "batch_count": summary.get("batch_count"),
        "batched_gap_count": summary.get("batched_gap_count"),
        "unbatched_gap_count": summary.get("unbatched_gap_count"),
    },
    {
        "timestamp": timestamp,
        "event": "feature_parity_gap_groups_source_gate_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "source_gate",
        "source_gate_report": rel(source_report_path),
        "source_gate_log": rel(source_log_path),
        "source_log_row_count": len(source_events),
        "source_check_count": len(checks),
    },
    {
        "timestamp": timestamp,
        "event": "feature_parity_gap_groups_completion_contract_pass",
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
    if event["event"] == "feature_parity_gap_groups_completion_contract_pass":
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
    "source_log_row_count": len(source_events),
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
    if event["event"] == "feature_parity_gap_groups_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if errors:
    print(f"FAIL: feature parity gap groups completion contract ({len(errors)} errors, report={rel(REPORT)})")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: feature parity gap groups completion contract "
    f"(ledger_gaps={summary.get('ledger_gap_count')}, "
    f"batches={summary.get('batch_count')}, "
    f"log_rows={len(source_events)}, "
    f"report={rel(REPORT)})"
)
PY
