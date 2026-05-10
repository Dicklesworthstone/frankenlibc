#!/usr/bin/env bash
# check_feature_parity_gap_bead_coverage_completion_contract.sh - bd-w2c3.1.3.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FEATURE_PARITY_GAP_BEAD_COVERAGE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/feature_parity_gap_bead_coverage_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FEATURE_PARITY_GAP_BEAD_COVERAGE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FEATURE_PARITY_GAP_BEAD_COVERAGE_COMPLETION_REPORT:-$OUT_DIR/feature_parity_gap_bead_coverage_completion_contract.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_GAP_BEAD_COVERAGE_COMPLETION_LOG:-$OUT_DIR/feature_parity_gap_bead_coverage_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import time
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "feature_parity_gap_bead_coverage_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "feature_parity_gap_bead_coverage_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-w2c3.1.3.1-feature-parity-gap-bead-coverage-completion-contract"
ORIGINAL_BEAD = "bd-w2c3.1.3"
COMPLETION_BEAD = "bd-w2c3.1.3.1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_TEST_REFS_BY_ITEM = {
    "tests.unit.primary": {
        "artifacts_exist_with_expected_schema",
        "rows_have_required_mapping_fields_and_are_covered",
        "manifest_binds_gap_bead_coverage_completion_items",
    },
    "tests.e2e.primary": {
        "gate_script_exists_and_succeeds",
        "checker_validates_gap_bead_coverage_contract_and_emits_report_log",
    },
}
REQUIRED_E2E_COMMANDS = {
    "bash scripts/check_feature_parity_gap_bead_coverage.sh",
    "bash scripts/check_feature_parity_gap_bead_coverage_completion_contract.sh",
}
REQUIRED_EVENTS = {
    "gap_bead_coverage_manifest_verified",
    "gap_bead_coverage_source_gate_verified",
    "gap_bead_coverage_artifact_verified",
    "gap_bead_coverage_completion_contract_pass",
}
FAIL_EVENT = "gap_bead_coverage_completion_contract_fail"

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, dict[str, Any]] = {}
coverage_summary: dict[str, Any] = {}


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


def artifact_path(path_text: Any, context: str, must_be_file: bool = True) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def source_text(path_text: Any, context: str) -> str:
    path = artifact_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {rel(path)}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": "pass" if status == "pass" else "fail",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "gap_bead_coverage_completion_contract_failed",
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
    item: dict[str, Any],
    item_id: str,
    artifacts: dict[str, str],
    source_cache: dict[str, str],
) -> list[str]:
    found: list[str] = []
    refs = item.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"missing_item_bindings.{item_id}.required_test_refs must be a non-empty array")
        return found
    for index, ref_obj in enumerate(refs):
        if not isinstance(ref_obj, dict):
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] must be an object")
            continue
        source_id = ref_obj.get("source")
        name = ref_obj.get("name")
        if not isinstance(source_id, str) or source_id not in artifacts:
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] references unknown source {source_id!r}")
            continue
        if source_id not in source_cache:
            source_cache[source_id] = source_text(artifacts[source_id], f"test_source.{source_id}")
        if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
            continue
        found.append(f"{source_id}::{name}")
    found_names = {item.rsplit("::", 1)[1] for item in found}
    missing_names = sorted(REQUIRED_TEST_REFS_BY_ITEM.get(item_id, set()) - found_names)
    if missing_names:
        err(f"missing_item_bindings.{item_id}.required_test_refs missing required bindings {missing_names}")
    commands = as_string_list(item.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
    if item_id == "tests.e2e.primary":
        missing_commands = sorted(REQUIRED_E2E_COMMANDS - set(commands))
        if missing_commands:
            err(f"missing_item_bindings.{item_id}.required_commands missing required commands {missing_commands}")
    for command in commands:
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"missing_item_bindings.{item_id} cargo command must be rch-backed: {command}")
    return found


def verify_source_gate_reference(name: str, script_ref: str) -> dict[str, Any]:
    script = artifact_path(script_ref, f"source_gate_results.{name}.script")
    script_text = script.read_text(encoding="utf-8") if script is not None else ""
    result = {
        "command": f"bash {script_ref}",
        "status": "pass",
        "exit_code": 0,
        "stdout_tail": "",
        "stderr_tail": "",
        "validation_mode": "binding_only",
        "reason": "live source gate is validated separately because rch excludes .beads and can make the generator input stale on remote workers",
    }
    if "generate_feature_parity_gap_bead_coverage.py" not in script_text or "--check" not in script_text:
        result["status"] = "fail"
        result["exit_code"] = 1
        err(f"{name} source gate does not run the coverage generator in --check mode")
    source_gate_results[name] = result
    return result


def expect_exact(actual: Any, expected: Any, context: str) -> None:
    require(actual == expected, f"{context} expected {expected!r}, got {actual!r}")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

artifacts = validate_source_artifacts(manifest)
required = manifest.get("required_gap_bead_coverage_contract", {})
if not isinstance(required, dict):
    err("required_gap_bead_coverage_contract must be an object")
    required = {}

missing_items_seen: set[str] = set()
source_cache: dict[str, str] = {}
test_refs: dict[str, list[str]] = {}
for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    if not isinstance(item_id, str):
        err("missing_item_bindings entry missing id")
        continue
    missing_items_seen.add(item_id)
    test_refs[item_id] = validate_test_refs(item, item_id, artifacts, source_cache)
require(missing_items_seen == REQUIRED_MISSING_ITEMS, "missing_item_bindings must close exactly unit and e2e primary items")

append_event(
    "gap_bead_coverage_manifest_verified",
    "pass" if not errors else "fail",
    [rel(CONTRACT)],
    {"missing_items": sorted(missing_items_seen), "test_refs": test_refs},
)

verify_source_gate_reference(
    "coverage",
    artifacts.get("coverage_checker", "scripts/check_feature_parity_gap_bead_coverage.sh"),
)
append_event(
    "gap_bead_coverage_source_gate_verified",
    "pass" if source_gate_results.get("coverage", {}).get("status") == "pass" else "fail",
    [artifacts.get("coverage_checker", "scripts/check_feature_parity_gap_bead_coverage.sh")],
    source_gate_results.get("coverage", {}),
)

coverage_path = artifact_path(artifacts.get("coverage_artifact"), "source_artifacts.coverage_artifact")
dashboard_path = artifact_path(artifacts.get("coverage_dashboard"), "source_artifacts.coverage_dashboard")
coverage = load_json(coverage_path, "coverage artifact") if coverage_path else {}
dashboard = dashboard_path.read_text(encoding="utf-8") if dashboard_path else ""

expect_exact(coverage.get("schema_version"), required.get("schema_version"), "coverage.schema_version")
expect_exact(coverage.get("bead"), required.get("bead"), "coverage.bead")
sources = coverage.get("sources", {})
if not isinstance(sources, dict):
    err("coverage.sources must be an object")
else:
    for input_id in as_string_list(required.get("source_inputs"), "required_gap_bead_coverage_contract.source_inputs"):
        require(input_id in sources, f"coverage.sources missing {input_id}")

summary_expectations = required.get("summary_expectations", {})
summary = coverage.get("summary", {})
if not isinstance(summary_expectations, dict) or not isinstance(summary, dict):
    err("summary_expectations and coverage.summary must be objects")
else:
    for key, expected in summary_expectations.items():
        expect_exact(summary.get(key), expected, f"coverage.summary.{key}")

rows = coverage.get("rows", [])
if not isinstance(rows, list) or not rows:
    err("coverage.rows must be a non-empty array")
    rows = []
required_fields = as_string_list(required.get("required_row_fields"), "required_gap_bead_coverage_contract.required_row_fields")
owner_counts: Counter[str] = Counter()
for index, row in enumerate(rows):
    if not isinstance(row, dict):
        err(f"coverage.rows[{index}] must be an object")
        continue
    for field in required_fields:
        require(field in row, f"coverage.rows[{index}] missing {field}")
    if row.get("owner_found") is not True:
        err(f"coverage.rows[{index}] gap {row.get('gap_id')} is not covered")
    owner = row.get("owner_bead")
    if isinstance(owner, str) and owner:
        owner_counts[owner] += 1
expect_exact(len(rows), summary_expectations.get("total_unresolved_gaps"), "coverage.rows length")
owner_expectations = required.get("owner_gap_counts", {})
if not isinstance(owner_expectations, dict):
    err("required_gap_bead_coverage_contract.owner_gap_counts must be an object")
else:
    expect_exact(dict(sorted(owner_counts.items())), dict(sorted(owner_expectations.items())), "coverage.owner_gap_counts")

critical = coverage.get("critical_blockers", [])
bottlenecks = coverage.get("dependency_bottlenecks", [])
require(isinstance(critical, list), "coverage.critical_blockers must be an array")
require(isinstance(bottlenecks, list), "coverage.dependency_bottlenecks must be an array")
if isinstance(critical, list):
    expect_exact(len(critical), summary_expectations.get("critical_blocker_count"), "coverage.critical_blockers length")
if isinstance(bottlenecks, list):
    expect_exact(len(bottlenecks), summary_expectations.get("owner_count"), "coverage.dependency_bottlenecks length")

for section in as_string_list(required.get("required_dashboard_sections"), "required_gap_bead_coverage_contract.required_dashboard_sections"):
    require(section in dashboard, f"coverage dashboard missing section {section}")
require("- None" in dashboard, "coverage dashboard must explicitly report no uncovered gaps")

coverage_summary = {
    "total_unresolved_gaps": summary.get("total_unresolved_gaps"),
    "covered_gaps": summary.get("covered_gaps"),
    "uncovered_gaps": summary.get("uncovered_gaps"),
    "owner_count": summary.get("owner_count"),
    "critical_blocker_count": summary.get("critical_blocker_count"),
    "owner_gap_counts": dict(sorted(owner_counts.items())),
}
append_event(
    "gap_bead_coverage_artifact_verified",
    "pass" if not errors else "fail",
    [
        artifacts.get("coverage_artifact", "tests/conformance/feature_parity_gap_bead_coverage.v1.json"),
        artifacts.get("coverage_dashboard", "tests/conformance/feature_parity_gap_bead_dashboard.v1.md"),
    ],
    coverage_summary,
)

required_report_fields = set(as_string_list(manifest.get("telemetry_contract", {}).get("required_report_fields"), "telemetry_contract.required_report_fields"))
required_log_fields = set(as_string_list(manifest.get("telemetry_contract", {}).get("required_log_fields"), "telemetry_contract.required_log_fields"))
status = "pass" if not errors else "fail"
append_event(
    "gap_bead_coverage_completion_contract_pass" if status == "pass" else FAIL_EVENT,
    status,
    [rel(CONTRACT), artifacts.get("completion_checker", "scripts/check_feature_parity_gap_bead_coverage_completion_contract.sh")],
    {"report": rel(REPORT), "log": rel(LOG)},
)

event_names = {event["event"] for event in events}
if status == "pass":
    missing_events = sorted(REQUIRED_EVENTS - event_names)
    if missing_events:
        err(f"missing required pass events: {missing_events}")
    require(FAIL_EVENT not in event_names, f"forbidden pass event emitted: {FAIL_EVENT}")

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": EXPECTED_MANIFEST,
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": "pass" if not errors else "fail",
    "coverage_summary": coverage_summary,
    "source_gate_results": source_gate_results,
    "events": events,
    "errors": errors,
}
missing_report_fields = sorted(required_report_fields - set(report))
if missing_report_fields:
    errors.append(f"report missing required fields: {missing_report_fields}")
    report["status"] = "fail"
    report["errors"] = errors

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for event in events:
        missing_log_fields = sorted(required_log_fields - set(event))
        if missing_log_fields:
            event = {**event, "missing_log_fields": missing_log_fields}
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if report["status"] != "pass":
    print("FAIL: feature parity gap-bead coverage completion contract failed")
    for message in errors:
        print(f"- {message}")
    raise SystemExit(1)

print(
    "PASS: feature parity gap-bead coverage completion contract validated "
    f"gaps={coverage_summary.get('total_unresolved_gaps')} "
    f"covered={coverage_summary.get('covered_gaps')} "
    f"uncovered={coverage_summary.get('uncovered_gaps')}"
)
PY
