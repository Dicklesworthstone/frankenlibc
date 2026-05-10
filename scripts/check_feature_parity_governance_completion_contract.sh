#!/usr/bin/env bash
# check_feature_parity_governance_completion_contract.sh - bd-w2c3.1.4 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/feature_parity_governance_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_REPORT:-$OUT_DIR/feature_parity_governance_completion_contract.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_GOVERNANCE_COMPLETION_LOG:-$OUT_DIR/feature_parity_governance_completion_contract.log.jsonl}"

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
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "feature_parity_governance_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "feature_parity_governance_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-w2c3.1.4-feature-parity-governance-completion-contract"
ORIGINAL_BEAD = "bd-w2c3.1"
COMPLETION_BEAD = "bd-w2c3.1.4"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "tests.conformance.primary"}
REQUIRED_TEST_REFS_BY_ITEM = {
    "tests.unit.primary": {
        "artifact_exists_and_valid",
        "row_ids_are_unique_and_parser_errors_empty",
        "done_rows_have_evidence_audit_records",
        "generator_self_tests_pass",
        "manifest_binds_track0_governance_completion_items",
    },
    "tests.e2e.primary": {
        "gate_passes_and_emits_required_diagnostic_schema",
        "gate_fails_when_unresolved_drift_loses_owner",
        "checker_validates_track0_governance_contract_and_emits_report_log",
    },
    "tests.conformance.primary": {
        "artifacts_exist_with_expected_schema",
        "rows_have_required_mapping_fields_and_are_covered",
        "checker_rejects_missing_required_conformance_command",
        "checker_rejects_missing_dashboard_section",
    },
}
REQUIRED_CONFORMANCE_COMMANDS = {
    "bash scripts/check_feature_parity_gap_ledger.sh",
    "bash scripts/check_feature_parity_drift.sh",
    "bash scripts/check_feature_parity_governance_completion_contract.sh",
}
REQUIRED_EVENTS = {
    "track0_governance_gap_ledger_verified",
    "track0_governance_drift_gate_verified",
    "track0_governance_coverage_gate_verified",
    "track0_governance_completion_contract_pass",
}
FAIL_EVENT = "track0_governance_completion_contract_fail"

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, dict[str, Any]] = {}


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
            "failure_signature": "none" if status == "pass" else "track0_governance_completion_contract_failed",
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
    if item_id == "tests.conformance.primary":
        missing_commands = sorted(REQUIRED_CONFORMANCE_COMMANDS - set(commands))
        if missing_commands:
            err(f"missing_item_bindings.{item_id}.required_commands missing required commands {missing_commands}")
    for command in commands:
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"missing_item_bindings.{item_id} cargo command must be rch-backed: {command}")
    return found


def run_gate(name: str, command: list[str], env: dict[str, str]) -> dict[str, Any]:
    proc = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, **env},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result = {
        "command": " ".join(command),
        "status": "pass" if proc.returncode == 0 else "fail",
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-1200:],
        "stderr_tail": proc.stderr[-1200:],
    }
    source_gate_results[name] = result
    if proc.returncode != 0:
        err(f"{name} source gate failed exit={proc.returncode} stdout={proc.stdout[-600:]!r} stderr={proc.stderr[-600:]!r}")
    return result


def expect_exact(actual: Any, expected: Any, context: str) -> None:
    require(actual == expected, f"{context} expected {expected!r}, got {actual!r}")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

artifacts = validate_source_artifacts(manifest)
required = manifest.get("required_track0_contract", {})
if not isinstance(required, dict):
    err("required_track0_contract must be an object")
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
require(missing_items_seen == REQUIRED_MISSING_ITEMS, "missing_item_bindings must close exactly unit, e2e, and conformance primary items")

for child in ["bd-w2c3.1.1", "bd-w2c3.1.2", "bd-w2c3.1.3"]:
    require(child in as_string_list(required.get("child_beads"), "required_track0_contract.child_beads"), f"child bead missing: {child}")
for script_id in as_string_list(required.get("required_scripts"), "required_track0_contract.required_scripts"):
    require(script_id in artifacts, f"required script artifact missing from source_artifacts: {script_id}")
for artifact_id in as_string_list(required.get("required_artifacts"), "required_track0_contract.required_artifacts"):
    require(artifact_id in artifacts, f"required artifact missing from source_artifacts: {artifact_id}")

OUT_DIR.mkdir(parents=True, exist_ok=True)
ledger_done_log = OUT_DIR / "feature_parity_governance_done_evidence.log.jsonl"
ledger_done_report = OUT_DIR / "feature_parity_governance_done_evidence.report.json"
drift_report = OUT_DIR / "feature_parity_governance_drift_diagnostics.v1.json"

run_gate(
    "gap_ledger",
    ["bash", artifacts.get("gap_ledger_checker", "")],
    {
        "FLC_FP_DONE_EVIDENCE_LOG": str(ledger_done_log),
        "FLC_FP_DONE_EVIDENCE_REPORT": str(ledger_done_report),
    },
)
run_gate(
    "drift",
    ["bash", artifacts.get("drift_checker", "")],
    {"FLC_FP_DRIFT_DIAGNOSTICS": str(drift_report)},
)

ledger = load_json(ROOT / artifacts.get("gap_ledger", ""), "gap ledger")
drift = load_json(ROOT / artifacts.get("drift_diagnostics", ""), "drift diagnostics")
coverage = load_json(ROOT / artifacts.get("gap_coverage", ""), "gap coverage")
dashboard_text = source_text(artifacts.get("gap_dashboard"), "gap dashboard")

ledger_expect = required.get("ledger_expectations", {})
if not isinstance(ledger_expect, dict):
    err("ledger_expectations must be an object")
    ledger_expect = {}
expect_exact(ledger.get("schema_version"), ledger_expect.get("schema_version"), "ledger.schema_version")
expect_exact(ledger.get("bead"), ledger_expect.get("bead"), "ledger.bead")
expect_exact(len(ledger.get("rows", [])), ledger_expect.get("row_count"), "ledger row count")
expect_exact(len(ledger.get("gaps", [])), ledger_expect.get("gap_count"), "ledger gap count")
expect_exact(len(ledger.get("deltas", [])), ledger_expect.get("delta_count"), "ledger delta count")
expect_exact(len(ledger.get("parse_errors", [])), ledger_expect.get("parse_error_count"), "ledger parse_error count")
expect_exact(len(ledger.get("done_evidence_audit", [])), ledger_expect.get("done_evidence_audit_count"), "ledger DONE evidence audit count")
for row in ledger.get("rows", []):
    if isinstance(row, dict):
        require(isinstance(row.get("row_id"), str) and row["row_id"].startswith("fp-"), "ledger rows must carry fp-* row_id values")

append_event(
    "track0_governance_gap_ledger_verified",
    "pass" if not errors else "fail",
    [artifacts.get("gap_ledger", ""), rel(ledger_done_report)],
    {
        "row_count": len(ledger.get("rows", [])),
        "gap_count": len(ledger.get("gaps", [])),
        "done_evidence_audit_count": len(ledger.get("done_evidence_audit", [])),
    },
)

drift_expect = required.get("drift_expectations", {})
if not isinstance(drift_expect, dict):
    err("drift_expectations must be an object")
    drift_expect = {}
expect_exact(drift.get("schema_version"), drift_expect.get("schema_version"), "drift.schema_version")
expect_exact(drift.get("bead"), drift_expect.get("bead"), "drift.bead")
expect_exact(len(drift.get("diagnostics", [])), drift_expect.get("diagnostic_count"), "drift diagnostic count")
drift_summary = drift.get("summary", {}) if isinstance(drift.get("summary"), dict) else {}
expect_exact(drift_summary.get("fail_count"), drift_expect.get("fail_count"), "drift fail_count")
expect_exact(drift_summary.get("tracked_count"), drift_expect.get("tracked_count"), "drift tracked_count")
for row in drift.get("diagnostics", []):
    if isinstance(row, dict):
        for field in ["gap_id", "owner_bead", "source_file", "expected_vs_actual"]:
            require(field in row, f"drift diagnostic missing {field}")

append_event(
    "track0_governance_drift_gate_verified",
    "pass" if not errors else "fail",
    [artifacts.get("drift_diagnostics", ""), rel(drift_report)],
    {
        "diagnostic_count": len(drift.get("diagnostics", [])),
        "fail_count": drift_summary.get("fail_count"),
        "tracked_count": drift_summary.get("tracked_count"),
    },
)

coverage_expect = required.get("coverage_expectations", {})
if not isinstance(coverage_expect, dict):
    err("coverage_expectations must be an object")
    coverage_expect = {}
expect_exact(coverage.get("schema_version"), coverage_expect.get("schema_version"), "coverage.schema_version")
expect_exact(coverage.get("bead"), coverage_expect.get("bead"), "coverage.bead")
coverage_summary = coverage.get("summary", {}) if isinstance(coverage.get("summary"), dict) else {}
for field in ["covered_gaps", "uncovered_gaps", "owner_count", "critical_blocker_count"]:
    expect_exact(coverage_summary.get(field), coverage_expect.get(field), f"coverage summary.{field}")
for row in coverage.get("rows", []):
    if isinstance(row, dict):
        require(row.get("owner_found") is True, f"coverage row lacks owner: {row.get('gap_id')}")
for section in as_string_list(required.get("required_dashboard_sections"), "required_track0_contract.required_dashboard_sections"):
    require(section in dashboard_text, f"dashboard missing required section {section}")
source_gate_results["coverage"] = {
    "command": "checked-in coverage artifact/dashboard validation",
    "status": "pass" if not errors else "fail",
    "exit_code": 0 if not errors else 1,
    "stdout_tail": "validated feature_parity_gap_bead_coverage.v1.json and dashboard sections",
    "stderr_tail": "",
}

append_event(
    "track0_governance_coverage_gate_verified",
    "pass" if not errors else "fail",
    [artifacts.get("gap_coverage", ""), artifacts.get("gap_dashboard", "")],
    {
        "covered_gaps": coverage_summary.get("covered_gaps"),
        "uncovered_gaps": coverage_summary.get("uncovered_gaps"),
        "owner_count": coverage_summary.get("owner_count"),
    },
)

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}

status = "pass" if not errors else "fail"
if status == "pass":
    append_event(
        "track0_governance_completion_contract_pass",
        "pass",
        [rel(CONTRACT), artifacts.get("completion_checker", "")],
        {"missing_items_closed": sorted(missing_items_seen), "test_ref_count": sum(len(refs) for refs in test_refs.values())},
    )
else:
    append_event(FAIL_EVENT, "fail", [rel(CONTRACT)], {"errors": errors.copy()})

event_names = {event["event"] for event in events}
for event_name in as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"):
    require(event_name in event_names, f"required telemetry event missing: {event_name}")
if status == "pass":
    forbidden = set(as_string_list(telemetry.get("forbidden_pass_events"), "telemetry_contract.forbidden_pass_events", allow_empty=True))
    observed_forbidden = sorted(forbidden & event_names)
    if observed_forbidden:
        err(f"forbidden pass events observed {observed_forbidden}")
for event in events:
    for field in as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"):
        require(field in event, f"telemetry event {event.get('event')} missing field {field}")

status = "pass" if not errors else "fail"
for event in events:
    event["status"] = status if event["event"] != FAIL_EVENT else "fail"
    if event["event"] == "track0_governance_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "track0_summary": {
        "ledger_rows": len(ledger.get("rows", [])),
        "ledger_gaps": len(ledger.get("gaps", [])),
        "drift_diagnostics": len(drift.get("diagnostics", [])),
        "coverage_rows": len(coverage.get("rows", [])),
        "coverage_uncovered_gaps": coverage_summary.get("uncovered_gaps"),
    },
    "test_refs": test_refs,
    "source_gate_results": source_gate_results,
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
    event["status"] = status if event["event"] != FAIL_EVENT else "fail"
    if event["event"] == "track0_governance_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if errors:
    for message in errors:
        print(f"ERROR: {message}", file=os.sys.stderr)
    raise SystemExit(1)

print(
    "PASS: feature parity governance completion contract validated "
    f"ledger_gaps={report['track0_summary']['ledger_gaps']} "
    f"drift_diagnostics={report['track0_summary']['drift_diagnostics']} "
    f"coverage_uncovered={report['track0_summary']['coverage_uncovered_gaps']}"
)
PY
