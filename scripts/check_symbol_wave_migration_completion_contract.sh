#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYMBOL_WAVE_MIGRATION_COMPLETION_CONTRACT:-$ROOT/tests/conformance/symbol_wave_migration_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SYMBOL_WAVE_MIGRATION_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_SYMBOL_WAVE_MIGRATION_COMPLETION_REPORT:-$OUT_DIR/symbol_wave_migration_completion_contract.report.json}"
LOG="${FRANKENLIBC_SYMBOL_WAVE_MIGRATION_COMPLETION_LOG:-$OUT_DIR/symbol_wave_migration_completion_contract.log.jsonl}"
REPLACEMENT_GUARD_REPORT="${FRANKENLIBC_SYMBOL_WAVE_REPLACEMENT_GUARD_REPORT:-$OUT_DIR/symbol_wave_migration.replacement_guard.report.json}"
REPLACEMENT_GUARD_LOG="${FRANKENLIBC_SYMBOL_WAVE_REPLACEMENT_GUARD_LOG:-$OUT_DIR/symbol_wave_migration.replacement_guard.log.jsonl}"
INTERPOSE_GUARD_REPORT="${FRANKENLIBC_SYMBOL_WAVE_INTERPOSE_GUARD_REPORT:-$OUT_DIR/symbol_wave_migration.interpose_guard.report.json}"
INTERPOSE_GUARD_LOG="${FRANKENLIBC_SYMBOL_WAVE_INTERPOSE_GUARD_LOG:-$OUT_DIR/symbol_wave_migration.interpose_guard.log.jsonl}"
RESIDUAL_REPORT="$ROOT/target/conformance/residual_replacement_callthrough_blockers.report.json"
RESIDUAL_LOG="$ROOT/target/conformance/residual_replacement_callthrough_blockers.log.jsonl"
CENSUS_REPORT="$ROOT/target/conformance/callthrough_census.report.json"
CENSUS_LOG="$ROOT/target/conformance/callthrough_census.log.jsonl"

mkdir -p \
  "$(dirname "$REPORT")" \
  "$(dirname "$LOG")" \
  "$(dirname "$REPLACEMENT_GUARD_REPORT")" \
  "$(dirname "$INTERPOSE_GUARD_REPORT")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
REPLACEMENT_GUARD_REPORT="$REPLACEMENT_GUARD_REPORT" \
REPLACEMENT_GUARD_LOG="$REPLACEMENT_GUARD_LOG" \
INTERPOSE_GUARD_REPORT="$INTERPOSE_GUARD_REPORT" \
INTERPOSE_GUARD_LOG="$INTERPOSE_GUARD_LOG" \
RESIDUAL_REPORT="$RESIDUAL_REPORT" \
RESIDUAL_LOG="$RESIDUAL_LOG" \
CENSUS_REPORT="$CENSUS_REPORT" \
CENSUS_LOG="$CENSUS_LOG" \
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
REPLACEMENT_GUARD_REPORT = pathlib.Path(os.environ["REPLACEMENT_GUARD_REPORT"])
REPLACEMENT_GUARD_LOG = pathlib.Path(os.environ["REPLACEMENT_GUARD_LOG"])
INTERPOSE_GUARD_REPORT = pathlib.Path(os.environ["INTERPOSE_GUARD_REPORT"])
INTERPOSE_GUARD_LOG = pathlib.Path(os.environ["INTERPOSE_GUARD_LOG"])
RESIDUAL_REPORT = pathlib.Path(os.environ["RESIDUAL_REPORT"])
RESIDUAL_LOG = pathlib.Path(os.environ["RESIDUAL_LOG"])
CENSUS_REPORT = pathlib.Path(os.environ["CENSUS_REPORT"])
CENSUS_LOG = pathlib.Path(os.environ["CENSUS_LOG"])

EXPECTED_SCHEMA = "symbol_wave_migration_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "symbol_wave_migration_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.2.1"
COMPLETION_BEAD = "bd-w2c3.2.1.3"

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


def run_command(command: list[str], env: dict[str, str] | None, label: str) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=merged,
        check=False,
    )
    if proc.returncode != 0:
        err(
            f"{label} failed: exit={proc.returncode} "
            f"stdout={proc.stdout[:1600]!r} stderr={proc.stderr[:1600]!r}"
        )


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


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

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

for ref in evidence.get("implementation_refs", []):
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

test_sources = evidence.get("test_sources", {})
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

support = load_json(ROOT / str(source_artifacts.get("support_matrix", "")), "support_matrix")
symbols = support.get("symbols", [])
if not isinstance(symbols, list):
    err("support_matrix.symbols must be an array")
    symbols = []
status_counts = Counter(str(row.get("status")) for row in symbols if isinstance(row, dict))
require(support.get("total_exported") == required.get("support_matrix_total_exported"), "support_matrix.total_exported mismatch")
for status, expected in required.get("support_matrix_status_counts", {}).items():
    require(status_counts.get(status, 0) == expected, f"support_matrix status count mismatch for {status}")

levels = load_json(ROOT / str(source_artifacts.get("replacement_levels", "")), "replacement_levels")
assessment = levels.get("current_assessment", {}) if isinstance(levels.get("current_assessment"), dict) else {}
for field, expected in required.get("replacement_current_assessment", {}).items():
    require(assessment.get(field) == expected, f"replacement current_assessment.{field} mismatch")

fixture_pack = load_json(ROOT / str(source_artifacts.get("replacement_zero_unapproved_fixtures", "")), "replacement_zero_unapproved_fixtures")
fixture_summary = fixture_pack.get("summary", {}) if isinstance(fixture_pack.get("summary"), dict) else {}
require(fixture_summary.get("replacement_forbidden_count") == 0, "fixture summary replacement_forbidden_count must be zero")
require(fixture_summary.get("interpose_allowed_count") == 0, "fixture summary interpose_allowed_count must be zero")

run_command(["bash", str(ROOT / "scripts/check_callthrough_census.sh")], None, "scripts/check_callthrough_census.sh")
run_command(
    ["bash", str(ROOT / "scripts/check_residual_replacement_callthrough_blockers.sh"), "--validate-only"],
    {
        "RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_REPORT": str(REPLACEMENT_GUARD_REPORT),
        "RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_LOG": str(REPLACEMENT_GUARD_LOG),
        "RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_REPORT": str(INTERPOSE_GUARD_REPORT),
        "RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_LOG": str(INTERPOSE_GUARD_LOG),
    },
    "scripts/check_residual_replacement_callthrough_blockers.sh",
)

census_artifact = load_json(ROOT / str(source_artifacts.get("callthrough_census", "")), "callthrough_census")
census_report = load_json(CENSUS_REPORT, "callthrough_census_report")
census_events = json_lines(CENSUS_LOG, "callthrough_census_log")
census_required = required.get("callthrough_census", {})
require(census_artifact.get("schema_version") == census_required.get("schema_version"), "callthrough census schema_version mismatch")
require(census_artifact.get("bead") == census_required.get("bead"), "callthrough census bead mismatch")
census_summary = census_artifact.get("summary", {}) if isinstance(census_artifact.get("summary"), dict) else {}
census_source = census_artifact.get("source", {}) if isinstance(census_artifact.get("source"), dict) else {}
for field in ["module_count", "symbol_count", "wave_count", "strict_hotpath_count", "coldpath_count"]:
    require(census_summary.get(field) == census_required.get(field), f"callthrough census summary.{field} mismatch")
for field in ["derived_callthrough_symbols", "status_summary_callthrough"]:
    require(census_source.get(field) == census_required.get(field), f"callthrough census source.{field} mismatch")
require(len(census_artifact.get("symbol_census", [])) == census_required.get("symbol_count"), "callthrough census symbol_census length mismatch")
require(len(census_artifact.get("module_census", [])) == census_required.get("module_count"), "callthrough census module_census length mismatch")
require(len(census_artifact.get("decommission_waves", [])) == census_required.get("wave_count"), "callthrough census decommission_waves length mismatch")
for check_id in as_string_list(required.get("required_census_checks"), "required_source_contract.required_census_checks"):
    require(census_report.get("checks", {}).get(check_id) == "pass", f"callthrough census check {check_id} did not pass")
require(census_report.get("summary", {}).get("symbol_count") == census_required.get("symbol_count"), "callthrough census report symbol_count mismatch")

residual_contract = load_json(ROOT / str(source_artifacts.get("residual_callthrough_blockers", "")), "residual_callthrough_blockers")
residual_report = load_json(RESIDUAL_REPORT, "residual_callthrough_report")
residual_events = json_lines(RESIDUAL_LOG, "residual_callthrough_log")
residual_required = required.get("residual_truth", {})
current_truth = residual_contract.get("current_truth", {}) if isinstance(residual_contract.get("current_truth"), dict) else {}
require(residual_contract.get("generated_by_bead") == residual_required.get("generated_by_bead"), "residual generated_by_bead mismatch")
require(current_truth.get("residual_forbidden_count") == residual_required.get("residual_forbidden_count"), "residual current_truth.residual_forbidden_count mismatch")
require(current_truth.get("followup_child_beads_created") == residual_required.get("followup_child_beads_created"), "residual current_truth.followup_child_beads_created mismatch")
require(current_truth.get("claim_status") == residual_required.get("claim_status"), "residual current_truth.claim_status mismatch")
todo_ids = current_truth.get("stale_ledger_reconciliation", {}).get("todo_ids")
if todo_ids is None:
    todo_ids = residual_contract.get("stale_ledger_reconciliation", {}).get("todo_ids")
require(sorted(todo_ids or []) == sorted(required.get("required_stale_todo_ids", [])), "residual stale todo ids mismatch")
require(residual_report.get("outcome") == "pass", "residual callthrough report outcome must be pass")
residual_summary = residual_report.get("summary", {}) if isinstance(residual_report.get("summary"), dict) else {}
require(residual_summary.get("replacement_total_call_throughs") == residual_required.get("replacement_total_call_throughs"), "residual replacement_total_call_throughs mismatch")
require(residual_summary.get("interpose_total_call_throughs") == residual_required.get("interpose_total_call_throughs"), "residual interpose_total_call_throughs mismatch")
require(residual_summary.get("residual_forbidden_count") == residual_required.get("residual_forbidden_count"), "residual report residual_forbidden_count mismatch")
for check_id in as_string_list(required.get("required_residual_checks"), "required_source_contract.required_residual_checks"):
    require(residual_report.get("checks", {}).get(check_id) == "pass", f"residual check {check_id} did not pass")

guard_reports = {
    "replacement": load_json(REPLACEMENT_GUARD_REPORT, "replacement_guard_report"),
    "interpose": load_json(INTERPOSE_GUARD_REPORT, "interpose_guard_report"),
}
for mode in as_string_list(required.get("required_guard_modes"), "required_source_contract.required_guard_modes"):
    report = guard_reports.get(mode, {})
    require(report.get("mode") == mode, f"{mode} guard report mode mismatch")
    require(report.get("ok") is True, f"{mode} guard report must be ok")
    require(report.get("total_call_throughs") == 0, f"{mode} guard total_call_throughs must be zero")
    require(report.get("modules_with_call_throughs") == 0, f"{mode} guard modules_with_call_throughs must be zero")
    require(report.get("violations") == 0, f"{mode} guard violations must be zero")
    require(report.get("mutex_forbidden_count") == 0, f"{mode} guard mutex_forbidden_count must be zero")

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

source_commit = git_head()
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
events = [
    {
        "timestamp": timestamp,
        "event": "symbol_wave_migration_completion_summary",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "summary",
        "source_commit": source_commit,
        "support_matrix_total_exported": support.get("total_exported"),
        "implemented": status_counts.get("Implemented", 0),
        "raw_syscall": status_counts.get("RawSyscall", 0),
        "callthrough": status_counts.get("GlibcCallThrough", 0),
        "stub": status_counts.get("Stub", 0),
        "artifact_refs": [rel(CONTRACT), str(source_artifacts.get("support_matrix")), str(source_artifacts.get("replacement_levels"))],
    },
    {
        "timestamp": timestamp,
        "event": "symbol_wave_migration_callthrough_census_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "callthrough_census",
        "source_commit": source_commit,
        "callthrough_census_report": rel(CENSUS_REPORT),
        "callthrough_census_log": rel(CENSUS_LOG),
        "source_log_row_count": len(census_events),
        "artifact_refs": [str(source_artifacts.get("callthrough_census")), rel(CENSUS_REPORT), rel(CENSUS_LOG)],
    },
    {
        "timestamp": timestamp,
        "event": "symbol_wave_migration_residual_guard_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "residual_guard",
        "source_commit": source_commit,
        "residual_callthrough_report": rel(RESIDUAL_REPORT),
        "residual_callthrough_log": rel(RESIDUAL_LOG),
        "replacement_guard_report": rel(REPLACEMENT_GUARD_REPORT),
        "interpose_guard_report": rel(INTERPOSE_GUARD_REPORT),
        "source_log_row_count": len(residual_events),
        "artifact_refs": [
            str(source_artifacts.get("residual_callthrough_blockers")),
            rel(RESIDUAL_REPORT),
            rel(REPLACEMENT_GUARD_REPORT),
            rel(INTERPOSE_GUARD_REPORT),
        ],
    },
    {
        "timestamp": timestamp,
        "event": "symbol_wave_migration_completion_contract_pass",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "pass" if status == "pass" else "fail",
        "source_commit": source_commit,
        "artifact_refs": [rel(REPORT), rel(LOG)],
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
    if event["event"] == "symbol_wave_migration_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "support_matrix_total_exported": support.get("total_exported"),
        "support_matrix_status_counts": {status: status_counts.get(status, 0) for status in sorted(required.get("support_matrix_status_counts", {}).keys())},
        "replacement_current_assessment": assessment,
        "callthrough_census": census_summary,
        "residual_forbidden_count": residual_summary.get("residual_forbidden_count"),
        "replacement_total_call_throughs": residual_summary.get("replacement_total_call_throughs"),
        "interpose_total_call_throughs": residual_summary.get("interpose_total_call_throughs"),
    },
    "callthrough_census_report": rel(CENSUS_REPORT),
    "callthrough_census_log": rel(CENSUS_LOG),
    "residual_callthrough_report": rel(RESIDUAL_REPORT),
    "residual_callthrough_log": rel(RESIDUAL_LOG),
    "replacement_guard_reports": {
        "replacement": rel(REPLACEMENT_GUARD_REPORT),
        "interpose": rel(INTERPOSE_GUARD_REPORT),
    },
    "source_log_row_counts": {
        "callthrough_census": len(census_events),
        "residual_callthrough": len(residual_events),
        "replacement_guard": len(json_lines(REPLACEMENT_GUARD_LOG, "replacement_guard_log")),
        "interpose_guard": len(json_lines(INTERPOSE_GUARD_LOG, "interpose_guard_log")),
    },
    "events": [event["event"] for event in events],
    "errors": errors,
}

for field in as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields"):
    if field not in report:
        err(f"completion report missing required field {field}")

status = "pass" if not errors else "fail"
report["status"] = status
for event in events:
    event["status"] = status
    if event["event"] == "symbol_wave_migration_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if status == "pass":
    print(
        "PASS: symbol-wave migration completion contract "
        f"(callthrough_symbols={census_summary.get('symbol_count')}, residual={residual_summary.get('residual_forbidden_count')}, report={rel(REPORT)})"
    )
else:
    print(f"FAIL: symbol-wave migration completion contract ({len(errors)} errors)")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)
PY
