#!/usr/bin/env bash
# check_matrix_dashboard_export_completion_contract.sh - bd-38s.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MATRIX_DASHBOARD_EXPORT_CONTRACT:-$ROOT/tests/conformance/matrix_dashboard_export_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_MATRIX_DASHBOARD_EXPORT_MATRIX:-$ROOT/tests/conformance/verification_matrix.json}"
REPORT="${FRANKENLIBC_MATRIX_DASHBOARD_EXPORT_REPORT:-$ROOT/target/conformance/matrix_dashboard_export_completion_contract.report.json}"
LOG="${FRANKENLIBC_MATRIX_DASHBOARD_EXPORT_LOG:-$ROOT/target/conformance/matrix_dashboard_export_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" MATRIX="$MATRIX" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
MATRIX = pathlib.Path(os.environ["MATRIX"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "matrix_dashboard_export_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "matrix_dashboard_export_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-38s"
COMPLETION_BEAD = "bd-38s.1"
PASS_EVENT = "matrix_dashboard_export_completion_contract_validated"
FAIL_EVENT = "matrix_dashboard_export_completion_contract_failed"
EXPECTED_DASHBOARD_EVENTS = {
    "matrix_dashboard_text_export_validated",
    "matrix_dashboard_json_export_validated",
    "matrix_dashboard_rows_validated",
    PASS_EVENT,
    FAIL_EVENT,
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "matrix_summary",
    "dashboard_summary",
    "row_count",
    "priority_buckets",
    "missing_items_bound",
    "test_refs",
    "artifact_refs",
    "failure_signature",
}
EXPECTED_FORMATS = {"text", "json"}
EXPECTED_TEXT_NEEDLES = {
    "Verification Matrix Dashboard",
    "Total beads:",
    "BEAD",
    "Legend:",
    "Gaps:",
}
EXPECTED_JSON_TOP_KEYS = {"generated_utc", "bead", "summary", "by_priority", "rows"}
EXPECTED_SUMMARY_FIELDS = {"total", "complete", "partial", "missing"}
EXPECTED_PRIORITY_BUCKETS = {"P0", "P1", "P2"}
EXPECTED_ROW_FIELDS = {
    "bead_id",
    "priority",
    "title",
    "overall",
    "required",
    "complete",
    "partial",
    "missing",
    "gaps",
}
EXPECTED_CONSISTENCY_CHECKS = {
    "summary_total_matches_rows",
    "summary_counts_sum_to_total",
    "priority_counts_sum_to_summary",
    "row_count_matches_matrix_entries",
    "rows_sorted_missing_partial_complete_then_priority",
}
EXPECTED_MISSING_ITEMS = {
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


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


def string_set(value: Any, context: str, allow_empty: bool = False) -> set[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_source(path_text: Any, source_name: str) -> str:
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_name} must be a non-empty string")
        return ""
    path = ROOT / path_text
    if not path.is_file():
        err(f"source_artifacts.{source_name} path missing: {path_text}")
        return ""
    return path.read_text(encoding="utf-8")


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def is_executable(path: pathlib.Path) -> bool:
    try:
        return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text


def run_dashboard(fmt: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "scripts/export_matrix_dashboard.sh", fmt],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require_subset(expected: set[str], actual: set[str], context: str) -> None:
    missing = sorted(expected - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")


contract = load_json(CONTRACT, "contract")
matrix = load_json(MATRIX, "verification_matrix")
source_commit = git_head()

if contract.get("schema_version") != EXPECTED_SCHEMA:
    err("schema_version drifted")
if contract.get("original_bead") != ORIGINAL_BEAD:
    err(f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    err(f"completion_debt_bead must be {COMPLETION_BEAD}")
audit = contract.get("audit_reference")
if not isinstance(audit, dict):
    err("audit_reference must be an object")
    audit = {}
if audit.get("score_threshold", 0) < 800:
    err("audit_reference.score_threshold must be >= 800")

sources = contract.get("source_artifacts")
if not isinstance(sources, dict):
    err("source_artifacts must be an object")
    sources = {}
source_texts = {key: read_source(path, key) for key, path in sources.items()}
script_text = source_texts.get("dashboard_script", "")

for index, ref in enumerate(contract.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"implementation_refs[{index}]")

script_path = ROOT / str(sources.get("dashboard_script", ""))
if not script_path.is_file():
    err("dashboard script missing")
elif not is_executable(script_path):
    err("dashboard script must be executable")

dashboard_contract = contract.get("dashboard_contract")
if not isinstance(dashboard_contract, dict):
    err("dashboard_contract must be an object")
    dashboard_contract = {}

formats = string_set(dashboard_contract.get("required_formats"), "dashboard_contract.required_formats")
text_needles = string_set(dashboard_contract.get("required_text_needles"), "dashboard_contract.required_text_needles")
json_top_keys = string_set(dashboard_contract.get("required_json_top_keys"), "dashboard_contract.required_json_top_keys")
summary_fields = string_set(dashboard_contract.get("required_summary_fields"), "dashboard_contract.required_summary_fields")
priority_buckets = string_set(dashboard_contract.get("required_priority_buckets"), "dashboard_contract.required_priority_buckets")
priority_fields = string_set(dashboard_contract.get("required_priority_fields"), "dashboard_contract.required_priority_fields")
row_fields = string_set(dashboard_contract.get("required_row_fields"), "dashboard_contract.required_row_fields")
consistency_checks = string_set(
    dashboard_contract.get("required_consistency_checks"),
    "dashboard_contract.required_consistency_checks",
)
require_subset(EXPECTED_FORMATS, formats, "dashboard_contract.required_formats")
require_subset(EXPECTED_TEXT_NEEDLES, text_needles, "dashboard_contract.required_text_needles")
require_subset(EXPECTED_JSON_TOP_KEYS, json_top_keys, "dashboard_contract.required_json_top_keys")
require_subset(EXPECTED_SUMMARY_FIELDS, summary_fields, "dashboard_contract.required_summary_fields")
require_subset(EXPECTED_PRIORITY_BUCKETS, priority_buckets, "dashboard_contract.required_priority_buckets")
require_subset(EXPECTED_SUMMARY_FIELDS, priority_fields, "dashboard_contract.required_priority_fields")
require_subset(EXPECTED_ROW_FIELDS, row_fields, "dashboard_contract.required_row_fields")
require_subset(EXPECTED_CONSISTENCY_CHECKS, consistency_checks, "dashboard_contract.required_consistency_checks")

for needle in ["FORMAT=", "rows = []", "'summary'", "'by_priority'", "'rows'", "Verification Matrix Dashboard", "Legend:"]:
    if needle not in script_text:
        err(f"dashboard script missing implementation needle {needle}")

text_proc = run_dashboard("text")
if text_proc.returncode != 0:
    err(f"text dashboard export failed: {text_proc.stderr[:300]}")
for needle in sorted(EXPECTED_TEXT_NEEDLES):
    if needle not in text_proc.stdout:
        err(f"text dashboard output missing {needle}")

json_proc = run_dashboard("json")
dashboard_json: dict[str, Any] = {}
if json_proc.returncode != 0:
    err(f"json dashboard export failed: {json_proc.stderr[:300]}")
else:
    try:
        parsed = json.loads(json_proc.stdout)
        if isinstance(parsed, dict):
            dashboard_json = parsed
        else:
            err("json dashboard output must be an object")
    except Exception as exc:
        err(f"json dashboard output is invalid JSON: {exc}")

matrix_entries = matrix.get("entries")
if not isinstance(matrix_entries, list) or not matrix_entries:
    err("verification_matrix.entries must be a non-empty array")
    matrix_entries = []
matrix_summary = {
    "matrix_entries": len(matrix_entries),
    "matrix_dashboard_total": matrix.get("dashboard", {}).get("total_entries")
    if isinstance(matrix.get("dashboard"), dict)
    else None,
}

dashboard_summary: dict[str, Any] = {}
priority_summary: dict[str, Any] = {}
row_count = 0
if dashboard_json:
    require_subset(EXPECTED_JSON_TOP_KEYS, set(dashboard_json.keys()), "dashboard_json")
    if dashboard_json.get("bead") != ORIGINAL_BEAD:
        err(f"dashboard_json.bead must be {ORIGINAL_BEAD}")
    summary = dashboard_json.get("summary")
    if not isinstance(summary, dict):
        err("dashboard_json.summary must be an object")
        summary = {}
    require_subset(EXPECTED_SUMMARY_FIELDS, set(summary.keys()), "dashboard_json.summary")
    dashboard_summary = {key: summary.get(key) for key in sorted(EXPECTED_SUMMARY_FIELDS)}
    rows = dashboard_json.get("rows")
    if not isinstance(rows, list):
        err("dashboard_json.rows must be an array")
        rows = []
    row_count = len(rows)
    if summary.get("total") != row_count:
        err("summary_total_matches_rows failed")
    counts_total = sum(int(summary.get(field, 0) or 0) for field in ["complete", "partial", "missing"])
    if summary.get("total") != counts_total:
        err("summary_counts_sum_to_total failed")
    if row_count != len(matrix_entries):
        err("row_count_matches_matrix_entries failed")

    by_priority = dashboard_json.get("by_priority")
    if not isinstance(by_priority, dict):
        err("dashboard_json.by_priority must be an object")
        by_priority = {}
    require_subset(EXPECTED_PRIORITY_BUCKETS, set(by_priority.keys()), "dashboard_json.by_priority")
    priority_total = 0
    for bucket in sorted(EXPECTED_PRIORITY_BUCKETS):
        block = by_priority.get(bucket)
        if not isinstance(block, dict):
            err(f"dashboard_json.by_priority.{bucket} must be an object")
            continue
        require_subset(EXPECTED_SUMMARY_FIELDS, set(block.keys()), f"dashboard_json.by_priority.{bucket}")
        priority_total += int(block.get("total", 0) or 0)
        priority_summary[bucket] = {key: block.get(key) for key in sorted(EXPECTED_SUMMARY_FIELDS)}
    if priority_total > int(summary.get("total", 0) or 0):
        err("priority_counts_sum_to_summary failed")

    status_order = {"missing": 0, "partial": 1, "complete": 2}
    sorted_keys = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            err(f"dashboard_json.rows[{index}] must be an object")
            continue
        require_subset(EXPECTED_ROW_FIELDS, set(row.keys()), f"dashboard_json.rows[{index}]")
        if not isinstance(row.get("gaps"), list):
            err(f"dashboard_json.rows[{index}].gaps must be an array")
        try:
            priority_value = int(row.get("priority", 99))
        except (TypeError, ValueError):
            priority_value = 99
        sorted_keys.append((
            status_order.get(row.get("overall"), 0),
            priority_value,
            str(row.get("bead_id", "")),
        ))
    if sorted_keys != sorted(sorted_keys):
        err("rows_sorted_missing_partial_complete_then_priority failed")

source_tests = {
    key: text
    for key, text in source_texts.items()
    if key in {"dashboard_harness", "completion_harness"}
}
test_refs: list[str] = []
missing_items_bound: list[str] = []
for section, expected_item in EXPECTED_MISSING_ITEMS.items():
    block = contract.get(section)
    if not isinstance(block, dict):
        err(f"{section} must be an object")
        continue
    if block.get("missing_item_id") != expected_item:
        err(f"{section}.missing_item_id must be {expected_item}")
    missing_items_bound.append(expected_item)
    refs = block.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"{section}.required_test_refs must be non-empty")
        continue
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"{section}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or source not in source_tests:
            err(f"{section}.required_test_refs[{index}] references unknown source {source!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_tests[source], name):
            err(f"{section}.required_test_refs[{index}] missing test {source}::{name}")
            continue
        test_refs.append(f"{source}::{name}")
    commands = block.get("required_commands", [])
    if section == "e2e_primary":
        if not isinstance(commands, list) or not commands:
            err("e2e_primary.required_commands must be non-empty")
        for command in commands:
            if isinstance(command, str) and "cargo " in command and "rch exec --" not in command:
                err(f"cargo command must route through rch: {command}")

telemetry = contract.get("telemetry_primary")
if not isinstance(telemetry, dict):
    err("telemetry_primary must be an object")
    telemetry = {}
events = string_set(telemetry.get("required_events"), "telemetry_primary.required_events")
fields = string_set(telemetry.get("required_fields"), "telemetry_primary.required_fields")
require_subset(EXPECTED_DASHBOARD_EVENTS, events, "telemetry_primary.required_events")
require_subset(EXPECTED_TELEMETRY_FIELDS, fields, "telemetry_primary.required_fields")
if telemetry.get("default_report_path") != "target/conformance/matrix_dashboard_export_completion_contract.report.json":
    err("telemetry_primary.default_report_path drifted")
if telemetry.get("default_log_path") != "target/conformance/matrix_dashboard_export_completion_contract.log.jsonl":
    err("telemetry_primary.default_log_path drifted")

status = "pass" if not errors else "fail"
artifact_refs = [rel(CONTRACT), rel(MATRIX), rel(REPORT), rel(LOG)]
failure_signature = "none" if not errors else ";".join(errors[:8])
base_row = {
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_BEAD}:matrix_dashboard_export",
    "level": "info" if not errors else "error",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "matrix_summary": matrix_summary,
    "dashboard_summary": dashboard_summary,
    "row_count": row_count,
    "priority_buckets": priority_summary,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": sorted(set(test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
if errors:
    rows = [base_row | {"event": FAIL_EVENT}]
else:
    rows = [
        base_row | {"event": "matrix_dashboard_text_export_validated"},
        base_row | {"event": "matrix_dashboard_json_export_validated"},
        base_row | {"event": "matrix_dashboard_rows_validated"},
        base_row | {"event": PASS_EVENT},
    ]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(CONTRACT),
    "matrix": rel(MATRIX),
    "report_path": rel(REPORT),
    "log_path": rel(LOG),
    "matrix_summary": matrix_summary,
    "dashboard_summary": dashboard_summary,
    "row_count": row_count,
    "priority_buckets": priority_summary,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": sorted(set(test_refs)),
    "required_events": sorted(events),
    "required_fields": sorted(fields),
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"ROW_COUNT={row_count}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    raise SystemExit(1)
PY
