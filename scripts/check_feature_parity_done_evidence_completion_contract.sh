#!/usr/bin/env bash
# Gate for bd-bp8fl.3.2.1 feature parity DONE evidence completion.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FEATURE_PARITY_DONE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/feature_parity_done_evidence_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_FEATURE_PARITY_DONE_COMPLETION_REPORT:-$ROOT/target/conformance/feature_parity_done_evidence_completion_contract.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_DONE_COMPLETION_LOG:-$ROOT/target/conformance/feature_parity_done_evidence_completion_contract.log.jsonl}"
SOURCE_REPORT="${FRANKENLIBC_FEATURE_PARITY_DONE_SOURCE_REPORT:-$ROOT/target/conformance/feature_parity_done_evidence.report.json}"
SOURCE_LOG="${FRANKENLIBC_FEATURE_PARITY_DONE_SOURCE_LOG:-$ROOT/target/conformance/feature_parity_done_evidence.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SOURCE_REPORT")" "$(dirname "$SOURCE_LOG")"

FLC_FP_DONE_EVIDENCE_REPORT="$SOURCE_REPORT" \
FLC_FP_DONE_EVIDENCE_LOG="$SOURCE_LOG" \
bash "$ROOT/scripts/check_feature_parity_gap_ledger.sh" >/dev/null

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" SOURCE_REPORT="$SOURCE_REPORT" SOURCE_LOG="$SOURCE_LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
SOURCE_LOG = pathlib.Path(os.environ["SOURCE_LOG"])

COMPLETION_BEAD = "bd-bp8fl.3.2.1"
ORIGINAL_BEAD = "bd-bp8fl.3.2"
EXPECTED_SCHEMA = "feature_parity_done_evidence_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.3.2.1-feature-parity-done-evidence-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_COUNTS = {
    "row_count": 170,
    "gap_count": 110,
    "delta_count": 5,
    "done_row_count": 60,
    "done_evidence_audit_count": 60,
    "invalid_done_evidence_count": 59,
    "done_evidence_pass_count": 1,
    "done_evidence_fail_count": 59,
    "fresh_done_evidence_count": 1,
    "prose_only_done_evidence_count": 34,
    "source_only_done_evidence_count": 25,
    "parse_error_count": 0,
    "transition_count": 0,
    "drift_delta_count": 0,
}
EXPECTED_NEGATIVE_CASES = {
    "fresh_evidence",
    "missing_artifact",
    "stale_commit",
    "contradictory_artifact",
    "archived_canonical_artifact",
    "prose_only_done_claim",
    "done_audit_count_drift",
}
EXPECTED_TELEMETRY_EVENTS = {
    "feature_parity_done_evidence_completion_contract_validated",
    "feature_parity_done_evidence_completion_contract_failed",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "schema_version",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "artifact_refs",
    "row_count",
    "done_evidence_audit_count",
    "invalid_done_evidence_count",
    "freshness_counts",
    "failure_signature",
}
EXPECTED_FRESHNESS = {"fresh": 1, "prose_only": 34, "source_only": 25}
EXPECTED_AUDIT_COUNTS = {"pass": 1, "fail": 59}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{rel(path)} must be a JSON object")
        return {}
    return value


def load_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{rel(path)} is not readable: {exc}")
        return rows
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except Exception as exc:
            err(f"{rel(path)}:{index} is not valid JSON: {exc}")
            continue
        if not isinstance(value, dict):
            err(f"{rel(path)}:{index} must be a JSON object")
            continue
        rows.append(value)
    return rows


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def as_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


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


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(key, str) or not key:
            err("test_sources keys must be non-empty strings")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def validate_test_refs(
    section: dict[str, Any], section_name: str, texts: dict[str, str]
) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(
                f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object"
            )
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(
                f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty"
            )
            continue
        if not isinstance(name, str) or not name:
            err(
                f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty"
            )
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif f"fn {name}" not in text:
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


manifest = load_json(CONTRACT)
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

for source in as_string_list(manifest.get("source_modules"), "source_modules"):
    if not (ROOT / source).is_file():
        err(f"source module missing: {source}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    err("completion_debt_evidence must be an object")
    completion = {}
if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")

for index, ref in enumerate(completion.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"implementation_refs[{index}]")

source_artifacts = completion.get("source_artifacts")
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("completion_debt_evidence.source_artifacts must be a non-empty object")
    source_artifacts = {}
for key, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{key} must be a non-empty string")
    elif not (ROOT / path_text).is_file():
        err(f"source_artifacts.{key} references missing file: {path_text}")

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, expected_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != expected_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {expected_item}")
    missing_items_bound.append(expected_item)
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)

conformance = completion.get("conformance_primary")
required_artifacts: list[str] = []
required_counts: dict[str, Any] = {}
required_negative_cases: set[str] = set()
if isinstance(conformance, dict):
    required_artifacts = as_string_list(
        conformance.get("required_artifacts"), "conformance_primary.required_artifacts"
    )
    for path_text in required_artifacts:
        if not (ROOT / path_text).is_file():
            err(f"conformance artifact missing: {path_text}")

    raw_required_counts = conformance.get("required_counts")
    if not isinstance(raw_required_counts, dict):
        err("conformance_primary.required_counts must be an object")
    else:
        required_counts = raw_required_counts
    for key, expected in EXPECTED_COUNTS.items():
        if required_counts.get(key) != expected:
            err(f"conformance_primary.required_counts.{key} expected {expected}")

    required_negative_cases = set(
        as_string_list(
            conformance.get("required_negative_cases"),
            "conformance_primary.required_negative_cases",
        )
    )
    missing_cases = sorted(EXPECTED_NEGATIVE_CASES - required_negative_cases)
    if missing_cases:
        err(f"conformance_primary.required_negative_cases missing {missing_cases}")
else:
    err("completion_debt_evidence.conformance_primary must be an object")

ledger_path = ROOT / source_artifacts.get(
    "feature_gap_ledger", "tests/conformance/feature_parity_gap_ledger.v1.json"
)
ledger = load_json(ledger_path)
summary = ledger.get("summary", {})
if not isinstance(summary, dict):
    err("feature parity ledger summary must be an object")
    summary = {}
rows = ledger.get("rows", [])
gaps = ledger.get("gaps", [])
deltas = ledger.get("deltas", [])
done_audit = ledger.get("done_evidence_audit", [])
parse_errors = ledger.get("parse_errors", [])
done_rows = [row for row in rows if isinstance(row, dict) and row.get("status") == "DONE"]
invalid_done = [row for row in done_audit if isinstance(row, dict) and row.get("audit_status") != "pass"]

observed_counts = {
    "row_count": len(rows) if isinstance(rows, list) else None,
    "gap_count": len(gaps) if isinstance(gaps, list) else None,
    "delta_count": len(deltas) if isinstance(deltas, list) else None,
    "done_row_count": len(done_rows),
    "done_evidence_audit_count": len(done_audit) if isinstance(done_audit, list) else None,
    "invalid_done_evidence_count": len(invalid_done),
    "done_evidence_pass_count": summary.get("done_evidence_audit_counts", {}).get("pass"),
    "done_evidence_fail_count": summary.get("done_evidence_audit_counts", {}).get("fail"),
    "fresh_done_evidence_count": summary.get("done_evidence_freshness_counts", {}).get("fresh"),
    "prose_only_done_evidence_count": summary.get("done_evidence_freshness_counts", {}).get("prose_only"),
    "source_only_done_evidence_count": summary.get("done_evidence_freshness_counts", {}).get("source_only"),
    "parse_error_count": len(parse_errors) if isinstance(parse_errors, list) else None,
    "transition_count": summary.get("transition_count"),
    "drift_delta_count": summary.get("drift_delta_count"),
}
for key, expected in EXPECTED_COUNTS.items():
    if observed_counts.get(key) != expected:
        err(f"observed {key} expected {expected}, got {observed_counts.get(key)}")
    if required_counts.get(key) != observed_counts.get(key):
        err(f"contract count {key} does not match observed ledger count")

if not isinstance(done_audit, list):
    err("done_evidence_audit must be an array")
else:
    seen_done_ids = {row.get("row_id") for row in done_rows if isinstance(row, dict)}
    for index, audit in enumerate(done_audit):
        if not isinstance(audit, dict):
            err(f"done_evidence_audit[{index}] must be an object")
            continue
        for key in [
            "ledger_row_id",
            "freshness_state",
            "expected",
            "actual",
            "source_commit",
            "artifact_refs",
            "failure_signature",
            "audit_status",
        ]:
            if key not in audit:
                err(f"done_evidence_audit[{index}] missing {key}")
        if audit.get("ledger_row_id") not in seen_done_ids:
            err(f"done_evidence_audit[{index}] references unknown DONE row")

source_report = load_json(SOURCE_REPORT)
source_log_rows = load_jsonl(SOURCE_LOG)
source_summary = source_report.get("summary", {})
if source_report.get("schema_version") != "v1":
    err("source DONE evidence report schema_version must be v1")
if source_report.get("bead") != ORIGINAL_BEAD:
    err(f"source DONE evidence report bead must be {ORIGINAL_BEAD}")
if isinstance(source_summary, dict):
    if source_summary.get("audited_done_row_count") != EXPECTED_COUNTS["done_evidence_audit_count"]:
        err("source report audited DONE row count drifted")
    if source_summary.get("invalid_done_evidence_count") != EXPECTED_COUNTS["invalid_done_evidence_count"]:
        err("source report invalid DONE row count drifted")
    if source_summary.get("freshness_counts") != EXPECTED_FRESHNESS:
        err("source report freshness distribution drifted")
else:
    err("source DONE evidence report summary must be an object")
if len(source_log_rows) != EXPECTED_COUNTS["done_evidence_audit_count"]:
    err("source DONE evidence log row count drifted")
for index, row in enumerate(source_log_rows):
    for key in [
        "trace_id",
        "bead_id",
        "ledger_row_id",
        "evidence_ref",
        "freshness_state",
        "expected",
        "actual",
        "source_commit",
        "artifact_refs",
        "failure_signature",
    ]:
        if key not in row:
            err(f"source DONE evidence log row {index} missing {key}")
    if row.get("bead_id") != ORIGINAL_BEAD:
        err(f"source DONE evidence log row {index} bead_id drifted")

telemetry = completion.get("telemetry_primary")
telemetry_events: set[str] = set()
telemetry_fields: set[str] = set()
if isinstance(telemetry, dict):
    telemetry_events = set(
        as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events")
    )
    telemetry_fields = set(
        as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields")
    )
    if telemetry.get("default_report_path") != "target/conformance/feature_parity_done_evidence_completion_contract.report.json":
        err("telemetry_primary.default_report_path drifted")
    if telemetry.get("default_log_path") != "target/conformance/feature_parity_done_evidence_completion_contract.log.jsonl":
        err("telemetry_primary.default_log_path drifted")
else:
    err("completion_debt_evidence.telemetry_primary must be an object")

missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - telemetry_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - telemetry_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

source_commit = git_head()
status = "pass" if not errors else "fail"
event = (
    "feature_parity_done_evidence_completion_contract_validated"
    if status == "pass"
    else "feature_parity_done_evidence_completion_contract_failed"
)
timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
all_test_refs = [
    f"{ref['source']}::{ref['name']}"
    for refs in test_refs_by_section.values()
    for ref in refs
]
artifact_refs = sorted(
    set(required_artifacts)
    | set(str(path) for path in source_artifacts.values() if isinstance(path, str))
    | {rel(CONTRACT), rel(REPORT), rel(LOG), rel(SOURCE_REPORT), rel(SOURCE_LOG)}
)
freshness_counts = summary.get("done_evidence_freshness_counts", {})
audit_counts = summary.get("done_evidence_audit_counts", {})

report = {
    "schema_version": "feature_parity_done_evidence_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "generated_at_utc": timestamp,
    "source_commit": source_commit,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": all_test_refs,
    "required_artifacts": required_artifacts,
    "required_counts": observed_counts,
    "audit_counts": audit_counts,
    "freshness_counts": freshness_counts,
    "required_negative_cases": sorted(required_negative_cases),
    "required_events": sorted(telemetry_events),
    "required_fields": sorted(telemetry_fields),
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_row = {
    "timestamp": timestamp,
    "trace_id": f"feature_parity::done_evidence_completion::{COMPLETION_BEAD}",
    "event": event,
    "level": "info" if status == "pass" else "error",
    "schema_version": "feature_parity_done_evidence_completion_contract.log.v1",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": all_test_refs,
    "artifact_refs": artifact_refs,
    "row_count": observed_counts.get("row_count"),
    "done_evidence_audit_count": observed_counts.get("done_evidence_audit_count"),
    "invalid_done_evidence_count": observed_counts.get("invalid_done_evidence_count"),
    "freshness_counts": freshness_counts,
    "failure_signature": "none" if status == "pass" else "feature_parity_done_evidence_completion_contract_failed",
    "errors": errors,
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print("FAIL: feature parity DONE evidence completion contract failed", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "feature parity DONE evidence completion contract validated: "
    f"missing_items={len(set(missing_items_bound))} "
    f"rows={observed_counts.get('row_count')} "
    f"done_audited={observed_counts.get('done_evidence_audit_count')} "
    f"invalid_done={observed_counts.get('invalid_done_evidence_count')}"
)
PY
