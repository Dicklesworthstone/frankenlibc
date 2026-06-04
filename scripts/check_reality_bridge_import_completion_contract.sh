#!/usr/bin/env bash
# Gate for bd-bp8fl.2.2.1 reality bridge import completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_CONTRACT:-$ROOT/tests/conformance/reality_bridge_import_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_REPORT:-$ROOT/target/conformance/reality_bridge_import_completion_contract.report.json}"
LOG="${FRANKENLIBC_REALITY_BRIDGE_IMPORT_COMPLETION_LOG:-$ROOT/target/conformance/reality_bridge_import_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
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

COMPLETION_BEAD = "bd-bp8fl.2.2.1"
ORIGINAL_BEAD = "bd-bp8fl.2.2"
EXPECTED_SCHEMA = "reality_bridge_import_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.2.2.1-reality-bridge-import-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_COUNTS = {
    "backlog_source_rows": 10,
    "backlog_import_rows": 10,
    "feature_ledger_rows": 170,
    "feature_ledger_unresolved_gaps": 110,
    "feature_gap_import_rows": 110,
    "feature_gap_batches": 10,
    "unique_target_issue_count": 64,
    "rejected_row_count": 0,
    "missing_target_issue_count": 0,
    "missing_acceptance_target_count": 0,
    "missing_dependency_count": 0,
    "stale_source_snapshot_count": 0,
    "lost_feature_gap_count": 0,
}
EXPECTED_NEGATIVE_CASES = {
    "duplicate_source_row",
    "missing_required_field",
    "stale_source_snapshot",
    "missing_dependency",
    "missing_acceptance",
    "no_feature_loss",
}
EXPECTED_TELEMETRY_EVENTS = {
    "reality_bridge_import_completion_contract_validated",
    "reality_bridge_import_completion_contract_failed",
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
    "backlog_source_rows",
    "feature_gap_import_rows",
    "unique_target_issue_count",
    "failure_signature",
}

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
if isinstance(conformance, dict):
    required_artifacts = as_string_list(
        conformance.get("required_artifacts"), "conformance_primary.required_artifacts"
    )
    for path_text in required_artifacts:
        if not (ROOT / path_text).is_file():
            err(f"conformance artifact missing: {path_text}")

    required_counts = conformance.get("required_counts")
    if not isinstance(required_counts, dict):
        err("conformance_primary.required_counts must be an object")
        required_counts = {}
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
    required_artifacts = []
    required_counts = {}
    required_negative_cases = set()

reconciliation_path = ROOT / source_artifacts.get(
    "reconciliation_artifact", "tests/conformance/reality_bridge_import_reconciliation.v1.json"
)
reconciliation = load_json(reconciliation_path)
summary = reconciliation.get("summary", {})
if not isinstance(summary, dict):
    err("reconciliation summary must be an object")
    summary = {}
for key, expected in EXPECTED_COUNTS.items():
    if summary.get(key) != expected:
        err(f"reconciliation.summary.{key} expected {expected}, got {summary.get(key)}")
    if isinstance(required_counts, dict) and required_counts.get(key) != summary.get(key):
        err(f"contract count {key} does not match reconciliation summary")

if len(reconciliation.get("backlog_import_rows", [])) != EXPECTED_COUNTS["backlog_import_rows"]:
    err("backlog_import_rows length drifted")
if len(reconciliation.get("feature_gap_import_rows", [])) != EXPECTED_COUNTS["feature_gap_import_rows"]:
    err("feature_gap_import_rows length drifted")
if reconciliation.get("rejected_rows") != []:
    err("reconciliation rejected_rows must remain empty")

for row in reconciliation.get("backlog_import_rows", []):
    if not isinstance(row, dict):
        err("backlog_import_rows entries must be objects")
        continue
    if row.get("failure_signature") != "ok":
        err(f"{row.get('source_row_id')}: failure_signature must be ok")
    if row.get("source_freshness", {}).get("state") != "fresh":
        err(f"{row.get('source_row_id')}: source freshness must be fresh")
for row in reconciliation.get("feature_gap_import_rows", []):
    if not isinstance(row, dict):
        err("feature_gap_import_rows entries must be objects")
        continue
    if row.get("failure_signature") != "ok":
        err(f"{row.get('source_row_id')}: failure_signature must be ok")
    if row.get("source_freshness", {}).get("state") != "fresh":
        err(f"{row.get('source_row_id')}: source freshness must be fresh")
    if row.get("missing_dependencies"):
        err(f"{row.get('source_row_id')}: missing_dependencies must remain empty")

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
    if telemetry.get("default_report_path") != "target/conformance/reality_bridge_import_completion_contract.report.json":
        err("telemetry_primary.default_report_path drifted")
    if telemetry.get("default_log_path") != "target/conformance/reality_bridge_import_completion_contract.log.jsonl":
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
    "reality_bridge_import_completion_contract_validated"
    if status == "pass"
    else "reality_bridge_import_completion_contract_failed"
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
    | {rel(CONTRACT), rel(REPORT), rel(LOG)}
)

report = {
    "schema_version": "reality_bridge_import_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "generated_at_utc": timestamp,
    "source_commit": source_commit,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": all_test_refs,
    "required_artifacts": required_artifacts,
    "required_counts": {key: summary.get(key) for key in EXPECTED_COUNTS},
    "required_negative_cases": sorted(required_negative_cases),
    "required_events": sorted(telemetry_events),
    "required_fields": sorted(telemetry_fields),
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_row = {
    "timestamp": timestamp,
    "trace_id": f"reality_bridge::import_completion::{COMPLETION_BEAD}",
    "event": event,
    "level": "info" if status == "pass" else "error",
    "schema_version": "reality_bridge_import_completion_contract.log.v1",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": all_test_refs,
    "artifact_refs": artifact_refs,
    "backlog_source_rows": summary.get("backlog_source_rows"),
    "feature_gap_import_rows": summary.get("feature_gap_import_rows"),
    "unique_target_issue_count": summary.get("unique_target_issue_count"),
    "failure_signature": "none" if status == "pass" else "reality_bridge_import_completion_contract_failed",
    "errors": errors,
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print("FAIL: reality bridge import completion contract failed", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "reality bridge import completion contract validated: "
    f"missing_items={len(set(missing_items_bound))} "
    f"backlog_rows={summary.get('backlog_import_rows')} "
    f"feature_gaps={summary.get('feature_gap_import_rows')}"
)
PY
