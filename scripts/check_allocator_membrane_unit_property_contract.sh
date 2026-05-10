#!/usr/bin/env bash
# Gate for bd-2x5.4.1 allocator/membrane unit and property completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_ALLOCATOR_MEMBRANE_CONTRACT:-$ROOT/tests/conformance/allocator_membrane_unit_property_contract.v1.json}"
REPORT="${FRANKENLIBC_ALLOCATOR_MEMBRANE_REPORT:-$ROOT/target/conformance/allocator_membrane_unit_property_contract.report.json}"
LOG="${FRANKENLIBC_ALLOCATOR_MEMBRANE_LOG:-$ROOT/target/conformance/allocator_membrane_unit_property_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

COMPLETION_BEAD = "bd-2x5.4.1"
ORIGINAL_BEAD = "bd-2x5.4"
EXPECTED_SCHEMA = "allocator_membrane_unit_property_contract.v1"
EXPECTED_MANIFEST = "bd-2x5.4.1-allocator-membrane-unit-property-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "property_primary": "tests.property.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_TELEMETRY_EVENTS = {
    "allocator_membrane_unit_property_contract_validated",
    "allocator_membrane_unit_property_contract_failed",
    "validation_stage",
    "fault_injection_matrix",
    "fault_injection_log",
    "double_free_report",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "required_events",
    "required_fields",
    "artifact_refs",
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


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
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
    completion = {}
    err("completion_debt_evidence must be an object")

if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 8:
    err("completion_debt_evidence.implementation_refs must contain at least 8 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800 or section_threshold > 1000:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be 800..1000")
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    commands = section.get("required_commands")
    if section_name != "telemetry_primary":
        as_string_list(commands, f"completion_debt_evidence.{section_name}.required_commands")

unit_sources = {ref["source"] for ref in test_refs_by_section.get("unit_primary", [])}
if not {"arena_unit", "fingerprint_unit", "ptr_validator_unit"}.issubset(unit_sources):
    err("unit_primary must include arena, fingerprint, and ptr-validator unit sources")
property_sources = {ref["source"] for ref in test_refs_by_section.get("property_primary", [])}
if not {"fingerprint_unit", "ptr_validator_unit", "allocator_sequences"}.issubset(property_sources):
    err("property_primary must include fingerprint, ptr-validator, and allocator-sequence sources")

telemetry = completion.get("telemetry_primary")
telemetry_events: set[str] = set()
telemetry_fields: set[str] = set()
if isinstance(telemetry, dict):
    telemetry_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    telemetry_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
    if telemetry.get("default_report_path") != "target/conformance/allocator_membrane_unit_property_contract.report.json":
        err("telemetry_primary.default_report_path drifted")
    if telemetry.get("default_log_path") != "target/conformance/allocator_membrane_unit_property_contract.log.jsonl":
        err("telemetry_primary.default_log_path drifted")
else:
    err("completion_debt_evidence.telemetry_primary must be an object")

missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - telemetry_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - telemetry_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

status = "fail" if errors else "pass"
source_commit = git_head()
timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
artifact_refs = [rel(REPORT), rel(LOG)]
report = {
    "schema_version": "allocator_membrane_unit_property_contract.report.v1",
    "status": status,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "missing_items": sorted(EXPECTED_MISSING_ITEMS.values()),
    "missing_items_bound": sorted(item for item in missing_items_bound if item),
    "next_audit_score_threshold": threshold,
    "source_commit": source_commit,
    "implementation_refs": implementation_refs if isinstance(implementation_refs, list) else [],
    "test_refs": test_refs_by_section,
    "required_events": sorted(telemetry_events),
    "required_fields": sorted(telemetry_fields),
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_BEAD}::allocator-membrane-contract::{status}",
    "level": "info" if status == "pass" else "error",
    "event": "allocator_membrane_unit_property_contract_validated"
    if status == "pass"
    else "allocator_membrane_unit_property_contract_failed",
    "bead_id": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": source_commit,
    "missing_items_bound": sorted(item for item in missing_items_bound if item),
    "test_refs": test_refs_by_section,
    "required_events": sorted(telemetry_events),
    "required_fields": sorted(telemetry_fields),
    "artifact_refs": artifact_refs,
    "failure_signature": "none" if status == "pass" else "allocator_membrane_contract_failed",
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

for message in errors:
    print(f"ALLOCATOR_MEMBRANE_CONTRACT_ERROR: {message}")
print(f"ALLOCATOR_MEMBRANE_CONTRACT_STATUS={status}")
print(f"ALLOCATOR_MEMBRANE_CONTRACT_ERRORS={len(errors)}")
print(f"ALLOCATOR_MEMBRANE_CONTRACT_REPORT={REPORT}")
print(f"ALLOCATOR_MEMBRANE_CONTRACT_LOG={LOG}")

raise SystemExit(1 if errors else 0)
PY
