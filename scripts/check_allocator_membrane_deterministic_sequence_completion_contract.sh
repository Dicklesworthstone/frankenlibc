#!/usr/bin/env bash
# check_allocator_membrane_deterministic_sequence_completion_contract.sh - bd-66wz.4.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_ALLOCATOR_SEQUENCE_CONTRACT:-$ROOT/tests/conformance/allocator_membrane_deterministic_sequence_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_ALLOCATOR_SEQUENCE_REPORT:-$ROOT/target/conformance/allocator_membrane_deterministic_sequence_completion_contract.report.json}"
LOG="${FRANKENLIBC_ALLOCATOR_SEQUENCE_LOG:-$ROOT/target/conformance/allocator_membrane_deterministic_sequence_completion_contract.log.jsonl}"

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

SCHEMA = "allocator_membrane_deterministic_sequence_completion_contract.v1"
MANIFEST = "bd-66wz.4.1-allocator-membrane-deterministic-sequence-completion-contract"
ORIGINAL_BEAD = "bd-66wz.4"
COMPLETION_BEAD = "bd-66wz.4.1"
EXPECTED_MISSING = {
    "unit_primary": "tests.unit.primary",
    "property_primary": "tests.property.primary",
}
EXPECTED_INVARIANTS = {
    "deterministic_replay",
    "foreign_pointer_unknown_unbounded",
    "live_pointer_permissiveness",
    "temporal_safety_after_free",
    "no_stale_cached_valid_after_free",
    "double_free_detection",
    "canary_corruption_detection",
}
EXPECTED_DETECTION_GUARANTEES = {
    "deterministic_replay_mismatches": 0,
    "freed_cached_valid_false_negatives": 0,
    "double_free_false_negatives": 0,
    "canary_corruption_false_negatives": 0,
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


def string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        out.append(item)
    return out


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must end with a positive line number")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return {}
    texts: dict[str, str] = {}
    for key, path_text in test_sources.items():
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[str(key)] = path.read_text(encoding="utf-8")
    return texts


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, item in enumerate(refs):
        if not isinstance(item, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = item.get("source")
        name = item.get("name")
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
if manifest.get("schema_version") != SCHEMA:
    err(f"schema_version must be {SCHEMA}")
if manifest.get("manifest_id") != MANIFEST:
    err(f"manifest_id must be {MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

for source in string_list(manifest.get("source_modules"), "source_modules"):
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

invariants = set(string_list(completion.get("invariant_classes"), "invariant_classes"))
missing_invariants = sorted(EXPECTED_INVARIANTS - invariants)
if missing_invariants:
    err(f"invariant_classes missing {missing_invariants}")

detection = completion.get("detection_guarantees")
if not isinstance(detection, dict):
    detection = {}
    err("detection_guarantees must be an object")
for key, expected in EXPECTED_DETECTION_GUARANTEES.items():
    if detection.get(key) != expected:
        err(f"detection_guarantees.{key} must be {expected}")

texts = source_texts(completion.get("test_sources"))
sequence_text = texts.get("allocator_sequences", "")
sequence_contract = completion.get("sequence_contract")
if not isinstance(sequence_contract, dict):
    sequence_contract = {}
    err("sequence_contract must be an object")
if sequence_contract.get("fixed_seeds") != [1, 2, 3, 4]:
    err("sequence_contract.fixed_seeds must be [1, 2, 3, 4]")
if sequence_contract.get("steps_per_seed") != 2000:
    err("sequence_contract.steps_per_seed must be 2000")
if sequence_contract.get("slot_count") != 32:
    err("sequence_contract.slot_count must be 32")
for marker in string_list(sequence_contract.get("required_source_markers"), "sequence_contract.required_source_markers"):
    if marker not in sequence_text:
        err(f"allocator sequence test missing marker: {marker}")

missing_items_bound: list[str] = []
test_refs: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be >= 800")
    commands = section.get("required_commands")
    if not isinstance(commands, list) or not commands:
        err(f"completion_debt_evidence.{section_name}.required_commands must be non-empty")
    else:
        for command in commands:
            if not isinstance(command, str) or "rch exec -- cargo test" not in command:
                err(f"completion_debt_evidence.{section_name}.required_commands must use rch cargo test")
    test_refs[section_name] = validate_test_refs(section, section_name, texts)

status = "pass" if not errors else "fail"
report = {
    "schema_version": "allocator_membrane_deterministic_sequence_completion_contract.report.v1",
    "status": status,
    "errors": errors,
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": git_head(),
    "missing_items_bound": missing_items_bound,
    "invariant_classes": sorted(invariants),
    "detection_guarantees": detection,
    "test_refs": test_refs,
    "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

row = {
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "trace_id": f"{COMPLETION_BEAD}::allocator_membrane_deterministic_sequence_completion",
    "event": "allocator_membrane_deterministic_sequence_completion_contract_validated"
    if status == "pass"
    else "allocator_membrane_deterministic_sequence_completion_contract_failed",
    "level": "info" if status == "pass" else "error",
    "bead_id": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": report["source_commit"],
    "missing_items_bound": missing_items_bound,
    "invariant_classes": sorted(invariants),
    "detection_guarantees": detection,
    "test_refs": test_refs,
    "artifact_refs": report["artifact_refs"],
    "failure_signature": "none" if status == "pass" else "allocator_membrane_deterministic_sequence_contract_failed",
}
LOG.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(f"allocator_membrane_deterministic_sequence_completion_contract: PASS report={rel(REPORT)} log={rel(LOG)}")
PY
