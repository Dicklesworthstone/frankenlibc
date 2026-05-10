#!/usr/bin/env bash
# check_tsm_arena_integrity_completion_contract.sh -- fail-closed evidence gate for bd-32e.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${TSM_ARENA_INTEGRITY_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/tsm_arena_integrity_completion_contract.v1.json}"
OUT_DIR="${TSM_ARENA_INTEGRITY_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${TSM_ARENA_INTEGRITY_COMPLETION_REPORT:-${OUT_DIR}/tsm_arena_integrity_completion_contract.report.json}"
LOG="${TSM_ARENA_INTEGRITY_COMPLETION_LOG:-${OUT_DIR}/tsm_arena_integrity_completion_contract.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])

BEAD_ID = "bd-32e.2"
COMPLETION_DEBT_BEAD_ID = "bd-32e.2.1"
MANIFEST_ID = "tsm-arena-integrity-completion-contract"
REPORT_SCHEMA = "tsm_arena_integrity_completion_contract.report.v1"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: Path, errors: list[str], context: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return value


def read_text(path_text: str, errors: list[str], context: str) -> str:
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} missing file: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{context} unreadable: {path_text}: {exc}")
        return ""


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            errors.append(f"{context} entries must be non-empty strings")
            continue
        out.append(item)
    return out


def validate_file_line_ref(value: Any, errors: list[str], context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} must be a file:line string")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {value}")


def validate_source_artifacts(contract: dict[str, Any], errors: list[str]) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    artifacts = contract.get("source_artifacts")
    rows: list[dict[str, Any]] = []
    source_paths: dict[str, str] = {}
    source_texts: dict[str, str] = {}
    if not isinstance(artifacts, dict):
        errors.append("source_artifacts must be object")
        return rows, source_paths, source_texts
    for artifact_id, path_text in artifacts.items():
        status = "pass" if isinstance(path_text, str) and (root / path_text).is_file() else "fail"
        if status == "fail":
            errors.append(f"source_artifacts.{artifact_id} missing file: {path_text}")
        rows.append({"artifact_id": artifact_id, "path": path_text, "status": status})
        if isinstance(path_text, str):
            source_paths[artifact_id] = path_text
            source_texts[artifact_id] = read_text(path_text, errors, f"source_artifacts.{artifact_id}")
    return rows, source_paths, source_texts


def validate_implementation_contract(contract: dict[str, Any], source_texts: dict[str, str], errors: list[str]) -> tuple[int, int]:
    spec = contract.get("implementation_contract")
    if not isinstance(spec, dict):
        errors.append("implementation_contract must be object")
        return 0, 0

    ptr_text = source_texts.get("ptr_validator", "")
    arena_text = source_texts.get("arena", "")
    fingerprint_text = source_texts.get("fingerprint", "")

    stage_labels = require_strings(spec.get("stage_labels"), errors, "implementation_contract.stage_labels")
    stage_paths = require_strings(spec.get("stage_paths"), errors, "implementation_contract.stage_paths")
    required_outcomes = require_strings(
        spec.get("required_outcomes"),
        errors,
        "implementation_contract.required_outcomes",
    )
    for label in ["arena_lookup", "fingerprint", "canary", "bounds"]:
        if label not in stage_labels:
            errors.append(f"implementation_contract.stage_labels missing {label}")
        if f'"{label}"' not in ptr_text:
            errors.append(f"ptr_validator source missing stage label {label}")
    for path in [
        "pipeline::stage4::arena",
        "pipeline::stage5::fingerprint",
        "pipeline::stage6::canary",
        "pipeline::stage7::bounds",
    ]:
        if path not in stage_paths:
            errors.append(f"implementation_contract.stage_paths missing {path}")
        if f'"{path}"' not in ptr_text:
            errors.append(f"ptr_validator source missing stage path {path}")
    for outcome in ["Validated", "TemporalViolation", "Invalid"]:
        if outcome not in required_outcomes:
            errors.append(f"implementation_contract.required_outcomes missing {outcome}")
        if f"ValidationOutcome::{outcome}" not in ptr_text and outcome not in ptr_text:
            errors.append(f"ptr_validator source missing outcome {outcome}")

    needle_count = 0
    for needle in require_strings(
        spec.get("ptr_validator_needles"),
        errors,
        "implementation_contract.ptr_validator_needles",
    ):
        needle_count += 1
        if needle not in ptr_text:
            errors.append(f"ptr_validator source missing needle {needle}")
    for needle in require_strings(spec.get("arena_needles"), errors, "implementation_contract.arena_needles"):
        needle_count += 1
        if needle not in arena_text:
            errors.append(f"arena source missing needle {needle}")
    for needle in require_strings(
        spec.get("fingerprint_needles"),
        errors,
        "implementation_contract.fingerprint_needles",
    ):
        needle_count += 1
        if needle not in fingerprint_text:
            errors.append(f"fingerprint source missing needle {needle}")

    refs = spec.get("implementation_refs")
    if not isinstance(refs, list) or len(refs) < 10:
        errors.append("implementation_contract.implementation_refs must contain at least 10 file:line refs")
    else:
        for index, ref in enumerate(refs):
            validate_file_line_ref(ref, errors, f"implementation_contract.implementation_refs[{index}]")
    return len(stage_paths), needle_count


def validate_test_refs(
    contract: dict[str, Any],
    section_name: str,
    missing_item_id: str,
    source_texts: dict[str, str],
    errors: list[str],
) -> int:
    section = contract.get(section_name)
    if not isinstance(section, dict):
        errors.append(f"{section_name} must be object")
        return 0
    if section.get("missing_item_id") != missing_item_id:
        errors.append(f"{section_name}.missing_item_id must be {missing_item_id}")
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section_name}.required_test_refs must be non-empty array")
        return 0
    seen: set[tuple[str, str]] = set()
    count = 0
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            errors.append(f"{section_name}.required_test_refs[{index}] must be object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            errors.append(f"{section_name}.required_test_refs[{index}].source must be non-empty string")
            continue
        if not isinstance(name, str) or not name:
            errors.append(f"{section_name}.required_test_refs[{index}].name must be non-empty string")
            continue
        if (source, name) in seen:
            errors.append(f"{section_name} duplicates test ref {source}::{name}")
        seen.add((source, name))
        text = source_texts.get(source, "")
        if not text:
            errors.append(f"{section_name} references undeclared source {source}")
        elif f"fn {name}" not in text:
            errors.append(f"{section_name} references missing test {source}::{name}")
        count += 1

    commands = require_strings(section.get("required_commands"), errors, f"{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and not command.startswith("rch cargo "):
            errors.append(f"{section_name} cargo command must use rch cargo: {command}")
    return count


def validate_completion_evidence(contract: dict[str, Any], source_texts: dict[str, str], errors: list[str]) -> int:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be object")
        return 0
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    test_source = evidence.get("test_source")
    source = read_text(test_source, errors, "completion_debt_evidence.test_source") if isinstance(test_source, str) else ""
    if isinstance(test_source, str):
        source_texts["completion_unit_test"] = source
    names = require_strings(evidence.get("required_test_names"), errors, "completion_debt_evidence.required_test_names")
    for name in names:
        if f"fn {name}(" not in source:
            errors.append(f"completion_debt_evidence references missing Rust test {name}")
    return len(names)


def validate_telemetry_contract(contract: dict[str, Any], errors: list[str]) -> tuple[int, int]:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be object")
        return 0, 0
    required_events = require_strings(telemetry.get("required_log_events"), errors, "telemetry_contract.required_log_events")
    required_fields = require_strings(telemetry.get("required_log_fields"), errors, "telemetry_contract.required_log_fields")
    for event in [
        "tsm_arena_integrity_completion_source",
        "tsm_arena_integrity_completion_implementation",
        "tsm_arena_integrity_completion_unit",
        "tsm_arena_integrity_completion_e2e",
        "tsm_arena_integrity_completion_summary",
    ]:
        if event not in required_events:
            errors.append(f"telemetry_contract.required_log_events missing {event}")
    for field in ["timestamp", "trace_id", "event", "status", "artifact_refs", "failure_signature"]:
        if field not in required_fields:
            errors.append(f"telemetry_contract.required_log_fields missing {field}")
    return len(required_events), len(required_fields)


errors: list[str] = []
contract = load_json(contract_path, errors, "contract")
source_rows: list[dict[str, Any]] = []
source_texts: dict[str, str] = {}
stage_path_count = 0
needle_count = 0
unit_count = 0
e2e_count = 0
completion_test_count = 0
event_count = 0
field_count = 0
if contract:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")
    source_rows, _, source_texts = validate_source_artifacts(contract, errors)
    stage_path_count, needle_count = validate_implementation_contract(contract, source_texts, errors)
    unit_count = validate_test_refs(contract, "unit_primary", "tests.unit.primary", source_texts, errors)
    e2e_count = validate_test_refs(contract, "e2e_primary", "tests.e2e.primary", source_texts, errors)
    completion_test_count = validate_completion_evidence(contract, source_texts, errors)
    event_count, field_count = validate_telemetry_contract(contract, errors)

timestamp = utc_now()
log_rows = []
for row in source_rows:
    log_rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:source:{row['artifact_id']}",
            "event": "tsm_arena_integrity_completion_source",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": row["status"],
            "artifact_refs": [row["path"], rel(contract_path)],
            "failure_signature": "none" if row["status"] == "pass" else "source_artifact_missing",
        }
    )

summary_status = "pass" if not errors else "fail"
log_rows.extend(
    [
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:implementation",
            "event": "tsm_arena_integrity_completion_implementation",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": "pass" if stage_path_count >= 4 and needle_count >= 20 and not errors else "fail",
            "artifact_refs": [
                "crates/frankenlibc-membrane/src/ptr_validator.rs",
                "crates/frankenlibc-membrane/src/arena.rs",
                "crates/frankenlibc-membrane/src/fingerprint.rs",
                rel(contract_path),
            ],
            "failure_signature": "none" if stage_path_count >= 4 and needle_count >= 20 and not errors else "implementation_contract_error",
        },
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:unit-primary",
            "event": "tsm_arena_integrity_completion_unit",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": "pass" if unit_count >= 14 and not errors else "fail",
            "artifact_refs": ["crates/frankenlibc-membrane/src/ptr_validator.rs", rel(contract_path)],
            "failure_signature": "none" if unit_count >= 14 and not errors else "unit_primary_contract_error",
        },
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:e2e-primary",
            "event": "tsm_arena_integrity_completion_e2e",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "status": "pass" if e2e_count >= 8 and not errors else "fail",
            "artifact_refs": ["crates/frankenlibc-membrane/tests/tsm_pipeline_e2e_test.rs", rel(contract_path)],
            "failure_signature": "none" if e2e_count >= 8 and not errors else "e2e_primary_contract_error",
        },
    ]
)

summary = {
    "schema_version": REPORT_SCHEMA,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "source_artifact_count": len(source_rows),
    "stage_path_count": stage_path_count,
    "implementation_needle_count": needle_count,
    "unit_required_test_count": unit_count,
    "e2e_required_test_count": e2e_count,
    "completion_required_test_count": completion_test_count,
    "telemetry_event_count": event_count,
    "telemetry_field_count": field_count,
    "errors": errors,
    "status": summary_status,
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}
log_rows.append(
    {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
        "event": "tsm_arena_integrity_completion_summary",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "status": summary_status,
        "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
        "failure_signature": "none" if not errors else "contract_validation_error",
    }
)

report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "tsm_arena_integrity_completion_contract: "
    f"status={summary['status']} sources={summary['source_artifact_count']} "
    f"stages={summary['stage_path_count']} needles={summary['implementation_needle_count']} "
    f"unit={summary['unit_required_test_count']} e2e={summary['e2e_required_test_count']} "
    f"completion_tests={summary['completion_required_test_count']} errors={len(errors)}"
)
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
