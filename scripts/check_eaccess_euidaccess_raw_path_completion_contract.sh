#!/usr/bin/env bash
# check_eaccess_euidaccess_raw_path_completion_contract.sh -- fail-closed gate for bd-2vv.26.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_EACCESS_EUIDACCESS_CONTRACT:-${ROOT}/tests/conformance/eaccess_euidaccess_raw_path_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_EACCESS_EUIDACCESS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_EACCESS_EUIDACCESS_REPORT:-${OUT_DIR}/eaccess_euidaccess_raw_path_completion_contract.report.json}"
LOG="${FRANKENLIBC_EACCESS_EUIDACCESS_LOG:-${OUT_DIR}/eaccess_euidaccess_raw_path_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-2vv.26"
COMPLETION_BEAD_ID = "bd-2vv.26.1"
MANIFEST_ID = "eaccess-euidaccess-raw-path-completion-contract"
REQUIRED_ITEMS = {"tests.unit.primary"}
REQUIRED_SOURCE_IDS = {
    "abi_unistd_raw_path",
    "abi_unistd_unit_tests",
    "core_unistd_validator",
    "core_syscall_veneer_tests",
    "support_matrix_status",
}
REQUIRED_EVENTS = {
    "eaccess_euidaccess_source",
    "eaccess_euidaccess_unit_binding",
    "eaccess_euidaccess_completion_summary",
}
REQUIRED_REPORT_FIELDS = {
    "status",
    "bead_id",
    "completion_debt_bead",
    "source_count",
    "missing_items_closed",
    "test_refs",
    "errors",
}


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


def strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            out.append(item)
    return out


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def validate_source_artifacts(
    contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]
) -> dict[str, str]:
    artifacts = contract.get("source_artifacts")
    paths: dict[str, str] = {}
    if not isinstance(artifacts, list):
        errors.append("source_artifacts must be an array")
        return paths
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        artifact_id = artifact.get("artifact_id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append("source artifact missing artifact_id")
            continue
        seen.add(artifact_id)
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{artifact_id}.path missing")
            continue
        paths[artifact_id] = path_text
        text = read_text(path_text, errors, artifact_id)
        missing_needles: list[str] = []
        forbidden_hits: list[str] = []
        for needle in strings(
            artifact.get("required_needles"),
            errors,
            f"{artifact_id}.required_needles",
        ):
            if needle not in text:
                missing_needles.append(needle)
                errors.append(f"{artifact_id} missing needle {needle!r}")
        for needle in artifact.get("forbidden_needles", []):
            if not isinstance(needle, str):
                errors.append(f"{artifact_id}.forbidden_needles entries must be strings")
            elif needle in text:
                forbidden_hits.append(needle)
                errors.append(f"{artifact_id} contains forbidden host-delegation needle {needle!r}")
        rows.append(
            {
                "event": "eaccess_euidaccess_source",
                "status": "pass" if text and not missing_needles and not forbidden_hits else "fail",
                "artifact_id": artifact_id,
                "artifact_refs": [path_text],
                "bead_id": BEAD_ID,
                "completion_debt_bead": COMPLETION_BEAD_ID,
                "missing_needles": missing_needles,
                "forbidden_hits": forbidden_hits,
                "timestamp": utc_now(),
            }
        )
    if seen != REQUIRED_SOURCE_IDS:
        errors.append(f"source_artifacts must be exactly {sorted(REQUIRED_SOURCE_IDS)}, got {sorted(seen)}")
    return paths


def validate_raw_path_expectations(contract: dict[str, Any], errors: list[str]) -> None:
    expectations = contract.get("raw_path_expectations")
    if not isinstance(expectations, dict):
        errors.append("raw_path_expectations must be an object")
        return
    if set(strings(expectations.get("symbols"), errors, "raw_path_expectations.symbols")) != {"eaccess", "euidaccess"}:
        errors.append("raw_path_expectations.symbols must contain eaccess and euidaccess")
    if expectations.get("expected_support_status") != "RawSyscall":
        errors.append("raw_path_expectations.expected_support_status must be RawSyscall")
    if expectations.get("eaccess_route") != "faccessat(AT_FDCWD, path, mode, AT_EACCESS)":
        errors.append("raw_path_expectations.eaccess_route drifted")
    if expectations.get("euidaccess_route") != "eaccess(path, mode)":
        errors.append("raw_path_expectations.euidaccess_route drifted")
    errno = expectations.get("errno_contract")
    if not isinstance(errno, dict):
        errors.append("raw_path_expectations.errno_contract must be an object")
    else:
        for key, expected in {
            "null_path": "EFAULT",
            "missing_path": "ENOENT",
            "existing_path": "success",
        }.items():
            if errno.get(key) != expected:
                errors.append(f"raw_path_expectations.errno_contract.{key} must be {expected}")


def validate_completion_evidence(
    contract: dict[str, Any], source_paths: dict[str, str], errors: list[str]
) -> dict[str, list[dict[str, str]]]:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return {}
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    missing = set(strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing != REQUIRED_ITEMS:
        errors.append(f"completion_debt_evidence.missing_items_closed must be {sorted(REQUIRED_ITEMS)}")

    unit = evidence.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("completion_debt_evidence.unit_primary must be an object")
        return {}
    refs = unit.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append("unit_primary.required_test_refs must be non-empty")
        refs = []
    normalized: list[dict[str, str]] = []
    for index, test_ref in enumerate(refs):
        if not isinstance(test_ref, dict):
            errors.append(f"unit_primary.required_test_refs[{index}] must be an object")
            continue
        source = test_ref.get("source")
        name = test_ref.get("name")
        if not isinstance(source, str) or not source:
            errors.append(f"unit_primary.required_test_refs[{index}].source missing")
            continue
        if not isinstance(name, str) or not name:
            errors.append(f"unit_primary.required_test_refs[{index}].name missing")
            continue
        source_path = (
            "crates/frankenlibc-harness/tests/eaccess_euidaccess_raw_path_completion_contract_test.rs"
            if source == "completion_harness"
            else source_paths.get(source)
        )
        if not source_path:
            errors.append(f"unit_primary references unknown source {source}")
        else:
            text = read_text(source_path, errors, f"unit_primary.{source}")
            if f"fn {name}" not in text:
                errors.append(f"unit_primary references missing Rust test {source}::{name}")
        normalized.append({"source": source, "name": name})
    commands = strings(unit.get("required_commands"), errors, "unit_primary.required_commands")
    for command in commands:
        if not command.startswith("rch exec -- cargo test "):
            errors.append(f"unit_primary.required_commands must use rch cargo test: {command}")
    return {"unit_primary": normalized}


def validate_report_contract(contract: dict[str, Any], errors: list[str]) -> tuple[list[str], list[str]]:
    report = contract.get("report_contract")
    if not isinstance(report, dict):
        errors.append("report_contract must be an object")
        return [], []
    events = strings(report.get("required_events"), errors, "report_contract.required_events")
    fields = strings(report.get("required_report_fields"), errors, "report_contract.required_report_fields")
    missing_events = REQUIRED_EVENTS - set(events)
    missing_fields = REQUIRED_REPORT_FIELDS - set(fields)
    if missing_events:
        errors.append(f"report_contract.required_events missing {sorted(missing_events)}")
    if missing_fields:
        errors.append(f"report_contract.required_report_fields missing {sorted(missing_fields)}")
    if report.get("report_env") != "FRANKENLIBC_EACCESS_EUIDACCESS_REPORT":
        errors.append("report_contract.report_env drifted")
    if report.get("log_env") != "FRANKENLIBC_EACCESS_EUIDACCESS_LOG":
        errors.append("report_contract.log_env drifted")
    return events, fields


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "contract")

if contract.get("schema_version") != "v1":
    errors.append("schema_version must be v1")
if contract.get("manifest_id") != MANIFEST_ID:
    errors.append(f"manifest_id must be {MANIFEST_ID}")
if contract.get("bead") != BEAD_ID:
    errors.append(f"bead must be {BEAD_ID}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")

source_paths = validate_source_artifacts(contract, errors, rows)
validate_raw_path_expectations(contract, errors)
test_refs = validate_completion_evidence(contract, source_paths, errors)
required_events, required_fields = validate_report_contract(contract, errors)

missing_items = sorted(
    contract.get("completion_debt_evidence", {}).get("missing_items_closed", [])
    if isinstance(contract.get("completion_debt_evidence"), dict)
    else []
)
status = "fail" if errors else "pass"
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
rows.append(
    {
        "event": "eaccess_euidaccess_unit_binding",
        "status": status,
        "artifact_refs": artifact_refs,
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "missing_items_closed": missing_items,
        "test_refs": test_refs,
        "timestamp": utc_now(),
    }
)
rows.append(
    {
        "event": "eaccess_euidaccess_completion_summary",
        "status": status,
        "artifact_refs": artifact_refs,
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "source_count": len(source_paths),
        "missing_items_closed": missing_items,
        "required_events": required_events,
        "required_report_fields": required_fields,
        "error_count": len(errors),
        "timestamp": utc_now(),
    }
)

report = {
    "schema_version": "eaccess_euidaccess_raw_path_completion_contract.report.v1",
    "status": status,
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "source_count": len(source_paths),
    "missing_items_closed": missing_items,
    "test_refs": test_refs,
    "required_events": required_events,
    "required_report_fields": required_fields,
    "artifact_refs": artifact_refs,
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

for message in errors:
    print(f"EACCESS_EUIDACCESS_COMPLETION_CONTRACT_ERROR: {message}")
print(f"eaccess_euidaccess_raw_path_completion_contract: {status.upper()} sources={len(source_paths)} events={len(rows)}")
print(f"EACCESS_EUIDACCESS_COMPLETION_CONTRACT_REPORT={report_path}")
print(f"EACCESS_EUIDACCESS_COMPLETION_CONTRACT_LOG={log_path}")

raise SystemExit(1 if errors else 0)
PY
