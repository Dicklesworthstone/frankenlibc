#!/usr/bin/env bash
# check_thread_safety_sos_completion_contract.sh -- fail-closed gate for bd-2ste.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_THREAD_SAFETY_SOS_CONTRACT:-${ROOT}/tests/conformance/thread_safety_sos_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_THREAD_SAFETY_SOS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_THREAD_SAFETY_SOS_REPORT:-${OUT_DIR}/thread_safety_sos_completion_contract.report.json}"
LOG="${FRANKENLIBC_THREAD_SAFETY_SOS_LOG:-${OUT_DIR}/thread_safety_sos_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-2ste.2"
COMPLETION_BEAD_ID = "bd-2ste.2.1"
MANIFEST_ID = "thread-safety-sos-completion-contract"
REQUIRED_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
REQUIRED_ARTIFACTS = {
    "runtime_sos_barrier",
    "thread_safety_task",
    "sos_build_generator",
    "arch_independence_tests",
}
REQUIRED_EVENTS = {
    "thread_safety_sos_source",
    "thread_safety_sos_certificate",
    "thread_safety_sos_tests",
    "thread_safety_sos_summary",
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


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


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


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}(" in source_text or f"fn {name}<" in source_text


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
        for needle in strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append(
            {
                "artifact_refs": [path_text],
                "bead": BEAD_ID,
                "completion_debt_bead": COMPLETION_BEAD_ID,
                "event": "thread_safety_sos_source",
                "status": "pass" if text else "fail",
                "timestamp": utc_now(),
            }
        )

    if seen != REQUIRED_ARTIFACTS:
        errors.append(f"source_artifacts must be exactly {sorted(REQUIRED_ARTIFACTS)}, got {sorted(seen)}")
    return paths


def parse_task(path_text: str, errors: list[str]) -> dict[str, Any]:
    text = read_text(path_text, errors, "thread_safety_task")
    result: dict[str, Any] = {"gram_matrix": []}
    reading_matrix = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if reading_matrix:
            if ":" in stripped:
                errors.append(f"unexpected key while reading gram_matrix: {stripped}")
                continue
            try:
                result["gram_matrix"].append([int(part.strip()) for part in stripped.split(",")])
            except ValueError:
                errors.append(f"invalid gram_matrix row: {stripped}")
            continue
        if stripped == "gram_matrix:":
            reading_matrix = True
            continue
        if ":" not in stripped:
            errors.append(f"invalid task line: {stripped}")
            continue
        key, value = stripped.split(":", 1)
        value = value.strip()
        if key in {"dimension", "monomial_degree", "barrier_budget_milli"}:
            try:
                result[key] = int(value)
            except ValueError:
                errors.append(f"{key} must be integer")
        else:
            result[key] = value
    return result


def validate_certificate(
    contract: dict[str, Any], paths: dict[str, str], errors: list[str], rows: list[dict[str, Any]]
) -> None:
    expectations = contract.get("certificate_expectations")
    if not isinstance(expectations, dict):
        errors.append("certificate_expectations must be an object")
        return
    task_path = expectations.get("path")
    if not isinstance(task_path, str) or task_path != paths.get("thread_safety_task"):
        errors.append("certificate_expectations.path must match thread_safety_task artifact")
        return

    task = parse_task(task_path, errors)
    for key in ("certificate", "dimension", "monomial_degree", "barrier_budget_milli"):
        if task.get(key) != expectations.get(key):
            errors.append(f"certificate {key} mismatch: task={task.get(key)!r} expected={expectations.get(key)!r}")

    matrix = task.get("gram_matrix")
    dimension = expectations.get("dimension")
    gram_rows = expectations.get("gram_rows")
    if not isinstance(matrix, list) or len(matrix) != gram_rows:
        errors.append("gram_matrix row count mismatch")
        matrix = []
    diagonal: list[int] = []
    if isinstance(dimension, int):
        for row_index, row in enumerate(matrix):
            if not isinstance(row, list) or len(row) != dimension:
                errors.append(f"gram_matrix row {row_index} width mismatch")
                continue
            diagonal.append(row[row_index])
        minimum = expectations.get("minimum_diagonal")
        if isinstance(minimum, int) and any(value < minimum for value in diagonal):
            errors.append(f"gram_matrix diagonal below minimum {minimum}: {diagonal}")

    rows.append(
        {
            "artifact_refs": [task_path],
            "barrier_budget_milli": task.get("barrier_budget_milli"),
            "bead": BEAD_ID,
            "completion_debt_bead": COMPLETION_BEAD_ID,
            "dimension": task.get("dimension"),
            "event": "thread_safety_sos_certificate",
            "gram_rows": len(matrix),
            "status": "pass" if not errors else "fail",
            "timestamp": utc_now(),
        }
    )


def validate_commands(commands: Any, errors: list[str], context: str) -> None:
    for command in strings(commands, errors, f"{context}.required_commands"):
        if "cargo " in command and "rch exec -- cargo " not in command:
            errors.append(f"{context} cargo command must be rch-backed: {command}")


def validate_test_section(
    evidence: dict[str, Any],
    section_name: str,
    expected_item: str,
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    section = evidence.get(section_name)
    if not isinstance(section, dict):
        errors.append(f"{section_name} must be an object")
        return
    if section.get("missing_item_id") != expected_item:
        errors.append(f"{section_name}.missing_item_id must be {expected_item}")
    source_path = section.get("source")
    if not isinstance(source_path, str) or not source_path:
        errors.append(f"{section_name}.source missing")
        return
    source_text = read_text(source_path, errors, f"{section_name}.source")
    found = []
    for name in strings(section.get("required_test_names"), errors, f"{section_name}.required_test_names"):
        if function_exists(source_text, name):
            found.append(name)
        else:
            errors.append(f"{section_name} references missing test {name}")
    validate_commands(section.get("required_commands"), errors, section_name)
    rows.append(
        {
            "artifact_refs": [source_path],
            "bead": BEAD_ID,
            "completion_debt_bead": COMPLETION_BEAD_ID,
            "event": "thread_safety_sos_tests",
            "section": section_name,
            "status": "pass" if len(found) == len(section.get("required_test_names", [])) else "fail",
            "test_count": len(found),
            "timestamp": utc_now(),
        }
    )


def validate_evidence(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    missing = set(strings(evidence.get("missing_items_closed"), errors, "missing_items_closed"))
    if missing != REQUIRED_ITEMS:
        errors.append(f"missing_items_closed must be {sorted(REQUIRED_ITEMS)}")

    validate_test_section(evidence, "unit_primary", "tests.unit.primary", errors, rows)
    validate_test_section(evidence, "e2e_primary", "tests.e2e.primary", errors, rows)

    telemetry = evidence.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_primary must be an object")
    else:
        if telemetry.get("missing_item_id") != "telemetry.primary":
            errors.append("telemetry_primary.missing_item_id must be telemetry.primary")
        events = set(strings(telemetry.get("required_events"), errors, "telemetry_primary.required_events"))
        if events != REQUIRED_EVENTS:
            errors.append(f"telemetry_primary.required_events must be {sorted(REQUIRED_EVENTS)}")
        required_fields = set(strings(telemetry.get("required_fields"), errors, "telemetry_primary.required_fields"))
        for field in ("timestamp", "trace_id", "event", "status", "bead", "completion_debt_bead", "artifact_refs"):
            if field not in required_fields:
                errors.append(f"telemetry_primary.required_fields missing {field}")
        for field in ("report_path", "log_path"):
            if not isinstance(telemetry.get(field), str) or not telemetry[field]:
                errors.append(f"telemetry_primary.{field} missing")


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "contract")

if contract.get("schema_version") != "thread_safety_sos_completion_contract.v1":
    errors.append("schema_version mismatch")
if contract.get("manifest_id") != MANIFEST_ID:
    errors.append(f"manifest_id must be {MANIFEST_ID}")
if contract.get("bead") != BEAD_ID:
    errors.append(f"bead must be {BEAD_ID}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
if not isinstance(contract.get("next_audit_score_threshold"), int) or contract["next_audit_score_threshold"] < 800:
    errors.append("next_audit_score_threshold must be >= 800")

paths = validate_source_artifacts(contract, errors, rows)
validate_certificate(contract, paths, errors, rows)
validate_evidence(contract, errors, rows)

status = "fail" if errors else "pass"
summary = {
    "artifact_refs": [str(contract_path.relative_to(root)) if contract_path.is_relative_to(root) else str(contract_path)],
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "event": "thread_safety_sos_summary",
    "source_count": len(paths),
    "status": status,
    "timestamp": utc_now(),
}
rows.append(summary)

report = {
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "errors": errors,
    "event_count": len(rows),
    "manifest_id": contract.get("manifest_id"),
    "source_count": len(paths),
    "status": status,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("thread_safety_sos_completion_contract: FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print(
    "thread_safety_sos_completion_contract: PASS "
    f"sources={len(paths)} events={len(rows)}"
)
PY
