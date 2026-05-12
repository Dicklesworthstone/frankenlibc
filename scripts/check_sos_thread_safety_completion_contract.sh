#!/usr/bin/env bash
# check_sos_thread_safety_completion_contract.sh -- fail-closed gate for bd-2ste.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SOS_THREAD_SAFETY_CONTRACT:-${ROOT}/tests/conformance/sos_thread_safety_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SOS_THREAD_SAFETY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_SOS_THREAD_SAFETY_REPORT:-${OUT_DIR}/sos_thread_safety_completion_contract.report.json}"
LOG="${FRANKENLIBC_SOS_THREAD_SAFETY_LOG:-${OUT_DIR}/sos_thread_safety_completion_contract.log.jsonl}"

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
MANIFEST_ID = "sos-thread-safety-completion-contract"
REQUIRED_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_IDS = {
    "sos_build_pipeline",
    "sos_barrier_runtime",
    "sos_arch_independence",
    "allocator_concurrency_evidence",
}
REQUIRED_EVENTS = {
    "sos_thread_safety_certificate_source",
    "sos_thread_safety_certificate_task",
    "sos_thread_safety_runtime_binding",
    "sos_thread_safety_completion_summary",
}
REQUIRED_LOG_FIELDS = {
    "event",
    "status",
    "timestamp",
    "artifact_refs",
    "bead_id",
    "completion_debt_bead",
    "matrix_dimension",
    "barrier_budget_milli",
    "missing_items_closed",
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


def parse_sos_task(path_text: str, errors: list[str]) -> dict[str, Any]:
    path = root / path_text
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        errors.append(f"certificate_artifact unreadable: {path_text}: {exc}")
        return {}

    fields: dict[str, Any] = {}
    matrix: list[list[int]] = []
    reading_matrix = False
    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if reading_matrix:
            if ":" in line:
                errors.append(
                    f"{path_text}:{line_no}: key/value found while reading gram_matrix"
                )
                continue
            row: list[int] = []
            for column, cell in enumerate(line.split(","), start=1):
                cell = cell.strip()
                if not cell:
                    errors.append(f"{path_text}:{line_no}: empty matrix cell {column}")
                    continue
                try:
                    row.append(int(cell))
                except ValueError:
                    errors.append(f"{path_text}:{line_no}: invalid integer matrix cell {cell!r}")
            matrix.append(row)
            continue
        if ":" not in line:
            errors.append(f"{path_text}:{line_no}: expected key/value line")
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key == "gram_matrix":
            if value:
                errors.append(f"{path_text}:{line_no}: gram_matrix must not have inline values")
            reading_matrix = True
        elif key in {"schema_version", "dimension", "monomial_degree", "barrier_budget_milli"}:
            try:
                fields[key] = int(value)
            except ValueError:
                errors.append(f"{path_text}:{line_no}: {key} must be an integer")
        elif key in {"solver_family", "certificate"}:
            if not value:
                errors.append(f"{path_text}:{line_no}: {key} must be non-empty")
            fields[key] = value
    fields["gram_matrix"] = matrix
    return fields


def validate_certificate(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> dict[str, Any]:
    certificate = contract.get("certificate_artifact")
    if not isinstance(certificate, dict):
        errors.append("certificate_artifact must be an object")
        return {}
    path_text = certificate.get("path")
    if not isinstance(path_text, str) or not path_text:
        errors.append("certificate_artifact.path missing")
        return {}

    task = parse_sos_task(path_text, errors)
    expected_fields = {
        "solver_family": "expected_solver_family",
        "certificate": "expected_certificate",
        "dimension": "expected_dimension",
        "monomial_degree": "expected_monomial_degree",
        "barrier_budget_milli": "expected_barrier_budget_milli",
    }
    for task_key, contract_key in expected_fields.items():
        expected = certificate.get(contract_key)
        if expected is None:
            errors.append(f"certificate_artifact.{contract_key} missing")
            continue
        if task.get(task_key) != expected:
            errors.append(
                f"certificate_artifact {task_key} expected {expected!r}, actual {task.get(task_key)!r}"
            )

    variables = strings(
        certificate.get("required_variables"),
        errors,
        "certificate_artifact.required_variables",
    )
    dimension = task.get("dimension")
    if isinstance(dimension, int) and len(variables) != dimension:
        errors.append(
            f"certificate_artifact.required_variables length {len(variables)} must match dimension {dimension}"
        )

    matrix = task.get("gram_matrix")
    if not isinstance(matrix, list) or not matrix:
        errors.append("certificate gram_matrix must be non-empty")
    elif isinstance(dimension, int):
        if len(matrix) != dimension:
            errors.append(f"gram_matrix row count {len(matrix)} must match dimension {dimension}")
        for row_index, row in enumerate(matrix):
            if not isinstance(row, list) or len(row) != dimension:
                errors.append(
                    f"gram_matrix row {row_index} length {len(row) if isinstance(row, list) else 'invalid'} must match dimension {dimension}"
                )
                continue
            diagonal = row[row_index] if row_index < len(row) else None
            if not isinstance(diagonal, int) or diagonal <= 0:
                errors.append(f"gram_matrix diagonal {row_index} must be positive")
        for i, row in enumerate(matrix):
            if not isinstance(row, list) or len(row) != dimension:
                continue
            for j in range(dimension):
                other_row = matrix[j] if j < len(matrix) and isinstance(matrix[j], list) else []
                if j < len(row) and i < len(other_row) and row[j] != other_row[i]:
                    errors.append(
                        f"gram_matrix is not symmetric at ({i}, {j}) => {row[j]} != {other_row[i]}"
                    )

    rows.append(
        {
            "event": "sos_thread_safety_certificate_task",
            "status": "pass" if not errors else "fail",
            "artifact_refs": [path_text],
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_BEAD_ID,
            "matrix_dimension": task.get("dimension"),
            "barrier_budget_milli": task.get("barrier_budget_milli"),
            "timestamp": utc_now(),
        }
    )
    return task


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
        for needle in strings(
            artifact.get("required_needles"),
            errors,
            f"{artifact_id}.required_needles",
        ):
            if needle not in text:
                missing_needles.append(needle)
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append(
            {
                "event": "sos_thread_safety_certificate_source",
                "status": "pass" if text and not missing_needles else "fail",
                "artifact_id": artifact_id,
                "artifact_refs": [path_text],
                "bead_id": BEAD_ID,
                "completion_debt_bead": COMPLETION_BEAD_ID,
                "missing_needles": missing_needles,
                "timestamp": utc_now(),
            }
        )
    if seen != REQUIRED_SOURCE_IDS:
        errors.append(f"source_artifacts must be exactly {sorted(REQUIRED_SOURCE_IDS)}, got {sorted(seen)}")
    return paths


def validate_runtime_expectations(contract: dict[str, Any], errors: list[str]) -> None:
    runtime = contract.get("runtime_expectations")
    if not isinstance(runtime, dict):
        errors.append("runtime_expectations must be an object")
        return
    if runtime.get("certificate_id") != "thread_safety":
        errors.append("runtime_expectations.certificate_id must be thread_safety")
    if set(strings(runtime.get("input_basis"), errors, "runtime_expectations.input_basis")) != {
        "thread_count",
        "concurrent_writers",
        "arena_owner_conflict",
        "free_list_skew_ppm",
        "allocation_epoch_lag_ppm",
    }:
        errors.append("runtime_expectations.input_basis does not match thread-safety evaluator inputs")
    for profile_name, expected_relation in [
        ("safe_profile", "barrier_value_positive"),
        ("violation_profile", "barrier_value_negative"),
    ]:
        profile = runtime.get(profile_name)
        if not isinstance(profile, dict):
            errors.append(f"runtime_expectations.{profile_name} must be an object")
            continue
        if profile.get("expected_relation") != expected_relation:
            errors.append(
                f"runtime_expectations.{profile_name}.expected_relation must be {expected_relation}"
            )
    properties = set(strings(runtime.get("matrix_properties"), errors, "runtime_expectations.matrix_properties"))
    required_properties = {
        "symmetric",
        "positive_diagonal",
        "positive_semidefinite",
        "hash_tamper_evident",
        "architecture_independent_integer_eval",
    }
    if not required_properties.issubset(properties):
        errors.append(f"runtime_expectations.matrix_properties missing {sorted(required_properties - properties)}")


def validate_test_refs(
    section_name: str,
    section: dict[str, Any],
    source_paths: dict[str, str],
    errors: list[str],
) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    for index, test_ref in enumerate(refs):
        if not isinstance(test_ref, dict):
            errors.append(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = test_ref.get("source")
        name = test_ref.get("name")
        if not isinstance(source, str) or not source:
            errors.append(f"{section_name}.required_test_refs[{index}].source missing")
            continue
        if not isinstance(name, str) or not name:
            errors.append(f"{section_name}.required_test_refs[{index}].name missing")
            continue
        if source == "completion_harness":
            source_path = "crates/frankenlibc-harness/tests/sos_thread_safety_completion_contract_test.rs"
        else:
            source_path = source_paths.get(source)
        if not source_path:
            errors.append(f"{section_name} references unknown source {source}")
        else:
            text = read_text(source_path, errors, f"{section_name}.{source}")
            if f"fn {name}" not in text:
                errors.append(f"{section_name} references missing Rust test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


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

    refs_by_section: dict[str, list[dict[str, str]]] = {}
    for section_name in ("unit_primary", "e2e_primary", "telemetry_primary"):
        section = evidence.get(section_name)
        if not isinstance(section, dict):
            errors.append(f"completion_debt_evidence.{section_name} must be an object")
            continue
        refs_by_section[section_name] = validate_test_refs(
            section_name, section, source_paths, errors
        )
        if section_name != "telemetry_primary":
            commands = strings(section.get("required_commands"), errors, f"{section_name}.required_commands")
            for command in commands:
                if not command.startswith("rch exec -- cargo test "):
                    errors.append(f"{section_name}.required_commands must use rch cargo test: {command}")
        else:
            for field in ("report_path", "log_path"):
                value = section.get(field)
                if not isinstance(value, str) or not value:
                    errors.append(f"telemetry_primary.{field} missing")
    return refs_by_section


def validate_telemetry_contract(contract: dict[str, Any], errors: list[str]) -> tuple[list[str], list[str]]:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return [], []
    events = strings(telemetry.get("required_events"), errors, "telemetry_contract.required_events")
    fields = strings(telemetry.get("required_log_fields"), errors, "telemetry_contract.required_log_fields")
    missing_events = REQUIRED_EVENTS - set(events)
    missing_fields = REQUIRED_LOG_FIELDS - set(fields)
    if missing_events:
        errors.append(f"telemetry_contract.required_events missing {sorted(missing_events)}")
    if missing_fields:
        errors.append(f"telemetry_contract.required_log_fields missing {sorted(missing_fields)}")
    if telemetry.get("report_env") != "FRANKENLIBC_SOS_THREAD_SAFETY_REPORT":
        errors.append("telemetry_contract.report_env drifted")
    if telemetry.get("log_env") != "FRANKENLIBC_SOS_THREAD_SAFETY_LOG":
        errors.append("telemetry_contract.log_env drifted")
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

task = validate_certificate(contract, errors, rows)
source_paths = validate_source_artifacts(contract, errors, rows)
validate_runtime_expectations(contract, errors)
test_refs = validate_completion_evidence(contract, source_paths, errors)
required_events, required_fields = validate_telemetry_contract(contract, errors)

missing_items = sorted(
    contract.get("completion_debt_evidence", {}).get("missing_items_closed", [])
    if isinstance(contract.get("completion_debt_evidence"), dict)
    else []
)
status = "fail" if errors else "pass"
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
summary_row = {
    "event": "sos_thread_safety_runtime_binding",
    "status": status,
    "artifact_refs": artifact_refs,
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "matrix_dimension": task.get("dimension"),
    "barrier_budget_milli": task.get("barrier_budget_milli"),
    "missing_items_closed": missing_items,
    "test_refs": test_refs,
    "timestamp": utc_now(),
}
rows.append(summary_row)
rows.append(
    {
        "event": "sos_thread_safety_completion_summary",
        "status": status,
        "artifact_refs": artifact_refs,
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "matrix_dimension": task.get("dimension"),
        "barrier_budget_milli": task.get("barrier_budget_milli"),
        "missing_items_closed": missing_items,
        "required_events": required_events,
        "required_log_fields": required_fields,
        "error_count": len(errors),
        "timestamp": utc_now(),
    }
)

report = {
    "schema_version": "sos_thread_safety_completion_contract.report.v1",
    "status": status,
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "source_count": len(source_paths),
    "matrix_dimension": task.get("dimension"),
    "monomial_degree": task.get("monomial_degree"),
    "barrier_budget_milli": task.get("barrier_budget_milli"),
    "solver_family": task.get("solver_family"),
    "certificate": task.get("certificate"),
    "matrix_row_count": len(task.get("gram_matrix", [])) if isinstance(task.get("gram_matrix"), list) else 0,
    "missing_items_closed": missing_items,
    "required_events": required_events,
    "required_log_fields": required_fields,
    "test_refs": test_refs,
    "artifact_refs": artifact_refs,
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

for message in errors:
    print(f"SOS_THREAD_SAFETY_COMPLETION_CONTRACT_ERROR: {message}")
print(
    "sos_thread_safety_completion_contract: "
    f"{status.upper()} sources={len(source_paths)} events={len(rows)}"
)
print(f"SOS_THREAD_SAFETY_COMPLETION_CONTRACT_REPORT={report_path}")
print(f"SOS_THREAD_SAFETY_COMPLETION_CONTRACT_LOG={log_path}")

raise SystemExit(1 if errors else 0)
PY
