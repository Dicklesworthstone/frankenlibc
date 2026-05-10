#!/usr/bin/env bash
# check_standalone_membrane_adoption_completion_contract.sh -- fail-closed evidence gate for bd-2yx2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${STANDALONE_MEMBRANE_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/standalone_membrane_adoption_completion_contract.v1.json}"
OUT_DIR="${STANDALONE_MEMBRANE_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${STANDALONE_MEMBRANE_COMPLETION_REPORT:-${OUT_DIR}/standalone_membrane_adoption_completion_contract.report.json}"
LOG="${STANDALONE_MEMBRANE_COMPLETION_LOG:-${OUT_DIR}/standalone_membrane_adoption_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-2yx2"
COMPLETION_DEBT_BEAD_ID = "bd-2yx2.1"
MANIFEST_ID = "standalone-membrane-adoption-completion-contract"


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


def validate_workspace_contract(contract: dict[str, Any], errors: list[str]) -> None:
    workspace = read_text("Cargo.toml", errors, "workspace_manifest")
    membrane_manifest = read_text("crates/frankenlibc-membrane/Cargo.toml", errors, "membrane_manifest")
    membrane_lib = read_text("crates/frankenlibc-membrane/src/lib.rs", errors, "membrane_lib")
    spec = contract.get("workspace_contract")
    if not isinstance(spec, dict):
        errors.append("workspace_contract must be object")
        return
    if spec.get("member") not in workspace:
        errors.append(f"workspace member missing: {spec.get('member')}")
    if spec.get("workspace_dependency") not in workspace:
        errors.append("workspace dependency missing for frankenlibc-membrane")
    if f"name = \"{spec.get('crate_name')}\"" not in membrane_manifest:
        errors.append("membrane manifest crate name drift")
    for needle in spec.get("required_features", []):
        if not isinstance(needle, str) or needle not in membrane_manifest:
            errors.append(f"membrane manifest missing feature needle {needle}")
    for needle in spec.get("required_lib_needles", []):
        if not isinstance(needle, str) or needle not in membrane_lib:
            errors.append(f"membrane lib missing needle {needle}")


def validate_adoption_edges(contract: dict[str, Any], errors: list[str]) -> int:
    edges = contract.get("adoption_edges")
    if not isinstance(edges, list) or not edges:
        errors.append("adoption_edges must be non-empty array")
        return 0
    for edge in edges:
        if not isinstance(edge, dict):
            errors.append("adoption edge entries must be objects")
            continue
        manifest = edge.get("manifest")
        dependency = edge.get("dependency")
        consumer = edge.get("consumer", "unknown")
        if not isinstance(manifest, str) or not isinstance(dependency, str):
            errors.append(f"{consumer} adoption edge missing manifest/dependency")
            continue
        source = read_text(manifest, errors, f"{consumer}.manifest")
        if dependency not in source:
            errors.append(f"{consumer} missing dependency edge {dependency}")
    return len(edges)


def validate_unit_primary(contract: dict[str, Any], errors: list[str]) -> int:
    unit = contract.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("unit_primary must be object")
        return 0
    if unit.get("missing_item_id") != "tests.unit.primary":
        errors.append("unit_primary.missing_item_id must be tests.unit.primary")
    test_file = unit.get("test_file")
    source = read_text(test_file, errors, "unit_primary.test_file") if isinstance(test_file, str) else ""
    names = unit.get("required_test_names")
    if not isinstance(names, list) or not names:
        errors.append("unit_primary.required_test_names must be non-empty array")
        return 0
    for name in names:
        if not isinstance(name, str) or f"fn {name}(" not in source:
            errors.append(f"unit_primary references missing membrane unit test {name}")
    return len(names)


def validate_e2e_primary(contract: dict[str, Any], errors: list[str]) -> int:
    e2e = contract.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be object")
        return 0
    if e2e.get("missing_item_id") != "tests.e2e.primary":
        errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
    scenarios = e2e.get("scenarios")
    if not isinstance(scenarios, list) or len(scenarios) < 3:
        errors.append("e2e_primary.scenarios must contain at least three scenarios")
        return 0
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            errors.append("e2e_primary scenarios must be objects")
            continue
        command = scenario.get("command")
        if not isinstance(command, str) or not command.startswith("rch cargo "):
            errors.append(f"e2e scenario must use rch cargo: {scenario.get('scenario_id')}")
        if "-p frankenlibc-membrane" not in command:
            errors.append(f"e2e scenario must target frankenlibc-membrane: {scenario.get('scenario_id')}")
    return len(scenarios)


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be object")
        return
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    test_source = evidence.get("test_source")
    source = read_text(test_source, errors, "completion_debt_evidence.test_source") if isinstance(test_source, str) else ""
    names = evidence.get("required_test_names")
    if not isinstance(names, list) or not names:
        errors.append("completion_debt_evidence.required_test_names must be non-empty array")
        return
    for name in names:
        if not isinstance(name, str) or f"fn {name}(" not in source:
            errors.append(f"completion_debt_evidence references missing Rust test {name}")


def validate_contract(contract: dict[str, Any], errors: list[str]) -> tuple[list[dict[str, Any]], int, int, int]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")
    artifacts = contract.get("source_artifacts")
    source_rows: list[dict[str, Any]] = []
    if not isinstance(artifacts, dict):
        errors.append("source_artifacts must be object")
        artifacts = {}
    for artifact_id, path_text in artifacts.items():
        status = "pass" if isinstance(path_text, str) and (root / path_text).is_file() else "fail"
        if status == "fail":
            errors.append(f"source_artifacts.{artifact_id} missing file: {path_text}")
        source_rows.append({"artifact_id": artifact_id, "path": path_text, "status": status})
    validate_workspace_contract(contract, errors)
    edge_count = validate_adoption_edges(contract, errors)
    unit_count = validate_unit_primary(contract, errors)
    e2e_count = validate_e2e_primary(contract, errors)
    validate_completion_evidence(contract, errors)
    return source_rows, edge_count, unit_count, e2e_count


errors: list[str] = []
contract = load_json(contract_path, errors, "contract")
source_rows: list[dict[str, Any]] = []
edge_count = 0
unit_count = 0
e2e_count = 0
if contract:
    source_rows, edge_count, unit_count, e2e_count = validate_contract(contract, errors)

timestamp = utc_now()
log_rows = []
for row in source_rows:
    log_rows.append({
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['artifact_id']}",
        "event": "standalone_membrane_completion_source",
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "status": row["status"],
        "artifact_refs": [row["path"], rel(contract_path)],
        "failure_signature": "none" if row["status"] == "pass" else "source_artifact_missing",
    })
log_rows.append({
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:unit-primary",
    "event": "standalone_membrane_completion_unit",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "status": "pass" if unit_count >= 2 and not errors else "fail",
    "artifact_refs": ["crates/frankenlibc-membrane/src/lib.rs", rel(contract_path)],
    "failure_signature": "none" if unit_count >= 2 and not errors else "unit_primary_contract_error",
})
log_rows.append({
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:e2e-primary",
    "event": "standalone_membrane_completion_e2e",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "status": "pass" if e2e_count >= 3 and not errors else "fail",
    "artifact_refs": ["crates/frankenlibc-membrane/Cargo.toml", rel(contract_path)],
    "failure_signature": "none" if e2e_count >= 3 and not errors else "e2e_contract_error",
})

summary = {
    "schema_version": "standalone_membrane_adoption_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "source_artifact_count": len(source_rows),
    "adoption_edge_count": edge_count,
    "unit_required_test_count": unit_count,
    "e2e_scenario_count": e2e_count,
    "errors": errors,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}
log_rows.append({
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "standalone_membrane_completion_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "status": summary["status"],
    "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
    "failure_signature": "none" if not errors else "contract_validation_error",
})

report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "standalone_membrane_adoption_completion_contract: "
    f"status={summary['status']} sources={summary['source_artifact_count']} "
    f"edges={summary['adoption_edge_count']} unit_tests={summary['unit_required_test_count']} "
    f"e2e={summary['e2e_scenario_count']} errors={len(errors)}"
)
print(f"report={rel(report_path)}")
print(f"log={rel(log_path)} rows={len(log_rows)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
