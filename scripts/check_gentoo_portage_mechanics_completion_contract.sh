#!/usr/bin/env bash
# check_gentoo_portage_mechanics_completion_contract.sh -- fail-closed completion gate for bd-2icq.2.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_CONTRACT:-${ROOT}/tests/conformance/gentoo_portage_mechanics_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_REPORT:-${OUT_DIR}/gentoo_portage_mechanics_completion_contract.report.json}"
LOG="${FRANKENLIBC_GENTOO_PORTAGE_MECHANICS_LOG:-${OUT_DIR}/gentoo_portage_mechanics_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-2icq.2"
COMPLETION_DEBT_BEAD_ID = "bd-2icq.2.1"
MANIFEST_ID = "gentoo-portage-mechanics-completion-contract"
REQUIRED_ARTIFACT_IDS = {
    "portage_workflow_refresher",
    "use_flag_matrix",
    "portage_bashrc_template",
    "ebuild_hook_implementation",
    "base_image_golden_contract",
}
REQUIRED_EVENTS = {
    "gentoo_portage_mechanics_artifact",
    "gentoo_portage_mechanics_golden",
    "gentoo_portage_mechanics_contract_summary",
}
REQUIRED_LOG_FIELDS = [
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "completion_debt_bead",
    "artifact_id",
    "artifact_path",
    "evidence_kind",
    "source_line_ref",
    "status",
    "artifact_refs",
    "failure_signature",
]


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


def validate_line_ref(ref: Any, errors: list[str], context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} has invalid line number: {ref}")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def validate_top_level(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")

    runtime = contract.get("runtime_target")
    if not isinstance(runtime, dict):
        errors.append("runtime_target must be an object")
        return
    if runtime.get("external_services_allowed") is not False:
        errors.append("runtime_target.external_services_allowed must be false")
    if runtime.get("docker_required") is not False:
        errors.append("runtime_target.docker_required must be false")
    if runtime.get("portage_required") is not False:
        errors.append("runtime_target.portage_required must be false")


def validate_source_evidence(contract: dict[str, Any], errors: list[str]) -> list[dict[str, Any]]:
    evidence = contract.get("source_evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("source_evidence must be a non-empty array")
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(evidence):
        if not isinstance(item, dict):
            errors.append(f"source_evidence[{index}] must be an object")
            continue
        artifact_id = item.get("artifact_id")
        kind = item.get("kind")
        path_text = item.get("path")
        line_ref = item.get("line_ref")
        needles = item.get("required_needles")
        context = f"source_evidence[{artifact_id or index}]"
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append(f"{context}.artifact_id missing")
            continue
        if artifact_id in seen:
            errors.append(f"duplicate source_evidence artifact_id {artifact_id}")
        seen.add(artifact_id)
        if not isinstance(kind, str) or not kind:
            errors.append(f"{context}.kind missing")
            kind = "unknown"
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{context}.path missing")
            path_text = ""
        source = read_text(path_text, errors, context) if path_text else ""
        validate_line_ref(line_ref, errors, f"{context}.line_ref")
        if not isinstance(needles, list) or not all(isinstance(needle, str) and needle for needle in needles):
            errors.append(f"{context}.required_needles must be non-empty strings")
            needles = []
        missing_needles = [needle for needle in needles if needle not in source]
        for needle in missing_needles:
            errors.append(f"{context} missing needle {needle!r}")
        rows.append(
            {
                "artifact_id": artifact_id,
                "artifact_path": path_text,
                "evidence_kind": kind,
                "source_line_ref": line_ref if isinstance(line_ref, str) else "",
                "status": "pass" if not missing_needles else "fail",
                "artifact_refs": [path_text, rel(contract_path)],
                "failure_signature": "none" if not missing_needles else "source_evidence_missing_needle",
            }
        )

    missing_ids = sorted(REQUIRED_ARTIFACT_IDS - seen)
    if missing_ids:
        errors.append(f"source_evidence missing required artifact ids: {missing_ids}")
    return rows


def flatten_required_lines(golden: dict[str, Any]) -> tuple[set[str], list[str]]:
    paths: set[str] = set()
    lines: list[str] = []
    for section_value in golden.values():
        if not isinstance(section_value, dict):
            continue
        path_text = section_value.get("path")
        if isinstance(path_text, str):
            paths.add(path_text)
        required_lines = section_value.get("required_lines")
        if isinstance(required_lines, list):
            lines.extend(str(item) for item in required_lines if isinstance(item, str))
    return paths, lines


def validate_golden_contract(contract: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    golden_contract = contract.get("golden_contract")
    if not isinstance(golden_contract, dict):
        errors.append("golden_contract must be an object")
        return {
            "artifact_id": "base_image_golden_contract",
            "artifact_path": "",
            "evidence_kind": "golden",
            "source_line_ref": "",
            "status": "fail",
            "artifact_refs": [rel(contract_path)],
            "failure_signature": "golden_contract_missing",
        }
    if golden_contract.get("missing_item_id") != "tests.golden.primary":
        errors.append("golden_contract.missing_item_id must be tests.golden.primary")
    golden_file = golden_contract.get("golden_file")
    if not isinstance(golden_file, str) or not golden_file:
        errors.append("golden_contract.golden_file missing")
        golden = {}
    else:
        golden = load_json(root / golden_file, errors, "golden_contract.golden_file")

    required_sections = golden_contract.get("required_sections")
    if not isinstance(required_sections, list) or not required_sections:
        errors.append("golden_contract.required_sections missing")
        required_sections = []
    required_paths = golden_contract.get("required_paths")
    if not isinstance(required_paths, list) or not required_paths:
        errors.append("golden_contract.required_paths missing")
        required_paths = []
    required_fragments = golden_contract.get("required_line_fragments")
    if not isinstance(required_fragments, list) or not required_fragments:
        errors.append("golden_contract.required_line_fragments missing")
        required_fragments = []

    section_errors = []
    for section in required_sections:
        if not isinstance(section, str) or section not in golden:
            section_errors.append(f"missing golden section {section}")
    paths, lines = flatten_required_lines(golden)
    for path_text in required_paths:
        if not isinstance(path_text, str) or path_text not in paths:
            section_errors.append(f"missing golden required path {path_text}")
    for fragment in required_fragments:
        if not isinstance(fragment, str) or not any(fragment in line for line in lines):
            section_errors.append(f"missing golden required line fragment {fragment}")
    errors.extend(f"golden_contract: {error}" for error in section_errors)

    return {
        "artifact_id": "base_image_golden_contract",
        "artifact_path": golden_file if isinstance(golden_file, str) else "",
        "evidence_kind": "golden",
        "source_line_ref": "tests/gentoo/base-image-contract.golden.json:1",
        "status": "pass" if not section_errors else "fail",
        "artifact_refs": [golden_file if isinstance(golden_file, str) else "", rel(contract_path)],
        "failure_signature": "none" if not section_errors else "golden_contract_drift",
    }


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    checker = evidence.get("checker")
    if not isinstance(checker, str) or not (root / checker).is_file():
        errors.append("completion_debt_evidence.checker must reference this checker")
    test_source = evidence.get("test_source")
    test_text = read_text(test_source, errors, "completion_debt_evidence.test_source") if isinstance(test_source, str) else ""
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    for section, missing_id in [
        ("golden_primary", "tests.golden.primary"),
        ("telemetry_primary", "telemetry.primary"),
    ]:
        value = evidence.get(section)
        if not isinstance(value, dict):
            errors.append(f"completion_debt_evidence.{section} missing")
            continue
        if value.get("missing_item_id") != missing_id:
            errors.append(f"completion_debt_evidence.{section}.missing_item_id must be {missing_id}")
        required_test_names = value.get("required_test_names")
        if not isinstance(required_test_names, list) or not required_test_names:
            errors.append(f"completion_debt_evidence.{section}.required_test_names missing")
            continue
        for test_name in required_test_names:
            if not isinstance(test_name, str) or f"fn {test_name}(" not in test_text:
                errors.append(f"completion_debt_evidence.{section} references missing Rust test {test_name}")


def validate_telemetry_contract(contract: dict[str, Any], errors: list[str]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return
    if telemetry.get("missing_item_id") != "telemetry.primary":
        errors.append("telemetry_contract.missing_item_id must be telemetry.primary")
    events = telemetry.get("required_log_events")
    if not isinstance(events, list) or set(events) != REQUIRED_EVENTS:
        errors.append("telemetry_contract.required_log_events drifted")
    fields = telemetry.get("required_log_fields")
    if not isinstance(fields, list) or fields != REQUIRED_LOG_FIELDS:
        errors.append("telemetry_contract.required_log_fields drifted")


errors: list[str] = []
warnings: list[str] = []
contract = load_json(contract_path, errors, "contract")
source_rows: list[dict[str, Any]] = []
golden_row: dict[str, Any] = {}

if contract:
    validate_top_level(contract, errors)
    source_rows = validate_source_evidence(contract, errors)
    golden_row = validate_golden_contract(contract, errors)
    validate_telemetry_contract(contract, errors)
    validate_completion_evidence(contract, errors)

timestamp = utc_now()
artifact_rows = []
for row in source_rows:
    row_errors = [
        error
        for error in errors
        if f"source_evidence[{row['artifact_id']}]" in error
        or f"duplicate source_evidence artifact_id {row['artifact_id']}" in error
    ]
    artifact_rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:{row['artifact_id']}",
            "event": "gentoo_portage_mechanics_artifact",
            "bead_id": BEAD_ID,
            "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
            "artifact_id": row["artifact_id"],
            "artifact_path": row["artifact_path"],
            "evidence_kind": row["evidence_kind"],
            "source_line_ref": row["source_line_ref"],
            "status": "pass" if not row_errors and row["status"] == "pass" else "fail",
            "artifact_refs": row["artifact_refs"],
            "failure_signature": "none" if not row_errors and row["status"] == "pass" else "contract_validation_error",
        }
    )

golden_status = "pass" if golden_row.get("status") == "pass" and not any(error.startswith("golden_contract:") for error in errors) else "fail"
golden_log_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:golden",
    "event": "gentoo_portage_mechanics_golden",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "artifact_id": golden_row.get("artifact_id", "base_image_golden_contract"),
    "artifact_path": golden_row.get("artifact_path", ""),
    "evidence_kind": golden_row.get("evidence_kind", "golden"),
    "source_line_ref": golden_row.get("source_line_ref", ""),
    "status": golden_status,
    "artifact_refs": golden_row.get("artifact_refs", [rel(contract_path)]),
    "failure_signature": "none" if golden_status == "pass" else "golden_contract_drift",
}

summary = {
    "schema_version": "gentoo_portage_mechanics_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "contract": rel(contract_path),
    "source_artifact_count": len(source_rows),
    "required_artifact_count": len(REQUIRED_ARTIFACT_IDS),
    "telemetry_row_count": len(artifact_rows) + 2,
    "golden_status": golden_status,
    "errors": errors,
    "warnings": warnings,
    "status": "pass" if not errors else "fail",
    "report_path": rel(report_path),
    "log_path": rel(log_path),
}

summary_row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:summary",
    "event": "gentoo_portage_mechanics_contract_summary",
    "bead_id": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "artifact_id": None,
    "artifact_path": rel(contract_path),
    "evidence_kind": "summary",
    "source_line_ref": None,
    "status": summary["status"],
    "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
    "failure_signature": "none" if not errors else "contract_validation_error",
}

log_rows = artifact_rows + [golden_log_row, summary_row]
report_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows), encoding="utf-8")

print(
    "PASS" if not errors else "FAIL",
    "gentoo_portage_mechanics_completion_contract",
    f"artifacts={len(source_rows)}",
    f"golden={golden_status}",
    f"telemetry_rows={len(log_rows)}",
    f"report={rel(report_path)}",
    f"log={rel(log_path)}",
)
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
PY
