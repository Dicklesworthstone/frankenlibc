#!/usr/bin/env bash
# check_reverse_round_unit_golden_completion_contract.sh -- fail-closed gate for bd-2a2.4.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_CONTRACT:-${ROOT}/tests/conformance/reverse_round_unit_golden_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_REPORT:-${OUT_DIR}/reverse_round_unit_golden_completion_contract.report.json}"
LOG="${FRANKENLIBC_REVERSE_ROUND_UNIT_GOLDEN_LOG:-${OUT_DIR}/reverse_round_unit_golden_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-2a2.4"
COMPLETION_BEAD_ID = "bd-2a2.4.1"
MANIFEST_ID = "reverse-round-unit-golden-completion-contract"
REQUIRED_EVENTS = {
    "reverse_round_unit_source",
    "reverse_round_unit_round",
    "reverse_round_golden_check",
    "reverse_round_unit_summary",
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


def require_strings(value: Any, errors: list[str], context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        errors.append(f"{context} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def collect_verification_paths(round_data: dict[str, Any]) -> set[str]:
    paths: set[str] = set()
    for hook in round_data.get("verification_strategy", []):
        if not isinstance(hook, dict):
            continue
        path = hook.get("path")
        if isinstance(path, str):
            paths.add(path)
        hook_paths = hook.get("paths")
        if isinstance(hook_paths, list):
            for item in hook_paths:
                if isinstance(item, dict) and isinstance(item.get("path"), str):
                    paths.add(item["path"])
    return paths


def validate_source_artifacts(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    artifacts = contract.get("source_artifacts")
    if not isinstance(artifacts, list) or len(artifacts) < 4:
        errors.append("source_artifacts must include report, generator, gate, and source tests")
        return
    required = {
        "reverse_round_report",
        "reverse_round_generator",
        "reverse_round_gate",
        "reverse_round_source_tests",
    }
    seen = set()
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
        text = read_text(path_text, errors, artifact_id)
        for needle in require_strings(artifact.get("required_needles"), errors, f"{artifact_id}.required_needles"):
            if needle not in text:
                errors.append(f"{artifact_id} missing needle {needle!r}")
        rows.append({
            "event": "reverse_round_unit_source",
            "status": "pass" if text else "fail",
            "artifact_id": artifact_id,
            "path": path_text,
            "timestamp": utc_now(),
        })
    if seen != required:
        errors.append(f"source_artifacts must be exactly {sorted(required)}, got {sorted(seen)}")


def validate_completion_evidence(contract: dict[str, Any], errors: list[str]) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    if not isinstance(evidence.get("next_audit_score_threshold"), int) or evidence["next_audit_score_threshold"] < 800:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 800")
    missing = set(require_strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing != {"tests.unit.primary", "tests.golden.primary"}:
        errors.append("completion_debt_evidence.missing_items_closed must close unit and golden items")
    events = set(require_strings(evidence.get("required_events"), errors, "completion_debt_evidence.required_events"))
    if events != REQUIRED_EVENTS:
        errors.append(f"completion_debt_evidence.required_events must be {sorted(REQUIRED_EVENTS)}")
    unit = evidence.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("completion_debt_evidence.unit_primary must be an object")
        source_text = ""
    else:
        test_source = unit.get("test_source")
        source_text = read_text(test_source, errors, "unit_primary.test_source") if isinstance(test_source, str) else ""
        for name in require_strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names"):
            if f"fn {name}(" not in source_text:
                errors.append(f"unit_primary references missing Rust test {name}")
    golden = evidence.get("golden_primary")
    if not isinstance(golden, dict):
        errors.append("completion_debt_evidence.golden_primary must be an object")
    else:
        golden_source = golden.get("golden_source")
        checked = golden.get("checked_artifact")
        if not isinstance(golden_source, str) or not (root / golden_source).is_file():
            errors.append("golden_primary.golden_source missing")
        if not isinstance(checked, str) or not (root / checked).is_file():
            errors.append("golden_primary.checked_artifact missing")
        for name in require_strings(golden.get("required_test_names"), errors, "golden_primary.required_test_names"):
            if f"fn {name}(" not in source_text:
                errors.append(f"golden_primary references missing Rust test {name}")


def validate_round_scope(contract: dict[str, Any], reverse_report: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> list[str]:
    scope = contract.get("round_scope")
    if not isinstance(scope, dict):
        errors.append("round_scope must be an object")
        return []
    required_rounds = require_strings(scope.get("required_rounds"), errors, "round_scope.required_rounds")
    if required_rounds != ["R7", "R8", "R9", "R10", "R11"]:
        errors.append("round_scope.required_rounds must be exactly R7-R11")
    min_families = scope.get("minimum_math_families_per_round")
    min_classes = scope.get("minimum_math_classes_per_round")
    if not isinstance(min_families, int) or min_families < 4:
        errors.append("round_scope.minimum_math_families_per_round must be >= 4")
    if not isinstance(min_classes, int) or min_classes < 3:
        errors.append("round_scope.minimum_math_classes_per_round must be >= 3")
    required_fields = set(require_strings(scope.get("required_round_fields"), errors, "round_scope.required_round_fields"))
    required_paths = scope.get("required_verification_paths")
    if not isinstance(required_paths, dict):
        errors.append("round_scope.required_verification_paths must be an object")
        required_paths = {}
    rounds = reverse_report.get("round_results")
    if not isinstance(rounds, dict):
        errors.append("reverse report round_results must be an object")
        return required_rounds
    for round_id in required_rounds:
        round_data = rounds.get(round_id)
        if not isinstance(round_data, dict):
            errors.append(f"reverse report missing required round {round_id}")
            continue
        for field in required_fields:
            if field not in round_data:
                errors.append(f"{round_id}: missing required round field {field}")
        families = round_data.get("math_families")
        family_count = len(families) if isinstance(families, dict) else 0
        class_count = round_data.get("branch_diversity", {}).get("class_count") if isinstance(round_data.get("branch_diversity"), dict) else None
        if family_count < min_families:
            errors.append(f"{round_id}: expected at least {min_families} math families")
        if not isinstance(class_count, int) or class_count < min_classes:
            errors.append(f"{round_id}: expected at least {min_classes} math classes")
        if not round_data.get("legacy_surfaces"):
            errors.append(f"{round_id}: legacy_surfaces must be non-empty")
        if not round_data.get("implementation_plan"):
            errors.append(f"{round_id}: implementation_plan must be non-empty")
        actual_paths = collect_verification_paths(round_data)
        for path in require_strings(required_paths.get(round_id), errors, f"required_verification_paths.{round_id}"):
            if path not in actual_paths:
                errors.append(f"{round_id}: verification hook missing {path}")
            if not (root / path).exists():
                errors.append(f"{round_id}: verification path does not exist {path}")
        rows.append({
            "event": "reverse_round_unit_round",
            "status": "pass",
            "round_id": round_id,
            "math_family_count": family_count,
            "math_class_count": class_count,
            "verification_path_count": len(actual_paths),
            "timestamp": utc_now(),
        })
    return required_rounds


def validate_golden(contract: dict[str, Any], reverse_report: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> None:
    golden = contract.get("golden_expectations")
    if not isinstance(golden, dict):
        errors.append("golden_expectations must be an object")
        return
    source = golden.get("source_artifact")
    if not isinstance(source, str) or not (root / source).is_file():
        errors.append("golden_expectations.source_artifact missing")
    if reverse_report.get("report_hash") != golden.get("report_hash"):
        errors.append("golden_expectations.report_hash drift")
    report_golden = reverse_report.get("golden_output")
    if not isinstance(report_golden, dict):
        errors.append("reverse report golden_output must be an object")
        return
    if report_golden.get("hash") != golden.get("report_hash"):
        errors.append("reverse report golden_output.hash must match golden_expectations.report_hash")
    round_hashes = golden.get("round_hashes")
    report_round_hashes = report_golden.get("round_hashes")
    if not isinstance(round_hashes, dict) or not isinstance(report_round_hashes, dict):
        errors.append("golden round_hashes must be objects")
    else:
        for round_id, expected_hash in sorted(round_hashes.items()):
            if report_round_hashes.get(round_id) != expected_hash:
                errors.append(f"golden round hash drift for {round_id}: expected {expected_hash}, got {report_round_hashes.get(round_id)}")
            rows.append({
                "event": "reverse_round_golden_check",
                "status": "pass" if report_round_hashes.get(round_id) == expected_hash else "fail",
                "round_id": round_id,
                "expected_hash": expected_hash,
                "actual_hash": report_round_hashes.get(round_id),
                "timestamp": utc_now(),
            })
    expected_summary = golden.get("summary")
    actual_summary = reverse_report.get("summary")
    if not isinstance(expected_summary, dict) or not isinstance(actual_summary, dict):
        errors.append("golden summary and reverse report summary must be objects")
    else:
        for field, expected in sorted(expected_summary.items()):
            if actual_summary.get(field) != expected:
                errors.append(f"golden summary drift for {field}: expected {expected!r}, got {actual_summary.get(field)!r}")


def validate_contract(contract: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> tuple[dict[str, Any], list[str]]:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
    validate_source_artifacts(contract, errors, rows)
    validate_completion_evidence(contract, errors)
    golden = contract.get("golden_expectations", {})
    source = golden.get("source_artifact") if isinstance(golden, dict) else None
    reverse_report = load_json(root / source, errors, "reverse round golden artifact") if isinstance(source, str) else {}
    rounds = validate_round_scope(contract, reverse_report, errors, rows)
    validate_golden(contract, reverse_report, errors, rows)
    return reverse_report, rounds


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "reverse-round unit/golden completion contract")
reverse_report, rounds = validate_contract(contract, errors, rows) if contract else ({}, [])
status = "pass" if not errors else "fail"

summary = reverse_report.get("summary", {}) if isinstance(reverse_report, dict) else {}
rows.append({
    "event": "reverse_round_unit_summary",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "round_count": len(rounds),
    "report_hash": reverse_report.get("report_hash") if isinstance(reverse_report, dict) else None,
    "rounds_verified": summary.get("rounds_verified"),
    "error_count": len(errors),
    "timestamp": utc_now(),
})
report = {
    "schema_version": "v1",
    "status": status,
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "contract": rel(contract_path),
    "log": rel(log_path),
    "rounds": rounds,
    "report_hash": reverse_report.get("report_hash") if isinstance(reverse_report, dict) else None,
    "errors": errors,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("reverse_round_unit_golden_completion_contract: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    sys.exit(1)

print(
    "reverse_round_unit_golden_completion_contract: PASS "
    f"rounds={len(rounds)} report_hash={report['report_hash']}"
)
PY
