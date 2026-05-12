#!/usr/bin/env bash
# check_stub_census_completion_contract.sh -- fail-closed gate for bd-2vb.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_STUB_CENSUS_CONTRACT:-${ROOT}/tests/conformance/stub_census_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STUB_CENSUS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_STUB_CENSUS_REPORT:-${OUT_DIR}/stub_census_completion_contract.report.json}"
LOG="${FRANKENLIBC_STUB_CENSUS_LOG:-${OUT_DIR}/stub_census_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-2vb"
COMPLETION_BEAD_ID = "bd-2vb.1"
MANIFEST_ID = "stub-census-completion-contract"
REQUIRED_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
REQUIRED_ARTIFACTS = {
    "stub_census_script",
    "stub_census_artifact",
    "stub_todo_debt_census",
    "stub_todo_generator",
    "stub_guard_script",
    "stub_guard_test",
}
REQUIRED_EVENTS = {
    "stub_census_source",
    "stub_census_inventory",
    "stub_census_tests",
    "stub_census_e2e",
    "stub_census_telemetry",
    "stub_census_summary",
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


def event_row(event: str, status: str, artifact_refs: list[str], **extra: Any) -> dict[str, Any]:
    row = {
        "artifact_refs": artifact_refs,
        "bead": BEAD_ID,
        "completion_debt_bead": COMPLETION_BEAD_ID,
        "event": event,
        "status": status,
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_BEAD_ID}::{event}::{len(artifact_refs)}",
    }
    row.update(extra)
    return row


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}(" in source_text or f"fn {name}<" in source_text


def validate_commands(commands: Any, errors: list[str], context: str) -> None:
    for command in strings(commands, errors, f"{context}.required_commands"):
        if "cargo " in command and "rch exec -- cargo " not in command and "rch exec -- env " not in command:
            errors.append(f"{context} cargo command must be rch-backed: {command}")


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
            event_row(
                "stub_census_source",
                "pass" if text else "fail",
                [path_text],
                artifact_id=artifact_id,
            )
        )

    if seen != REQUIRED_ARTIFACTS:
        errors.append(f"source_artifacts must be exactly {sorted(REQUIRED_ARTIFACTS)}, got {sorted(seen)}")
    return paths


def expect_equal(
    actual: Any,
    expected: Any,
    errors: list[str],
    context: str,
) -> None:
    if actual != expected:
        errors.append(f"{context} expected {expected!r}, got {actual!r}")


def validate_inventory(
    contract: dict[str, Any],
    paths: dict[str, str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    expectations = contract.get("inventory_expectations")
    if not isinstance(expectations, dict):
        errors.append("inventory_expectations must be an object")
        return

    stub_census = load_json(root / paths.get("stub_census_artifact", ""), errors, "stub_census_artifact")
    summary = stub_census.get("summary")
    if not isinstance(summary, dict):
        errors.append("stub_census.summary must be an object")
        summary = {}
    if not isinstance(stub_census.get("total_abi_exports"), int) or stub_census["total_abi_exports"] < expectations.get("minimum_total_abi_exports", 0):
        errors.append("stub_census total_abi_exports below expectation")
    if not isinstance(stub_census.get("total_matrix_symbols"), int) or stub_census["total_matrix_symbols"] < expectations.get("minimum_total_matrix_symbols", 0):
        errors.append("stub_census total_matrix_symbols below expectation")
    expect_equal(summary.get("reachable_stubs"), expectations.get("reachable_stubs"), errors, "stub_census.summary.reachable_stubs")
    expect_equal(
        summary.get("matrix_inconsistencies"),
        expectations.get("matrix_inconsistencies"),
        errors,
        "stub_census.summary.matrix_inconsistencies",
    )
    expect_equal(summary.get("missing_symbols"), expectations.get("missing_symbols"), errors, "stub_census.summary.missing_symbols")

    todo_census = load_json(root / paths.get("stub_todo_debt_census", ""), errors, "stub_todo_debt_census")
    exported = todo_census.get("exported_taxonomy_view")
    critical = todo_census.get("critical_source_debt")
    reconciliation = todo_census.get("reconciliation")
    todo_summary = todo_census.get("summary")
    for name, value in (
        ("exported_taxonomy_view", exported),
        ("critical_source_debt", critical),
        ("reconciliation", reconciliation),
        ("summary", todo_summary),
    ):
        if not isinstance(value, dict):
            errors.append(f"stub_todo_debt_census.{name} must be an object")
    exported = exported if isinstance(exported, dict) else {}
    critical = critical if isinstance(critical, dict) else {}
    reconciliation = reconciliation if isinstance(reconciliation, dict) else {}
    todo_summary = todo_summary if isinstance(todo_summary, dict) else {}

    if exported.get("total_exported_declared", 0) < expectations.get("minimum_total_matrix_symbols", 0):
        errors.append("exported_taxonomy_view.total_exported_declared below expectation")
    expect_equal(exported.get("stub_symbols"), [], errors, "exported_taxonomy_view.stub_symbols")
    expect_equal(
        exported.get("non_implemented_exported_symbols"),
        [],
        errors,
        "exported_taxonomy_view.non_implemented_exported_symbols",
    )
    expect_equal(
        critical.get("occurrence_count"),
        expectations.get("critical_source_debt_occurrence_count"),
        errors,
        "critical_source_debt.occurrence_count",
    )
    expect_equal(reconciliation.get("exported_stub_count"), expectations.get("exported_stub_count"), errors, "reconciliation.exported_stub_count")
    expect_equal(
        reconciliation.get("exported_non_implemented_count"),
        expectations.get("exported_non_implemented_count"),
        errors,
        "reconciliation.exported_non_implemented_count",
    )
    expect_equal(
        reconciliation.get("replacement_blocker_count"),
        expectations.get("replacement_blocker_count"),
        errors,
        "reconciliation.replacement_blocker_count",
    )
    expect_equal(
        reconciliation.get("interpose_unapproved_callthrough_count"),
        expectations.get("interpose_unapproved_callthrough_count"),
        errors,
        "reconciliation.interpose_unapproved_callthrough_count",
    )
    expect_equal(todo_summary.get("priority_item_count"), expectations.get("priority_item_count"), errors, "summary.priority_item_count")
    expect_equal(todo_census.get("risk_ranked_debt"), [], errors, "risk_ranked_debt")

    rows.append(
        event_row(
            "stub_census_inventory",
            "pass",
            [paths.get("stub_census_artifact", ""), paths.get("stub_todo_debt_census", "")],
            total_abi_exports=stub_census.get("total_abi_exports"),
            total_matrix_symbols=stub_census.get("total_matrix_symbols"),
            priority_item_count=todo_summary.get("priority_item_count"),
        )
    )


def validate_artifact_ids(value: Any, paths: dict[str, str], errors: list[str], context: str) -> list[str]:
    refs: list[str] = []
    for artifact_id in strings(value, errors, f"{context}.artifact_ids"):
        path = paths.get(artifact_id)
        if path is None:
            errors.append(f"{context} references unknown artifact_id {artifact_id}")
        else:
            refs.append(path)
    return refs


def validate_evidence(
    contract: dict[str, Any],
    paths: dict[str, str],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    evidence = contract.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        errors.append("completion_debt_evidence must be an object")
        return
    if evidence.get("bead") != COMPLETION_BEAD_ID:
        errors.append(f"completion_debt_evidence.bead must be {COMPLETION_BEAD_ID}")
    if evidence.get("original_bead") != BEAD_ID:
        errors.append(f"completion_debt_evidence.original_bead must be {BEAD_ID}")
    threshold = evidence.get("next_audit_score_threshold")
    if not isinstance(threshold, int) or threshold < 900:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be >= 900")
    missing = set(strings(evidence.get("missing_items_closed"), errors, "completion_debt_evidence.missing_items_closed"))
    if missing != REQUIRED_ITEMS:
        errors.append(f"completion_debt_evidence.missing_items_closed must be {sorted(REQUIRED_ITEMS)}")

    unit = evidence.get("unit_primary")
    if not isinstance(unit, dict):
        errors.append("unit_primary must be an object")
    else:
        if unit.get("missing_item_id") != "tests.unit.primary":
            errors.append("unit_primary.missing_item_id must be tests.unit.primary")
        test_source = unit.get("test_source")
        if not isinstance(test_source, str) or not test_source:
            errors.append("unit_primary.test_source missing")
            source_text = ""
        else:
            source_text = read_text(test_source, errors, "unit_primary.test_source")
        found = 0
        for name in strings(unit.get("required_test_names"), errors, "unit_primary.required_test_names"):
            if function_exists(source_text, name):
                found += 1
            else:
                errors.append(f"unit_primary references missing test {name}")
        validate_commands(unit.get("required_commands"), errors, "unit_primary")
        rows.append(event_row("stub_census_tests", "pass", [test_source] if isinstance(test_source, str) else [], test_count=found))

    e2e = evidence.get("e2e_primary")
    if not isinstance(e2e, dict):
        errors.append("e2e_primary must be an object")
    else:
        if e2e.get("missing_item_id") != "tests.e2e.primary":
            errors.append("e2e_primary.missing_item_id must be tests.e2e.primary")
        validate_commands(e2e.get("required_commands"), errors, "e2e_primary")
        refs = validate_artifact_ids(e2e.get("artifact_ids"), paths, errors, "e2e_primary")
        rows.append(event_row("stub_census_e2e", "pass", refs, artifact_count=len(refs)))

    telemetry = evidence.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_primary must be an object")
    else:
        if telemetry.get("missing_item_id") != "telemetry.primary":
            errors.append("telemetry_primary.missing_item_id must be telemetry.primary")
        events = set(strings(telemetry.get("required_events"), errors, "telemetry_primary.required_events"))
        if events != REQUIRED_EVENTS:
            errors.append(f"telemetry_primary.required_events must be {sorted(REQUIRED_EVENTS)}")
        fields = set(strings(telemetry.get("required_fields"), errors, "telemetry_primary.required_fields"))
        for field in ("timestamp", "trace_id", "event", "status", "bead", "completion_debt_bead", "artifact_refs"):
            if field not in fields:
                errors.append(f"telemetry_primary.required_fields missing {field}")
        artifact_ids = set(strings(telemetry.get("required_artifact_ids"), errors, "telemetry_primary.required_artifact_ids"))
        if artifact_ids != REQUIRED_ARTIFACTS:
            errors.append(f"telemetry_primary.required_artifact_ids must be {sorted(REQUIRED_ARTIFACTS)}")
        for field in ("report_path", "log_path"):
            if not isinstance(telemetry.get(field), str) or not telemetry[field]:
                errors.append(f"telemetry_primary.{field} missing")
        rows.append(
            event_row(
                "stub_census_telemetry",
                "pass" if events == REQUIRED_EVENTS else "fail",
                sorted(paths.values()),
                required_event_count=len(events),
            )
        )


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, errors, "contract")

if contract.get("schema_version") != "stub_census_completion_contract.v1":
    errors.append("schema_version mismatch")
if contract.get("manifest_id") != MANIFEST_ID:
    errors.append(f"manifest_id must be {MANIFEST_ID}")
if contract.get("bead") != BEAD_ID:
    errors.append(f"bead must be {BEAD_ID}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD_ID:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD_ID}")
if not isinstance(contract.get("next_audit_score_threshold"), int) or contract["next_audit_score_threshold"] < 900:
    errors.append("next_audit_score_threshold must be >= 900")

paths = validate_source_artifacts(contract, errors, rows)
validate_inventory(contract, paths, errors, rows)
validate_evidence(contract, paths, errors, rows)

status = "fail" if errors else "pass"
rows.append(
    event_row(
        "stub_census_summary",
        status,
        [rel(contract_path)],
        source_count=len(paths),
        missing_item_count=len(REQUIRED_ITEMS),
    )
)
report = {
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_BEAD_ID,
    "errors": errors,
    "event_count": len(rows),
    "manifest_id": contract.get("manifest_id"),
    "missing_item_count": len(REQUIRED_ITEMS),
    "source_count": len(paths),
    "status": status,
}
write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("stub_census_completion_contract: FAIL")
    for error in errors:
        print(f"- {error}")
    sys.exit(1)

print(f"stub_census_completion_contract: PASS sources={len(paths)} events={len(rows)}")
PY
