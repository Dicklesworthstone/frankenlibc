#!/usr/bin/env bash
# check_observability_dashboard_completion_contract.sh -- fail-closed gate for bd-282v.1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_OBSERVABILITY_DASHBOARD_CONTRACT:-${ROOT}/tests/conformance/observability_dashboard_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_OBSERVABILITY_DASHBOARD_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_OBSERVABILITY_DASHBOARD_REPORT:-${OUT_DIR}/observability_dashboard_completion_contract.report.json}"
LOG="${FRANKENLIBC_OBSERVABILITY_DASHBOARD_LOG:-${OUT_DIR}/observability_dashboard_completion_contract.log.jsonl}"

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

BEAD_ID = "bd-282v"
COMPLETION_DEBT_BEAD_ID = "bd-282v.1"
MANIFEST_ID = "observability-dashboard-completion-contract"
REQUIRED_SOURCE_IDS = {
    "dashboard_aggregator",
    "dashboard_writer",
    "dashboard_capture_pipeline",
    "dashboard_unit_test",
    "allocator_jsonl_export",
    "cli_capture_command",
    "dashboard_e2e_test",
}
REQUIRED_BINDINGS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_GENERATED_OUTPUTS = {
    "inputs/membrane_metrics.jsonl",
    "inputs/allocator_metrics.jsonl",
    "inputs/runtime_math.jsonl",
    "observability_dashboard.current.v1.json",
    "observability_dashboard.prom",
    "observability_dashboard.statsd",
    "observability_dashboard.grafana.json",
    "observability_dashboard.alerts.yaml",
}
REQUIRED_METRIC_FRAGMENTS = {
    "frankenlibc_validations_total",
    "frankenlibc_allocator_bytes_allocated",
    "frankenlibc_runtime_decisions_total",
    "frankenlibc.allocator.allocations_total:2|g",
    "FrankenLibCAllocatorArenaPressure",
}
REQUIRED_EVENTS = {
    "observability_dashboard_source_bound",
    "observability_dashboard_test_binding_bound",
    "observability_dashboard_telemetry_bound",
    "observability_dashboard_completion_contract_summary",
}
REQUIRED_LOG_FIELDS = [
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "completion_debt_bead",
    "artifact_id",
    "artifact_path",
    "missing_item_id",
    "evidence_kind",
    "source_line_ref",
    "status",
    "artifact_refs",
    "failure_signature",
]
FORBIDDEN_COMMAND_SUBSTRINGS = {
    "git reset --hard",
    "git clean -fd",
    "rm -rf",
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


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}(" in source or f"fn {name}<" in source or f"def {name}(" in source


def compact_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def compact_write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def base_row(
    *,
    event: str,
    artifact_id: str,
    artifact_path: str,
    missing_item_id: str,
    evidence_kind: str,
    source_line_ref: str,
    status: str,
    artifact_refs: list[str],
    failure_signature: str,
) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{COMPLETION_DEBT_BEAD_ID}:observability-dashboard-completion",
        "event": event,
        "bead_id": BEAD_ID,
        "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
        "artifact_id": artifact_id,
        "artifact_path": artifact_path,
        "missing_item_id": missing_item_id,
        "evidence_kind": evidence_kind,
        "source_line_ref": source_line_ref,
        "status": status,
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature,
    }


def validate_top_level(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("schema_version must be v1")
    if contract.get("manifest_id") != MANIFEST_ID:
        errors.append(f"manifest_id must be {MANIFEST_ID}")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"bead must be {BEAD_ID}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD_ID:
        errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD_ID}")
    audit = contract.get("audit_reference")
    if not isinstance(audit, dict):
        errors.append("audit_reference must be an object")
        return
    missing_items = audit.get("missing_items")
    if set(missing_items if isinstance(missing_items, list) else []) != set(REQUIRED_BINDINGS.values()):
        errors.append("audit_reference.missing_items must match completion-debt missing items")


def validate_sources(contract: dict[str, Any], errors: list[str]) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[dict[str, Any]]]:
    sources = contract.get("source_evidence")
    if not isinstance(sources, list) or not sources:
        errors.append("source_evidence must be a non-empty array")
        return {}, {}, []

    by_id: dict[str, dict[str, Any]] = {}
    source_texts: dict[str, str] = {}
    rows: list[dict[str, Any]] = []
    for index, item in enumerate(sources):
        if not isinstance(item, dict):
            errors.append(f"source_evidence[{index}] must be an object")
            continue
        artifact_id = item.get("artifact_id")
        path_text = item.get("path")
        kind = item.get("kind")
        line_ref = item.get("line_ref")
        needles = item.get("required_needles")
        context = f"source_evidence[{artifact_id or index}]"
        if not isinstance(artifact_id, str) or not artifact_id:
            errors.append(f"{context}.artifact_id missing")
            continue
        if artifact_id in by_id:
            errors.append(f"duplicate source_evidence artifact_id {artifact_id}")
        by_id[artifact_id] = item
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"{context}.path missing")
            path_text = ""
        if not isinstance(kind, str) or not kind:
            errors.append(f"{context}.kind missing")
            kind = "unknown"
        validate_line_ref(line_ref, errors, f"{context}.line_ref")
        source = read_text(path_text, errors, context) if path_text else ""
        source_texts[artifact_id] = source
        if not isinstance(needles, list) or not all(isinstance(needle, str) and needle for needle in needles):
            errors.append(f"{context}.required_needles must be non-empty strings")
            needles = []
        missing_needles = [needle for needle in needles if needle not in source]
        for needle in missing_needles:
            errors.append(f"{context} missing needle {needle!r}")
        rows.append(
            base_row(
                event="observability_dashboard_source_bound",
                artifact_id=artifact_id,
                artifact_path=path_text,
                missing_item_id="source.primary",
                evidence_kind=kind,
                source_line_ref=line_ref if isinstance(line_ref, str) else "",
                status="pass" if not missing_needles else "fail",
                artifact_refs=[path_text, rel(contract_path)],
                failure_signature="none" if not missing_needles else "source_evidence_missing_needle",
            )
        )

    missing_source_ids = sorted(REQUIRED_SOURCE_IDS - set(by_id))
    if missing_source_ids:
        errors.append(f"source_evidence missing required artifact ids: {missing_source_ids}")
    return by_id, source_texts, rows


def validate_command(command: Any, errors: list[str], context: str) -> None:
    if not isinstance(command, str) or not command:
        errors.append(f"{context} command must be a non-empty string")
        return
    for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS:
        if forbidden in command:
            errors.append(f"{context} command contains forbidden substring {forbidden!r}: {command}")
    if "cargo " in command and "rch exec" not in command:
        errors.append(f"{context} cargo command must be rch-backed: {command}")


def validate_bindings(
    contract: dict[str, Any],
    sources: dict[str, dict[str, Any]],
    source_texts: dict[str, str],
    errors: list[str],
) -> list[dict[str, Any]]:
    bindings = contract.get("test_bindings")
    if not isinstance(bindings, list) or not bindings:
        errors.append("test_bindings must be a non-empty array")
        return []

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            errors.append(f"test_bindings[{index}] must be an object")
            continue
        binding_id = binding.get("binding_id")
        missing_item_id = binding.get("missing_item_id")
        context = f"test_bindings[{binding_id or index}]"
        if not isinstance(binding_id, str) or not binding_id:
            errors.append(f"{context}.binding_id missing")
            continue
        seen.add(binding_id)
        if REQUIRED_BINDINGS.get(binding_id) != missing_item_id:
            errors.append(f"{context}.missing_item_id must be {REQUIRED_BINDINGS.get(binding_id)}")

        artifact_ids = binding.get("required_artifact_ids")
        if not isinstance(artifact_ids, list) or not artifact_ids:
            errors.append(f"{context}.required_artifact_ids must be non-empty")
            artifact_ids = []
        for artifact_id in artifact_ids:
            if not isinstance(artifact_id, str) or artifact_id not in sources:
                errors.append(f"{context} references unknown artifact id {artifact_id!r}")

        test_refs = binding.get("required_test_refs")
        if binding_id in {"unit_primary", "e2e_primary"} and (not isinstance(test_refs, list) or not test_refs):
            errors.append(f"{context}.required_test_refs must be non-empty")
            test_refs = []
        elif not isinstance(test_refs, list):
            test_refs = []
        for ref_index, test_ref in enumerate(test_refs):
            if not isinstance(test_ref, dict):
                errors.append(f"{context}.required_test_refs[{ref_index}] must be an object")
                continue
            source_id = test_ref.get("source_artifact_id")
            name = test_ref.get("name")
            if not isinstance(source_id, str) or source_id not in source_texts:
                errors.append(f"{context}.required_test_refs[{ref_index}] unknown source_artifact_id")
                continue
            if not isinstance(name, str) or not name:
                errors.append(f"{context}.required_test_refs[{ref_index}] missing name")
                continue
            if not function_exists(source_texts[source_id], name):
                errors.append(f"{context}.required_test_refs[{ref_index}] missing function {name}")

        commands = binding.get("required_commands")
        if not isinstance(commands, list) or not commands:
            errors.append(f"{context}.required_commands must be non-empty")
            commands = []
        for command in commands:
            validate_command(command, errors, context)

        fragments = binding.get("required_fragments")
        if fragments is None:
            fragments = []
        if not isinstance(fragments, list):
            errors.append(f"{context}.required_fragments must be an array when present")
            fragments = []
        combined = "\n".join(source_texts.get(str(artifact_id), "") for artifact_id in artifact_ids)
        for fragment in fragments:
            if not isinstance(fragment, str) or not fragment:
                errors.append(f"{context}.required_fragments must contain non-empty strings")
            elif fragment not in combined:
                errors.append(f"{context} missing fragment {fragment!r}")

        rows.append(
            base_row(
                event="observability_dashboard_test_binding_bound",
                artifact_id=binding_id,
                artifact_path=",".join(str(item) for item in artifact_ids if isinstance(item, str)),
                missing_item_id=missing_item_id if isinstance(missing_item_id, str) else "",
                evidence_kind="test_binding",
                source_line_ref=rel(contract_path),
                status="pass",
                artifact_refs=[rel(contract_path)],
                failure_signature="none",
            )
        )

    missing_bindings = sorted(set(REQUIRED_BINDINGS) - seen)
    if missing_bindings:
        errors.append(f"test_bindings missing required binding ids: {missing_bindings}")
    return rows


def validate_telemetry_contract(
    contract: dict[str, Any],
    source_texts: dict[str, str],
    errors: list[str],
) -> list[dict[str, Any]]:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_contract must be an object")
        return []
    if telemetry.get("missing_item_id") != "telemetry.primary":
        errors.append("telemetry_contract.missing_item_id must be telemetry.primary")

    outputs = telemetry.get("required_generated_outputs")
    output_set = set(outputs if isinstance(outputs, list) else [])
    if output_set != REQUIRED_GENERATED_OUTPUTS:
        errors.append("telemetry_contract.required_generated_outputs must match dashboard output contract")
    fragments = telemetry.get("required_metric_fragments")
    fragment_set = set(fragments if isinstance(fragments, list) else [])
    if fragment_set != REQUIRED_METRIC_FRAGMENTS:
        errors.append("telemetry_contract.required_metric_fragments must match dashboard metric contract")
    events = telemetry.get("required_log_events")
    if set(events if isinstance(events, list) else []) != REQUIRED_EVENTS:
        errors.append("telemetry_contract.required_log_events must match checker telemetry events")
    fields = telemetry.get("required_log_fields")
    if list(fields if isinstance(fields, list) else []) != REQUIRED_LOG_FIELDS:
        errors.append("telemetry_contract.required_log_fields must match checker telemetry fields")

    combined = "\n".join(source_texts.values())
    for output in REQUIRED_GENERATED_OUTPUTS:
        bare_name = output.split("/", 1)[-1]
        if bare_name not in combined:
            errors.append(f"telemetry source evidence missing generated output {output}")
    for fragment in REQUIRED_METRIC_FRAGMENTS:
        if fragment not in combined:
            errors.append(f"telemetry source evidence missing metric fragment {fragment}")

    return [
        base_row(
            event="observability_dashboard_telemetry_bound",
            artifact_id="telemetry_contract",
            artifact_path=rel(contract_path),
            missing_item_id="telemetry.primary",
            evidence_kind="completion_telemetry",
            source_line_ref=rel(contract_path),
            status="pass",
            artifact_refs=[
                rel(contract_path),
                rel(report_path),
                rel(log_path),
            ],
            failure_signature="none",
        )
    ]


def validate_log_rows(rows: list[dict[str, Any]], errors: list[str]) -> None:
    events = {row.get("event") for row in rows}
    if not REQUIRED_EVENTS.issubset(events):
        errors.append(f"log rows missing required events: {sorted(REQUIRED_EVENTS - events)}")
    for index, row in enumerate(rows):
        for field in REQUIRED_LOG_FIELDS:
            if field not in row:
                errors.append(f"log row {index} missing field {field}")


errors: list[str] = []
contract = load_json(contract_path, errors, "contract")
validate_top_level(contract, errors)
sources, source_texts, source_rows = validate_sources(contract, errors)
binding_rows = validate_bindings(contract, sources, source_texts, errors)
telemetry_rows = validate_telemetry_contract(contract, source_texts, errors)

rows = source_rows + binding_rows + telemetry_rows
summary_status = "pass" if not errors else "fail"
rows.append(
    base_row(
        event="observability_dashboard_completion_contract_summary",
        artifact_id="completion_summary",
        artifact_path=rel(contract_path),
        missing_item_id="tests.unit.primary,tests.e2e.primary,telemetry.primary",
        evidence_kind="summary",
        source_line_ref=rel(contract_path),
        status=summary_status,
        artifact_refs=[rel(contract_path), rel(report_path), rel(log_path)],
        failure_signature="none" if not errors else "completion_contract_failed",
    )
)
validate_log_rows(rows, errors)

report = {
    "schema_version": "observability_dashboard_completion_contract.report.v1",
    "bead": BEAD_ID,
    "completion_debt_bead": COMPLETION_DEBT_BEAD_ID,
    "status": "pass" if not errors else "fail",
    "checked_source_artifacts": len(sources),
    "checked_test_bindings": len(binding_rows),
    "checked_telemetry_outputs": len(REQUIRED_GENERATED_OUTPUTS),
    "checked_metric_fragments": len(REQUIRED_METRIC_FRAGMENTS),
    "required_events": sorted(REQUIRED_EVENTS),
    "artifact_refs": [rel(contract_path), rel(log_path)],
    "errors": errors,
}
compact_write_json(report_path, report)
compact_write_jsonl(log_path, rows)

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    sys.exit(1)

print(
    "observability dashboard completion contract PASS: "
    f"sources={len(sources)} bindings={len(binding_rows)} telemetry_outputs={len(REQUIRED_GENERATED_OUTPUTS)}"
)
PY
