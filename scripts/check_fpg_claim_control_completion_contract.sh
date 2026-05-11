#!/usr/bin/env bash
# Validate bd-bp8fl.3.5.1 fpg-claim-control conformance completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_FPG_CLAIM_CONTROL_COMPLETION_CONTRACT:-${1:-${ROOT}/tests/conformance/fpg_claim_control_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_FPG_CLAIM_CONTROL_COMPLETION_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_FPG_CLAIM_CONTROL_COMPLETION_REPORT:-${OUT_DIR}/fpg_claim_control_completion_contract.report.json}"
LOG="${FRANKENLIBC_FPG_CLAIM_CONTROL_COMPLETION_LOG:-${OUT_DIR}/fpg_claim_control_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2]).resolve()
report_path = Path(sys.argv[3]).resolve()
log_path = Path(sys.argv[4]).resolve()
source_commit = sys.argv[5]

SCHEMA = "fpg_claim_control_completion_contract.v1"
BEAD_ID = "bd-bp8fl.3.5.1"
ORIGINAL_BEAD = "bd-bp8fl.3.5"
TRACE_ID = "bd-bp8fl.3.5.1::fpg-claim-control::v1"
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_conformance_binding",
    "gap_id_drift",
    "source_gate_invalid",
    "source_checker_failed",
    "completion_output_contract_failed",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {row["failure_signature"] for row in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "fpg_claim_control_completion_contract_failed"


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error("malformed_contract", f"{label}: cannot parse {rel(path)}: {exc}")
        return {}


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def resolve_ref(ref: str) -> Path:
    return resolve(ref.split(":", 1)[0])


def require(condition: bool, signature: str, message: str) -> None:
    if not condition:
        add_error(signature, message)


def require_array(row: dict[str, Any], field: str, ctx: str) -> list[Any]:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    add_error("malformed_contract", f"{ctx}.{field} must be a non-empty array")
    return []


def string_list(row: dict[str, Any], field: str, ctx: str) -> list[str]:
    result: list[str] = []
    for index, value in enumerate(require_array(row, field, ctx)):
        if isinstance(value, str) and value:
            result.append(value)
        else:
            add_error("malformed_contract", f"{ctx}.{field}[{index}] must be a non-empty string")
    return result


def event(name: str, status: str, scenario_id: str, expected: Any, actual: Any, refs: list[str], failure: str = "none") -> dict[str, Any]:
    return {
        "timestamp": now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "scenario_id": scenario_id,
        "event": name,
        "status": status,
        "expected": expected,
        "actual": actual,
        "artifact_refs": sorted(set(refs)),
        "source_commit": source_commit,
        "failure_signature": failure,
    }


def fail_report(stage: str, refs: list[str] | None = None) -> None:
    refs = sorted(set([rel(contract_path), rel(report_path), rel(log_path), *(refs or [])]))
    events.append(
        event(stage + "_failed", "fail", stage, "completion contract passes", primary_signature(), refs, primary_signature())
    )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": "fail",
        "summary": {"gap_count": 0, "binding_count": 0, "log_row_count": len(events)},
        "source_artifacts": [],
        "missing_item_bindings": [],
        "fpg_claim_control": {},
        "artifact_refs": refs,
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    raise SystemExit(1)


def validate_source_artifacts(contract: dict[str, Any]) -> list[str]:
    refs: list[str] = []
    for index, artifact in enumerate(require_array(contract, "source_artifacts", "contract")):
        if not isinstance(artifact, dict):
            add_error("malformed_contract", f"source_artifacts[{index}] must be an object")
            continue
        artifact_id = artifact.get("id")
        path_text = artifact.get("path")
        if not isinstance(artifact_id, str) or not artifact_id:
            add_error("malformed_contract", f"source_artifacts[{index}].id must be non-empty")
        if not isinstance(path_text, str) or not path_text:
            add_error("malformed_contract", f"source_artifacts[{index}].path must be non-empty")
            continue
        path = resolve(path_text)
        refs.append(rel(path))
        if not path.exists():
            add_error("missing_source_artifact", f"{artifact_id or index}: missing {rel(path)}")
    if not errors:
        events.append(
            event("source_artifacts_validated", "pass", "source-artifacts", "all sources exist", len(refs), refs)
        )
    return refs


def validate_binding(contract: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = contract.get("completion_debt_evidence", {})
    if not isinstance(evidence, dict):
        add_error("malformed_contract", "completion_debt_evidence must be an object")
        return []
    bindings = require_array(evidence, "missing_item_bindings", "completion_debt_evidence")
    seen: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("malformed_contract", f"missing_item_bindings[{index}] must be an object")
            continue
        spec = binding.get("spec_item")
        if isinstance(spec, str):
            seen.add(spec)
        for field in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests", "required_commands"):
            for ref in string_list(binding, field, f"missing_item_bindings[{index}]"):
                if field.endswith("_refs") and not resolve_ref(ref).exists():
                    add_error("missing_source_artifact", f"{spec}: missing referenced path {ref}")
    if seen != {"tests.conformance.primary"}:
        add_error("missing_conformance_binding", f"expected only tests.conformance.primary binding, got {sorted(seen)}")
    else:
        events.append(
            event("conformance_binding_validated", "pass", "conformance-binding", ["tests.conformance.primary"], sorted(seen), [rel(contract_path)])
        )
    return [row for row in bindings if isinstance(row, dict)]


def select_value(value: Any, path: str) -> Any:
    cursor = value
    for segment in path.split("."):
        if isinstance(cursor, dict) and segment in cursor:
            cursor = cursor[segment]
        else:
            return None
    return cursor


def validate_fpg_gate(contract: dict[str, Any]) -> tuple[list[str], dict[str, Any]]:
    cfg = contract.get("fpg_claim_control_contract", {})
    if not isinstance(cfg, dict):
        add_error("malformed_contract", "fpg_claim_control_contract must be an object")
        return [], {}
    gate = load_json(resolve(str(cfg.get("gate_path", ""))), "fpg claim-control gate")
    if not isinstance(gate, dict):
        add_error("source_gate_invalid", "fpg claim-control gate must be an object")
        return [], {}
    expected_ids = set(string_list(cfg, "expected_gap_ids", "fpg_claim_control_contract"))
    rows = gate.get("rows")
    if not isinstance(rows, list):
        add_error("source_gate_invalid", "gate.rows must be an array")
        rows = []
    actual_ids = {row.get("gap_id") for row in rows if isinstance(row, dict)}
    if actual_ids != expected_ids:
        add_error("gap_id_drift", f"expected gap ids {sorted(expected_ids)}, got {sorted(actual_ids)}")
    require(len(rows) == int(cfg.get("expected_validate_only_rows", 8)), "gap_id_drift", "gate row count mismatch")
    require(gate.get("bead") == ORIGINAL_BEAD, "source_gate_invalid", "source gate bead mismatch")
    require(gate.get("owner_family_group") == "fpg-claim-control", "source_gate_invalid", "owner_family_group mismatch")
    require(gate.get("required_log_fields") == string_list(cfg, "required_log_fields", "fpg_claim_control_contract"), "source_gate_invalid", "required_log_fields drifted")
    policy = gate.get("claim_policy", {})
    required_policy = cfg.get("required_claim_policy", {})
    if not isinstance(policy, dict) or not isinstance(required_policy, dict):
        add_error("source_gate_invalid", "claim_policy and required_claim_policy must be objects")
    else:
        for key in ("default_decision", "allow_status", "block_status_without_evidence", "block_replacement_levels_without_evidence"):
            require(policy.get(key) == required_policy.get(key), "source_gate_invalid", f"claim_policy.{key} drifted")
    freshness = gate.get("source_commit_freshness_policy", {})
    if isinstance(freshness, dict) and isinstance(required_policy, dict):
        for key in ("stale_result", "claim_control_evidence_allowed_when_stale", "rejected_evidence_kind"):
            require(freshness.get(key) == required_policy.get(key), "source_gate_invalid", f"source_commit_freshness_policy.{key} drifted")
    inputs = gate.get("inputs", {})
    if not isinstance(inputs, dict):
        add_error("source_gate_invalid", "gate.inputs must be an object")
    else:
        for key in string_list(cfg, "required_inputs", "fpg_claim_control_contract"):
            path_text = inputs.get(key)
            if not isinstance(path_text, str) or not resolve(path_text).exists():
                add_error("missing_source_artifact", f"gate input {key} missing at {path_text!r}")
    for row in rows:
        if not isinstance(row, dict):
            continue
        anchors = row.get("evidence_anchors")
        if not isinstance(anchors, list) or not anchors:
            add_error("source_gate_invalid", f"row {row.get('gap_id')}: evidence_anchors must be non-empty")
            continue
        for anchor in anchors:
            if not isinstance(anchor, dict):
                add_error("source_gate_invalid", f"row {row.get('gap_id')}: evidence anchor must be object")
                continue
            artifact = anchor.get("artifact")
            field = anchor.get("field")
            if not isinstance(artifact, str) or not isinstance(field, str):
                add_error("source_gate_invalid", f"row {row.get('gap_id')}: anchor artifact/field must be strings")
            elif not artifact.startswith("tests/conformance/feature_parity_gap_ledger") and not resolve(artifact).exists():
                add_error("missing_source_artifact", f"row {row.get('gap_id')}: anchor artifact missing {artifact}")
    owner_path = resolve("tests/conformance/feature_parity_gap_owner_family_groups.v1.md")
    owner_text = owner_path.read_text(encoding="utf-8")
    for term in string_list(cfg, "expected_owner_family_terms", "fpg_claim_control_contract"):
        require(term in owner_text, "source_gate_invalid", f"owner-family groups missing {term!r}")
    events.append(
        event("fpg_claim_control_gate_validated", "pass", "source-gate", sorted(expected_ids), sorted(actual_ids), [rel(resolve(str(cfg.get("gate_path", "")))), rel(owner_path)])
    )
    return sorted(actual_ids), gate


def replay_source_checker(contract: dict[str, Any]) -> dict[str, Any]:
    cfg = contract.get("fpg_claim_control_contract", {})
    checker = resolve(str(cfg.get("checker_path", "")))
    env = os.environ.copy()
    env.setdefault("TMPDIR", "/data/tmp" if Path("/data/tmp").is_dir() else str(root / "target"))
    completed = subprocess.run(
        ["bash", str(checker), "--validate-only"],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if completed.returncode != 0:
        add_error("source_checker_failed", f"source checker failed rc={completed.returncode}; stderr={completed.stderr[-1200:]}")
        return {}
    try:
        payload = json.loads(completed.stdout)
    except Exception as exc:
        add_error("source_checker_failed", f"source checker stdout was not JSON: {exc}")
        return {}
    expected_status = cfg.get("expected_validate_only_status", "pass")
    expected_rows = cfg.get("expected_validate_only_rows", 8)
    require(payload.get("status") == expected_status, "source_checker_failed", "source checker status mismatch")
    require(payload.get("rows") == expected_rows, "source_checker_failed", "source checker row count mismatch")
    events.append(
        event("source_checker_validate_only_replayed", "pass", "source-checker", {"status": expected_status, "rows": expected_rows}, payload, [rel(checker)])
    )
    return payload


def validate_output_contract(contract: dict[str, Any], report: dict[str, Any], log_rows: list[dict[str, Any]]) -> None:
    output = contract.get("completion_output_contract", {})
    if not isinstance(output, dict):
        add_error("malformed_contract", "completion_output_contract must be an object")
        return
    for field in string_list(output, "required_report_fields", "completion_output_contract"):
        if field not in report:
            add_error("completion_output_contract_failed", f"report missing {field}")
    for index, row in enumerate(log_rows):
        for field in string_list(output, "required_log_fields", "completion_output_contract"):
            if field not in row:
                add_error("completion_output_contract_failed", f"log row {index} missing {field}")
    present = {str(row.get("event", "")) for row in log_rows}
    for event_name in string_list(output, "required_events", "completion_output_contract"):
        if event_name not in present:
            add_error("completion_output_contract_failed", f"missing event {event_name}")


contract = load_json(contract_path, "completion contract")
if not isinstance(contract, dict):
    fail_report("load_contract")
require(contract.get("schema_version") == SCHEMA, "malformed_contract", "schema_version mismatch")
require(contract.get("bead") == BEAD_ID, "malformed_contract", "bead mismatch")
require(contract.get("original_bead") == ORIGINAL_BEAD, "malformed_contract", "original_bead mismatch")
require(contract.get("trace_id") == TRACE_ID, "malformed_contract", "trace_id mismatch")
source_refs = validate_source_artifacts(contract)
bindings = validate_binding(contract)
gap_ids, gate = validate_fpg_gate(contract)
checker_payload = replay_source_checker(contract)
if errors:
    fail_report("validation", source_refs)

events.append(
    event(
        "fpg_claim_control_completion_contract_pass",
        "pass",
        "completion-output",
        "all conformance checks pass",
        {"gap_count": len(gap_ids), "binding_count": len(bindings)},
        source_refs,
    )
)
report = {
    "schema_version": f"{SCHEMA}.report",
    "bead_id": BEAD_ID,
    "original_bead": ORIGINAL_BEAD,
    "trace_id": TRACE_ID,
    "source_commit": source_commit,
    "status": "pass",
    "summary": {
        "gap_count": len(gap_ids),
        "binding_count": len(bindings),
        "source_checker_status": checker_payload.get("status"),
        "log_row_count": len(events),
    },
    "source_artifacts": source_refs,
    "missing_item_bindings": [row["spec_item"] for row in bindings],
    "fpg_claim_control": {
        "gap_ids": gap_ids,
        "owner_family_group": gate.get("owner_family_group"),
        "required_log_fields": gate.get("required_log_fields"),
        "claim_policy": gate.get("claim_policy"),
        "source_checker": checker_payload,
    },
    "artifact_refs": sorted(set([rel(contract_path), rel(report_path), rel(log_path), *source_refs])),
    "errors": [],
}
validate_output_contract(contract, report, events)
if errors:
    fail_report("output_contract", source_refs)
write_json(report_path, report)
write_jsonl(log_path, events)
print(
    "PASS fpg_claim_control_completion_contract "
    f"gaps={len(gap_ids)} bindings={len(bindings)} events={len(events)} "
    f"report={rel(report_path)} log={rel(log_path)}"
)
PY
