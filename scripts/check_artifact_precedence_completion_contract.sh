#!/usr/bin/env bash
# Validate bd-bp8fl.7.7.1 artifact precedence completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_ARTIFACT_PRECEDENCE_COMPLETION_CONTRACT:-${1:-${ROOT}/tests/conformance/artifact_precedence_completion_contract.v1.json}}"
OUT_DIR="${FRANKENLIBC_ARTIFACT_PRECEDENCE_COMPLETION_OUT_DIR:-${2:-${ROOT}/target/conformance}}"
REPORT="${FRANKENLIBC_ARTIFACT_PRECEDENCE_COMPLETION_REPORT:-${OUT_DIR}/artifact_precedence_completion_contract.report.json}"
LOG="${FRANKENLIBC_ARTIFACT_PRECEDENCE_COMPLETION_LOG:-${OUT_DIR}/artifact_precedence_completion_contract.log.jsonl}"
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

SCHEMA = "artifact_precedence_completion_contract.v1"
BEAD_ID = "bd-bp8fl.7.7.1"
ORIGINAL_BEAD = "bd-bp8fl.7.7"
TRACE_ID = "bd-bp8fl.7.7.1::artifact-precedence::v1"
REQUIRED_SPEC_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_completion_binding",
    "source_manifest_drift",
    "ci_wiring_drift",
    "source_tests_drift",
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
    return "artifact_precedence_completion_contract_failed"


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


def event(
    name: str,
    status: str,
    scenario_id: str,
    expected: Any,
    actual: Any,
    refs: list[str],
    failure: str = "none",
) -> dict[str, Any]:
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
        event(
            stage + "_failed",
            "fail",
            stage,
            "completion contract passes",
            primary_signature(),
            refs,
            primary_signature(),
        )
    )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": source_commit,
        "status": "fail",
        "summary": {"artifact_count": 0, "claim_count": 0, "binding_count": 0, "log_row_count": len(events)},
        "source_artifacts": [],
        "missing_item_bindings": [],
        "artifact_precedence": {},
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


def validate_bindings(contract: dict[str, Any]) -> list[dict[str, Any]]:
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
    if seen != REQUIRED_SPEC_ITEMS:
        add_error("missing_completion_binding", f"expected {sorted(REQUIRED_SPEC_ITEMS)}, got {sorted(seen)}")
    else:
        events.append(
            event("missing_item_bindings_validated", "pass", "missing-item-bindings", sorted(REQUIRED_SPEC_ITEMS), sorted(seen), [rel(contract_path)])
        )
    return [row for row in bindings if isinstance(row, dict)]


def validate_source_manifest(contract: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    cfg = contract.get("artifact_precedence_contract", {})
    if not isinstance(cfg, dict):
        add_error("malformed_contract", "artifact_precedence_contract must be an object")
        return {}, {}
    manifest = load_json(resolve(str(cfg.get("manifest_path", ""))), "artifact precedence manifest")
    if not isinstance(manifest, dict):
        add_error("source_manifest_drift", "artifact precedence manifest must be an object")
        return cfg, {}
    require(manifest.get("schema_version") == "v1", "source_manifest_drift", "manifest schema_version drifted")
    require(manifest.get("bead") == ORIGINAL_BEAD, "source_manifest_drift", "manifest bead drifted")
    require(
        manifest.get("required_log_fields") == string_list(cfg, "required_log_fields", "artifact_precedence_contract"),
        "source_manifest_drift",
        "required_log_fields drifted",
    )
    artifacts = manifest.get("artifacts")
    claims = manifest.get("claims")
    if not isinstance(artifacts, list):
        add_error("source_manifest_drift", "manifest.artifacts must be an array")
        artifacts = []
    if not isinstance(claims, list):
        add_error("source_manifest_drift", "manifest.claims must be an array")
        claims = []
    expected_artifact_ids = set(string_list(cfg, "expected_artifact_ids", "artifact_precedence_contract"))
    actual_artifact_ids = {row.get("id") for row in artifacts if isinstance(row, dict)}
    if actual_artifact_ids != expected_artifact_ids:
        add_error("source_manifest_drift", f"artifact ids drifted: expected {sorted(expected_artifact_ids)}, got {sorted(actual_artifact_ids)}")
    expected_claim_ids = set(string_list(cfg, "expected_claim_ids", "artifact_precedence_contract"))
    actual_claim_ids = {row.get("id") for row in claims if isinstance(row, dict)}
    if actual_claim_ids != expected_claim_ids:
        add_error("source_manifest_drift", f"claim ids drifted: expected {sorted(expected_claim_ids)}, got {sorted(actual_claim_ids)}")
    summary = manifest.get("expected_current_summary", {})
    expected_summary = cfg.get("expected_summary", {})
    if not isinstance(summary, dict) or not isinstance(expected_summary, dict) or summary != expected_summary:
        add_error("source_manifest_drift", f"expected_current_summary drifted: expected {expected_summary}, got {summary}")
    for row in artifacts:
        if not isinstance(row, dict):
            add_error("source_manifest_drift", "artifact row must be an object")
            continue
        for field in ("id", "artifact_type", "path", "producer_bead", "consumer_surfaces", "authority_rank", "freshness_rule", "source_commit_required", "regeneration_command", "conflict_resolution"):
            if field not in row:
                add_error("source_manifest_drift", f"artifact {row.get('id')}: missing {field}")
        path_text = row.get("path")
        if not isinstance(path_text, str) or not resolve(path_text).exists():
            add_error("missing_source_artifact", f"artifact {row.get('id')}: missing path {path_text!r}")
    for row in claims:
        if not isinstance(row, dict):
            add_error("source_manifest_drift", "claim row must be an object")
            continue
        if row.get("prose_only_forbidden") is not True or row.get("blocked_if_missing") is not True:
            add_error("source_manifest_drift", f"claim {row.get('id')}: claim policy must fail closed")
        auth_ids = row.get("authoritative_artifact_ids")
        if not isinstance(auth_ids, list) or not auth_ids:
            add_error("source_manifest_drift", f"claim {row.get('id')}: authoritative_artifact_ids must be non-empty")
    events.append(
        event(
            "source_manifest_validated",
            "pass",
            "source-manifest",
            {"artifacts": sorted(expected_artifact_ids), "claims": sorted(expected_claim_ids)},
            {"artifacts": sorted(actual_artifact_ids), "claims": sorted(actual_claim_ids)},
            [rel(resolve(str(cfg.get("manifest_path", ""))))],
        )
    )
    return cfg, manifest


def validate_ci_wiring(cfg: dict[str, Any]) -> None:
    ci_path = resolve(str(cfg.get("ci_path", "")))
    try:
        ci_text = ci_path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_source_artifact", f"cannot read CI file {rel(ci_path)}: {exc}")
        return
    missing = [term for term in string_list(cfg, "required_ci_terms", "artifact_precedence_contract") if term not in ci_text]
    if missing:
        add_error("ci_wiring_drift", f"missing CI terms {missing}")
    events.append(
        event("ci_wiring_validated", "pass", "ci-wiring", "artifact precedence gate wired", "present", [rel(ci_path)])
    )


def validate_source_tests(cfg: dict[str, Any]) -> None:
    test_path = resolve(str(cfg.get("source_test_path", "")))
    try:
        test_text = test_path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_source_artifact", f"cannot read source test {rel(test_path)}: {exc}")
        return
    missing = []
    for test_name in string_list(cfg, "required_source_tests", "artifact_precedence_contract"):
        if f"fn {test_name}" not in test_text:
            missing.append(test_name)
    if missing:
        add_error("source_tests_drift", f"missing source tests {missing}")
    events.append(
        event("source_tests_validated", "pass", "source-tests", "all required source tests present", string_list(cfg, "required_source_tests", "artifact_precedence_contract"), [rel(test_path)])
    )


def parse_log_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                if isinstance(row, dict):
                    rows.append(row)
    except Exception as exc:
        add_error("source_checker_failed", f"cannot parse source checker log {rel(path)}: {exc}")
    return rows


def replay_source_checker(cfg: dict[str, Any]) -> dict[str, Any]:
    checker = resolve(str(cfg.get("checker_path", "")))
    source_out_dir = report_path.parent / "artifact_precedence_source_gate"
    env = os.environ.copy()
    env.setdefault("TMPDIR", "/data/tmp" if Path("/data/tmp").is_dir() else str(root / "target"))
    env["FLC_ARTIFACT_PRECEDENCE_OUT_DIR"] = str(source_out_dir)
    completed = subprocess.run(
        ["bash", str(checker)],
        cwd=root,
        env=env,
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )
    expected_status = cfg.get("expected_status", "pass")
    if completed.returncode != 0 and expected_status == "pass":
        add_error("source_checker_failed", f"source checker failed rc={completed.returncode}; stderr={completed.stderr[-1200:]}")
        return {}
    try:
        payload = json.loads(completed.stdout)
    except Exception as exc:
        add_error("source_checker_failed", f"source checker stdout was not JSON: {exc}")
        return {}
    if completed.returncode == 0 and expected_status != "pass":
        add_error("source_checker_failed", f"source checker unexpectedly exited 0 while expected_status={expected_status}")
    require(payload.get("status") == expected_status, "source_checker_failed", "source checker status mismatch")
    expected_summary = cfg.get("expected_summary", {})
    summary = payload.get("summary", {})
    if not isinstance(summary, dict) or not isinstance(expected_summary, dict):
        add_error("source_checker_failed", "source checker summary missing")
    else:
        for key, expected_value in expected_summary.items():
            if summary.get(key) != expected_value:
                add_error("source_checker_failed", f"source checker summary.{key} expected {expected_value}, got {summary.get(key)}")
    checks = payload.get("checks", {})
    if not isinstance(checks, dict):
        add_error("source_checker_failed", "source checker checks missing")
    else:
        expected_check_statuses = cfg.get("expected_check_statuses")
        if isinstance(expected_check_statuses, dict):
            for key, expected_check_status in expected_check_statuses.items():
                if checks.get(key) != expected_check_status:
                    add_error("source_checker_failed", f"source checker check {key} expected {expected_check_status}, got {checks.get(key)}")
        else:
            for key in string_list(cfg, "expected_checks", "artifact_precedence_contract"):
                if checks.get(key) != "pass":
                    add_error("source_checker_failed", f"source checker check {key} expected pass, got {checks.get(key)}")
    log_path_value = payload.get("log_path")
    if isinstance(log_path_value, str):
        source_log = resolve(log_path_value)
        rows = parse_log_rows(source_log)
        required_fields = string_list(cfg, "required_log_fields", "artifact_precedence_contract")
        for index, row in enumerate(rows):
            for field in required_fields:
                if field not in row:
                    add_error("source_checker_failed", f"source checker log row {index} missing {field}")
    else:
        add_error("source_checker_failed", "source checker report missing log_path")
    events.append(
        event(
            "source_checker_replayed",
            "pass",
            "source-checker",
            {"status": expected_status, "summary": expected_summary},
            {"status": payload.get("status"), "summary": summary},
            [rel(checker), rel(source_out_dir)],
        )
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
bindings = validate_bindings(contract)
cfg, manifest = validate_source_manifest(contract)
validate_ci_wiring(cfg)
validate_source_tests(cfg)
checker_payload = replay_source_checker(cfg)
if errors:
    fail_report("validation", source_refs)

events.append(
    event(
        "artifact_precedence_completion_contract_pass",
        "pass",
        "completion-output",
        "all artifact precedence completion checks pass",
        {"artifact_count": len(manifest.get("artifacts", [])), "claim_count": len(manifest.get("claims", [])), "binding_count": len(bindings)},
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
        "artifact_count": len(manifest.get("artifacts", [])),
        "claim_count": len(manifest.get("claims", [])),
        "binding_count": len(bindings),
        "source_checker_status": checker_payload.get("status"),
        "log_row_count": len(events),
    },
    "source_artifacts": source_refs,
    "missing_item_bindings": [row["spec_item"] for row in bindings],
    "artifact_precedence": {
        "artifact_ids": [row.get("id") for row in manifest.get("artifacts", [])],
        "claim_ids": [row.get("id") for row in manifest.get("claims", [])],
        "expected_summary": manifest.get("expected_current_summary"),
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
    "PASS artifact_precedence_completion_contract "
    f"artifacts={len(manifest.get('artifacts', []))} claims={len(manifest.get('claims', []))} "
    f"bindings={len(bindings)} events={len(events)} report={rel(report_path)} log={rel(log_path)}"
)
PY
