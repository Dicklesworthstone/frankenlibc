#!/usr/bin/env bash
# check_crt_tls_atexit_direct_link_proof_dashboard_completion_contract.sh - bd-zyck1.114.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_CONTRACT:-$ROOT/tests/conformance/crt_tls_atexit_direct_link_proof_dashboard_completion_contract.v1.json}"
DASHBOARD="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_DASHBOARD:-$ROOT/tests/conformance/l1_dry_run_readiness_dashboard.v1.json}"
OUT_DIR="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_OUT_DIR:-$ROOT/target/conformance/crt_tls_atexit_direct_link_proof_dashboard_completion_contract}"
REPORT="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"
GATE_DIR="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_GATE_DIR:-$OUT_DIR/source_gates}"
CRT_TLS_SOURCE_REPORT="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_SOURCE_REPORT:-$GATE_DIR/crt_tls_atexit_direct_link_run_proof_fixtures.report.json}"
CRT_TLS_SOURCE_LOG="${FRANKENLIBC_CRT_TLS_DASHBOARD_COMPLETION_SOURCE_LOG:-$GATE_DIR/crt_tls_atexit_direct_link_run_proof_fixtures.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$GATE_DIR"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
DASHBOARD="$DASHBOARD" \
REPORT="$REPORT" \
LOG="$LOG" \
GATE_DIR="$GATE_DIR" \
CRT_TLS_SOURCE_REPORT="$CRT_TLS_SOURCE_REPORT" \
CRT_TLS_SOURCE_LOG="$CRT_TLS_SOURCE_LOG" \
python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
DASHBOARD = pathlib.Path(os.environ["DASHBOARD"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GATE_DIR = pathlib.Path(os.environ["GATE_DIR"])
CRT_TLS_SOURCE_REPORT = pathlib.Path(os.environ["CRT_TLS_SOURCE_REPORT"])
CRT_TLS_SOURCE_LOG = pathlib.Path(os.environ["CRT_TLS_SOURCE_LOG"])

EXPECTED_SCHEMA = "crt_tls_atexit_direct_link_proof_dashboard_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "crt_tls_atexit_direct_link_proof_dashboard_completion_contract.report.v1"
EXPECTED_BEAD = "bd-zyck1.114.1"
EXPECTED_ORIGINAL_BEAD = "bd-zyck1.114"
EXPECTED_TRACE_ID = "bd-zyck1.114.1::crt-tls-atexit-direct-link-proof-dashboard::completion::v1"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary", "telemetry.primary"}
REQUIRED_SOURCE_ARTIFACTS = {
    "l1_dashboard",
    "l1_dashboard_harness",
    "crt_tls_manifest",
    "crt_tls_gate",
    "crt_tls_harness",
    "completion_checker",
    "completion_harness",
}
PASS_EVENTS = [
    "crt_tls_dashboard.sources_validated",
    "crt_tls_dashboard.rows_validated",
    "crt_tls_dashboard.bindings_validated",
    "crt_tls_dashboard.source_gates_replayed",
    "crt_tls_dashboard.completion_contract_pass",
]
FAIL_EVENT = "crt_tls_dashboard.completion_contract_fail"
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_dashboard_conformance_and_telemetry",
    "checker_accepts_dashboard_completion_contract",
    "checker_replays_crt_tls_source_gate",
}
REQUIRED_NEGATIVE_TESTS = {
    "checker_rejects_missing_dashboard_row",
    "checker_rejects_missing_telemetry_binding",
    "checker_rejects_dashboard_row_count_drift",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_gate_results: dict[str, dict[str, Any]] = {}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


SOURCE_COMMIT = git_head()


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def emit(event: str, outcome: str = "pass", **details: Any) -> None:
    timestamp = now()
    events.append(
        {
            "timestamp": timestamp,
            "ts": timestamp,
            "trace_id": EXPECTED_TRACE_ID,
            "level": "info" if outcome == "pass" else "error",
            "event": event,
            "bead_id": EXPECTED_BEAD,
            "stream": "conformance",
            "gate": "crt_tls_atexit_direct_link_proof_dashboard_completion_contract",
            "scenario_id": event,
            "mode": "strict",
            "api_family": "startup",
            "symbol": "crt_tls_atexit_direct_link_proof",
            "oracle_kind": "l1_dashboard_completion",
            "expected": "pass",
            "actual": outcome,
            "decision_path": "dashboard->crt_tls_direct_link_proof_gate->telemetry",
            "outcome": outcome,
            "errno": 0,
            "latency_ns": 0,
            "source_commit": SOURCE_COMMIT,
            "failure_signature": "" if outcome == "pass" else "; ".join(errors[:3]),
            "artifact_refs": [rel(CONTRACT), rel(DASHBOARD)],
            "details": details,
        }
    )


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def as_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        err(f"{label} must be an object")
        return {}
    return value


def as_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        err(f"{label} must be an array")
        return []
    return value


def repo_path(path_text: Any, label: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{label} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{label} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{label} references missing path: {path_text}")
        return None
    return full


def source_text(path_text: str, label: str) -> str:
    path = repo_path(path_text, label)
    if path is None or not path.is_file():
        err(f"{label} must reference a file: {path_text}")
        return ""
    return path.read_text(encoding="utf-8")


def value_at_path(value: Any, dotted_path: str) -> Any:
    current = value
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return None
    return current


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}" in text or f"def {name}" in text


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        err("contract_identity: schema_version mismatch")
    if manifest.get("bead_id") != EXPECTED_BEAD:
        err("contract_identity: bead_id mismatch")
    if manifest.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
        err("contract_identity: original_bead mismatch")
    if manifest.get("trace_id") != EXPECTED_TRACE_ID:
        err("contract_identity: trace_id mismatch")

    artifacts = as_object(manifest.get("source_artifacts"), "source_artifacts")
    keys = set(artifacts)
    if keys != REQUIRED_SOURCE_ARTIFACTS:
        err(f"source_artifacts mismatch: expected={sorted(REQUIRED_SOURCE_ARTIFACTS)} got={sorted(keys)}")
    for key, path_text in artifacts.items():
        repo_path(path_text, f"source_artifacts.{key}")
    emit("crt_tls_dashboard.sources_validated", source_artifact_count=len(keys))

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing_items = {
        item for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids")
        if isinstance(item, str)
    }
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    required_tests = as_object(manifest.get("required_test_functions"), "required_test_functions")
    positives = {
        item for item in as_list(required_tests.get("positive"), "required_test_functions.positive")
        if isinstance(item, str)
    }
    negatives = {
        item for item in as_list(required_tests.get("negative"), "required_test_functions.negative")
        if isinstance(item, str)
    }
    if positives != REQUIRED_POSITIVE_TESTS:
        err(f"positive test functions mismatch: expected={sorted(REQUIRED_POSITIVE_TESTS)} got={sorted(positives)}")
    if negatives != REQUIRED_NEGATIVE_TESTS:
        err(f"negative test functions mismatch: expected={sorted(REQUIRED_NEGATIVE_TESTS)} got={sorted(negatives)}")

    return artifacts


def validate_dashboard(manifest: dict[str, Any], dashboard: dict[str, Any]) -> tuple[int, int]:
    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    required = as_object(contract.get("required_dashboard"), "completion_contract.required_dashboard")
    rows = as_list(dashboard.get("rows"), "dashboard.rows")
    total_min = required.get("total_rows_min")
    if not isinstance(total_min, int) or len(rows) < total_min:
        err(f"dashboard total row count drifted: expected at least {total_min}, got {len(rows)}")

    prefix = required.get("crt_tls_row_prefix")
    if not isinstance(prefix, str) or not prefix:
        err("required_dashboard.crt_tls_row_prefix must be a string")
        prefix = "crt-tls-atexit-direct-link-proof-"
    expected_count = required.get("crt_tls_row_count")
    if not isinstance(expected_count, int):
        err("required_dashboard.crt_tls_row_count must be an integer")
        expected_count = -1
    expected_kind = required.get("required_row_kind")
    expected_artifact = required.get("required_evidence_artifact")
    expected_ids = [
        item for item in as_list(required.get("required_row_ids"), "required_dashboard.required_row_ids")
        if isinstance(item, str)
    ]
    expectations = as_object(required.get("required_expectations"), "required_dashboard.required_expectations")
    if set(expected_ids) != set(expectations):
        err("required_dashboard row ids and required_expectations keys must match exactly")

    crt_rows = [
        row for row in rows
        if isinstance(row, dict) and isinstance(row.get("row_id"), str) and row["row_id"].startswith(prefix)
    ]
    if len(crt_rows) != expected_count:
        err(f"CRT/TLS/atexit dashboard row count mismatch: expected {expected_count}, got {len(crt_rows)}")

    rows_by_id = {
        row["row_id"]: row for row in crt_rows
        if isinstance(row, dict) and isinstance(row.get("row_id"), str)
    }
    if set(rows_by_id) != set(expected_ids):
        err(f"CRT/TLS/atexit dashboard row id set mismatch: missing={sorted(set(expected_ids) - set(rows_by_id))} extra={sorted(set(rows_by_id) - set(expected_ids))}")

    source_manifest_path = manifest.get("source_artifacts", {}).get("crt_tls_manifest")
    source_manifest = load_json(ROOT / source_manifest_path, "crt_tls_manifest") if isinstance(source_manifest_path, str) else {}
    for row_id in expected_ids:
        row = rows_by_id.get(row_id)
        expectation = as_object(expectations.get(row_id), f"required_expectations.{row_id}")
        if row is None:
            continue
        if row.get("row_kind") != expected_kind:
            err(f"{row_id}: row_kind mismatch: expected {expected_kind!r}, got {row.get('row_kind')!r}")
        if row.get("evidence_artifact") != expected_artifact:
            err(f"{row_id}: evidence_artifact mismatch: expected {expected_artifact!r}, got {row.get('evidence_artifact')!r}")
        if row.get("field") != expectation.get("field"):
            err(f"{row_id}: field mismatch: expected {expectation.get('field')!r}, got {row.get('field')!r}")
        if row.get("expected_value") != expectation.get("expected_value"):
            err(f"{row_id}: expected_value mismatch: expected {expectation.get('expected_value')!r}, got {row.get('expected_value')!r}")
        field = expectation.get("field")
        if isinstance(field, str) and value_at_path(source_manifest, field) != expectation.get("expected_value"):
            err(f"{row_id}: source manifest field {field} does not match required expected_value")

    emit("crt_tls_dashboard.rows_validated", dashboard_rows=len(rows), crt_tls_rows=len(crt_rows))
    return len(rows), len(crt_rows)


def validate_bindings(manifest: dict[str, Any], artifacts: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids = {
        binding.get("id") for binding in bindings
        if isinstance(binding, dict) and isinstance(binding.get("id"), str)
    }
    if ids != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_bindings mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")

    test_texts: dict[str, str] = {}
    for key in ["l1_dashboard_harness", "crt_tls_harness", "completion_harness"]:
        path_text = artifacts.get(key)
        if isinstance(path_text, str):
            test_texts[path_text] = source_text(path_text, f"source_artifacts.{key}")

    for binding in bindings:
        binding = as_object(binding, "missing_item_bindings.item")
        binding_id = binding.get("id", "<unknown>")
        for key in ["implementation_refs", "test_refs"]:
            for path_text in as_list(binding.get(key), f"{binding_id}.{key}"):
                if isinstance(path_text, str):
                    repo_path(path_text, f"{binding_id}.{key}")
        for validation in as_list(binding.get("runtime_validation"), f"{binding_id}.runtime_validation"):
            if not isinstance(validation, str) or "::" not in validation:
                err(f"{binding_id}.runtime_validation must use test_file::function format")
                continue
            function_name = validation.rsplit("::", 1)[1]
            if not any(function_exists(text, function_name) for text in test_texts.values()):
                err(f"{binding_id}.runtime_validation references missing function: {function_name}")

    telemetry = as_object(manifest.get("telemetry_contract"), "telemetry_contract")
    if telemetry.get("report_schema_version") != EXPECTED_REPORT_SCHEMA:
        err("telemetry_contract.report_schema_version mismatch")
    required_events = [
        event for event in as_list(telemetry.get("required_events"), "telemetry_contract.required_events")
        if isinstance(event, str)
    ]
    if required_events != PASS_EVENTS:
        err(f"telemetry required_events mismatch: expected={PASS_EVENTS} got={required_events}")

    emit("crt_tls_dashboard.bindings_validated", binding_count=len(bindings))
    return len(bindings)


def run_source_gate(artifacts: dict[str, Any]) -> dict[str, Any]:
    gate_path_text = artifacts.get("crt_tls_gate")
    if not isinstance(gate_path_text, str):
        err("source_artifacts.crt_tls_gate missing")
        return {}
    gate_path = repo_path(gate_path_text, "source_artifacts.crt_tls_gate")
    if gate_path is None:
        return {}

    source_out_dir = GATE_DIR / "crt_tls_atexit_direct_link_run_proof_fixtures"
    source_out_dir.mkdir(parents=True, exist_ok=True)
    output_path = source_out_dir / "stdout_stderr.txt"
    env = os.environ.copy()
    env.update(
        {
            "FLC_CRT_TLS_PROOF_OUT_DIR": str(source_out_dir),
            "FLC_CRT_TLS_PROOF_REPORT": str(CRT_TLS_SOURCE_REPORT),
            "FLC_CRT_TLS_PROOF_LOG": str(CRT_TLS_SOURCE_LOG),
        }
    )
    result = subprocess.run(["bash", str(gate_path)], cwd=ROOT, text=True, capture_output=True, check=False, env=env)
    output_path.write_text(result.stdout + result.stderr, encoding="utf-8")
    gate_report = load_json(CRT_TLS_SOURCE_REPORT, "crt_tls_source_report")
    source_gate_results["crt_tls_gate"] = {
        "command": f"bash {rel(gate_path)}",
        "exit_code": result.returncode,
        "output": rel(output_path),
        "report": rel(CRT_TLS_SOURCE_REPORT),
        "log": rel(CRT_TLS_SOURCE_LOG),
        "status": gate_report.get("status"),
    }
    if result.returncode != 0:
        err(f"source_gate_failed: crt_tls_gate exit={result.returncode}: {(result.stdout + result.stderr)[-2000:]}")
    if gate_report.get("status") != "pass":
        err(f"source_gate_report_status mismatch: expected 'pass', got {gate_report.get('status')!r}")
    summary = as_object(gate_report.get("summary"), "crt_tls_source_report.summary")
    for key, expected in {
        "fixture_count": 8,
        "claim_blocked_count": 8,
        "required_scenario_count": 8,
        "strict_hardened_mode_count": 2,
        "direct_link_execution_rows": 10,
    }.items():
        if summary.get(key) != expected:
            err(f"crt_tls_source_report.summary.{key} mismatch: expected {expected}, got {summary.get(key)!r}")
    emit("crt_tls_dashboard.source_gates_replayed", source_gate_count=1, crt_tls_gate_status=gate_report.get("status"))
    return gate_report


manifest = load_json(CONTRACT, "completion_contract")
dashboard = load_json(DASHBOARD, "l1_dashboard")
artifacts = validate_manifest(manifest)
dashboard_rows, crt_tls_rows = validate_dashboard(manifest, dashboard)
binding_count = validate_bindings(manifest, artifacts)
source_report = run_source_gate(artifacts)

if errors:
    emit(FAIL_EVENT, "fail", error_count=len(errors))
else:
    emit("crt_tls_dashboard.completion_contract_pass", dashboard_rows=dashboard_rows, crt_tls_rows=crt_tls_rows)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": "fail" if errors else "pass",
    "bead_id": EXPECTED_BEAD,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "trace_id": EXPECTED_TRACE_ID,
    "source_commit": SOURCE_COMMIT,
    "contract": rel(CONTRACT),
    "dashboard": rel(DASHBOARD),
    "report": rel(REPORT),
    "log": rel(LOG),
    "errors": errors,
    "events": [event["event"] for event in events],
    "summary": {
        "dashboard_rows": dashboard_rows,
        "crt_tls_rows": crt_tls_rows,
        "binding_count": binding_count,
        "source_gate_status": source_report.get("status"),
        "source_gate_fixture_count": value_at_path(source_report, "summary.fixture_count"),
        "source_gate_direct_link_execution_rows": value_at_path(source_report, "summary.direct_link_execution_rows"),
    },
    "source_gate_results": source_gate_results,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL: crt tls atexit direct-link proof dashboard completion contract", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: crt tls atexit direct-link proof dashboard completion contract "
    f"dashboard_rows={dashboard_rows} crt_tls_rows={crt_tls_rows} bindings={binding_count}"
)
PY
