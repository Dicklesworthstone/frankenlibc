#!/usr/bin/env bash
# check_runtime_evidence_replay_gate_dashboard_completion_contract.sh - bd-zyck1.111.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_CONTRACT:-$ROOT/tests/conformance/runtime_evidence_replay_gate_dashboard_completion_contract.v1.json}"
DASHBOARD="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_DASHBOARD:-$ROOT/tests/conformance/l1_dry_run_readiness_dashboard.v1.json}"
OUT_DIR="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_OUT_DIR:-$ROOT/target/conformance/runtime_evidence_replay_gate_dashboard_completion_contract}"
REPORT="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"
GATE_DIR="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_GATE_DIR:-$OUT_DIR/source_gates}"
RUNTIME_REPLAY_REPORT="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_SOURCE_REPORT:-$GATE_DIR/runtime_evidence_replay_gate.report.json}"
RUNTIME_REPLAY_LOG="${FRANKENLIBC_RUNTIME_REPLAY_DASHBOARD_COMPLETION_SOURCE_LOG:-$GATE_DIR/runtime_evidence_replay_gate.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$GATE_DIR"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
DASHBOARD="$DASHBOARD" \
REPORT="$REPORT" \
LOG="$LOG" \
GATE_DIR="$GATE_DIR" \
RUNTIME_REPLAY_REPORT="$RUNTIME_REPLAY_REPORT" \
RUNTIME_REPLAY_LOG="$RUNTIME_REPLAY_LOG" \
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
RUNTIME_REPLAY_REPORT = pathlib.Path(os.environ["RUNTIME_REPLAY_REPORT"])
RUNTIME_REPLAY_LOG = pathlib.Path(os.environ["RUNTIME_REPLAY_LOG"])

EXPECTED_SCHEMA = "runtime_evidence_replay_gate_dashboard_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_evidence_replay_gate_dashboard_completion_contract.report.v1"
EXPECTED_BEAD = "bd-zyck1.111.1"
EXPECTED_ORIGINAL_BEAD = "bd-zyck1.111"
EXPECTED_TRACE_ID = "bd-zyck1.111.1::runtime-evidence-replay-gate-dashboard::completion::v1"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary", "telemetry.primary"}
REQUIRED_SOURCE_ARTIFACTS = {
    "l1_dashboard",
    "l1_dashboard_harness",
    "runtime_replay_manifest",
    "runtime_replay_gate",
    "runtime_replay_harness",
    "completion_checker",
    "completion_harness",
}
PASS_EVENTS = [
    "runtime_replay_dashboard.sources_validated",
    "runtime_replay_dashboard.rows_validated",
    "runtime_replay_dashboard.bindings_validated",
    "runtime_replay_dashboard.source_gates_replayed",
    "runtime_replay_dashboard.completion_contract_pass",
]
FAIL_EVENT = "runtime_replay_dashboard.completion_contract_fail"
REQUIRED_POSITIVE_TESTS = {
    "contract_binds_dashboard_conformance_and_telemetry",
    "checker_accepts_dashboard_completion_contract",
    "checker_replays_runtime_replay_source_gate",
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
            "gate": "runtime_evidence_replay_gate_dashboard_completion_contract",
            "scenario_id": event,
            "mode": "strict",
            "api_family": "runtime",
            "symbol": "runtime_evidence_replay_gate",
            "oracle_kind": "l1_dashboard_completion",
            "expected": "pass",
            "actual": outcome,
            "decision_path": "dashboard->runtime_replay_gate->telemetry",
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


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}" in text or f"def {name}" in text


def run_command(command: list[str], *, marker: str, label: str, env: dict[str, str]) -> None:
    run_env = os.environ.copy()
    run_env.update(env)
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False, env=run_env)
    output_path = GATE_DIR / f"{label}.out"
    output_path.write_text(result.stdout + result.stderr, encoding="utf-8")
    source_gate_results[label] = {
        "command": " ".join(command),
        "exit_code": result.returncode,
        "marker": marker,
        "output": rel(output_path),
    }
    if result.returncode != 0:
        err(f"source_gate_failed: {label} exit={result.returncode}: {(result.stdout + result.stderr)[-2000:]}")
    if marker not in (result.stdout + result.stderr):
        err(f"source_gate_marker_missing: {label} marker={marker!r}")


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
    emit("runtime_replay_dashboard.sources_validated", source_artifact_count=len(keys))

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing_items = {item for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids") if isinstance(item, str)}
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"completion_contract.missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    required_functions = as_object(manifest.get("required_test_functions"), "required_test_functions")
    positive = {item for item in as_list(required_functions.get("positive"), "required_test_functions.positive") if isinstance(item, str)}
    negative = {item for item in as_list(required_functions.get("negative"), "required_test_functions.negative") if isinstance(item, str)}
    if positive != REQUIRED_POSITIVE_TESTS:
        err(f"required_test_functions.positive mismatch: expected={sorted(REQUIRED_POSITIVE_TESTS)} got={sorted(positive)}")
    if negative != REQUIRED_NEGATIVE_TESTS:
        err(f"required_test_functions.negative mismatch: expected={sorted(REQUIRED_NEGATIVE_TESTS)} got={sorted(negative)}")
    return contract


def validate_dashboard(dashboard: dict[str, Any], required: dict[str, Any]) -> dict[str, Any]:
    if dashboard.get("schema_version") != required.get("schema_version"):
        err("dashboard_drift: schema_version mismatch")
    rows = as_list(dashboard.get("rows"), "dashboard.rows")
    total_rows_min = int(required.get("total_rows_min", 0))
    if len(rows) < total_rows_min:
        err(f"dashboard_drift: total rows expected >= {total_rows_min}, got {len(rows)}")

    prefix = str(required.get("runtime_replay_row_prefix", ""))
    replay_rows = [row for row in rows if isinstance(row, dict) and str(row.get("row_id", "")).startswith(prefix)]
    required_count = int(required.get("runtime_replay_row_count", 0))
    if len(replay_rows) != required_count:
        err(f"dashboard_row_count_drift: expected {required_count} runtime replay rows, got {len(replay_rows)}")

    required_kind = required.get("required_row_kind")
    required_artifact = required.get("required_evidence_artifact")
    row_by_id = {row.get("row_id"): row for row in replay_rows if isinstance(row.get("row_id"), str)}
    required_ids = {item for item in as_list(required.get("required_row_ids"), "required_dashboard.required_row_ids") if isinstance(item, str)}
    if set(row_by_id) != required_ids:
        missing = sorted(required_ids - set(row_by_id))
        extra = sorted(set(row_by_id) - required_ids)
        if missing:
            err(f"missing_dashboard_row: {missing[0]}")
        err(f"dashboard_drift: row id mismatch missing={missing} extra={extra}")
    for row_id, row in row_by_id.items():
        if row.get("row_kind") != required_kind:
            err(f"dashboard_drift: {row_id}.row_kind expected {required_kind!r}, got {row.get('row_kind')!r}")
        if row.get("evidence_artifact") != required_artifact:
            err(f"dashboard_drift: {row_id}.evidence_artifact expected {required_artifact!r}, got {row.get('evidence_artifact')!r}")

    expectations = as_object(required.get("required_expectations"), "required_dashboard.required_expectations")
    for row_id, expectation in expectations.items():
        row = row_by_id.get(row_id)
        if row is None:
            err(f"missing_dashboard_row: {row_id}")
            continue
        expectation_obj = as_object(expectation, f"required_expectations.{row_id}")
        if row.get("field") != expectation_obj.get("field"):
            err(f"dashboard_drift: {row_id}.field expected {expectation_obj.get('field')!r}, got {row.get('field')!r}")
        if row.get("expected_value") != expectation_obj.get("expected_value"):
            err(f"dashboard_drift: {row_id}.expected_value expected {expectation_obj.get('expected_value')!r}, got {row.get('expected_value')!r}")

    summary = {"dashboard_rows": len(rows), "runtime_replay_rows": len(replay_rows)}
    emit("runtime_replay_dashboard.rows_validated", **summary)
    return summary


def validate_bindings(manifest: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids: set[str] = set()
    for index, binding in enumerate(bindings):
        binding_obj = as_object(binding, f"missing_item_bindings[{index}]")
        binding_id = binding_obj.get("id")
        if isinstance(binding_id, str):
            ids.add(binding_id)
        else:
            err(f"missing_item_bindings[{index}].id must be a string")
            continue
        for field in ("implementation_refs", "test_refs", "runtime_validation"):
            values = as_list(binding_obj.get(field), f"missing_item_bindings.{binding_id}.{field}")
            if not values:
                err(f"missing_item_bindings.{binding_id}.{field} must be non-empty")
            for value in values:
                if isinstance(value, str) and field in {"implementation_refs", "test_refs"} and "::" not in value:
                    repo_path(value, f"missing_item_bindings.{binding_id}.{field}")
    if ids != EXPECTED_MISSING_ITEMS:
        if "telemetry.primary" not in ids:
            err("missing_telemetry_binding: telemetry.primary")
        if "tests.conformance.primary" not in ids:
            err("missing_conformance_binding: tests.conformance.primary")
        err(f"missing_item_bindings ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")

    test_surfaces = {
        "crates/frankenlibc-harness/tests/l1_dry_run_readiness_dashboard_test.rs": {"runtime_replay_gate_rows_are_explicit"},
        "crates/frankenlibc-harness/tests/runtime_evidence_replay_gate_test.rs": {"gate_artifact_covers_runtime_evidence_replay_contract"},
        "crates/frankenlibc-harness/tests/runtime_evidence_replay_gate_dashboard_completion_contract_test.rs": REQUIRED_POSITIVE_TESTS | REQUIRED_NEGATIVE_TESTS,
    }
    for path_text, names in test_surfaces.items():
        text = source_text(path_text, f"test_surface.{path_text}")
        for name in names:
            if not function_exists(text, name):
                err(f"test_surface_drift: {path_text} missing {name}")
    emit("runtime_replay_dashboard.bindings_validated", binding_count=len(ids))
    return len(ids)


def replay_source_gates(required: dict[str, Any]) -> None:
    markers = as_object(required.get("required_source_gate_markers"), "completion_contract.required_source_gate_markers")
    run_command(
        ["bash", "scripts/check_runtime_evidence_replay_gate.sh"],
        marker=str(markers.get("runtime_replay_gate", "")),
        label="runtime_replay_gate",
        env={
            "FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_REPORT": str(RUNTIME_REPLAY_REPORT),
            "FRANKENLIBC_RUNTIME_EVIDENCE_REPLAY_LOG": str(RUNTIME_REPLAY_LOG),
        },
    )
    emit("runtime_replay_dashboard.source_gates_replayed", gate_count=1)


def write_outputs(status: str, summary: dict[str, Any]) -> None:
    final = FAIL_EVENT if status != "pass" else "runtime_replay_dashboard.completion_contract_pass"
    emit(final, status if status in {"pass", "fail", "error", "skip", "timeout"} else "error", summary=summary)
    event_names = [row["event"] for row in events]
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "status": status,
        "generated_at": now(),
        "source_commit": SOURCE_COMMIT,
        "completion_debt_bead": EXPECTED_BEAD,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "summary": summary,
        "source_gate_results": source_gate_results,
        "events": event_names,
        "errors": errors,
    }
    write_json(REPORT, report)
    write_jsonl(LOG, events)


def main() -> int:
    manifest = load_json(CONTRACT, "completion contract")
    contract = validate_manifest(manifest)
    required_dashboard = as_object(contract.get("required_dashboard"), "completion_contract.required_dashboard")
    dashboard_summary = validate_dashboard(load_json(DASHBOARD, "l1 dashboard"), required_dashboard)
    binding_count = validate_bindings(manifest)
    if not errors:
        replay_source_gates(contract)
    summary = {**dashboard_summary, "binding_count": binding_count}
    if errors:
        write_outputs("fail", summary)
        for message in errors:
            print(message, file=sys.stderr)
        return 1
    write_outputs("pass", summary)
    print(
        "PASS: runtime evidence replay gate dashboard completion contract "
        f"dashboard_rows={summary['dashboard_rows']} "
        f"runtime_replay_rows={summary['runtime_replay_rows']} "
        f"bindings={summary['binding_count']}"
    )
    return 0


raise SystemExit(main())
PY
