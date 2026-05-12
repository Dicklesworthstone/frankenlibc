#!/usr/bin/env bash
# check_tracker_recovery_feature_parity_backlog_completion_contract.sh - bd-bp8fl.2.10 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_CONTRACT:-$ROOT/tests/conformance/tracker_recovery_feature_parity_backlog_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_OUT_DIR:-$ROOT/target/conformance/tracker_recovery_feature_parity_backlog_completion_contract}"
REPORT="${FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"
SOURCE_GATE_DIR="${FRANKENLIBC_TRACKER_RECOVERY_BACKLOG_COMPLETION_SOURCE_GATE_DIR:-$OUT_DIR/source_gates}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$SOURCE_GATE_DIR"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
SOURCE_GATE_DIR="$SOURCE_GATE_DIR" \
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
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_GATE_DIR = pathlib.Path(os.environ["SOURCE_GATE_DIR"])

EXPECTED_SCHEMA = "tracker_recovery_feature_parity_backlog_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "tracker_recovery_feature_parity_backlog_completion_contract.report.v1"
EXPECTED_BEAD = "bd-bp8fl.2.10"
EXPECTED_ORIGINAL_BEAD = "bd-bp8fl.2"
EXPECTED_TRACE_ID = "bd-bp8fl.2.10::tracker-recovery-feature-parity-backlog::completion::v1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_SOURCE_GATES = {
    "tracker_health",
    "br_bv_disagreement",
    "ambition_graph_readiness",
    "crypt_dashboard",
    "feature_parity_closure",
    "hard_parts_replay",
    "workstream_done_templates",
    "reality_bridge_reconciliation",
}
PASS_EVENTS = [
    "tracker_recovery_backlog.sources_validated",
    "tracker_recovery_backlog.bindings_validated",
    "tracker_recovery_backlog.source_gates_replayed",
    "tracker_recovery_backlog.completion_contract_pass",
]
FAIL_EVENT = "tracker_recovery_backlog.completion_contract_fail"

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
            "gate": "tracker_recovery_feature_parity_backlog_completion_contract",
            "scenario_id": event,
            "mode": "strict",
            "api_family": "tracker",
            "symbol": "tracker_recovery_feature_parity_backlog",
            "oracle_kind": "completion_contract",
            "expected": "pass",
            "actual": outcome,
            "decision_path": "source_gates->bindings->telemetry",
            "outcome": outcome,
            "errno": 0,
            "latency_ns": 0,
            "source_commit": SOURCE_COMMIT,
            "failure_signature": "" if outcome == "pass" else "; ".join(errors[:3]),
            "artifact_refs": [rel(CONTRACT)],
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


def validate_sources(manifest: dict[str, Any]) -> dict[str, pathlib.Path]:
    source_artifacts = as_object(manifest.get("source_artifacts"), "source_artifacts")
    resolved: dict[str, pathlib.Path] = {}
    for key, value in sorted(source_artifacts.items()):
        path = repo_path(value, f"source_artifacts.{key}")
        if path is not None:
            resolved[key] = path
    emit(
        "tracker_recovery_backlog.sources_validated",
        source_artifact_count=len(resolved),
    )
    return resolved


def validate_bindings(manifest: dict[str, Any], resolved: dict[str, pathlib.Path]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids: set[str] = set()
    for index, binding_value in enumerate(bindings):
        binding = as_object(binding_value, f"missing_item_bindings[{index}]")
        binding_id = binding.get("id")
        if isinstance(binding_id, str):
            ids.add(binding_id)
        else:
            err(f"missing_item_bindings[{index}].id must be a string")
        for field in ["artifacts", "required_tests"]:
            values = as_list(binding.get(field), f"missing_item_bindings.{binding_id}.{field}")
            if not values:
                err(f"missing_item_bindings.{binding_id}.{field} must be non-empty")
            for item_index, value in enumerate(values):
                if not isinstance(value, str) or not value:
                    err(f"missing_item_bindings.{binding_id}.{field}[{item_index}] must be string")
                    continue
                if field == "artifacts" and value.startswith(("tests/", "scripts/", "crates/")):
                    repo_path(value, f"missing_item_bindings.{binding_id}.{field}[{item_index}]")
    if ids != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_bindings mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")

    completion_harness = resolved.get("completion_harness")
    if completion_harness is not None:
        harness_text = completion_harness.read_text(encoding="utf-8")
        for binding in bindings:
            for test_name in as_list(as_object(binding, "binding").get("required_tests"), "required_tests"):
                if isinstance(test_name, str) and f"fn {test_name}" not in harness_text:
                    err(f"required completion harness test missing: {test_name}")

    emit("tracker_recovery_backlog.bindings_validated", binding_count=len(ids))
    return len(ids)


def gate_path(gate: dict[str, Any], filename_key: str, gate_out_dir: pathlib.Path) -> pathlib.Path:
    filename = gate.get(filename_key)
    if not isinstance(filename, str) or not filename:
        return gate_out_dir / filename_key
    path = pathlib.Path(filename)
    if path.parts[:2] == ("target", "conformance"):
        return ROOT / path
    if path.is_absolute():
        return path
    return gate_out_dir / path


def run_source_gate(gate: dict[str, Any]) -> None:
    gate_id = gate.get("id")
    if not isinstance(gate_id, str) or not gate_id:
        err("source gate id must be a non-empty string")
        return
    script = repo_path(gate.get("script"), f"source_gates.{gate_id}.script")
    artifact = repo_path(gate.get("artifact"), f"source_gates.{gate_id}.artifact")
    if script is None or artifact is None:
        return

    expected_summary = as_object(gate.get("expected_summary", {}), f"source_gates.{gate_id}.expected_summary")
    if gate.get("replay") is False:
        artifact_json = load_json(artifact, f"source_gate.{gate_id}.artifact")
        summary = as_object(artifact_json.get("summary", {}), f"source_gates.{gate_id}.artifact.summary")
        for key, expected_value in expected_summary.items():
            candidates = [artifact_json.get(key), summary.get(key)]
            if expected_value not in candidates:
                err(
                    f"source_gate_artifact_summary_mismatch: {gate_id}.{key} "
                    f"expected={expected_value!r} got_artifact={artifact_json.get(key)!r} got_summary={summary.get(key)!r}"
                )
        source_gate_results[gate_id] = {
            "status": "pass",
            "report": rel(artifact),
            "log": "",
            "output": "",
            "replay": False,
        }
        return

    args = [str(arg) for arg in as_list(gate.get("args", []), f"source_gates.{gate_id}.args")]
    gate_out_dir = SOURCE_GATE_DIR / gate_id
    gate_out_dir.mkdir(parents=True, exist_ok=True)
    report_path = gate_path(gate, "report_filename", gate_out_dir)
    log_path = gate_path(gate, "log_filename", gate_out_dir)

    env = os.environ.copy()
    artifact_env = gate.get("artifact_env")
    target_env = gate.get("target_env")
    report_env = gate.get("report_env")
    log_env = gate.get("log_env")
    if isinstance(artifact_env, str) and artifact_env:
        env[artifact_env] = str(artifact)
    if isinstance(target_env, str) and target_env:
        env[target_env] = str(gate_out_dir)
    if isinstance(report_env, str) and report_env:
        env[report_env] = str(report_path)
    if isinstance(log_env, str) and log_env:
        env[log_env] = str(log_path)

    result = subprocess.run(
        ["bash", str(script), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=env,
    )
    combined = result.stdout + result.stderr
    output_path = gate_out_dir / "output.txt"
    output_path.write_text(combined, encoding="utf-8")
    if result.returncode != 0:
        err(f"source_gate_failed: {gate_id} exit={result.returncode}: {combined[-2000:]}")

    marker = gate.get("expected_stdout_contains")
    if isinstance(marker, str) and marker and marker not in combined:
        err(f"source_gate_marker_missing: {gate_id} marker={marker!r}")

    report = load_json(report_path, f"source_gate.{gate_id}.report")
    expected_status = gate.get("expected_report_status")
    actual_status = report.get("status")
    if expected_status and actual_status != expected_status:
        err(f"source_gate_status_mismatch: {gate_id} expected={expected_status!r} got={actual_status!r}")

    summary = as_object(report.get("summary", {}), f"source_gates.{gate_id}.report.summary")
    for key, expected_value in expected_summary.items():
        candidates = [report.get(key), summary.get(key)]
        if expected_value not in candidates:
            err(
                f"source_gate_summary_mismatch: {gate_id}.{key} "
                f"expected={expected_value!r} got_report={report.get(key)!r} got_summary={summary.get(key)!r}"
            )

    source_gate_results[gate_id] = {
        "status": actual_status,
        "report": rel(report_path),
        "log": rel(log_path),
        "output": rel(output_path),
    }


def validate_source_gates(manifest: dict[str, Any]) -> int:
    completion = as_object(manifest.get("completion_contract"), "completion_contract")
    gates = as_list(completion.get("required_source_gates"), "completion_contract.required_source_gates")
    gate_ids = {str(as_object(gate, "gate").get("id")) for gate in gates if isinstance(gate, dict)}
    if gate_ids != REQUIRED_SOURCE_GATES:
        err(f"source gate ids mismatch: expected={sorted(REQUIRED_SOURCE_GATES)} got={sorted(gate_ids)}")
    for gate in gates:
        run_source_gate(as_object(gate, "source_gate"))
    emit(
        "tracker_recovery_backlog.source_gates_replayed",
        source_gate_count=len(source_gate_results),
        source_gates=source_gate_results,
    )
    return len(source_gate_results)


manifest = load_json(CONTRACT, "completion_contract")
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("bead_id") != EXPECTED_BEAD:
    err(f"bead_id must be {EXPECTED_BEAD}")
if manifest.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
    err(f"original_bead must be {EXPECTED_ORIGINAL_BEAD}")
if manifest.get("trace_id") != EXPECTED_TRACE_ID:
    err(f"trace_id must be {EXPECTED_TRACE_ID}")

completion = as_object(manifest.get("completion_contract"), "completion_contract")
missing_items = {str(item) for item in as_list(completion.get("missing_item_ids"), "missing_item_ids")}
if missing_items != EXPECTED_MISSING_ITEMS:
    err(f"missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

resolved_sources = validate_sources(manifest)
binding_count = validate_bindings(manifest, resolved_sources)
source_gate_count = validate_source_gates(manifest)

telemetry = as_object(manifest.get("telemetry"), "telemetry")
if telemetry.get("report_schema_version") != EXPECTED_REPORT_SCHEMA:
    err(f"telemetry.report_schema_version must be {EXPECTED_REPORT_SCHEMA}")
if telemetry.get("required_events") != PASS_EVENTS:
    err(f"telemetry.required_events mismatch: expected={PASS_EVENTS} got={telemetry.get('required_events')}")
if telemetry.get("failure_event") != FAIL_EVENT:
    err(f"telemetry.failure_event must be {FAIL_EVENT}")

status = "fail" if errors else "pass"
final_event = FAIL_EVENT if errors else "tracker_recovery_backlog.completion_contract_pass"
emit(
    final_event,
    outcome=status,
    source_gate_count=source_gate_count,
    binding_count=binding_count,
    error_count=len(errors),
)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "bead_id": EXPECTED_BEAD,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "trace_id": EXPECTED_TRACE_ID,
    "status": status,
    "source_commit": SOURCE_COMMIT,
    "generated_at": now(),
    "contract": rel(CONTRACT),
    "source_gates": source_gate_results,
    "summary": {
        "source_artifact_count": len(resolved_sources),
        "source_gate_count": source_gate_count,
        "binding_count": binding_count,
        "error_count": len(errors),
    },
    "errors": errors,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL: tracker recovery feature parity backlog completion contract", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: tracker recovery feature parity backlog completion contract "
    f"source_gates={source_gate_count} bindings={binding_count}"
)
PY
