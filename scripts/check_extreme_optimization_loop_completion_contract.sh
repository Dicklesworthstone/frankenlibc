#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_EXTREME_OPTIMIZATION_CONTRACT:-$ROOT/tests/conformance/extreme_optimization_loop_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_EXTREME_OPTIMIZATION_OUT_DIR:-$ROOT/target/conformance/extreme_optimization_loop_completion_contract}"
REPORT="${FRANKENLIBC_EXTREME_OPTIMIZATION_REPORT:-$OUT_DIR/extreme_optimization_loop_completion_contract.report.json}"
LOG="${FRANKENLIBC_EXTREME_OPTIMIZATION_LOG:-$OUT_DIR/extreme_optimization_loop_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"]).resolve()
CONTRACT = pathlib.Path(os.environ["CONTRACT"]).resolve()
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"]).resolve()
REPORT = pathlib.Path(os.environ["REPORT"]).resolve()
LOG = pathlib.Path(os.environ["LOG"]).resolve()

EXPECTED_SCHEMA = "extreme_optimization_loop_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "extreme_optimization_loop_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-3fb.1-extreme-optimization-loop-completion-contract"
SOURCE_BEAD = "bd-3fb"
COMPLETION_BEAD = "bd-3fb.1"
REQUIRED_SOURCE_IDS = {
    "perf_baseline_spec",
    "perf_baseline_suite_contract",
    "perf_baseline_suite_checker",
    "perf_baseline_suite_test",
    "hot_path_profile_contract",
    "hot_path_profile_report",
    "hot_path_profile_checker",
    "hot_path_profile_test",
    "runtime_hot_path_perf_golden_contract",
    "runtime_hot_path_perf_golden_checker",
    "runtime_hot_path_perf_golden_test",
    "golden_fixture_protocol",
    "optimization_proof_ledger",
    "optimization_proof_ledger_contract",
    "optimization_proof_ledger_checker",
    "optimization_proof_ledger_test",
    "perf_regression_prevention",
    "perf_regression_prevention_contract",
    "perf_regression_prevention_checker",
    "perf_regression_prevention_test",
    "completion_checker",
    "completion_test",
}
REQUIRED_LANES = {"baselines", "profiles", "goldens", "proof-ledger", "regressions"}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.golden.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "extreme_optimization_sources_bound",
    "extreme_optimization_lanes_validated",
    "extreme_optimization_missing_items_bound",
    "extreme_optimization_telemetry_validated",
    "extreme_optimization_child_gates_replayed",
    "extreme_optimization_completion_contract_pass",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "event",
    "source_bead",
    "completion_debt_bead",
    "status",
    "artifact_refs",
    "failure_signature",
    "details",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
source_paths: dict[str, pathlib.Path] = {}
child_gate_results: list[dict[str, Any]] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return path.as_posix()


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}


def repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative without parent traversal: {path_text}")
        return None
    full = (ROOT / path).resolve()
    if ROOT not in full.parents and full != ROOT:
        err(f"{context} escapes repo root: {path_text}")
        return None
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def as_string_list(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not allow_empty and not value):
        err(f"{context} must be a {'possibly empty ' if allow_empty else ''}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(
    event: str,
    status: str,
    artifact_refs: list[str],
    details: dict[str, Any] | None = None,
) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "source_bead": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "extreme_optimization_completion_failed",
            "details": details or {},
        }
    )


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def write_outputs(status: str, summary: dict[str, Any] | None = None) -> None:
    if status != "pass":
        append_event(
            "extreme_optimization_completion_contract_fail",
            "fail",
            [rel(CONTRACT)],
            {"error_count": len(errors)},
        )
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "source_bead": SOURCE_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "source_commit": source_commit(),
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": summary or {},
        "child_gates": child_gate_results,
        "errors": errors,
        "events": events,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text(
        "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def validate_header(manifest: dict[str, Any]) -> None:
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
    require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
    require(manifest.get("original_bead") == SOURCE_BEAD, "original_bead mismatch")
    require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")
    require(
        isinstance(manifest.get("next_audit_score_threshold"), int)
        and manifest["next_audit_score_threshold"] >= 800,
        "next_audit_score_threshold must be at least 800",
    )


def validate_sources(manifest: dict[str, Any]) -> None:
    sources = manifest.get("source_artifacts")
    if not isinstance(sources, dict):
        err("source_artifacts must be an object")
        return
    actual_ids = set(sources)
    require(REQUIRED_SOURCE_IDS <= actual_ids, f"source_artifacts missing {sorted(REQUIRED_SOURCE_IDS - actual_ids)}")

    for artifact_id, spec in sources.items():
        if not isinstance(spec, dict):
            err(f"source_artifacts.{artifact_id} must be an object")
            continue
        path = repo_path(spec.get("path"), f"source_artifacts.{artifact_id}.path")
        if path is None:
            continue
        source_paths[artifact_id] = path
        expected_schema = spec.get("expected_schema")
        if expected_schema is not None:
            value = load_json(path, f"source_artifacts.{artifact_id}")
            actual_schema = value.get("schema_version") if isinstance(value, dict) else None
            require(
                str(actual_schema) == str(expected_schema),
                f"source_artifacts.{artifact_id} schema drift: expected {expected_schema!r} got {actual_schema!r}",
            )
        for needle in as_string_list(spec.get("required_text", []), f"source_artifacts.{artifact_id}.required_text", allow_empty=True):
            try:
                text = path.read_text(encoding="utf-8")
            except Exception as exc:
                err(f"source_artifacts.{artifact_id} unreadable for text check: {exc}")
                continue
            require(needle in text, f"source_artifacts.{artifact_id} missing required text {needle!r}")

    append_event(
        "extreme_optimization_sources_bound",
        "pass" if not errors else "fail",
        [rel(path) for path in source_paths.values()],
        {"source_count": len(source_paths)},
    )


def validate_lanes(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    lanes = manifest.get("proof_lanes")
    if not isinstance(lanes, list):
        err("proof_lanes must be an array")
        return []
    lane_ids = {lane.get("id") for lane in lanes if isinstance(lane, dict)}
    require(lane_ids == REQUIRED_LANES, f"proof_lanes mismatch: {sorted(str(item) for item in lane_ids)}")

    for lane in lanes:
        if not isinstance(lane, dict):
            err("proof_lanes entries must be objects")
            continue
        lane_id = lane.get("id")
        if not isinstance(lane_id, str):
            err("proof_lanes entry missing id")
            continue
        for item in as_string_list(lane.get("missing_items"), f"proof_lanes.{lane_id}.missing_items"):
            require(item in REQUIRED_MISSING_ITEMS, f"proof_lanes.{lane_id} references unknown missing item {item}")
        for artifact_id in as_string_list(lane.get("artifact_ids"), f"proof_lanes.{lane_id}.artifact_ids"):
            require(artifact_id in source_paths, f"proof_lanes.{lane_id} references missing artifact {artifact_id}")
        checker_id = lane.get("checker_artifact")
        test_id = lane.get("test_artifact")
        require(checker_id in source_paths, f"proof_lanes.{lane_id}.checker_artifact is not file-backed")
        require(test_id in source_paths, f"proof_lanes.{lane_id}.test_artifact is not file-backed")
        command = lane.get("checker_command")
        if not isinstance(command, str) or not command.startswith("bash scripts/check_"):
            err(f"proof_lanes.{lane_id}.checker_command must be a bash checker command")
        elif checker_id in source_paths:
            require(
                command == f"bash {rel(source_paths[checker_id])}",
                f"proof_lanes.{lane_id}.checker_command does not match checker artifact",
            )
        test_text = source_paths.get(test_id, pathlib.Path()).read_text(encoding="utf-8") if test_id in source_paths else ""
        for test_ref in as_string_list(lane.get("required_test_refs"), f"proof_lanes.{lane_id}.required_test_refs"):
            require(test_ref in test_text, f"proof_lanes.{lane_id} missing required test ref {test_ref}")

    append_event(
        "extreme_optimization_lanes_validated",
        "pass" if not errors else "fail",
        [rel(source_paths.get(lane.get("checker_artifact", ""), "")) for lane in lanes if isinstance(lane, dict)],
        {"lane_count": len(lanes)},
    )
    return lanes


def command_is_allowed(command: str) -> bool:
    if "cargo " in command:
        return "rch exec -- cargo " in command or command.startswith("rch cargo ")
    return (
        command.startswith("bash scripts/check_")
        or command.startswith("jq ")
        or command.startswith("python3 scripts/")
    )


def validate_missing_items(manifest: dict[str, Any]) -> None:
    bindings = manifest.get("missing_item_bindings")
    if not isinstance(bindings, list):
        err("missing_item_bindings must be an array")
        return
    ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
    require(ids == REQUIRED_MISSING_ITEMS, f"missing_item_bindings mismatch: {sorted(str(item) for item in ids)}")
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing_item_bindings entries must be objects")
            continue
        binding_id = binding.get("id")
        for lane_id in as_string_list(binding.get("lane_ids"), f"missing_item_bindings.{binding_id}.lane_ids"):
            require(lane_id in REQUIRED_LANES, f"missing_item_bindings.{binding_id} references unknown lane {lane_id}")
        for artifact_id in as_string_list(binding.get("required_artifacts", []), f"missing_item_bindings.{binding_id}.required_artifacts", allow_empty=True):
            require(artifact_id in source_paths, f"missing_item_bindings.{binding_id} references missing artifact {artifact_id}")
        for command in as_string_list(binding.get("required_commands", []), f"missing_item_bindings.{binding_id}.required_commands", allow_empty=True):
            require(command_is_allowed(command), f"{binding_id} command must use rch for cargo or a checked script: {command}")
        for test_ref in as_string_list(binding.get("required_test_refs", []), f"missing_item_bindings.{binding_id}.required_test_refs", allow_empty=True):
            completion_test = source_paths.get("completion_test")
            test_text = completion_test.read_text(encoding="utf-8") if completion_test else ""
            require(test_ref in test_text, f"{binding_id} missing completion test ref {test_ref}")
    append_event(
        "extreme_optimization_missing_items_bound",
        "pass" if not errors else "fail",
        [rel(CONTRACT)],
        {"missing_item_count": len(bindings)},
    )


def validate_telemetry(manifest: dict[str, Any]) -> None:
    telemetry = manifest.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return
    events = set(as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
    fields = set(as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"))
    require(REQUIRED_EVENTS <= events, f"telemetry_contract.required_events missing {sorted(REQUIRED_EVENTS - events)}")
    require(REQUIRED_LOG_FIELDS <= fields, f"telemetry_contract.required_log_fields missing {sorted(REQUIRED_LOG_FIELDS - fields)}")
    append_event(
        "extreme_optimization_telemetry_validated",
        "pass" if not errors else "fail",
        [rel(CONTRACT)],
        {"required_event_count": len(events), "required_log_field_count": len(fields)},
    )


def run_child_gates(lanes: list[dict[str, Any]]) -> None:
    for lane in lanes:
        if not isinstance(lane, dict):
            continue
        lane_id = lane.get("id", "unknown")
        command = lane.get("checker_command")
        if not isinstance(command, str):
            err(f"proof_lanes.{lane_id}.checker_command must be string")
            continue
        parts = command.split()
        if len(parts) != 2 or parts[0] != "bash":
            err(f"proof_lanes.{lane_id}.checker_command must be bash <script>")
            continue
        proc = subprocess.run(
            ["bash", parts[1]],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        result = {
            "lane_id": lane_id,
            "command": command,
            "exit_code": proc.returncode,
            "stdout_tail": proc.stdout.splitlines()[-5:],
            "stderr_tail": proc.stderr.splitlines()[-5:],
        }
        child_gate_results.append(result)
        if proc.returncode != 0:
            err(f"child gate {lane_id} failed with exit {proc.returncode}")
    append_event(
        "extreme_optimization_child_gates_replayed",
        "pass" if not errors else "fail",
        [row["command"] for row in child_gate_results],
        {"child_gate_count": len(child_gate_results)},
    )


manifest_value = load_json(CONTRACT, "completion contract")
manifest = manifest_value if isinstance(manifest_value, dict) else {}
validate_header(manifest)
validate_sources(manifest)
lanes = validate_lanes(manifest)
validate_missing_items(manifest)
validate_telemetry(manifest)
if errors:
    write_outputs(
        "fail",
        {
            "source_count": len(source_paths),
            "lane_count": len(lanes),
            "missing_item_count": len(manifest.get("missing_item_bindings", []) if isinstance(manifest.get("missing_item_bindings"), list) else []),
        },
    )
    raise SystemExit(1)

run_child_gates(lanes)
if errors:
    write_outputs(
        "fail",
        {
            "source_count": len(source_paths),
            "lane_count": len(lanes),
            "child_gate_count": len(child_gate_results),
        },
    )
    raise SystemExit(1)

append_event(
    "extreme_optimization_completion_contract_pass",
    "pass",
    [rel(CONTRACT), rel(REPORT), rel(LOG)],
    {"lane_count": len(lanes), "child_gate_count": len(child_gate_results)},
)
write_outputs(
    "pass",
    {
        "source_count": len(source_paths),
        "lane_count": len(lanes),
        "missing_item_count": len(manifest.get("missing_item_bindings", [])),
        "child_gate_count": len(child_gate_results),
        "required_event_count": len(REQUIRED_EVENTS),
    },
)
print(
    "PASS: extreme optimization loop completion contract "
    f"sources={len(source_paths)} lanes={len(lanes)} child_gates={len(child_gate_results)} "
    f"report={rel(REPORT)}"
)
PY
