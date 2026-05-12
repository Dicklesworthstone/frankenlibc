#!/usr/bin/env bash
# check_stdio_abi_teardown_completion_contract.sh - bd-ypst.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_CONTRACT:-$ROOT/tests/conformance/stdio_abi_teardown_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_OUT_DIR:-$ROOT/target/conformance/stdio_abi_teardown_completion_contract}"
REPORT="${FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_STDIO_ABI_TEARDOWN_COMPLETION_LOG:-$OUT_DIR/events.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "stdio_abi_teardown_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "stdio_abi_teardown_completion_contract.report.v1"
EXPECTED_BEAD = "bd-ypst.1"
EXPECTED_ORIGINAL_BEAD = "bd-ypst"
EXPECTED_TRACE_ID = "bd-ypst.1::stdio-abi-teardown::completion::v1"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary"}
REQUIRED_SOURCE_ARTIFACTS = {
    "stdio_abi",
    "io_internal_abi",
    "stdio_abi_test",
    "version_script",
    "completion_checker",
    "completion_harness",
}
PASS_EVENTS = [
    "stdio_abi_teardown.sources_validated",
    "stdio_abi_teardown.implementation_markers_validated",
    "stdio_abi_teardown.test_surface_validated",
    "stdio_abi_teardown.bindings_validated",
    "stdio_abi_teardown.completion_contract_pass",
]
FAIL_EVENT = "stdio_abi_teardown.completion_contract_fail"

errors: list[str] = []
events: list[dict[str, Any]] = []


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
            "gate": "stdio_abi_teardown_completion_contract",
            "scenario_id": event,
            "mode": "strict",
            "api_family": "stdio",
            "symbol": "stdio_abi_teardown",
            "oracle_kind": "completion_contract",
            "expected": "pass",
            "actual": outcome,
            "decision_path": "stdio_abi->host_libio_exit_patch->_IO_list_all->stdio_abi_test",
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


def read_artifact(artifacts: dict[str, Any], key: str) -> str:
    path = repo_path(artifacts.get(key), f"source_artifacts.{key}")
    if path is None or not path.is_file():
        err(f"source_artifacts.{key} must reference a file")
        return ""
    return path.read_text(encoding="utf-8")


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

    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    missing_items = {
        item for item in as_list(contract.get("missing_item_ids"), "completion_contract.missing_item_ids")
        if isinstance(item, str)
    }
    if missing_items != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_ids mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(missing_items)}")

    emit("stdio_abi_teardown.sources_validated", source_artifact_count=len(keys))
    return artifacts


def validate_implementation_markers(manifest: dict[str, Any], artifacts: dict[str, Any]) -> int:
    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    marker_groups = as_object(contract.get("implementation_markers"), "completion_contract.implementation_markers")
    marker_count = 0
    for key in ["stdio_abi", "io_internal_abi", "version_script"]:
        text = read_artifact(artifacts, key)
        for marker in as_list(marker_groups.get(key), f"implementation_markers.{key}"):
            if not isinstance(marker, str) or not marker:
                err(f"implementation_markers.{key} must contain non-empty strings")
                continue
            marker_count += 1
            if marker not in text:
                err(f"missing implementation marker in {key}: {marker}")

    stdio_text = read_artifact(artifacts, "stdio_abi")
    registry_pos = stdio_text.find("fn registry() -> &'static Mutex<StreamRegistry>")
    guard_pos = stdio_text.find("ensure_host_libio_exit_safe();", registry_pos)
    if registry_pos < 0 or guard_pos < 0:
        err("stdio_abi registry must call ensure_host_libio_exit_safe before returning the registry")
    init_pos = stdio_text.find("pub(crate) fn init_host_stdio_streams()")
    init_guard_pos = stdio_text.find("ensure_host_libio_exit_safe();", init_pos)
    if init_pos < 0 or init_guard_pos < 0:
        err("init_host_stdio_streams must call ensure_host_libio_exit_safe")

    emit("stdio_abi_teardown.implementation_markers_validated", marker_count=marker_count)
    return marker_count


def validate_test_surface(manifest: dict[str, Any], artifacts: dict[str, Any]) -> tuple[int, int]:
    contract = as_object(manifest.get("completion_contract"), "completion_contract")
    test_contract = as_object(contract.get("test_contract"), "completion_contract.test_contract")
    test_text = read_artifact(artifacts, "stdio_abi_test")
    test_count = len(re.findall(r"#\[test\]", test_text))
    ignore_count = len(re.findall(r"#\[ignore", test_text))
    minimum_test_count = test_contract.get("minimum_test_count")
    required_ignore_count = test_contract.get("required_ignore_count")
    if not isinstance(minimum_test_count, int) or test_count < minimum_test_count:
        err(f"stdio_abi_test test count below contract: expected >= {minimum_test_count}, got {test_count}")
    if not isinstance(required_ignore_count, int) or ignore_count != required_ignore_count:
        err(f"stdio_abi_test ignore count drifted: expected {required_ignore_count}, got {ignore_count}")
    for function_name in as_list(test_contract.get("required_test_functions"), "test_contract.required_test_functions"):
        if not isinstance(function_name, str) or not function_exists(test_text, function_name):
            err(f"stdio_abi_test missing required function: {function_name}")
    commands = {
        item for item in as_list(test_contract.get("required_remote_commands"), "test_contract.required_remote_commands")
        if isinstance(item, str)
    }
    for required in [
        "cargo test -p frankenlibc-abi --test stdio_abi_test -- --nocapture",
        "cargo test -p frankenlibc-harness --test stdio_abi_teardown_completion_contract_test -- --nocapture",
        "cargo clippy -p frankenlibc-harness --test stdio_abi_teardown_completion_contract_test -- -D warnings",
    ]:
        if required not in commands:
            err(f"test_contract.required_remote_commands missing: {required}")

    emit("stdio_abi_teardown.test_surface_validated", test_count=test_count, ignore_count=ignore_count)
    return test_count, ignore_count


def validate_bindings(manifest: dict[str, Any], artifacts: dict[str, Any]) -> int:
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    ids = {
        binding.get("id") for binding in bindings
        if isinstance(binding, dict) and isinstance(binding.get("id"), str)
    }
    if ids != EXPECTED_MISSING_ITEMS:
        err(f"missing_item_bindings mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(ids)}")

    source_texts = {
        key: read_artifact(artifacts, key)
        for key in ["stdio_abi", "io_internal_abi", "stdio_abi_test", "completion_harness"]
    }
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
            if not any(function_exists(text, function_name) for text in source_texts.values()):
                err(f"{binding_id}.runtime_validation references missing function: {function_name}")

    telemetry = as_object(manifest.get("telemetry_contract"), "telemetry_contract")
    if telemetry.get("report_schema_version") != EXPECTED_REPORT_SCHEMA:
        err("telemetry_contract.report_schema_version mismatch")
    events = [
        item for item in as_list(telemetry.get("required_events"), "telemetry_contract.required_events")
        if isinstance(item, str)
    ]
    if events != PASS_EVENTS:
        err(f"telemetry required_events mismatch: expected={PASS_EVENTS} got={events}")

    emit("stdio_abi_teardown.bindings_validated", binding_count=len(bindings))
    return len(bindings)


manifest = load_json(CONTRACT, "stdio_abi_teardown_completion_contract")
artifacts = validate_manifest(manifest)
marker_count = validate_implementation_markers(manifest, artifacts)
test_count, ignore_count = validate_test_surface(manifest, artifacts)
binding_count = validate_bindings(manifest, artifacts)

if errors:
    emit(FAIL_EVENT, "fail", error_count=len(errors))
else:
    emit("stdio_abi_teardown.completion_contract_pass", marker_count=marker_count, test_count=test_count)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "status": "fail" if errors else "pass",
    "bead_id": EXPECTED_BEAD,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "trace_id": EXPECTED_TRACE_ID,
    "source_commit": SOURCE_COMMIT,
    "contract": rel(CONTRACT),
    "report": rel(REPORT),
    "log": rel(LOG),
    "errors": errors,
    "events": [event["event"] for event in events],
    "summary": {
        "source_artifact_count": len(artifacts),
        "marker_count": marker_count,
        "stdio_abi_test_count": test_count,
        "stdio_abi_ignore_count": ignore_count,
        "binding_count": binding_count,
    },
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print("FAIL: stdio ABI teardown completion contract", file=sys.stderr)
    for message in errors:
        print(f"- {message}", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: stdio ABI teardown completion contract "
    f"markers={marker_count} stdio_tests={test_count} ignored={ignore_count} bindings={binding_count}"
)
PY
