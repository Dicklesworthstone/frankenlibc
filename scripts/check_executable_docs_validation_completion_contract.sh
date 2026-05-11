#!/usr/bin/env bash
# check_executable_docs_validation_completion_contract.sh -- bd-3rw.5.2 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_EXEC_DOCS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/executable_docs_validation_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_EXEC_DOCS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_EXEC_DOCS_COMPLETION_REPORT:-${OUT_DIR}/executable_docs_validation_completion_contract.report.json}"
LOG="${FRANKENLIBC_EXEC_DOCS_COMPLETION_LOG:-${OUT_DIR}/executable_docs_validation_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"
SKIP_BASE_GATES="${FRANKENLIBC_EXEC_DOCS_SKIP_BASE_GATES:-0}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${OUT_DIR}" "${SOURCE_COMMIT}" "${SKIP_BASE_GATES}" <<'PY'
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
out_dir = Path(sys.argv[5])
source_commit = sys.argv[6]
skip_base_gates = sys.argv[7] == "1"

SCHEMA = "executable_docs_validation_completion_contract.v1"
BEAD_ID = "bd-3rw.5.2"
ORIGINAL_BEAD = "bd-3rw.5"
TRACE_ID = "bd-3rw.5.2::executable-docs-validation::completion::v1"
REQUIRED_SOURCE_IDS = {
    "docs_env_generator",
    "docs_env_gate",
    "docs_env_report",
    "docs_source_map",
    "docs_trace",
    "claim_reconciliation",
    "claim_reconciliation_gate",
    "claim_reconciliation_report",
    "ld_preload_smoke_summary",
    "release_dossier_validator",
    "release_dossier_completion_gate",
    "release_dossier_report",
    "fuzz_phase1_completion_contract",
    "fuzz_phase1_completion_gate",
    "fuzz_phase1_harness_test",
    "completion_contract",
    "completion_gate",
    "completion_harness_test",
}
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "tests.fuzz.primary",
    "tests.conformance.primary",
    "telemetry.primary",
}
REQUIRED_EVENTS = {
    "executable_docs_sources_validated",
    "executable_docs_base_gates_validated",
    "executable_docs_bindings_validated",
    "executable_docs_completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "bead_id",
    "original_bead",
    "trace_id",
    "status",
    "source_commit",
    "summary",
    "artifact_refs",
    "base_gate_results",
    "errors",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "bead_id",
    "event",
    "status",
    "failure_signature",
    "artifact_refs",
}
FAILURE_PRIORITY = [
    "malformed_contract",
    "missing_source_artifact",
    "missing_implementation_ref",
    "missing_source_marker",
    "base_gate_failed",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_fuzz_binding",
    "missing_conformance_binding",
    "missing_telemetry_binding",
    "missing_test_binding",
    "telemetry_contract_failed",
]

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []
artifact_refs: set[str] = {str(contract_path)}
base_gate_results: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def resolve(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def add_error(signature: str, message: str) -> None:
    errors.append({"failure_signature": signature, "message": message})


def primary_signature() -> str:
    present = {error["failure_signature"] for error in errors}
    for signature in FAILURE_PRIORITY:
        if signature in present:
            return signature
    return "executable_docs_completion_contract_failed"


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def load_jsonl(path: Path, context: str, signature: str) -> list[Any]:
    rows: list[Any] = []
    try:
        artifact_refs.add(rel(path))
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
    return rows


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(name: str, status: str, failure_signature: str = "none", **fields: Any) -> dict[str, Any]:
    return {
        "timestamp": utc_now(),
        "trace_id": f"{TRACE_ID}::{name}",
        "bead_id": BEAD_ID,
        "event": name,
        "status": status,
        "source_commit": source_commit,
        "failure_signature": failure_signature,
        "artifact_refs": sorted(artifact_refs),
        **fields,
    }


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def string_set(value: Any, context: str, signature: str) -> set[str]:
    rows = as_array(value, context, signature)
    result = {row for row in rows if isinstance(row, str)}
    if len(result) != len(rows):
        add_error(signature, f"{context} must contain only strings")
    return result


def validate_line_ref(ref: Any, signature: str, context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        add_error(signature, f"{context} must be a file:line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        add_error(signature, f"{context} has invalid line number: {ref}")
        return
    path = resolve(path_text)
    if not path.is_file():
        add_error(signature, f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines) or not lines[line_no - 1].strip():
        add_error(signature, f"{context} references blank or missing line: {ref}")
    artifact_refs.add(path_text)


def function_exists(path_text: str, function_name: str) -> bool:
    path = resolve(path_text)
    if not path.is_file():
        return False
    text = path.read_text(encoding="utf-8")
    return f"fn {function_name}(" in text or f"fn {function_name}<" in text


def command_for_gate(command: str) -> tuple[list[str], dict[str, str]]:
    command = command.replace("<out_dir>", str(out_dir))
    env = os.environ.copy()
    env["TMPDIR"] = str(out_dir)
    env["FRANKENLIBC_RELEASE_DOSSIER_COMPLETION_OUT_DIR"] = str(out_dir / "release_dossier")
    env["FRANKENLIBC_FUZZ_PHASE1_COMPLETION_OUT_DIR"] = str(out_dir / "fuzz_phase1")
    return shlex.split(command), env


def run_base_gate(gate: dict[str, Any]) -> None:
    gate_id = str(gate.get("id", "unknown"))
    command = str(gate.get("command", ""))
    if not command:
        add_error("base_gate_failed", f"{gate_id}: command missing")
        return
    argv, env = command_for_gate(command)
    started = time.time()
    try:
        output = subprocess.run(
            argv,
            cwd=root,
            env=env,
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
    except Exception as exc:
        add_error("base_gate_failed", f"{gate_id}: execution failed: {exc}")
        return
    stdout = output.stdout
    stderr = output.stderr
    result = {
        "id": gate_id,
        "command": command,
        "exit_code": output.returncode,
        "duration_ms": int((time.time() - started) * 1000),
        "stdout_tail": stdout[-1000:],
        "stderr_tail": stderr[-1000:],
    }
    base_gate_results.append(result)
    if output.returncode != 0:
        add_error("base_gate_failed", f"{gate_id}: exit={output.returncode}; stderr={stderr[-500:]}")
    for expected in as_array(gate.get("expected_stdout"), f"{gate_id}.expected_stdout", "base_gate_failed"):
        if isinstance(expected, str) and expected not in stdout:
            add_error("base_gate_failed", f"{gate_id}: stdout missing {expected!r}")


def finish(summary: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    if status == "pass":
        events.append(event("executable_docs_completion_contract_validated", "pass"))
    else:
        events.append(
            event(
                "executable_docs_completion_contract_failed",
                "fail",
                primary_signature(),
            )
        )
    report = {
        "schema_version": f"{SCHEMA}.report",
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "status": status,
        "source_commit": source_commit,
        "summary": {**summary, "event_count": len(events)},
        "artifact_refs": sorted(artifact_refs),
        "base_gate_results": base_gate_results,
        "errors": errors,
    }
    write_json(report_path, report)
    write_jsonl(log_path, events)
    if errors:
        print(f"FAIL: executable docs completion contract errors={len(errors)}")
        for error in errors[:12]:
            print(f"- {error['failure_signature']}: {error['message']}")
        sys.exit(1)
    print(
        "PASS: executable docs completion contract "
        f"sources={summary.get('source_count', 0)} "
        f"bindings={summary.get('binding_count', 0)} "
        f"base_gates={summary.get('base_gate_count', 0)}"
    )


contract = load_json(contract_path, "contract")
if contract.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if contract.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")

source_artifacts = as_array(contract.get("source_artifacts"), "source_artifacts")
source_by_id: dict[str, dict[str, Any]] = {}
for artifact in source_artifacts:
    row = as_object(artifact, "source_artifacts[]")
    artifact_id = row.get("id")
    path_text = row.get("path")
    if not isinstance(artifact_id, str) or not isinstance(path_text, str):
        add_error("malformed_contract", "source_artifacts entries need id and path strings")
        continue
    source_by_id[artifact_id] = row
    path = resolve(path_text)
    if not path.is_file():
        add_error("missing_source_artifact", f"{artifact_id}: missing {path_text}")
    else:
        artifact_refs.add(path_text)

missing_sources = sorted(REQUIRED_SOURCE_IDS - set(source_by_id))
if missing_sources:
    add_error("missing_source_artifact", f"missing source artifact ids: {missing_sources}")
events.append(event("executable_docs_sources_validated", "pending"))

for index, ref in enumerate(as_array(contract.get("implementation_refs"), "implementation_refs")):
    validate_line_ref(ref, "missing_implementation_ref", f"implementation_refs[{index}]")

for row in as_array(contract.get("required_source_markers"), "required_source_markers"):
    marker_row = as_object(row, "required_source_markers[]")
    path_text = marker_row.get("path")
    if not isinstance(path_text, str):
        add_error("missing_source_marker", "required_source_markers.path must be a string")
        continue
    path = resolve(path_text)
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        add_error("missing_source_marker", f"cannot read {path_text}: {exc}")
        continue
    for marker in as_array(marker_row.get("markers"), f"{path_text}.markers", "missing_source_marker"):
        if isinstance(marker, str) and marker not in text:
            add_error("missing_source_marker", f"{path_text} missing marker {marker}")

if not skip_base_gates:
    for gate in as_array(contract.get("base_gates"), "base_gates"):
        run_base_gate(as_object(gate, "base_gates[]", "base_gate_failed"))
else:
    base_gate_results.append({"id": "base_gates", "skipped": True})
events.append(
    event(
        "executable_docs_base_gates_validated",
        "pass" if not any(error["failure_signature"] == "base_gate_failed" for error in errors) else "fail",
        "base_gate_failed" if any(error["failure_signature"] == "base_gate_failed" for error in errors) else "none",
        skipped=skip_base_gates,
    )
)

bindings = as_array(contract.get("missing_item_bindings"), "missing_item_bindings")
binding_ids: set[str] = set()
for row in bindings:
    binding = as_object(row, "missing_item_bindings[]")
    missing_item_id = binding.get("missing_item_id")
    if not isinstance(missing_item_id, str):
        add_error("malformed_contract", "missing_item_bindings entries need missing_item_id")
        continue
    binding_ids.add(missing_item_id)
    signature = {
        "tests.unit.primary": "missing_unit_binding",
        "tests.e2e.primary": "missing_e2e_binding",
        "tests.fuzz.primary": "missing_fuzz_binding",
        "tests.conformance.primary": "missing_conformance_binding",
        "telemetry.primary": "missing_telemetry_binding",
    }.get(missing_item_id, "malformed_contract")
    for field in ("implementation_refs", "test_refs", "runtime_validation"):
        values = as_array(binding.get(field), f"{missing_item_id}.{field}", signature)
        if not values:
            add_error(signature, f"{missing_item_id}.{field} must be non-empty")
    for ref in as_array(binding.get("implementation_refs"), f"{missing_item_id}.implementation_refs", signature):
        validate_line_ref(ref, signature, f"{missing_item_id}.implementation_refs")
    for ref in as_array(binding.get("test_refs"), f"{missing_item_id}.test_refs", signature):
        validate_line_ref(ref, signature, f"{missing_item_id}.test_refs")

for required in REQUIRED_MISSING_ITEMS:
    if required not in binding_ids:
        add_error(
            {
                "tests.unit.primary": "missing_unit_binding",
                "tests.e2e.primary": "missing_e2e_binding",
                "tests.fuzz.primary": "missing_fuzz_binding",
                "tests.conformance.primary": "missing_conformance_binding",
                "telemetry.primary": "missing_telemetry_binding",
            }[required],
            f"missing binding for {required}",
        )

required_tests = as_object(contract.get("required_test_functions"), "required_test_functions")
for path_text, function_rows in required_tests.items():
    for function_name in as_array(function_rows, f"{path_text}.required_test_functions", "missing_test_binding"):
        if isinstance(function_name, str) and not function_exists(path_text, function_name):
            add_error("missing_test_binding", f"{path_text} missing test function {function_name}")

telemetry = as_object(contract.get("telemetry_contract"), "telemetry_contract", "telemetry_contract_failed")
events_required = string_set(telemetry.get("required_events"), "telemetry_contract.required_events", "telemetry_contract_failed")
if not REQUIRED_EVENTS <= events_required:
    add_error("telemetry_contract_failed", f"telemetry required_events missing {sorted(REQUIRED_EVENTS - events_required)}")
report_fields = string_set(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields", "telemetry_contract_failed")
if not REQUIRED_REPORT_FIELDS <= report_fields:
    add_error("telemetry_contract_failed", f"report fields missing {sorted(REQUIRED_REPORT_FIELDS - report_fields)}")
log_fields = string_set(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields", "telemetry_contract_failed")
if not REQUIRED_LOG_FIELDS <= log_fields:
    add_error("telemetry_contract_failed", f"log fields missing {sorted(REQUIRED_LOG_FIELDS - log_fields)}")

docs_report = load_json(root / "tests/conformance/env_docs_code_mismatch_report.v1.json", "docs mismatch report", "missing_source_artifact")
claim_report = load_json(root / "tests/conformance/claim_reconciliation_report.v1.json", "claim reconciliation report", "missing_source_artifact")
release_report = load_json(root / "tests/release/dossier_validation_report.v1.json", "release dossier report", "missing_source_artifact")
docs_trace = load_jsonl(root / "tests/conformance/docs_source_of_truth_trace.v1.jsonl", "docs trace", "missing_source_artifact")
if docs_report.get("summary", {}).get("missing_in_docs_count") not in (0, None):
    add_error("missing_conformance_binding", "docs mismatch report has missing_in_docs_count drift")
if claim_report.get("summary", {}).get("errors", 0) != 0:
    add_error("missing_conformance_binding", "claim reconciliation report has errors")
if "release_notes_hook" not in release_report:
    add_error("missing_telemetry_binding", "release dossier report missing release_notes_hook")
if not docs_trace:
    add_error("missing_telemetry_binding", "docs source-of-truth trace is empty")

events.append(
    event(
        "executable_docs_bindings_validated",
        "pass" if not errors else "fail",
        primary_signature() if errors else "none",
    )
)

finish(
    {
        "source_count": len(source_by_id),
        "binding_count": len(binding_ids),
        "base_gate_count": len(base_gate_results),
        "skip_base_gates": skip_base_gates,
        "required_missing_items": sorted(REQUIRED_MISSING_ITEMS),
    }
)
PY
