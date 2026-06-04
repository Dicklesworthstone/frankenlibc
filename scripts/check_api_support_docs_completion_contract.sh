#!/usr/bin/env bash
# check_api_support_docs_completion_contract.sh -- bd-3rw.4.1 completion gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/api_support_docs_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_REPORT:-${OUT_DIR}/api_support_docs_completion_contract.report.json}"
LOG="${FRANKENLIBC_API_SUPPORT_DOCS_COMPLETION_LOG:-${OUT_DIR}/api_support_docs_completion_contract.log.jsonl}"
SKIP_BASE_GATES="${FRANKENLIBC_API_SUPPORT_DOCS_SKIP_BASE_GATES:-0}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${OUT_DIR}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${SKIP_BASE_GATES}" <<'PY'
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
out_dir = Path(sys.argv[3])
report_path = Path(sys.argv[4])
log_path = Path(sys.argv[5])
source_commit = sys.argv[6]
skip_base_gates = sys.argv[7] == "1"

SCHEMA = "api_support_docs_completion_contract.v1"
REPORT_SCHEMA = "api_support_docs_completion_contract.report.v1"
BEAD_ID = "bd-3rw.4.1"
ORIGINAL_BEAD = "bd-3rw.4"
TRACE_ID = "bd-3rw.4.1::api-support-docs::completion::v1"

REQUIRED_SOURCE_IDS = {
    "docs_env_generator",
    "docs_env_gate",
    "docs_source_map",
    "docs_source_trace",
    "docs_env_report",
    "docs_semantic_contract",
    "docs_semantic_gate",
    "support_matrix",
    "support_matrix_maintenance_gate",
    "support_matrix_maintenance_report",
    "support_matrix_universe_contract",
    "support_matrix_universe_gate",
    "symbol_fixture_coverage",
    "per_symbol_fixture_tests",
    "claim_reconciliation_gate",
    "claim_reconciliation_report",
    "fuzz_phase1_completion_contract",
    "fuzz_phase1_completion_gate",
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
    "api_support_docs_sources_validated",
    "api_support_docs_surface_bindings_validated",
    "api_support_docs_base_gates_validated",
    "api_support_docs_completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "bead_id",
    "original_bead",
    "trace_id",
    "status",
    "source_commit",
    "summary",
    "source_artifacts",
    "api_surface_contract",
    "base_gate_results",
    "artifact_refs",
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
    "api_surface_contract_failed",
    "missing_unit_binding",
    "missing_e2e_binding",
    "missing_fuzz_binding",
    "missing_conformance_binding",
    "missing_telemetry_binding",
    "missing_test_binding",
    "bare_cargo_command",
    "base_gate_failed",
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
    return "api_support_docs_completion_contract_failed"


def emit_event(
    name: str, status: str, failure_signature: str = "none", **fields: Any
) -> None:
    events.append(
        {
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
    )


def as_object(value: Any, context: str, signature: str = "malformed_contract") -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    add_error(signature, f"{context} must be an object")
    return {}


def as_array(value: Any, context: str, signature: str = "malformed_contract") -> list[Any]:
    if isinstance(value, list):
        return value
    add_error(signature, f"{context} must be an array")
    return []


def string_list(value: Any, context: str, signature: str = "malformed_contract") -> list[str]:
    rows = as_array(value, context, signature)
    out: list[str] = []
    for index, item in enumerate(rows):
        if not isinstance(item, str) or not item:
            add_error(signature, f"{context}[{index}] must be a non-empty string")
        else:
            out.append(item)
    return out


def load_json(path: Path, context: str, signature: str = "malformed_contract") -> Any:
    try:
        artifact_refs.add(rel(path))
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
        return {}


def load_jsonl(path: Path, context: str, signature: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        artifact_refs.add(rel(path))
        for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                add_error(signature, f"{context} line {index} must be an object")
                continue
            rows.append(value)
    except Exception as exc:
        add_error(signature, f"{context}: cannot parse {rel(path)}: {exc}")
    return rows


def validate_file_line_ref(ref: Any, signature: str, context: str) -> None:
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


def validate_command(command: Any, context: str) -> None:
    if not isinstance(command, str) or not command:
        add_error("malformed_contract", f"{context} must be a non-empty command string")
        return
    bare_cargo = re.search(r"(^|[;&|()\s])cargo\s+(build|check|test|clippy|fmt)\b", command)
    routed = "rch cargo " in command or "rch exec -- cargo " in command
    if bare_cargo and not routed:
        add_error("bare_cargo_command", f"{context} must route cargo through rch: {command}")


def validate_base_gate(gate: dict[str, Any]) -> None:
    command = str(gate.get("command", ""))
    validate_command(command, f"base_gates.{gate.get('id', '<unknown>')}.command")


def command_for_gate(gate: dict[str, Any]) -> tuple[list[str], dict[str, str]]:
    command = str(gate.get("command", "")).replace("<out_dir>", str(out_dir))
    env = os.environ.copy()
    env["TMPDIR"] = str(out_dir)
    for key, value in as_object(gate.get("env", {}), "base_gate.env").items():
        if not isinstance(key, str) or not isinstance(value, str):
            add_error("malformed_contract", "base_gate.env keys and values must be strings")
            continue
        env[key] = value.replace("<out_dir>", str(out_dir))
    return shlex.split(command), env


def run_base_gate(gate: dict[str, Any]) -> None:
    gate_id = str(gate.get("id", "unknown"))
    validate_base_gate(gate)
    if errors:
        return
    argv, env = command_for_gate(gate)
    started = time.time()
    output = subprocess.run(
        argv,
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=int(gate.get("timeout_seconds", 180)),
        check=False,
    )
    duration_ms = int((time.time() - started) * 1000)
    stdout = output.stdout
    stderr = output.stderr
    result = {
        "id": gate_id,
        "command": str(gate.get("command", "")),
        "status": "pass" if output.returncode == 0 else "fail",
        "exit_code": output.returncode,
        "duration_ms": duration_ms,
        "stdout_tail": stdout[-2000:],
        "stderr_tail": stderr[-2000:],
    }
    base_gate_results.append(result)
    for needle in string_list(gate.get("expected_stdout", []), f"base_gates.{gate_id}.expected_stdout"):
        if needle not in stdout:
            add_error("base_gate_failed", f"{gate_id}: expected stdout missing {needle!r}")
    if output.returncode != 0:
        add_error(
            "base_gate_failed",
            f"{gate_id}: exit={output.returncode} stdout={stdout[-500:]} stderr={stderr[-500:]}",
        )


def write_outputs(manifest: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    report = {
        "schema_version": REPORT_SCHEMA,
        "bead_id": BEAD_ID,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "status": status,
        "source_commit": source_commit,
        "summary": {
            "source_artifact_count": len(as_object(manifest.get("source_artifacts", {}), "source_artifacts")),
            "binding_count": len(as_array(manifest.get("missing_item_bindings", []), "missing_item_bindings")),
            "base_gate_count": len(base_gate_results),
            "api_surface": as_object(manifest.get("api_surface_contract", {}), "api_surface_contract").get("surface_id"),
        },
        "source_artifacts": manifest.get("source_artifacts", {}),
        "api_surface_contract": manifest.get("api_surface_contract", {}),
        "base_gate_results": base_gate_results,
        "artifact_refs": sorted(artifact_refs),
        "errors": errors,
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in events),
        encoding="utf-8",
    )


manifest = as_object(load_json(contract_path, "contract"), "contract")

if manifest.get("schema_version") != SCHEMA:
    add_error("malformed_contract", f"schema_version must be {SCHEMA}")
if manifest.get("bead_id") != BEAD_ID:
    add_error("malformed_contract", f"bead_id must be {BEAD_ID}")
if manifest.get("original_bead") != ORIGINAL_BEAD:
    add_error("malformed_contract", f"original_bead must be {ORIGINAL_BEAD}")
if manifest.get("trace_id") != TRACE_ID:
    add_error("malformed_contract", f"trace_id must be {TRACE_ID}")

source_artifacts = as_object(manifest.get("source_artifacts"), "source_artifacts")
missing_source_ids = sorted(REQUIRED_SOURCE_IDS - set(source_artifacts))
if missing_source_ids:
    add_error("missing_source_artifact", f"source_artifacts missing {missing_source_ids}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        add_error("missing_source_artifact", f"source_artifacts.{source_id} must be a non-empty path")
        continue
    path = resolve(path_text)
    if not path.is_file():
        add_error("missing_source_artifact", f"source_artifacts.{source_id} missing: {path_text}")
    artifact_refs.add(path_text)

for index, ref in enumerate(as_array(manifest.get("implementation_refs"), "implementation_refs")):
    validate_file_line_ref(ref, "missing_implementation_ref", f"implementation_refs[{index}]")

for path_text, markers in as_object(
    manifest.get("required_source_markers"), "required_source_markers"
).items():
    if not isinstance(path_text, str):
        add_error("missing_source_marker", "required_source_markers keys must be paths")
        continue
    path = resolve(path_text)
    if not path.is_file():
        add_error("missing_source_marker", f"required source marker file missing: {path_text}")
        continue
    text = path.read_text(encoding="utf-8")
    artifact_refs.add(path_text)
    for marker in string_list(markers, f"required_source_markers.{path_text}", "missing_source_marker"):
        if marker not in text:
            add_error("missing_source_marker", f"{path_text} missing marker {marker}")

emit_event("api_support_docs_sources_validated", "fail" if errors else "pass", primary_signature() if errors else "none")

api_contract = as_object(manifest.get("api_surface_contract"), "api_surface_contract")
source_map = load_json(resolve(str(api_contract.get("source_map", ""))), "docs_source_map", "api_surface_contract_failed")
trace_rows = load_jsonl(resolve(str(api_contract.get("trace", ""))), "docs_source_trace", "api_surface_contract_failed")
surface_id = str(api_contract.get("surface_id", ""))
surfaces = as_array(source_map.get("surfaces"), "docs_source_map.surfaces", "api_surface_contract_failed")
surface = next((row for row in surfaces if isinstance(row, dict) and row.get("surface_id") == surface_id), None)
if not isinstance(surface, dict):
    add_error("api_surface_contract_failed", f"docs source map missing surface {surface_id}")
else:
    if surface.get("future_target_path") != api_contract.get("future_target_path"):
        add_error("api_surface_contract_failed", f"{surface_id}: future_target_path drift")
    sections = as_array(surface.get("sections"), f"{surface_id}.sections", "api_surface_contract_failed")
    by_section = {row.get("section_id"): row for row in sections if isinstance(row, dict)}
    for expected in as_array(api_contract.get("required_sections"), "api_surface_contract.required_sections", "api_surface_contract_failed"):
        expected = as_object(expected, "api_surface_contract.required_sections[]", "api_surface_contract_failed")
        section_id = expected.get("section_id")
        section = by_section.get(section_id)
        if not isinstance(section, dict):
            add_error("api_surface_contract_failed", f"{surface_id}: missing section {section_id}")
            continue
        for key in ("owner", "review_policy", "freshness_status"):
            if section.get(key) != expected.get(key):
                add_error("api_surface_contract_failed", f"{surface_id}/{section_id}: {key} drift")
        if section.get("freshness_status") != "fresh":
            add_error("api_surface_contract_failed", f"{surface_id}/{section_id}: stale freshness")
        for key in ("source_artifacts", "update_triggers", "backing_paths"):
            actual = {item for item in section.get(key, []) if isinstance(item, str)}
            required = {item for item in expected.get(key, []) if isinstance(item, str)}
            missing = sorted(required - actual)
            if missing:
                add_error("api_surface_contract_failed", f"{surface_id}/{section_id}: {key} missing {missing}")

required_trace_fields = set(
    string_list(api_contract.get("required_trace_fields"), "api_surface_contract.required_trace_fields", "api_surface_contract_failed")
)
for row_index, row in enumerate(trace_rows, start=1):
    missing = [field for field in required_trace_fields if row.get(field) in ("", [], None)]
    if missing:
        add_error("api_surface_contract_failed", f"trace row {row_index} missing {missing}")

for expected in as_array(api_contract.get("required_trace_rows"), "api_surface_contract.required_trace_rows", "api_surface_contract_failed"):
    expected = as_object(expected, "api_surface_contract.required_trace_rows[]", "api_surface_contract_failed")
    match = next(
        (
            row
            for row in trace_rows
            if row.get("doc_surface") == expected.get("doc_surface")
            and row.get("owner") == expected.get("owner")
            and row.get("source_artifact") == expected.get("source_artifact")
        ),
        None,
    )
    if match is None:
        add_error("api_surface_contract_failed", f"missing trace row {expected}")

emit_event(
    "api_support_docs_surface_bindings_validated",
    "fail" if errors else "pass",
    primary_signature() if errors else "none",
    trace_rows=len(trace_rows),
    surface_id=surface_id,
)

binding_ids = set()
for binding in as_array(manifest.get("missing_item_bindings"), "missing_item_bindings"):
    binding = as_object(binding, "missing_item_bindings[]")
    missing_item_id = str(binding.get("missing_item_id", ""))
    binding_ids.add(missing_item_id)
    signature = {
        "tests.unit.primary": "missing_unit_binding",
        "tests.e2e.primary": "missing_e2e_binding",
        "tests.fuzz.primary": "missing_fuzz_binding",
        "tests.conformance.primary": "missing_conformance_binding",
        "telemetry.primary": "missing_telemetry_binding",
    }.get(missing_item_id, "malformed_contract")
    for field in ("implementation_refs", "test_refs", "runtime_validation", "required_commands"):
        rows = as_array(binding.get(field), f"{missing_item_id}.{field}", signature)
        if not rows:
            add_error(signature, f"{missing_item_id}.{field} must be non-empty")
    for index, ref in enumerate(as_array(binding.get("implementation_refs"), f"{missing_item_id}.implementation_refs", signature)):
        validate_file_line_ref(ref, signature, f"{missing_item_id}.implementation_refs[{index}]")
    for index, ref in enumerate(as_array(binding.get("test_refs"), f"{missing_item_id}.test_refs", signature)):
        validate_file_line_ref(ref, signature, f"{missing_item_id}.test_refs[{index}]")
    for index, command in enumerate(as_array(binding.get("required_commands"), f"{missing_item_id}.required_commands", signature)):
        validate_command(command, f"{missing_item_id}.required_commands[{index}]")

missing_bindings = sorted(REQUIRED_MISSING_ITEMS - binding_ids)
for missing in missing_bindings:
    add_error(
        {
            "tests.unit.primary": "missing_unit_binding",
            "tests.e2e.primary": "missing_e2e_binding",
            "tests.fuzz.primary": "missing_fuzz_binding",
            "tests.conformance.primary": "missing_conformance_binding",
            "telemetry.primary": "missing_telemetry_binding",
        }[missing],
        f"missing binding for {missing}",
    )

for path_text, functions in as_object(manifest.get("required_test_functions"), "required_test_functions").items():
    if not isinstance(path_text, str):
        add_error("missing_test_binding", "required_test_functions keys must be paths")
        continue
    for function_name in string_list(functions, f"required_test_functions.{path_text}", "missing_test_binding"):
        if not function_exists(path_text, function_name):
            add_error("missing_test_binding", f"{path_text} missing test function {function_name}")
        artifact_refs.add(path_text)

if not skip_base_gates:
    for gate in as_array(manifest.get("base_gates"), "base_gates"):
        run_base_gate(as_object(gate, "base_gates[]"))
else:
    for gate in as_array(manifest.get("base_gates"), "base_gates"):
        gate_id = as_object(gate, "base_gates[]").get("id", "unknown")
        validate_base_gate(as_object(gate, "base_gates[]"))
        base_gate_results.append({"id": gate_id, "status": "skipped", "command": gate.get("command", "")})

emit_event(
    "api_support_docs_base_gates_validated",
    "fail" if any(row.get("status") == "fail" for row in base_gate_results) else "pass",
    "base_gate_failed" if any(row.get("status") == "fail" for row in base_gate_results) else "none",
    base_gate_results=base_gate_results,
)

telemetry = as_object(manifest.get("telemetry_contract"), "telemetry_contract")
events_declared = set(string_list(telemetry.get("required_events"), "telemetry_contract.required_events", "telemetry_contract_failed"))
report_fields_declared = set(string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields", "telemetry_contract_failed"))
log_fields_declared = set(string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields", "telemetry_contract_failed"))
if missing := sorted(REQUIRED_EVENTS - events_declared):
    add_error("telemetry_contract_failed", f"telemetry missing required events {missing}")
if missing := sorted(REQUIRED_REPORT_FIELDS - report_fields_declared):
    add_error("telemetry_contract_failed", f"telemetry missing report fields {missing}")
if missing := sorted(REQUIRED_LOG_FIELDS - log_fields_declared):
    add_error("telemetry_contract_failed", f"telemetry missing log fields {missing}")

emit_event(
    "api_support_docs_completion_contract_validated",
    "fail" if errors else "pass",
    primary_signature() if errors else "none",
)

write_outputs(manifest)
if errors:
    print(f"FAIL: api support docs completion contract ({primary_signature()})", file=sys.stderr)
    for error in errors[:20]:
        print(f"  - {error['failure_signature']}: {error['message']}", file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS: api support docs completion contract "
    f"sources={len(source_artifacts)} bindings={len(binding_ids)} base_gates={len(base_gate_results)}"
)
PY
