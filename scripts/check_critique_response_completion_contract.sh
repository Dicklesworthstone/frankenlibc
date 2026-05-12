#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/critique_response_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_OUT_DIR:-$ROOT/target/conformance/critique_response_completion_contract}"
REPORT="${FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_REPORT:-$OUT_DIR/critique_response_completion_contract.report.json}"
LOG="${FRANKENLIBC_CRITIQUE_RESPONSE_COMPLETION_LOG:-$OUT_DIR/critique_response_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" OUT_DIR="$OUT_DIR" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import datetime as _dt
import json
import os
import pathlib
import subprocess
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"]).resolve()
CONTRACT = pathlib.Path(os.environ["CONTRACT"]).resolve()
REPORT = pathlib.Path(os.environ["REPORT"]).resolve()
LOG = pathlib.Path(os.environ["LOG"]).resolve()

EXPECTED_SCHEMA = "critique_response_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "critique_response_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-3qq.1-critique-response-completion-contract"
SOURCE_BEAD = "bd-3qq"
COMPLETION_BEAD = "bd-3qq.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
EXPECTED_SOURCE_KEYS = {
    "issues_jsonl",
    "support_matrix",
    "stub_census",
    "ld_preload_smoke_summary",
    "ld_preload_smoke_index",
    "ld_preload_smoke_index_test",
    "real_program_smoke_contract",
    "real_program_smoke_test",
    "e2e_reality_gate_contract",
    "e2e_reality_gate_test",
    "stub_guard_test",
    "verification_matrix",
    "verification_matrix_test",
    "replacement_level_contract",
    "replacement_level_test",
    "runtime_mode_evidence_contract",
    "runtime_mode_evidence_test",
    "canonical_evidence_contract",
    "canonical_evidence_test",
    "evidence_compliance_contract",
    "evidence_compliance_test",
    "completion_checker",
    "completion_test",
}
EXPECTED_EVENTS = {
    "critique_response_dependencies_validated",
    "critique_response_support_surface_validated",
    "critique_response_ld_preload_validated",
    "critique_response_missing_items_bound",
    "critique_response_completion_contract_validated",
    "critique_response_completion_contract_failed",
}
LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "stream",
    "gate",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


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


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {line_number} is invalid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {line_number} must be an object")
            continue
        rows.append(row)
    return rows


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def repo_path(value: Any, context: str, *, must_be_file: bool = True) -> pathlib.Path | None:
    if not isinstance(value, str) or not value:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(value)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {value}")
        return None
    full = (ROOT / path).resolve()
    if ROOT not in full.parents and full != ROOT:
        err(f"{context} escapes repo root: {value}")
        return None
    if must_be_file and not full.is_file():
        err(f"{context} references missing file: {value}")
        return None
    if not must_be_file and not full.exists():
        err(f"{context} references missing path: {value}")
        return None
    return full


def text_for(path_text: str, context: str) -> str:
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        err(f"{context} is not UTF-8: {path_text}: {exc}")
        return ""


def string_list(value: Any, context: str, *, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any] | None = None) -> None:
    events.append(
        {
            "timestamp": now(),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "level": "info" if status == "pass" else "error",
            "event": event,
            "bead_id": SOURCE_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": SOURCE_BEAD,
            "source_commit": SOURCE_COMMIT,
            "status": status,
            "stream": "completion-debt",
            "gate": "critique_response_completion_contract",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "critique_response_completion_contract_failed",
            "details": details or {},
        }
    )


def validate_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"{context} has invalid line number: {value}")
        return
    path = repo_path(path_text, context, must_be_file=True)
    if path is None:
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    if line_no <= 0 or line_no > len(lines):
        err(f"{context} points outside file: {value}")
        return
    if not lines[line_no - 1].strip():
        err(f"{context} points to blank line: {value}")


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}(" in source_text or f"fn {name}<" in source_text


def validate_test_ref(ref: Any, artifacts: dict[str, Any], context: str) -> None:
    if not isinstance(ref, dict):
        err(f"{context} must be object")
        return
    source = ref.get("source")
    name = ref.get("name")
    if not isinstance(source, str) or source not in artifacts:
        err(f"{context}.source is unknown: {source!r}")
        return
    if not isinstance(name, str) or not name:
        err(f"{context}.name must be a non-empty string")
        return
    source_text = text_for(str(artifacts[source]), f"{context}.source")
    if not function_exists(source_text, name):
        err(f"{context} references missing Rust test/function {source}::{name}")


def command_policy_ok(command: str) -> bool:
    if "cargo " in command:
        return command.startswith("rch exec -- ")
    return command.startswith("bash scripts/") or command.startswith("jq ")


manifest = load_json(CONTRACT, "contract")
artifacts = manifest.get("source_artifacts")
if not isinstance(artifacts, dict):
    err("source_artifacts must be an object")
    artifacts = {}

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("original_bead") != SOURCE_BEAD:
    err(f"original_bead must be {SOURCE_BEAD}")
if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
    err(f"completion_debt_bead must be {COMPLETION_BEAD}")
if int(manifest.get("next_audit_score_threshold", 0) or 0) < 800:
    err("next_audit_score_threshold must be >= 800")

if set(artifacts) != EXPECTED_SOURCE_KEYS:
    err(f"source_artifacts key mismatch: expected={sorted(EXPECTED_SOURCE_KEYS)} got={sorted(artifacts)}")
for key, path_text in artifacts.items():
    repo_path(path_text, f"source_artifacts.{key}", must_be_file=True)

for index, ref in enumerate(string_list(manifest.get("implementation_refs"), "implementation_refs")):
    validate_line_ref(ref, f"implementation_refs[{index}]")

issues_path = repo_path(artifacts.get("issues_jsonl"), "source_artifacts.issues_jsonl", must_be_file=True)
issue_rows = load_jsonl(issues_path, "issues_jsonl") if issues_path else []
rows_by_id = {row.get("id"): row for row in issue_rows if isinstance(row.get("id"), str)}
source_row = rows_by_id.get(SOURCE_BEAD)
if not isinstance(source_row, dict):
    err(f"{SOURCE_BEAD} missing from issues_jsonl")
else:
    if source_row.get("status") != "closed":
        err(f"{SOURCE_BEAD} must be closed")
    close_reason = str(source_row.get("close_reason", ""))
    for needle in ["real, honest", "falsifiable", "zero stubs"]:
        if needle not in close_reason:
            err(f"{SOURCE_BEAD} close_reason missing {needle!r}")

required_dependency_ids = string_list(manifest.get("required_dependency_closure"), "required_dependency_closure")
dependency_statuses: dict[str, str] = {}
if isinstance(source_row, dict):
    for dep in source_row.get("dependencies", []):
        if isinstance(dep, dict) and isinstance(dep.get("id"), str):
            dependency_statuses[dep["id"]] = str(dep.get("status", ""))
for dep_id in required_dependency_ids:
    row_status = rows_by_id.get(dep_id, {}).get("status")
    dep_status = dependency_statuses.get(dep_id, row_status)
    if dep_status != "closed":
        err(f"required dependency {dep_id} must be closed, got {dep_status!r}")
append_event(
    "critique_response_dependencies_validated",
    "pass" if not errors else "fail",
    [str(artifacts.get("issues_jsonl", ""))],
    {"dependency_count": len(required_dependency_ids)},
)

claims = manifest.get("claim_bindings")
if not isinstance(claims, dict):
    err("claim_bindings must be an object")
    claims = {}

support_claim = claims.get("support_surface", {})
support_path = repo_path(artifacts.get("support_matrix"), "source_artifacts.support_matrix", must_be_file=True)
support = load_json(support_path, "support_matrix") if support_path else {}
support_summary = support.get("summary") if isinstance(support.get("summary"), dict) else {}
if int(support_summary.get("total", 0) or 0) < int(support_claim.get("minimum_classified_symbols", 0) or 0):
    err("support_matrix total classified symbols below required minimum")
for field, expected_key in [
    ("stub", "expected_stub"),
    ("glibc_call_through", "expected_glibc_call_through"),
    ("wraps_host_libc", "expected_wraps_host_libc"),
]:
    if int(support_summary.get(field, -1) or 0) != int(support_claim.get(expected_key, -999) or 0):
        err(f"support_matrix summary.{field} mismatch")

stub_claim = claims.get("stub_census", {})
stub_path = repo_path(artifacts.get("stub_census"), "source_artifacts.stub_census", must_be_file=True)
stub = load_json(stub_path, "stub_census") if stub_path else {}
stub_summary = stub.get("summary") if isinstance(stub.get("summary"), dict) else {}
for field, expected_key in [
    ("reachable_stubs", "expected_reachable_stubs"),
    ("unreachable_stubs", "expected_unreachable_stubs"),
    ("matrix_inconsistencies", "expected_matrix_inconsistencies"),
]:
    if int(stub_summary.get(field, -1) or 0) != int(stub_claim.get(expected_key, -999) or 0):
        err(f"stub_census summary.{field} mismatch")
if int(stub.get("total_unique_stub_symbols", -1) or 0) != int(stub_claim.get("expected_total_unique_stub_symbols", -999) or 0):
    err("stub_census total_unique_stub_symbols mismatch")
append_event(
    "critique_response_support_surface_validated",
    "pass" if not errors else "fail",
    [str(artifacts.get("support_matrix", "")), str(artifacts.get("stub_census", ""))],
    {
        "classified_symbols": support_summary.get("total"),
        "reachable_stubs": stub_summary.get("reachable_stubs"),
        "total_unique_stub_symbols": stub.get("total_unique_stub_symbols"),
    },
)

smoke_claim = claims.get("ld_preload_smoke", {})
smoke_path = repo_path(artifacts.get("ld_preload_smoke_summary"), "source_artifacts.ld_preload_smoke_summary", must_be_file=True)
smoke = load_json(smoke_path, "ld_preload_smoke_summary") if smoke_path else {}
smoke_summary = smoke.get("summary") if isinstance(smoke.get("summary"), dict) else {}
if int(smoke_summary.get("total_cases", 0) or 0) < int(smoke_claim.get("minimum_total_cases", 0) or 0):
    err("ld_preload_smoke_summary total_cases below minimum")
if int(smoke_summary.get("fails", -1) or 0) != int(smoke_claim.get("expected_fails", -999) or 0):
    err("ld_preload_smoke_summary fails mismatch")
if bool(smoke_summary.get("overall_failed", True)) != bool(smoke_claim.get("expected_overall_failed", False)):
    err("ld_preload_smoke_summary overall_failed mismatch")
required_modes = smoke_claim.get("required_mode_status")
if not isinstance(required_modes, dict):
    err("ld_preload_smoke.required_mode_status must be object")
    required_modes = {}
modes = smoke.get("modes") if isinstance(smoke.get("modes"), dict) else {}
for mode, expected_status in required_modes.items():
    actual = modes.get(mode, {}).get("status") if isinstance(modes.get(mode), dict) else None
    if actual != expected_status:
        err(f"ld_preload_smoke mode {mode} status mismatch: expected {expected_status!r} got {actual!r}")
append_event(
    "critique_response_ld_preload_validated",
    "pass" if not errors else "fail",
    [str(artifacts.get("ld_preload_smoke_summary", "")), str(artifacts.get("ld_preload_smoke_index", ""))],
    {"total_cases": smoke_summary.get("total_cases"), "fails": smoke_summary.get("fails")},
)

bindings = manifest.get("missing_item_bindings")
if not isinstance(bindings, list):
    err("missing_item_bindings must be an array")
    bindings = []
item_ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
if item_ids != EXPECTED_MISSING_ITEMS:
    err(f"missing_item_bindings id mismatch: expected={sorted(EXPECTED_MISSING_ITEMS)} got={sorted(item_ids)}")
for binding_index, binding in enumerate(bindings):
    if not isinstance(binding, dict):
        err(f"missing_item_bindings[{binding_index}] must be object")
        continue
    item_id = binding.get("id", f"binding[{binding_index}]")
    impl_refs = string_list(binding.get("implementation_refs"), f"missing_item_bindings.{item_id}.implementation_refs")
    for ref_index, ref in enumerate(impl_refs):
        validate_line_ref(ref, f"missing_item_bindings.{item_id}.implementation_refs[{ref_index}]")
    test_refs = binding.get("required_test_refs")
    if not isinstance(test_refs, list) or not test_refs:
        err(f"missing_item_bindings.{item_id}.required_test_refs must be non-empty array")
    else:
        for ref_index, ref in enumerate(test_refs):
            validate_test_ref(ref, artifacts, f"missing_item_bindings.{item_id}.required_test_refs[{ref_index}]")
    commands = string_list(binding.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
    for command in commands:
        if not command_policy_ok(command):
            err(f"missing_item_bindings.{item_id}.required_commands has non-rch cargo or unsupported command: {command}")
append_event(
    "critique_response_missing_items_bound",
    "pass" if not errors else "fail",
    [
        str(artifacts.get("completion_checker", "")),
        str(artifacts.get("completion_test", "")),
    ],
    {"missing_items": sorted(item_ids)},
)

telemetry = manifest.get("telemetry_contract")
if not isinstance(telemetry, dict):
    err("telemetry_contract must be object")
    telemetry = {}
event_set = set(string_list(telemetry.get("required_events"), "telemetry_contract.required_events"))
if event_set != EXPECTED_EVENTS:
    err(f"telemetry_contract.required_events mismatch: expected={sorted(EXPECTED_EVENTS)} got={sorted(event_set)}")
field_set = set(string_list(telemetry.get("required_fields"), "telemetry_contract.required_fields"))
if not LOG_FIELDS.issubset(field_set):
    err(f"telemetry_contract.required_fields missing {sorted(LOG_FIELDS - field_set)}")

status = "fail" if errors else "pass"
append_event(
    "critique_response_completion_contract_validated" if status == "pass" else "critique_response_completion_contract_failed",
    status,
    [
        rel(CONTRACT),
        str(artifacts.get("support_matrix", "")),
        str(artifacts.get("stub_census", "")),
        str(artifacts.get("ld_preload_smoke_summary", "")),
    ],
    {"error_count": len(errors)},
)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "source_commit": SOURCE_COMMIT,
    "status": status,
    "error_count": len(errors),
    "errors": errors,
    "original_bead": SOURCE_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "dependency_count": len(required_dependency_ids),
    "missing_items": sorted(item_ids),
    "support_summary": support_summary,
    "stub_summary": stub_summary,
    "ld_preload_summary": smoke_summary,
    "artifact_refs": [
        rel(CONTRACT),
        str(artifacts.get("support_matrix", "")),
        str(artifacts.get("stub_census", "")),
        str(artifacts.get("ld_preload_smoke_summary", "")),
        str(artifacts.get("canonical_evidence_contract", "")),
        str(artifacts.get("evidence_compliance_contract", "")),
    ],
    "events": events,
}
write_json(REPORT, report)
write_jsonl(LOG, events)

if errors:
    print(f"critique response completion contract failed: errors={len(errors)} report={rel(REPORT)} log={rel(LOG)}")
    for message in errors:
        print(f"ERROR: {message}")
    raise SystemExit(1)

print(
    "critique response completion contract validated: "
    f"dependencies={len(required_dependency_ids)} "
    f"missing_items={len(item_ids)} "
    f"classified_symbols={support_summary.get('total')} "
    f"smoke_cases={smoke_summary.get('total_cases')} "
    f"report={rel(REPORT)}"
)
PY
