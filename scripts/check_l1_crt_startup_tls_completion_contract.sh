#!/usr/bin/env bash
# check_l1_crt_startup_tls_completion_contract.sh - bd-bp8fl.6.3.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_L1_CRT_STARTUP_TLS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/l1_crt_startup_tls_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_L1_CRT_STARTUP_TLS_MATRIX:-$ROOT/tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json}"
REPORT="${FRANKENLIBC_L1_CRT_STARTUP_TLS_COMPLETION_REPORT:-$ROOT/target/conformance/l1_crt_startup_tls_completion_contract.report.json}"
LOG="${FRANKENLIBC_L1_CRT_STARTUP_TLS_COMPLETION_LOG:-$ROOT/target/conformance/l1_crt_startup_tls_completion_contract.log.jsonl}"
REPLACEMENT_REPORT="${FRANKENLIBC_L1_CRT_STARTUP_TLS_REPLACEMENT_REPORT:-$ROOT/target/conformance/l1_crt_startup_tls_completion_contract.replacement_levels.report.json}"
REPLACEMENT_LOG="${FRANKENLIBC_L1_CRT_STARTUP_TLS_REPLACEMENT_LOG:-$ROOT/target/conformance/l1_crt_startup_tls_completion_contract.replacement_levels.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$REPLACEMENT_REPORT")" "$(dirname "$REPLACEMENT_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
MATRIX="$MATRIX" \
REPORT="$REPORT" \
LOG="$LOG" \
REPLACEMENT_REPORT="$REPLACEMENT_REPORT" \
REPLACEMENT_LOG="$REPLACEMENT_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
MATRIX = pathlib.Path(os.environ["MATRIX"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
REPLACEMENT_REPORT = pathlib.Path(os.environ["REPLACEMENT_REPORT"])
REPLACEMENT_LOG = pathlib.Path(os.environ["REPLACEMENT_LOG"])

COMPLETION_BEAD = "bd-bp8fl.6.3.1"
ORIGINAL_BEAD = "bd-bp8fl.6.3"
EXPECTED_SCHEMA = "l1_crt_startup_tls_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.6.3.1-l1-crt-startup-tls-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_TELEMETRY_EVENTS = {
    "l1_crt_startup_tls_completion_contract_validated",
    "l1_crt_startup_tls_completion_contract_failed",
    "l1_crt_startup_tls_summary",
    "l1_crt_startup_tls_blockers_preserved",
    "replacement_levels_l1_gate_replayed",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "l1_summary",
    "replacement_gate_report",
    "replacement_gate_log",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
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
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            err(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label} line {index} must be an object")
            continue
        rows.append(row)
    return rows


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
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


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(key, str) or not key:
            err("test_sources keys must be non-empty strings")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif not function_exists(text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def rows_by_decision(rows: list[dict[str, Any]], decision: str) -> list[dict[str, Any]]:
    return [row for row in rows if row.get("promotion_decision") == decision]


def row_ids(rows: list[dict[str, Any]]) -> list[str]:
    return [row["id"] for row in rows if isinstance(row.get("id"), str)]


def run_replacement_gate(source_commit: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "FLC_L1_CRT_MATRIX_PATH": str(MATRIX),
            "FLC_REPLACEMENT_LEVELS_REPORT_PATH": str(REPLACEMENT_REPORT),
            "FLC_REPLACEMENT_LEVELS_LOG_PATH": str(REPLACEMENT_LOG),
            "SOURCE_COMMIT": source_commit,
            "CARGO_TARGET_DIR": env.get("CARGO_TARGET_DIR", "target"),
        }
    )
    result = subprocess.run(
        ["bash", "scripts/check_replacement_levels.sh"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        err(
            "replacement levels L1 gate failed: "
            f"exit={result.returncode} stdout={result.stdout[-1600:]} stderr={result.stderr[-1600:]}"
        )


source_commit = git_head()
contract = load_json(CONTRACT, "completion contract")
matrix = load_json(MATRIX, "L1 CRT/startup/TLS proof matrix")

if contract.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if contract.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

evidence = contract.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
if evidence.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if int(evidence.get("next_audit_score_threshold", 0) or 0) < 800:
    err("completion_debt_evidence.next_audit_score_threshold must be at least 800")

for index, ref in enumerate(evidence.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(evidence.get("test_sources"))
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
missing_items_bound: list[str] = []
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = evidence.get(section_name, {})
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    if int(section.get("next_audit_score_threshold", 0) or 0) < 800:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be at least 800")
    validate_required_commands(section, section_name)
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    missing_items_bound.append(missing_item)

matrix_rows_raw = matrix.get("proof_rows", [])
matrix_rows = [row for row in matrix_rows_raw if isinstance(row, dict)]
required_log_fields = as_string_list(evidence.get("required_log_fields"), "completion_debt_evidence.required_log_fields")
required_row_ids = as_string_list(evidence.get("required_proof_row_ids"), "completion_debt_evidence.required_proof_row_ids")
required_blocked_rows = as_string_list(evidence.get("required_blocked_rows"), "completion_debt_evidence.required_blocked_rows")
required_negative_tests = as_string_list(
    evidence.get("required_negative_claim_tests"),
    "completion_debt_evidence.required_negative_claim_tests",
)

if required_log_fields != matrix.get("required_log_fields"):
    err("completion_debt_evidence.required_log_fields must match proof matrix required_log_fields")
if required_row_ids != matrix.get("required_proof_row_ids"):
    err("completion_debt_evidence.required_proof_row_ids must match proof matrix required_proof_row_ids")
blocked_rows = rows_by_decision(matrix_rows, "claim_blocked")
satisfied_rows = rows_by_decision(matrix_rows, "satisfied")
if required_blocked_rows != row_ids(blocked_rows):
    err("completion_debt_evidence.required_blocked_rows must match proof matrix claim_blocked rows")
negative_ids = row_ids([row for row in matrix.get("negative_claim_tests", []) if isinstance(row, dict)])
if required_negative_tests != negative_ids:
    err("completion_debt_evidence.required_negative_claim_tests must match proof matrix negative_claim_tests")

expectations = evidence.get("minimum_l1_expectations", {})
if not isinstance(expectations, dict):
    err("completion_debt_evidence.minimum_l1_expectations must be an object")
    expectations = {}
expected_runtime_modes = set(expectations.get("runtime_modes", []))
for row in matrix_rows:
    row_id = row.get("id", "<missing>")
    if row.get("replacement_level") != expectations.get("replacement_level"):
        err(f"{row_id}: replacement_level does not match completion expectation")
    modes = set(row.get("runtime_modes", []))
    if not expected_runtime_modes.issubset(modes):
        err(f"{row_id}: runtime modes do not satisfy completion expectation")
    if not row.get("failure_signature"):
        err(f"{row_id}: failure_signature must be non-empty")
    if not row.get("artifact_refs"):
        err(f"{row_id}: artifact_refs must be non-empty")

summary = matrix.get("summary", {}) if isinstance(matrix.get("summary"), dict) else {}
claim_policy = matrix.get("claim_policy", {}) if isinstance(matrix.get("claim_policy"), dict) else {}
if len(matrix_rows) != int(expectations.get("proof_row_count", 0) or 0):
    err("proof row count does not match completion expectation")
if len(satisfied_rows) != int(expectations.get("satisfied_row_count", 0) or 0):
    err("satisfied row count does not match completion expectation")
if len(blocked_rows) != int(expectations.get("blocked_row_count", 0) or 0):
    err("blocked row count does not match completion expectation")
if summary.get("current_gate_status") != expectations.get("current_gate_status"):
    err("matrix summary current_gate_status does not match completion expectation")
if claim_policy.get("current_claim_status") != expectations.get("claim_policy_status"):
    err("claim_policy current_claim_status does not match completion expectation")
if len(matrix.get("negative_claim_tests", [])) < int(expectations.get("negative_claim_count_min", 0) or 0):
    err("negative claim test count is below completion expectation")

telemetry = evidence.get("telemetry_primary", {})
if isinstance(telemetry, dict):
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - required_events)
    if missing_events:
        err(f"telemetry_primary.required_events missing {missing_events}")
    required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
    missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_fields)
    if missing_fields:
        err(f"telemetry_primary.required_fields missing {missing_fields}")
else:
    err("completion_debt_evidence.telemetry_primary must be an object")
    required_events = set()
    required_fields = set()

run_replacement_gate(source_commit)
replacement_report = load_json(REPLACEMENT_REPORT, "replacement-level report")
replacement_log_rows = load_jsonl(REPLACEMENT_LOG, "replacement-level log")

if replacement_report.get("gate_id") != "replacement_levels_l1_gate":
    err("replacement-level report gate_id must be replacement_levels_l1_gate")
if replacement_report.get("status") != expectations.get("replacement_gate_status"):
    err("replacement-level report status does not match completion expectation")
if replacement_report.get("current_level") != expectations.get("current_level_must_remain"):
    err("replacement-level report current_level does not match completion expectation")
if replacement_report.get("objective_gate_status") != expectations.get("objective_gate_status"):
    err("replacement-level objective_gate_status does not match completion expectation")
report_l1 = replacement_report.get("l1_crt_startup_tls_proof_matrix", {})
if not isinstance(report_l1, dict):
    err("replacement-level report missing l1_crt_startup_tls_proof_matrix object")
    report_l1 = {}
if report_l1.get("current_gate_status") != expectations.get("current_gate_status"):
    err("replacement-level report L1 CRT current_gate_status does not match completion expectation")
report_summary = replacement_report.get("summary", {})
if isinstance(report_summary, dict):
    if int(report_summary.get("l1_crt_proof_row_count", 0) or 0) != len(matrix_rows):
        err("replacement-level report L1 CRT row count mismatch")
    decisions = report_summary.get("l1_crt_promotion_decisions", {})
    if isinstance(decisions, dict):
        if int(decisions.get("satisfied", 0) or 0) != len(satisfied_rows):
            err("replacement-level report satisfied-row count mismatch")
        if int(decisions.get("claim_blocked", 0) or 0) != len(blocked_rows):
            err("replacement-level report blocked-row count mismatch")
    else:
        err("replacement-level report promotion decisions must be an object")
else:
    err("replacement-level report summary must be an object")

l1_log_rows = [
    row
    for row in replacement_log_rows
    if row.get("source") == "l1_crt_startup_tls_proof_matrix"
]
if len(l1_log_rows) < int(expectations.get("l1_log_row_count_min", 0) or 0):
    err("replacement-level log did not emit enough L1 CRT proof rows")
for index, row in enumerate(l1_log_rows):
    for field in required_log_fields:
        if field not in row:
            err(f"replacement-level L1 log row {index} missing required field {field}")
    if row.get("bead_id") != ORIGINAL_BEAD:
        err(f"replacement-level L1 log row {index} bead_id must be {ORIGINAL_BEAD}")
    if row.get("proof_row_id") in required_blocked_rows and row.get("outcome") != "claim_blocked":
        err(f"replacement-level L1 blocked row {row.get('proof_row_id')} did not remain claim_blocked")

l1_summary = {
    "proof_row_count": len(matrix_rows),
    "satisfied_row_count": len(satisfied_rows),
    "blocked_row_count": len(blocked_rows),
    "blocked_rows": required_blocked_rows,
    "negative_claim_tests": required_negative_tests,
    "claim_policy_status": claim_policy.get("current_claim_status"),
    "current_gate_status": summary.get("current_gate_status"),
    "blocker_reason": summary.get("blocker_reason"),
    "replacement_current_level": replacement_report.get("current_level"),
    "replacement_objective_gate_status": replacement_report.get("objective_gate_status"),
}

status = "fail" if errors else "pass"


def event_payload(event: str, level: str, failure_signature: str = "none") -> dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": f"{COMPLETION_BEAD}::{event}",
        "event": event,
        "level": level,
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "source_commit": source_commit,
        "missing_items_bound": missing_items_bound,
        "test_refs": test_refs_by_section,
        "l1_summary": l1_summary,
        "replacement_gate_report": rel(REPLACEMENT_REPORT),
        "replacement_gate_log": rel(REPLACEMENT_LOG),
        "artifact_refs": [
            rel(CONTRACT),
            rel(MATRIX),
            rel(REPLACEMENT_REPORT),
            rel(REPLACEMENT_LOG),
            rel(REPORT),
            rel(LOG),
        ],
        "failure_signature": failure_signature,
    }


events: list[dict[str, Any]] = [
    event_payload("l1_crt_startup_tls_summary", "info"),
    event_payload("replacement_levels_l1_gate_replayed", "info"),
]
if required_blocked_rows and len(blocked_rows) == len(required_blocked_rows):
    events.append(event_payload("l1_crt_startup_tls_blockers_preserved", "warning"))
if errors:
    events.append(event_payload("l1_crt_startup_tls_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("l1_crt_startup_tls_completion_contract_validated", "info"))

for index, event in enumerate(events):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - set(event))
    if missing:
        err(f"generated telemetry event {index} missing fields {missing}")
if not errors:
    emitted = {event["event"] for event in events}
    required_for_pass = EXPECTED_TELEMETRY_EVENTS - {"l1_crt_startup_tls_completion_contract_failed"}
    missing = sorted(required_for_pass - emitted)
    if missing:
        err(f"pass telemetry missing events {missing}")
        status = "fail"

LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

report = {
    "schema_version": "l1_crt_startup_tls_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": l1_summary,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "replacement_gate_report": rel(REPLACEMENT_REPORT),
    "replacement_gate_log": rel(REPLACEMENT_LOG),
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "errors": errors,
    "log": rel(LOG),
    "artifact_refs": [
        rel(CONTRACT),
        rel(MATRIX),
        rel(REPLACEMENT_REPORT),
        rel(REPLACEMENT_LOG),
        rel(REPORT),
        rel(LOG),
    ],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: L1 CRT/startup/TLS completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: L1 CRT/startup/TLS completion contract "
    f"(rows={len(matrix_rows)}, blocked={len(blocked_rows)}, report={rel(REPORT)})"
)
PY
