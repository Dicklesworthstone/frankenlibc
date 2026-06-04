#!/usr/bin/env bash
# check_standalone_readiness_matrix_completion_contract.sh - bd-bp8fl.6.6.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_CONTRACT:-$ROOT/tests/conformance/standalone_readiness_matrix_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_MATRIX:-$ROOT/tests/conformance/standalone_readiness_proof_matrix.v1.json}"
LEVELS="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_LEVELS:-$ROOT/tests/conformance/replacement_levels.json}"
REPORT="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_REPORT:-$ROOT/target/conformance/standalone_readiness_matrix_completion_contract.report.json}"
LOG="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_LOG:-$ROOT/target/conformance/standalone_readiness_matrix_completion_contract.log.jsonl}"
READINESS_REPORT="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_SOURCE_REPORT:-$ROOT/target/conformance/standalone_readiness_matrix_completion_contract.source.report.json}"
READINESS_LOG="${FRANKENLIBC_STANDALONE_READINESS_COMPLETION_SOURCE_LOG:-$ROOT/target/conformance/standalone_readiness_matrix_completion_contract.source.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$READINESS_REPORT")" "$(dirname "$READINESS_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
MATRIX="$MATRIX" \
LEVELS="$LEVELS" \
REPORT="$REPORT" \
LOG="$LOG" \
READINESS_REPORT="$READINESS_REPORT" \
READINESS_LOG="$READINESS_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
MATRIX = pathlib.Path(os.environ["MATRIX"])
LEVELS = pathlib.Path(os.environ["LEVELS"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
READINESS_REPORT = pathlib.Path(os.environ["READINESS_REPORT"])
READINESS_LOG = pathlib.Path(os.environ["READINESS_LOG"])

COMPLETION_BEAD = "bd-bp8fl.6.6.1"
ORIGINAL_BEAD = "bd-bp8fl.6.6"
EXPECTED_SCHEMA = "standalone_readiness_matrix_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.6.6.1-standalone-readiness-matrix-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_PASS_EVENTS = {
    "standalone_readiness_matrix_completion_contract_validated",
    "standalone_readiness_matrix_replayed",
    "standalone_readiness_l2_l3_blockers_preserved",
    "standalone_readiness_completion_summary",
}
EXPECTED_EVENTS = EXPECTED_PASS_EVENTS | {
    "standalone_readiness_matrix_completion_contract_failed",
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
    "readiness_summary",
    "readiness_gate_report",
    "readiness_gate_log",
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


def validate_repo_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must stay repo-relative: {path_text}")
        return None
    full = ROOT / path
    if not full.exists():
        err(f"{context} references missing path: {path_text}")
        return None
    return full


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        path = validate_repo_path(path_text, f"test_sources.{key}")
        if path is not None:
            texts[key] = path.read_text(encoding="utf-8")
    return texts


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
        source_text = texts.get(source, "")
        if not source_text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif not function_exists(source_text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def run_source_gate() -> None:
    env = os.environ.copy()
    env.update(
        {
            "FLC_STANDALONE_READINESS_MATRIX": str(MATRIX),
            "FLC_STANDALONE_READINESS_LEVELS": str(LEVELS),
            "FLC_STANDALONE_READINESS_REPORT": str(READINESS_REPORT),
            "FLC_STANDALONE_READINESS_LOG": str(READINESS_LOG),
        }
    )
    proc = subprocess.run(
        ["bash", str(ROOT / "scripts/check_standalone_readiness_matrix.sh")],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        err(
            "source standalone readiness gate failed "
            f"exit={proc.returncode} stdout={proc.stdout[-2000:]} stderr={proc.stderr[-2000:]}"
        )


def event_payload(event: str, level: str, status: str, source_commit: str, test_refs: list[dict[str, str]], readiness_summary: dict[str, Any]) -> dict[str, Any]:
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
        "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS.values()),
        "test_refs": test_refs,
        "readiness_summary": readiness_summary,
        "readiness_gate_report": rel(READINESS_REPORT),
        "readiness_gate_log": rel(READINESS_LOG),
        "artifact_refs": [
            "tests/conformance/standalone_readiness_matrix_completion_contract.v1.json",
            "tests/conformance/standalone_readiness_proof_matrix.v1.json",
            "scripts/check_standalone_readiness_matrix_completion_contract.sh",
            "scripts/check_standalone_readiness_matrix.sh",
        ],
        "failure_signature": None if status == "pass" else "standalone_readiness_matrix_completion_contract_failed",
    }


contract = load_json(CONTRACT, "completion contract")
matrix = load_json(MATRIX, "standalone readiness matrix")
levels = load_json(LEVELS, "replacement levels")
source_commit = git_head()

if contract.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if contract.get("bead") != COMPLETION_BEAD or contract.get("original_bead") != ORIGINAL_BEAD:
    err("contract bead/original_bead binding is incorrect")

for key, path_text in contract.get("source_artifacts", {}).items():
    validate_repo_path(path_text, f"source_artifacts.{key}")

evidence = contract.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

bindings = evidence.get("missing_item_bindings", [])
bound_items = {}
if not isinstance(bindings, list) or not bindings:
    err("completion_debt_evidence.missing_item_bindings must be a non-empty array")
else:
    for binding in bindings:
        if not isinstance(binding, dict):
            err("missing item binding must be an object")
            continue
        section = binding.get("evidence_section")
        item = binding.get("missing_item_id")
        if section not in EXPECTED_MISSING_ITEMS:
            err(f"unexpected missing item evidence section: {section}")
            continue
        bound_items[section] = item
for section, expected in EXPECTED_MISSING_ITEMS.items():
    if bound_items.get(section) != expected:
        err(f"{section} must bind missing item {expected}")

for index, ref in enumerate(evidence.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"implementation_refs[{index}]")

texts = source_texts(evidence.get("test_sources"))
all_test_refs: list[dict[str, str]] = []
for section_name in EXPECTED_MISSING_ITEMS:
    section = evidence.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != EXPECTED_MISSING_ITEMS[section_name]:
        err(f"completion_debt_evidence.{section_name}.missing_item_id is incorrect")
    all_test_refs.extend(validate_test_refs(section, section_name, texts))
    validate_required_commands(section, section_name)

matrix_contract = evidence.get("required_matrix_contract", {})
if not isinstance(matrix_contract, dict):
    err("completion_debt_evidence.required_matrix_contract must be an object")
    matrix_contract = {}

required_log_fields = as_string_list(matrix_contract.get("required_log_fields"), "required_matrix_contract.required_log_fields")
if matrix.get("required_log_fields") != required_log_fields:
    err("standalone readiness matrix required_log_fields do not match completion contract")

required_proof_ids = set(as_string_list(matrix_contract.get("required_proof_row_ids"), "required_matrix_contract.required_proof_row_ids"))
proof_rows = matrix.get("proof_rows", [])
proof_by_id = {row.get("proof_row_id"): row for row in proof_rows if isinstance(row, dict)}
missing_proof_ids = sorted(required_proof_ids - set(proof_by_id))
if missing_proof_ids:
    err("standalone readiness matrix missing proof rows: " + ", ".join(missing_proof_ids))
if len(proof_rows) < int(matrix_contract.get("minimum_proof_row_count", 0)):
    err("standalone readiness matrix proof_row_count below completion threshold")
for proof_id in required_proof_ids:
    row = proof_by_id.get(proof_id, {})
    if row.get("expected_decision") != "claim_blocked" or row.get("actual_decision") != "claim_blocked":
        err(f"{proof_id}: proof row must fail closed with claim_blocked")
    if not row.get("missing_evidence"):
        err(f"{proof_id}: proof row must retain explicit missing_evidence")

required_obligation_ids = set(as_string_list(matrix_contract.get("required_obligation_ids"), "required_matrix_contract.required_obligation_ids"))
obligations = matrix.get("obligations", [])
obligation_by_id = {row.get("id"): row for row in obligations if isinstance(row, dict)}
missing_obligations = sorted(required_obligation_ids - set(obligation_by_id))
if missing_obligations:
    err("standalone readiness matrix missing obligations: " + ", ".join(missing_obligations))
if len(obligations) < int(matrix_contract.get("minimum_obligation_count", 0)):
    err("standalone readiness matrix obligation_count below completion threshold")
negative_count = 0
for obligation_id in required_obligation_ids:
    obligation = obligation_by_id.get(obligation_id, {})
    if obligation.get("current_state") != "blocked":
        err(f"{obligation_id}: current_state must remain blocked")
    tests = obligation.get("negative_claim_tests", [])
    if not isinstance(tests, list) or not tests:
        err(f"{obligation_id}: negative_claim_tests must be non-empty")
    else:
        negative_count += len(tests)
        for test in tests:
            if not isinstance(test, dict) or test.get("expected_result") != "claim_blocked":
                err(f"{obligation_id}: negative claim test must expect claim_blocked")
if negative_count < int(matrix_contract.get("minimum_negative_claim_test_count", 0)):
    err("standalone readiness matrix negative_claim_test_count below completion threshold")

levels_seen = {
    entry.get("level")
    for entry in matrix.get("readiness_levels", [])
    if isinstance(entry, dict)
}
expected_levels = set(as_string_list(matrix_contract.get("required_readiness_levels"), "required_matrix_contract.required_readiness_levels"))
if levels_seen != expected_levels:
    err(f"readiness_levels must be exactly {sorted(expected_levels)}")
readiness_by_level = {
    entry.get("level"): entry
    for entry in matrix.get("readiness_levels", [])
    if isinstance(entry, dict)
}
for level in expected_levels:
    entry = readiness_by_level.get(level, {})
    if entry.get("current_claim_status") != "blocked" or not entry.get("blocked_reason"):
        err(f"{level}: current_claim_status must remain blocked with blocked_reason")

claim_policy = matrix.get("claim_policy", {})
for key, expected in matrix_contract.get("claim_policy_must_block", {}).items():
    if claim_policy.get(key) != expected:
        err(f"claim_policy.{key} must remain {expected!r}")
expected_current_level = matrix_contract.get("replacement_levels_current_level")
if expected_current_level not in {"L0", "L1"}:
    err("replacement_levels current_level contract must remain below L2")
elif levels.get("current_level") != expected_current_level:
    err("replacement_levels current_level does not match readiness completion contract")

run_source_gate()
source_report = load_json(READINESS_REPORT, "source readiness report")
source_log_rows = load_jsonl(READINESS_LOG, "source readiness log")
if source_report.get("status") != "pass":
    err("source readiness report must pass")
for check in as_string_list(matrix_contract.get("required_gate_checks"), "required_matrix_contract.required_gate_checks"):
    if source_report.get("checks", {}).get(check) != "pass":
        err(f"source readiness report check {check} must pass")
if source_report.get("proof_row_count", 0) < matrix_contract.get("minimum_proof_row_count", 0):
    err("source readiness report proof_row_count below threshold")
if source_report.get("obligation_count", 0) < matrix_contract.get("minimum_obligation_count", 0):
    err("source readiness report obligation_count below threshold")
if source_report.get("claim_blocked_proof_row_count") != source_report.get("proof_row_count"):
    err("source readiness report must keep all proof rows claim_blocked")
if len(source_log_rows) != source_report.get("proof_row_count"):
    err("source readiness log row count must match proof_row_count")
for index, row in enumerate(source_log_rows, start=1):
    missing_fields = [field for field in required_log_fields if field not in row]
    if missing_fields:
        err(f"source readiness log row {index} missing fields: {', '.join(missing_fields)}")

telemetry = evidence.get("telemetry_primary", {})
declared_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
if declared_events != EXPECTED_EVENTS:
    err("telemetry_primary.required_events must include exactly the expected pass and fail events")
declared_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
if declared_fields != EXPECTED_TELEMETRY_FIELDS:
    err("telemetry_primary.required_fields must match the completion log schema")

readiness_summary = {
    "proof_row_count": source_report.get("proof_row_count"),
    "obligation_count": source_report.get("obligation_count"),
    "negative_claim_test_count": source_report.get("negative_claim_test_count"),
    "claim_blocked_proof_row_count": source_report.get("claim_blocked_proof_row_count"),
    "missing_evidence_proof_row_count": source_report.get("missing_evidence_proof_row_count"),
    "by_level": source_report.get("by_level"),
    "missing_dimensions": source_report.get("missing_dimensions"),
    "missing_proof_surfaces": source_report.get("missing_proof_surfaces"),
}

status = "pass" if not errors else "fail"
event_names = (
    sorted(EXPECTED_PASS_EVENTS)
    if status == "pass"
    else ["standalone_readiness_matrix_completion_contract_failed"]
)
events = [
    event_payload(
        event=name,
        level="info" if status == "pass" else "error",
        status=status,
        source_commit=source_commit,
        test_refs=all_test_refs,
        readiness_summary=readiness_summary,
    )
    for name in event_names
]

report = {
    "schema_version": EXPECTED_SCHEMA,
    "bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "status": status,
    "source_commit": source_commit,
    "missing_items_bound": sorted(EXPECTED_MISSING_ITEMS.values()),
    "readiness_summary": readiness_summary,
    "source_report": rel(READINESS_REPORT),
    "source_log": rel(READINESS_LOG),
    "completion_report": rel(REPORT),
    "completion_log": rel(LOG),
    "telemetry_events": [event["event"] for event in events],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
