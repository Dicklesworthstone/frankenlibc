#!/usr/bin/env bash
# check_l2_partial_replace_completion_contract.sh - bd-gtf.5.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_L2_PARTIAL_REPLACE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/l2_partial_replace_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_L2_PARTIAL_REPLACE_READINESS_MATRIX:-$ROOT/tests/conformance/standalone_readiness_proof_matrix.v1.json}"
LEVELS="${FRANKENLIBC_L2_PARTIAL_REPLACE_REPLACEMENT_LEVELS:-$ROOT/tests/conformance/replacement_levels.json}"
ARTIFACT="${FRANKENLIBC_L2_PARTIAL_REPLACE_STANDALONE_ARTIFACT:-$ROOT/tests/conformance/standalone_replacement_artifact.v1.json}"
REPORT="${FRANKENLIBC_L2_PARTIAL_REPLACE_COMPLETION_REPORT:-$ROOT/target/conformance/l2_partial_replace_completion_contract.report.json}"
LOG="${FRANKENLIBC_L2_PARTIAL_REPLACE_COMPLETION_LOG:-$ROOT/target/conformance/l2_partial_replace_completion_contract.log.jsonl}"
READINESS_REPORT="${FRANKENLIBC_L2_PARTIAL_REPLACE_READINESS_REPORT:-$ROOT/target/conformance/l2_partial_replace_completion_contract.standalone_readiness.report.json}"
READINESS_LOG="${FRANKENLIBC_L2_PARTIAL_REPLACE_READINESS_LOG:-$ROOT/target/conformance/l2_partial_replace_completion_contract.standalone_readiness.log.jsonl}"
ARTIFACT_REPORT="${FRANKENLIBC_L2_PARTIAL_REPLACE_ARTIFACT_REPORT:-$ROOT/target/conformance/l2_partial_replace_completion_contract.standalone_artifact.report.json}"
ARTIFACT_LOG="${FRANKENLIBC_L2_PARTIAL_REPLACE_ARTIFACT_LOG:-$ROOT/target/conformance/l2_partial_replace_completion_contract.standalone_artifact.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$READINESS_REPORT")" "$(dirname "$READINESS_LOG")" "$(dirname "$ARTIFACT_REPORT")" "$(dirname "$ARTIFACT_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
MATRIX="$MATRIX" \
LEVELS="$LEVELS" \
ARTIFACT="$ARTIFACT" \
REPORT="$REPORT" \
LOG="$LOG" \
READINESS_REPORT="$READINESS_REPORT" \
READINESS_LOG="$READINESS_LOG" \
ARTIFACT_REPORT="$ARTIFACT_REPORT" \
ARTIFACT_LOG="$ARTIFACT_LOG" \
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
LEVELS = pathlib.Path(os.environ["LEVELS"])
ARTIFACT = pathlib.Path(os.environ["ARTIFACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
READINESS_REPORT = pathlib.Path(os.environ["READINESS_REPORT"])
READINESS_LOG = pathlib.Path(os.environ["READINESS_LOG"])
ARTIFACT_REPORT = pathlib.Path(os.environ["ARTIFACT_REPORT"])
ARTIFACT_LOG = pathlib.Path(os.environ["ARTIFACT_LOG"])

COMPLETION_BEAD = "bd-gtf.5.1"
ORIGINAL_BEAD = "bd-gtf.5"
MATRIX_BEAD = "bd-bp8fl.6.6"
ARTIFACT_BEAD = "bd-srtkq"
EXPECTED_SCHEMA = "l2_partial_replace_completion_contract.v1"
EXPECTED_MANIFEST = "bd-gtf.5.1-l2-partial-replace-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "fuzz_primary": "tests.fuzz.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_FUZZ_MUTATION_TARGETS = {
    "completion_debt_evidence.required_log_fields",
    "completion_debt_evidence.required_l2_obligation_ids",
    "completion_debt_evidence.required_negative_claim_tests",
    "completion_debt_evidence.telemetry_primary.required_fields",
}
EXPECTED_PASS_TELEMETRY_EVENTS = {
    "l2_partial_replace_completion_contract_validated",
    "l2_partial_replace_summary",
    "standalone_readiness_matrix_replayed",
    "standalone_artifact_validate_only_replayed",
    "standalone_dependency_policy_blockers_preserved",
}
EXPECTED_TELEMETRY_EVENTS = EXPECTED_PASS_TELEMETRY_EVENTS | {
    "l2_partial_replace_completion_contract_failed",
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
    "l2_summary",
    "readiness_gate_report",
    "readiness_gate_log",
    "artifact_gate_report",
    "artifact_gate_log",
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


def run_readiness_gate(source_commit: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "FLC_STANDALONE_READINESS_MATRIX": str(MATRIX),
            "FLC_STANDALONE_READINESS_LEVELS": str(LEVELS),
            "FLC_STANDALONE_READINESS_OUT_DIR": str(READINESS_REPORT.parent),
            "FLC_STANDALONE_READINESS_REPORT": str(READINESS_REPORT),
            "FLC_STANDALONE_READINESS_LOG": str(READINESS_LOG),
            "SOURCE_COMMIT": source_commit,
        }
    )
    result = subprocess.run(
        ["bash", "scripts/check_standalone_readiness_matrix.sh"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        err(
            "standalone readiness matrix gate failed: "
            f"exit={result.returncode} stdout={result.stdout[-1600:]} stderr={result.stderr[-1600:]}"
        )


def run_artifact_gate() -> None:
    out_dir = ARTIFACT_REPORT.parent / "l2_partial_replace_completion_contract.artifact-out"
    env = os.environ.copy()
    env.update(
        {
            "STANDALONE_REPLACEMENT_MANIFEST": str(ARTIFACT),
            "STANDALONE_REPLACEMENT_OUT_DIR": str(out_dir),
            "STANDALONE_REPLACEMENT_CARGO_TARGET_DIR": str(out_dir / "cargo-target"),
            "STANDALONE_REPLACEMENT_REPORT": str(ARTIFACT_REPORT),
            "STANDALONE_REPLACEMENT_LOG": str(ARTIFACT_LOG),
        }
    )
    env.pop("FRANKENLIBC_STANDALONE_LIB", None)
    env.pop("LD_PRELOAD", None)
    result = subprocess.run(
        ["bash", "scripts/check_standalone_replacement_artifact.sh", "--validate-only"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        err(
            "standalone replacement artifact validate-only gate failed: "
            f"exit={result.returncode} stdout={result.stdout[-1600:]} stderr={result.stderr[-1600:]}"
        )


source_commit = git_head()
contract = load_json(CONTRACT, "completion contract")
matrix = load_json(MATRIX, "standalone readiness matrix")
levels = load_json(LEVELS, "replacement levels")
artifact = load_json(ARTIFACT, "standalone replacement artifact")

if contract.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if contract.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

source_artifacts = contract.get("source_artifacts", {})
if not isinstance(source_artifacts, dict):
    err("source_artifacts must be an object")
else:
    for key in [
        "standalone_readiness_matrix",
        "standalone_readiness_gate",
        "standalone_readiness_harness",
        "standalone_replacement_artifact",
        "standalone_replacement_artifact_gate",
        "standalone_replacement_artifact_harness",
        "replacement_levels",
        "completion_gate",
        "completion_harness",
    ]:
        value = source_artifacts.get(key)
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{key} must be a non-empty string")
        elif not (ROOT / value).is_file():
            err(f"source_artifacts.{key} references missing file: {value}")

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

fuzz_targets = set(as_string_list(evidence.get("required_fuzz_mutation_targets"), "completion_debt_evidence.required_fuzz_mutation_targets"))
missing_fuzz_targets = sorted(EXPECTED_FUZZ_MUTATION_TARGETS - fuzz_targets)
if missing_fuzz_targets:
    err(f"completion_debt_evidence.required_fuzz_mutation_targets missing {missing_fuzz_targets}")

matrix_rows = [row for row in matrix.get("proof_rows", []) if isinstance(row, dict)]
obligations = [row for row in matrix.get("obligations", []) if isinstance(row, dict)]
required_log_fields = as_string_list(evidence.get("required_log_fields"), "completion_debt_evidence.required_log_fields")
required_row_ids = as_string_list(evidence.get("required_proof_row_ids"), "completion_debt_evidence.required_proof_row_ids")
required_l2_obligations = as_string_list(evidence.get("required_l2_obligation_ids"), "completion_debt_evidence.required_l2_obligation_ids")
required_obligations = as_string_list(evidence.get("required_obligation_ids"), "completion_debt_evidence.required_obligation_ids")
required_negative_tests = as_string_list(
    evidence.get("required_negative_claim_tests"),
    "completion_debt_evidence.required_negative_claim_tests",
)

matrix_log_fields = matrix.get("required_log_fields")
if required_log_fields != matrix_log_fields:
    err("completion_debt_evidence.required_log_fields must match standalone readiness matrix required_log_fields")
matrix_row_ids = [str(row.get("proof_row_id")) for row in matrix_rows if isinstance(row.get("proof_row_id"), str)]
if required_row_ids != matrix_row_ids:
    err("completion_debt_evidence.required_proof_row_ids must match standalone readiness matrix proof_rows")
l2_obligations = [row for row in obligations if row.get("level") == "L2"]
l3_obligations = [row for row in obligations if row.get("level") == "L3"]
l2_obligation_ids = [str(row.get("id")) for row in l2_obligations if isinstance(row.get("id"), str)]
obligation_ids = [str(row.get("id")) for row in obligations if isinstance(row.get("id"), str)]
if required_l2_obligations != l2_obligation_ids:
    err("completion_debt_evidence.required_l2_obligation_ids must match standalone readiness matrix L2 obligations")
if required_obligations != obligation_ids:
    err("completion_debt_evidence.required_obligation_ids must match standalone readiness matrix obligations")
negative_ids = [
    str(test.get("id"))
    for row in obligations
    for test in row.get("negative_claim_tests", [])
    if isinstance(test, dict) and isinstance(test.get("id"), str)
]
if required_negative_tests != negative_ids:
    err("completion_debt_evidence.required_negative_claim_tests must match standalone readiness matrix negative claim tests")

expectations = evidence.get("minimum_l2_expectations", {})
if not isinstance(expectations, dict):
    err("completion_debt_evidence.minimum_l2_expectations must be an object")
    expectations = {}

claim_policy = matrix.get("claim_policy", {}) if isinstance(matrix.get("claim_policy"), dict) else {}
summary = matrix.get("summary", {}) if isinstance(matrix.get("summary"), dict) else {}
proof_rows_by_level = {
    "L2": sum(1 for row in matrix_rows if row.get("replacement_level") == "L2"),
    "L3": sum(1 for row in matrix_rows if row.get("replacement_level") == "L3"),
}

for row in matrix_rows:
    row_id = row.get("proof_row_id", "<missing>")
    if row.get("replacement_level") not in {"L2", "L3"}:
        err(f"{row_id}: replacement_level must be L2 or L3")
    if row.get("expected_decision") != "claim_blocked" or row.get("actual_decision") != "claim_blocked":
        err(f"{row_id}: standalone readiness proof rows must fail closed as claim_blocked")
    for field in ["artifact_refs", "required_evidence", "present_evidence", "missing_evidence"]:
        if not row.get(field):
            err(f"{row_id}: {field} must be non-empty")
    if not row.get("failure_signature"):
        err(f"{row_id}: failure_signature must be non-empty")

for obligation in obligations:
    obligation_id = obligation.get("id", "<missing>")
    if obligation.get("current_state") != "blocked":
        err(f"{obligation_id}: current_state must remain blocked")
    if obligation.get("log_fields") != "required_log_fields":
        err(f"{obligation_id}: log_fields must reference required_log_fields")
    if not obligation.get("unit_tests_required"):
        err(f"{obligation_id}: unit_tests_required must be non-empty")
    if not obligation.get("e2e_or_smoke_required"):
        err(f"{obligation_id}: e2e_or_smoke_required must be non-empty")
    tests = obligation.get("negative_claim_tests")
    if not isinstance(tests, list) or not tests:
        err(f"{obligation_id}: negative_claim_tests must be non-empty")
    else:
        for test in tests:
            if not isinstance(test, dict) or test.get("expected_result") != "claim_blocked":
                err(f"{obligation_id}: negative claim tests must fail closed as claim_blocked")

if len(matrix_rows) != int(expectations.get("proof_row_count", 0) or 0):
    err("proof row count does not match completion expectation")
if proof_rows_by_level["L2"] != int(expectations.get("l2_proof_row_count", 0) or 0):
    err("L2 proof row count does not match completion expectation")
if proof_rows_by_level["L3"] != int(expectations.get("l3_proof_row_count", 0) or 0):
    err("L3 proof row count does not match completion expectation")
if len(obligations) != int(expectations.get("obligation_count", 0) or 0):
    err("obligation count does not match completion expectation")
if len(l2_obligations) != int(expectations.get("l2_obligation_count", 0) or 0):
    err("L2 obligation count does not match completion expectation")
if len(l3_obligations) != int(expectations.get("l3_obligation_count", 0) or 0):
    err("L3 obligation count does not match completion expectation")
if len(negative_ids) != int(expectations.get("negative_claim_test_count", 0) or 0):
    err("negative claim test count does not match completion expectation")
if int(summary.get("blocked_obligation_count", 0) or 0) != int(expectations.get("blocked_obligation_count", 0) or 0):
    err("blocked obligation count does not match completion expectation")
if int(summary.get("claim_blocked_proof_row_count", 0) or 0) != int(expectations.get("claim_blocked_proof_row_count", 0) or 0):
    err("claim-blocked proof row count does not match completion expectation")
if int(summary.get("missing_evidence_proof_row_count", 0) or 0) != int(expectations.get("missing_evidence_proof_row_count", 0) or 0):
    err("missing-evidence proof row count does not match completion expectation")
if claim_policy.get("current_level_must_remain") != expectations.get("current_level_must_remain"):
    err("claim_policy current_level_must_remain does not match completion expectation")
if claim_policy.get("l2_current_claim_status") != expectations.get("l2_current_claim_status"):
    err("claim_policy l2_current_claim_status does not match completion expectation")
if claim_policy.get("l3_current_claim_status") != expectations.get("l3_current_claim_status"):
    err("claim_policy l3_current_claim_status does not match completion expectation")
if claim_policy.get("symbol_counts_are_insufficient") is not expectations.get("symbol_counts_are_insufficient"):
    err("claim_policy symbol_counts_are_insufficient does not match completion expectation")
if claim_policy.get("interpose_value_is_not_standalone_readiness") is not expectations.get("interpose_value_is_not_standalone_readiness"):
    err("claim_policy interpose_value_is_not_standalone_readiness does not match completion expectation")

l2_level = next((row for row in levels.get("levels", []) if isinstance(row, dict) and row.get("level") == "L2"), {})
if levels.get("current_level") != expectations.get("current_level_must_remain"):
    err("replacement_levels current_level does not match completion expectation")
if not isinstance(l2_level, dict) or l2_level.get("status") != expectations.get("l2_replacement_level_status"):
    err("replacement_levels L2 status does not match completion expectation")

if artifact.get("bead") != ARTIFACT_BEAD:
    err(f"standalone replacement artifact bead must be {ARTIFACT_BEAD}")
artifact_policy = artifact.get("artifact_policy", {}) if isinstance(artifact.get("artifact_policy"), dict) else {}
if artifact_policy.get("ld_preload_substitutes_allowed") is not False:
    err("standalone artifact policy must forbid LD_PRELOAD substituting for standalone evidence")
if artifact_policy.get("canonical_artifact_name") != "libfrankenlibc_replace.so":
    err("standalone artifact policy canonical name must be libfrankenlibc_replace.so")

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

run_readiness_gate(source_commit)
run_artifact_gate()

readiness_report = load_json(READINESS_REPORT, "standalone readiness report")
readiness_log_rows = load_jsonl(READINESS_LOG, "standalone readiness log")
artifact_report = load_json(ARTIFACT_REPORT, "standalone artifact validate-only report")
artifact_log_rows = load_jsonl(ARTIFACT_LOG, "standalone artifact validate-only log")

if readiness_report.get("status") != expectations.get("readiness_matrix_gate_status"):
    err("standalone readiness report status does not match completion expectation")
if readiness_report.get("bead") != MATRIX_BEAD:
    err(f"standalone readiness report bead must be {MATRIX_BEAD}")
if int(readiness_report.get("proof_row_count", 0) or 0) != len(matrix_rows):
    err("standalone readiness report proof_row_count mismatch")
if int(readiness_report.get("obligation_count", 0) or 0) != len(obligations):
    err("standalone readiness report obligation_count mismatch")
if int(readiness_report.get("negative_claim_test_count", 0) or 0) != len(negative_ids):
    err("standalone readiness report negative_claim_test_count mismatch")

if len(readiness_log_rows) != len(matrix_rows):
    err("standalone readiness log row count must match proof row count")
for index, row in enumerate(readiness_log_rows):
    for field in required_log_fields:
        if field not in row:
            err(f"standalone readiness log row {index} missing required field {field}")
    if row.get("actual_decision") != "claim_blocked":
        err(f"standalone readiness log row {index} actual_decision must remain claim_blocked")

if artifact_report.get("status") != expectations.get("standalone_artifact_validate_only_status"):
    err("standalone artifact validate-only report status does not match completion expectation")
if artifact_report.get("claim_status") != expectations.get("standalone_artifact_validate_only_claim_status"):
    err("standalone artifact validate-only claim_status does not match completion expectation")
if artifact_report.get("mode") != "validate-only":
    err("standalone artifact report mode must be validate-only")
artifact_state = artifact_report.get("artifact_state", {}) if isinstance(artifact_report.get("artifact_state"), dict) else {}
if artifact_state.get("status") != "not_checked":
    err("standalone artifact validate-only must not inspect or claim a current artifact")
if len(artifact_log_rows) != 1:
    err("standalone artifact validate-only log must contain exactly one row")
for index, row in enumerate(artifact_log_rows):
    for field in artifact.get("required_log_fields", []):
        if field not in row:
            err(f"standalone artifact validate-only log row {index} missing required field {field}")

l2_summary = {
    "proof_row_count": len(matrix_rows),
    "l2_proof_row_count": proof_rows_by_level["L2"],
    "l3_proof_row_count": proof_rows_by_level["L3"],
    "obligation_count": len(obligations),
    "l2_obligation_count": len(l2_obligations),
    "l3_obligation_count": len(l3_obligations),
    "l2_obligations": required_l2_obligations,
    "negative_claim_tests": required_negative_tests,
    "claim_policy": claim_policy,
    "replacement_current_level": levels.get("current_level"),
    "replacement_l2_status": l2_level.get("status") if isinstance(l2_level, dict) else None,
    "readiness_gate_status": readiness_report.get("status"),
    "artifact_gate_status": artifact_report.get("status"),
    "artifact_claim_status": artifact_report.get("claim_status"),
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
        "l2_summary": l2_summary,
        "readiness_gate_report": rel(READINESS_REPORT),
        "readiness_gate_log": rel(READINESS_LOG),
        "artifact_gate_report": rel(ARTIFACT_REPORT),
        "artifact_gate_log": rel(ARTIFACT_LOG),
        "artifact_refs": [
            rel(CONTRACT),
            rel(MATRIX),
            rel(LEVELS),
            rel(ARTIFACT),
            rel(READINESS_REPORT),
            rel(READINESS_LOG),
            rel(ARTIFACT_REPORT),
            rel(ARTIFACT_LOG),
            rel(REPORT),
            rel(LOG),
        ],
        "failure_signature": failure_signature,
    }


events: list[dict[str, Any]] = [
    event_payload("l2_partial_replace_summary", "info"),
    event_payload("standalone_readiness_matrix_replayed", "info"),
    event_payload("standalone_artifact_validate_only_replayed", "info"),
]
if l2_obligations and all(row.get("current_state") == "blocked" for row in l2_obligations):
    events.append(event_payload("standalone_dependency_policy_blockers_preserved", "warning"))
if errors:
    events.append(event_payload("l2_partial_replace_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("l2_partial_replace_completion_contract_validated", "info"))

for index, event in enumerate(events):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - set(event))
    if missing:
        err(f"generated telemetry event {index} missing fields {missing}")
if not errors:
    emitted = {event["event"] for event in events}
    missing = sorted(EXPECTED_PASS_TELEMETRY_EVENTS - emitted)
    if missing:
        err(f"pass telemetry missing events {missing}")
        status = "fail"
        for event in events:
            event["status"] = status

LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

report = {
    "schema_version": "l2_partial_replace_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": l2_summary,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "readiness_gate_report": rel(READINESS_REPORT),
    "readiness_gate_log": rel(READINESS_LOG),
    "artifact_gate_report": rel(ARTIFACT_REPORT),
    "artifact_gate_log": rel(ARTIFACT_LOG),
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "errors": errors,
    "log": rel(LOG),
    "artifact_refs": [
        rel(CONTRACT),
        rel(MATRIX),
        rel(LEVELS),
        rel(ARTIFACT),
        rel(READINESS_REPORT),
        rel(READINESS_LOG),
        rel(ARTIFACT_REPORT),
        rel(ARTIFACT_LOG),
        rel(REPORT),
        rel(LOG),
    ],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: L2 partial-replacement completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: L2 partial-replacement completion contract "
    f"(proof_rows={len(matrix_rows)}, l2_obligations={len(l2_obligations)}, report={rel(REPORT)})"
)
PY
