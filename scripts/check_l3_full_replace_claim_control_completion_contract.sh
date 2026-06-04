#!/usr/bin/env bash
# check_l3_full_replace_claim_control_completion_contract.sh - bd-gtf.6.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_L3_FULL_REPLACE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/l3_full_replace_claim_control_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_L3_FULL_REPLACE_READINESS_MATRIX:-$ROOT/tests/conformance/standalone_readiness_proof_matrix.v1.json}"
LEVELS="${FRANKENLIBC_L3_FULL_REPLACE_REPLACEMENT_LEVELS:-$ROOT/tests/conformance/replacement_levels.json}"
DOSSIER_REPORT="${FRANKENLIBC_L3_FULL_REPLACE_DOSSIER_REPORT:-$ROOT/tests/release/dossier_validation_report.v1.json}"
REPORT="${FRANKENLIBC_L3_FULL_REPLACE_COMPLETION_REPORT:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.report.json}"
LOG="${FRANKENLIBC_L3_FULL_REPLACE_COMPLETION_LOG:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.log.jsonl}"
CURRENT_CLAIM_REPORT="${FRANKENLIBC_L3_FULL_REPLACE_CURRENT_CLAIM_REPORT:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.current_claim.report.json}"
CURRENT_CLAIM_LOG="${FRANKENLIBC_L3_FULL_REPLACE_CURRENT_CLAIM_LOG:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.current_claim.log.jsonl}"
L3_OVERCLAIM_CLAIMS="${FRANKENLIBC_L3_FULL_REPLACE_OVERCLAIM_CLAIMS:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.l3_overclaim.claims.json}"
L3_OVERCLAIM_REPORT="${FRANKENLIBC_L3_FULL_REPLACE_OVERCLAIM_REPORT:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.l3_overclaim.report.json}"
L3_OVERCLAIM_LOG="${FRANKENLIBC_L3_FULL_REPLACE_OVERCLAIM_LOG:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.l3_overclaim.log.jsonl}"
READINESS_REPORT="${FRANKENLIBC_L3_FULL_REPLACE_READINESS_REPORT:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.standalone_readiness.report.json}"
READINESS_LOG="${FRANKENLIBC_L3_FULL_REPLACE_READINESS_LOG:-$ROOT/target/conformance/l3_full_replace_claim_control_completion_contract.standalone_readiness.log.jsonl}"

mkdir -p \
  "$(dirname "$REPORT")" \
  "$(dirname "$LOG")" \
  "$(dirname "$CURRENT_CLAIM_REPORT")" \
  "$(dirname "$CURRENT_CLAIM_LOG")" \
  "$(dirname "$L3_OVERCLAIM_CLAIMS")" \
  "$(dirname "$L3_OVERCLAIM_REPORT")" \
  "$(dirname "$L3_OVERCLAIM_LOG")" \
  "$(dirname "$READINESS_REPORT")" \
  "$(dirname "$READINESS_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
MATRIX="$MATRIX" \
LEVELS="$LEVELS" \
DOSSIER_REPORT="$DOSSIER_REPORT" \
REPORT="$REPORT" \
LOG="$LOG" \
CURRENT_CLAIM_REPORT="$CURRENT_CLAIM_REPORT" \
CURRENT_CLAIM_LOG="$CURRENT_CLAIM_LOG" \
L3_OVERCLAIM_CLAIMS="$L3_OVERCLAIM_CLAIMS" \
L3_OVERCLAIM_REPORT="$L3_OVERCLAIM_REPORT" \
L3_OVERCLAIM_LOG="$L3_OVERCLAIM_LOG" \
READINESS_REPORT="$READINESS_REPORT" \
READINESS_LOG="$READINESS_LOG" \
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
DOSSIER_REPORT = pathlib.Path(os.environ["DOSSIER_REPORT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
CURRENT_CLAIM_REPORT = pathlib.Path(os.environ["CURRENT_CLAIM_REPORT"])
CURRENT_CLAIM_LOG = pathlib.Path(os.environ["CURRENT_CLAIM_LOG"])
L3_OVERCLAIM_CLAIMS = pathlib.Path(os.environ["L3_OVERCLAIM_CLAIMS"])
L3_OVERCLAIM_REPORT = pathlib.Path(os.environ["L3_OVERCLAIM_REPORT"])
L3_OVERCLAIM_LOG = pathlib.Path(os.environ["L3_OVERCLAIM_LOG"])
READINESS_REPORT = pathlib.Path(os.environ["READINESS_REPORT"])
READINESS_LOG = pathlib.Path(os.environ["READINESS_LOG"])

COMPLETION_BEAD = "bd-gtf.6.1"
ORIGINAL_BEAD = "bd-gtf.6"
EXPECTED_SCHEMA = "l3_full_replace_claim_control_completion_contract.v1"
EXPECTED_MANIFEST = "bd-gtf.6.1-l3-full-replace-claim-control-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "fuzz_primary": "tests.fuzz.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_CLAIM_LOG_FIELDS = {
    "trace_id",
    "bead_id",
    "release_claim_id",
    "replacement_level",
    "required_evidence",
    "present_evidence",
    "expected_decision",
    "actual_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
}
EXPECTED_FUZZ_MUTATION_TARGETS = {
    "completion_debt_evidence.required_claim_log_fields",
    "completion_debt_evidence.required_l3_obligation_ids",
    "completion_debt_evidence.required_l3_release_claim_failure_signatures",
    "completion_debt_evidence.telemetry_primary.required_fields",
    "synthetic_claims.claimed_level",
    "release_dossier.FLC_RELEASE_DOSSIER_RELEASE_NOTES_LIMIT",
}
EXPECTED_L3_FAILURE_SIGNATURES = {
    "release_claim_missing_l2_evidence",
    "release_claim_missing_l3_evidence",
}
EXPECTED_PASS_TELEMETRY_EVENTS = {
    "l3_full_replace_completion_contract_validated",
    "l3_full_replace_summary",
    "release_claim_current_l1_replayed",
    "release_claim_l3_overclaim_blocked",
    "release_dossier_policy_bound",
    "standalone_l3_blockers_preserved",
}
EXPECTED_TELEMETRY_EVENTS = EXPECTED_PASS_TELEMETRY_EVENTS | {
    "l3_full_replace_completion_contract_failed",
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
    "l3_summary",
    "current_claim_report",
    "current_claim_log",
    "l3_overclaim_report",
    "l3_overclaim_log",
    "readiness_gate_report",
    "readiness_gate_log",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def missing_ordered(expected: list[str], actual: list[str]) -> list[str]:
    actual_set = set(actual)
    return [item for item in expected if item not in actual_set]


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


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


def run_current_claim_gate() -> None:
    env = os.environ.copy()
    env.update({"TRACE_ID": f"{COMPLETION_BEAD}-current-l1"})
    result = subprocess.run(
        [
            "bash",
            "scripts/release/check_replacement_claim_evidence.sh",
            "--report",
            str(CURRENT_CLAIM_REPORT),
            "--log",
            str(CURRENT_CLAIM_LOG),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode != 0:
        err(
            "current L1 release claim gate failed: "
            f"exit={result.returncode} stdout={result.stdout[-1600:]} stderr={result.stderr[-1600:]}"
        )


def write_l3_overclaim_fixture() -> None:
    claims = {
        "schema_version": "v1",
        "claims": [
            {
                "id": "bd-gtf.6.1-synthetic-l3-release-overclaim",
                "tag": "v9.9.9-L3",
                "claimed_level": "L3",
                "artifact_refs": [
                    "tests/conformance/replacement_levels.json",
                    "support_matrix.json",
                    "tests/conformance/claim_reconciliation_report.v1.json",
                    "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json",
                    "tests/conformance/l1_dry_run_readiness_dashboard.v1.json",
                ],
            }
        ],
    }
    L3_OVERCLAIM_CLAIMS.write_text(json.dumps(claims, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_l3_overclaim_gate() -> None:
    write_l3_overclaim_fixture()
    env = os.environ.copy()
    env.update({"TRACE_ID": f"{COMPLETION_BEAD}-l3-overclaim"})
    result = subprocess.run(
        [
            "bash",
            "scripts/release/check_replacement_claim_evidence.sh",
            "--claims",
            str(L3_OVERCLAIM_CLAIMS),
            "--report",
            str(L3_OVERCLAIM_REPORT),
            "--log",
            str(L3_OVERCLAIM_LOG),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if result.returncode == 0:
        err("synthetic L3 overclaim gate unexpectedly passed")


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


source_commit = git_head()
contract = load_json(CONTRACT, "completion contract")
matrix = load_json(MATRIX, "standalone readiness matrix")
levels = load_json(LEVELS, "replacement levels")
dossier_report = load_json(DOSSIER_REPORT, "release dossier report")

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
        "release_claim_gate",
        "release_claim_harness",
        "release_dossier_validator",
        "release_dossier_gate",
        "release_dossier_harness",
        "release_dossier_report",
        "replacement_levels",
        "standalone_readiness_matrix",
        "standalone_readiness_gate",
        "standalone_readiness_harness",
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

required_claim_log_fields = as_string_list(
    evidence.get("required_claim_log_fields"),
    "completion_debt_evidence.required_claim_log_fields",
)
claim_log_fields = set(required_claim_log_fields)
if claim_log_fields != EXPECTED_CLAIM_LOG_FIELDS:
    missing_claim_log_fields = missing_ordered(
        sorted(EXPECTED_CLAIM_LOG_FIELDS),
        required_claim_log_fields,
    )
    if missing_claim_log_fields:
        err(
            "completion_debt_evidence.required_claim_log_fields missing "
            f"{missing_claim_log_fields}"
        )
    else:
        err(
            "completion_debt_evidence.required_claim_log_fields must match "
            "release claim gate row fields"
        )

required_l3_signature_values = as_string_list(
    evidence.get("required_l3_release_claim_failure_signatures"),
    "completion_debt_evidence.required_l3_release_claim_failure_signatures",
)
required_l3_signatures = set(required_l3_signature_values)
if not EXPECTED_L3_FAILURE_SIGNATURES.issubset(required_l3_signatures):
    missing_l3_signatures = missing_ordered(
        sorted(EXPECTED_L3_FAILURE_SIGNATURES),
        required_l3_signature_values,
    )
    if missing_l3_signatures:
        err(
            "completion_debt_evidence.required_l3_release_claim_failure_signatures missing "
            f"{missing_l3_signatures}"
        )
    else:
        err(
            "completion_debt_evidence.required_l3_release_claim_failure_signatures "
            "must include L2 and L3 missing-evidence blockers"
        )

matrix_rows = [row for row in matrix.get("proof_rows", []) if isinstance(row, dict)]
obligations = [row for row in matrix.get("obligations", []) if isinstance(row, dict)]
l3_rows = [row for row in matrix_rows if row.get("replacement_level") == "L3"]
l3_obligations = [row for row in obligations if row.get("level") == "L3"]
l3_obligation_ids = [str(row.get("id")) for row in l3_obligations if isinstance(row.get("id"), str)]
l3_negative_ids = [
    str(test.get("id"))
    for row in l3_obligations
    for test in row.get("negative_claim_tests", [])
    if isinstance(test, dict) and isinstance(test.get("id"), str)
]

required_l3_obligations = as_string_list(
    evidence.get("required_l3_obligation_ids"),
    "completion_debt_evidence.required_l3_obligation_ids",
)
if required_l3_obligations != l3_obligation_ids:
    missing_l3_obligations = missing_ordered(l3_obligation_ids, required_l3_obligations)
    if missing_l3_obligations:
        err(
            "completion_debt_evidence.required_l3_obligation_ids missing "
            f"{missing_l3_obligations}"
        )
    else:
        err(
            "completion_debt_evidence.required_l3_obligation_ids must match "
            "standalone readiness L3 obligations"
        )
required_l3_negative_tests = as_string_list(
    evidence.get("required_l3_negative_claim_tests"),
    "completion_debt_evidence.required_l3_negative_claim_tests",
)
if required_l3_negative_tests != l3_negative_ids:
    err("completion_debt_evidence.required_l3_negative_claim_tests must match standalone readiness L3 negative claim tests")

for row in l3_rows:
    row_id = row.get("proof_row_id", "<missing>")
    if row.get("expected_decision") != "claim_blocked" or row.get("actual_decision") != "claim_blocked":
        err(f"{row_id}: L3 proof rows must fail closed as claim_blocked")
    if not row.get("failure_signature"):
        err(f"{row_id}: failure_signature must be non-empty")
    if not row.get("missing_evidence"):
        err(f"{row_id}: missing_evidence must be non-empty")

for obligation in l3_obligations:
    obligation_id = obligation.get("id", "<missing>")
    if obligation.get("current_state") != "blocked":
        err(f"{obligation_id}: current_state must remain blocked")
    if obligation.get("log_fields") != "required_log_fields":
        err(f"{obligation_id}: log_fields must reference required_log_fields")
    if not obligation.get("unit_tests_required"):
        err(f"{obligation_id}: unit_tests_required must be non-empty")
    if not obligation.get("e2e_or_smoke_required"):
        err(f"{obligation_id}: e2e_or_smoke_required must be non-empty")
    negative = obligation.get("negative_claim_tests")
    if not isinstance(negative, list) or not negative:
        err(f"{obligation_id}: negative_claim_tests must be non-empty")
    elif any(not isinstance(test, dict) or test.get("expected_result") != "claim_blocked" for test in negative):
        err(f"{obligation_id}: negative claim tests must fail closed as claim_blocked")

expectations = evidence.get("minimum_l3_expectations", {})
if not isinstance(expectations, dict):
    err("completion_debt_evidence.minimum_l3_expectations must be an object")
    expectations = {}

claim_policy = matrix.get("claim_policy", {}) if isinstance(matrix.get("claim_policy"), dict) else {}
summary = matrix.get("summary", {}) if isinstance(matrix.get("summary"), dict) else {}
levels_by_id = {
    row.get("level"): row
    for row in levels.get("levels", [])
    if isinstance(row, dict) and isinstance(row.get("level"), str)
}
l3_level = levels_by_id.get("L3", {})

if len(matrix_rows) != int(expectations.get("proof_row_count", 0) or 0):
    err("proof row count does not match completion expectation")
if len(l3_rows) != int(expectations.get("l3_proof_row_count", 0) or 0):
    err("L3 proof row count does not match completion expectation")
if len(obligations) != int(expectations.get("obligation_count", 0) or 0):
    err("obligation count does not match completion expectation")
if len(l3_obligations) != int(expectations.get("l3_obligation_count", 0) or 0):
    err("L3 obligation count does not match completion expectation")
if len(l3_negative_ids) != int(expectations.get("l3_negative_claim_test_count", 0) or 0):
    err("L3 negative claim test count does not match completion expectation")
if int(summary.get("negative_claim_test_count", 0) or 0) != int(expectations.get("negative_claim_test_count", 0) or 0):
    err("negative claim test count does not match completion expectation")
if int(summary.get("blocked_obligation_count", 0) or 0) != int(expectations.get("blocked_obligation_count", 0) or 0):
    err("blocked obligation count does not match completion expectation")
if int(summary.get("claim_blocked_proof_row_count", 0) or 0) != int(expectations.get("claim_blocked_proof_row_count", 0) or 0):
    err("claim-blocked proof row count does not match completion expectation")
if int(summary.get("missing_evidence_proof_row_count", 0) or 0) != int(expectations.get("missing_evidence_proof_row_count", 0) or 0):
    err("missing-evidence proof row count does not match completion expectation")
if levels.get("current_level") != expectations.get("current_level_must_remain"):
    err("replacement_levels current_level does not match completion expectation")
if levels.get("release_tag_policy", {}).get("current_release_level") != expectations.get("current_release_level_must_remain"):
    err("replacement_levels release_tag_policy.current_release_level does not match completion expectation")
if claim_policy.get("l3_current_claim_status") != expectations.get("l3_current_claim_status"):
    err("claim_policy l3_current_claim_status does not match completion expectation")
if l3_level.get("status") != expectations.get("l3_replacement_level_status"):
    err("replacement_levels L3 status does not match completion expectation")
if l3_level.get("host_glibc_required") is not expectations.get("l3_host_glibc_required"):
    err("replacement_levels L3 host_glibc_required does not match completion expectation")
if len(l3_level.get("blockers", [])) < int(expectations.get("l3_min_blocker_count", 0) or 0):
    err("replacement_levels L3 blocker count is below completion expectation")

if dossier_report.get("status") != expectations.get("release_dossier_report_status"):
    err("release dossier report status does not match completion expectation")
if dossier_report.get("verdict") != expectations.get("release_dossier_verdict"):
    err("release dossier verdict does not match completion expectation")
if not isinstance(dossier_report.get("release_notes_hook"), dict):
    err("release dossier report must include release_notes_hook")
if not any(
    isinstance(row, dict) and row.get("id") == "replacement_levels" and row.get("status") == "VALID"
    for row in dossier_report.get("artifact_results", [])
):
    err("release dossier report must bind replacement_levels as a valid artifact")
if not any(
    isinstance(row, dict) and row.get("id") == "closure_contract" and row.get("status") == "VALID"
    for row in dossier_report.get("artifact_results", [])
):
    err("release dossier report must bind closure_contract as a valid artifact")

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

run_current_claim_gate()
run_l3_overclaim_gate()
run_readiness_gate(source_commit)

current_claim_report = load_json(CURRENT_CLAIM_REPORT, "current L1 release claim report")
current_claim_rows = load_jsonl(CURRENT_CLAIM_LOG, "current L1 release claim log")
l3_overclaim_report = load_json(L3_OVERCLAIM_REPORT, "synthetic L3 overclaim report")
l3_overclaim_rows = load_jsonl(L3_OVERCLAIM_LOG, "synthetic L3 overclaim log")
readiness_report = load_json(READINESS_REPORT, "standalone readiness report")
readiness_rows = load_jsonl(READINESS_LOG, "standalone readiness log")

if current_claim_report.get("status") != expectations.get("release_claim_current_l1_status"):
    err("current L1 release claim report status does not match completion expectation")
if len(current_claim_rows) != int(current_claim_report.get("claim_count", 0) or 0):
    err("current L1 release claim log row count mismatch")
for index, row in enumerate(current_claim_rows):
    missing = sorted(EXPECTED_CLAIM_LOG_FIELDS - set(row))
    if missing:
        err(f"current L1 release claim log row {index} missing fields {missing}")
    if row.get("actual_decision") != "claim_allowed":
        err(f"current L1 release claim log row {index} must remain claim_allowed")

if l3_overclaim_report.get("status") != expectations.get("l3_overclaim_status"):
    err("synthetic L3 overclaim report status does not match completion expectation")
if not l3_overclaim_rows:
    err("synthetic L3 overclaim log must contain at least one row")
for index, row in enumerate(l3_overclaim_rows):
    missing = sorted(EXPECTED_CLAIM_LOG_FIELDS - set(row))
    if missing:
        err(f"synthetic L3 overclaim log row {index} missing fields {missing}")
    if row.get("replacement_level") != "L3":
        err(f"synthetic L3 overclaim log row {index} replacement_level must be L3")
    if row.get("actual_decision") != expectations.get("l3_overclaim_actual_decision"):
        err(f"synthetic L3 overclaim log row {index} actual_decision must remain claim_blocked")
    signature = str(row.get("failure_signature", ""))
    for required in required_l3_signatures:
        if required not in signature:
            err(f"synthetic L3 overclaim log row {index} missing failure signature {required}")

if readiness_report.get("status") != expectations.get("readiness_matrix_gate_status"):
    err("standalone readiness report status does not match completion expectation")
if int(readiness_report.get("proof_row_count", 0) or 0) != len(matrix_rows):
    err("standalone readiness report proof_row_count mismatch")
if int(readiness_report.get("obligation_count", 0) or 0) != len(obligations):
    err("standalone readiness report obligation_count mismatch")
if len(readiness_rows) != len(matrix_rows):
    err("standalone readiness log row count must match proof row count")

l3_summary = {
    "proof_row_count": len(matrix_rows),
    "l3_proof_row_count": len(l3_rows),
    "obligation_count": len(obligations),
    "l3_obligation_count": len(l3_obligations),
    "l3_obligations": l3_obligation_ids,
    "l3_negative_claim_tests": l3_negative_ids,
    "claim_policy": claim_policy,
    "replacement_current_level": levels.get("current_level"),
    "replacement_current_release_level": levels.get("release_tag_policy", {}).get("current_release_level"),
    "replacement_l3_status": l3_level.get("status") if isinstance(l3_level, dict) else None,
    "replacement_l3_host_glibc_required": l3_level.get("host_glibc_required") if isinstance(l3_level, dict) else None,
    "replacement_l3_blocker_count": len(l3_level.get("blockers", [])) if isinstance(l3_level, dict) else 0,
    "current_claim_status": current_claim_report.get("status"),
    "l3_overclaim_status": l3_overclaim_report.get("status"),
    "l3_overclaim_failure_signature": (
        l3_overclaim_rows[0].get("failure_signature") if l3_overclaim_rows else ""
    ),
    "readiness_gate_status": readiness_report.get("status"),
    "dossier_status": dossier_report.get("status"),
    "dossier_verdict": dossier_report.get("verdict"),
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
        "l3_summary": l3_summary,
        "current_claim_report": rel(CURRENT_CLAIM_REPORT),
        "current_claim_log": rel(CURRENT_CLAIM_LOG),
        "l3_overclaim_report": rel(L3_OVERCLAIM_REPORT),
        "l3_overclaim_log": rel(L3_OVERCLAIM_LOG),
        "readiness_gate_report": rel(READINESS_REPORT),
        "readiness_gate_log": rel(READINESS_LOG),
        "artifact_refs": [
            rel(CONTRACT),
            rel(MATRIX),
            rel(LEVELS),
            rel(DOSSIER_REPORT),
            rel(CURRENT_CLAIM_REPORT),
            rel(CURRENT_CLAIM_LOG),
            rel(L3_OVERCLAIM_CLAIMS),
            rel(L3_OVERCLAIM_REPORT),
            rel(L3_OVERCLAIM_LOG),
            rel(READINESS_REPORT),
            rel(READINESS_LOG),
            rel(REPORT),
            rel(LOG),
        ],
        "failure_signature": failure_signature,
    }


events: list[dict[str, Any]] = [
    event_payload("l3_full_replace_summary", "info"),
    event_payload("release_claim_current_l1_replayed", "info"),
    event_payload("release_claim_l3_overclaim_blocked", "warning"),
    event_payload("release_dossier_policy_bound", "info"),
]
if l3_obligations and all(row.get("current_state") == "blocked" for row in l3_obligations):
    events.append(event_payload("standalone_l3_blockers_preserved", "warning"))
if errors:
    events.append(event_payload("l3_full_replace_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("l3_full_replace_completion_contract_validated", "info"))

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
    "schema_version": "l3_full_replace_claim_control_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": l3_summary,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "current_claim_report": rel(CURRENT_CLAIM_REPORT),
    "current_claim_log": rel(CURRENT_CLAIM_LOG),
    "l3_overclaim_report": rel(L3_OVERCLAIM_REPORT),
    "l3_overclaim_log": rel(L3_OVERCLAIM_LOG),
    "readiness_gate_report": rel(READINESS_REPORT),
    "readiness_gate_log": rel(READINESS_LOG),
    "dossier_report": rel(DOSSIER_REPORT),
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "errors": errors,
    "log": rel(LOG),
    "artifact_refs": [
        rel(CONTRACT),
        rel(MATRIX),
        rel(LEVELS),
        rel(DOSSIER_REPORT),
        rel(CURRENT_CLAIM_REPORT),
        rel(CURRENT_CLAIM_LOG),
        rel(L3_OVERCLAIM_CLAIMS),
        rel(L3_OVERCLAIM_REPORT),
        rel(L3_OVERCLAIM_LOG),
        rel(READINESS_REPORT),
        rel(READINESS_LOG),
        rel(REPORT),
        rel(LOG),
    ],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: L3 full-replacement claim-control completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: L3 full-replacement claim-control completion contract "
    f"(l3_obligations={len(l3_obligations)}, l3_proof_rows={len(l3_rows)}, report={rel(REPORT)})"
)
PY
