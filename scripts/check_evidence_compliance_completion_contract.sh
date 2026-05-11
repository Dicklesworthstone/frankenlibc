#!/usr/bin/env bash
# check_evidence_compliance_completion_contract.sh - bd-33p.3.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_EVIDENCE_COMPLIANCE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/evidence_compliance_gate_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_EVIDENCE_COMPLIANCE_COMPLETION_REPORT:-$ROOT/target/conformance/evidence_compliance_gate_completion_contract.report.json}"
LOG="${FRANKENLIBC_EVIDENCE_COMPLIANCE_COMPLETION_LOG:-$ROOT/target/conformance/evidence_compliance_gate_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

COMPLETION_BEAD = "bd-33p.3.1"
ORIGINAL_BEAD = "bd-33p.3"
EXPECTED_SCHEMA = "evidence_compliance_gate_completion_contract.v1"
EXPECTED_MANIFEST = "bd-33p.3.1-evidence-compliance-gate-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
}
EXPECTED_VIOLATION_CODES = {
    "artifact_index.join_keys.empty",
    "artifact_index.join_keys.bad_trace_id",
    "artifact_index.join_keys.bad_decision_id",
    "artifact_index.join_keys.bad_policy_id",
    "artifact_index.missing",
    "artifact_index.invalid_json",
    "artifact_index.bad_version",
    "artifact_index.artifact_missing",
    "artifact_index.sha_mismatch",
    "artifact_index.sha_error",
    "log.schema_violation",
    "log.missing",
    "failure_event.missing_artifact_refs",
    "failure_artifact_ref.missing",
    "failure_artifact_ref.not_indexed",
}
EXPECTED_PROOF_EVENTS = {
    "evidence_compliance.proof_start",
    "evidence_compliance.artifact_index_load",
    "evidence_compliance.artifact_index_loaded",
    "evidence_compliance.artifact_index_legacy_defaults",
    "evidence_compliance.artifact_hash_compute",
    "evidence_compliance.artifact_hash_mismatch",
    "evidence_compliance.log_schema_violation",
    "evidence_compliance.failure_event_missing_artifact_refs",
    "evidence_compliance.proof_summary",
    "evidence_compliance.proof_failure",
}
EXPECTED_TRIAGE_FIELDS = {
    "violation_code",
    "offending_event",
    "expected_fields",
    "remediation_hint",
    "artifact_pointer",
    "line_number",
    "message",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "stream",
    "gate",
    "outcome",
    "violation_code_count",
    "triage_fields",
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


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{rel(path)} must be a JSON object")
        return {}
    return value


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def as_string_list(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value:
        err(f"{context} must be a non-empty array")
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


def validate_test_ref(ref: Any, context: str, texts: dict[str, str]) -> dict[str, str] | None:
    if not isinstance(ref, dict):
        err(f"{context} must be an object")
        return None
    source = ref.get("source")
    name = ref.get("name")
    if not isinstance(source, str) or not source:
        err(f"{context}.source must be non-empty")
        return None
    if not isinstance(name, str) or not name:
        err(f"{context}.name must be non-empty")
        return None
    text = texts.get(source, "")
    if not text:
        err(f"{context} references unknown source {source}")
    elif f"fn {name}" not in text:
        err(f"{context} references missing test {source}::{name}")
    return {"source": source, "name": name}


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        normalized_ref = validate_test_ref(
            ref,
            f"completion_debt_evidence.{section_name}.required_test_refs[{index}]",
            texts,
        )
        if normalized_ref is None:
            continue
        key = (normalized_ref["source"], normalized_ref["name"])
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {key[0]}::{key[1]}")
        seen.add(key)
        normalized.append(normalized_ref)
    return normalized


manifest = load_json(CONTRACT)
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

for source in as_string_list(manifest.get("source_modules"), "source_modules"):
    if not (ROOT / source).is_file():
        err(f"source module missing: {source}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    completion = {}
    err("completion_debt_evidence must be an object")

if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 15:
    err("completion_debt_evidence.implementation_refs must contain at least 15 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800 or section_threshold > 1000:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be 800..1000")
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")

contract = completion.get("compliance_contract")
if not isinstance(contract, dict):
    err("completion_debt_evidence.compliance_contract must be an object")
    contract = {}

violation_codes = set(as_string_list(contract.get("required_violation_codes"), "compliance_contract.required_violation_codes"))
missing_codes = sorted(EXPECTED_VIOLATION_CODES - violation_codes)
if missing_codes:
    err(f"compliance_contract.required_violation_codes missing {missing_codes}")

proof_events = set(as_string_list(contract.get("required_proof_events"), "compliance_contract.required_proof_events"))
missing_events = sorted(EXPECTED_PROOF_EVENTS - proof_events)
if missing_events:
    err(f"compliance_contract.required_proof_events missing {missing_events}")

triage_fields = set(as_string_list(contract.get("required_triage_fields"), "compliance_contract.required_triage_fields"))
missing_triage = sorted(EXPECTED_TRIAGE_FIELDS - triage_fields)
if missing_triage:
    err(f"compliance_contract.required_triage_fields missing {missing_triage}")

module_text = texts.get("evidence_compliance_module", "")
for code in EXPECTED_VIOLATION_CODES:
    if f'"{code}"' not in module_text:
        err(f"evidence_compliance module no longer emits violation code {code}")
for event in EXPECTED_PROOF_EVENTS:
    if f'"{event}"' not in module_text:
        err(f"evidence_compliance module no longer emits proof event {event}")

cli_text = texts.get("harness_cli", "")
for field in EXPECTED_TRIAGE_FIELDS:
    if f'"{field}"' not in cli_text:
        err(f"harness CLI triage output no longer includes field {field}")

gate_scripts = as_string_list(contract.get("required_gate_scripts"), "compliance_contract.required_gate_scripts")
for script in gate_scripts:
    if not (ROOT / script).is_file():
        err(f"required gate script missing: {script}")

check_script = (ROOT / "scripts/check_evidence_compliance.sh").read_text(encoding="utf-8")
for needle in [
    "cargo build -p frankenlibc-harness --bin harness",
    "cargo test -p frankenlibc-harness --test evidence_compliance_test -- --nocapture",
]:
    if needle not in check_script:
        err(f"scripts/check_evidence_compliance.sh missing needle {needle}")

ci_text = (ROOT / "scripts/ci.sh").read_text(encoding="utf-8")
for needle in as_string_list(contract.get("required_ci_needles"), "compliance_contract.required_ci_needles"):
    if needle not in ci_text:
        err(f"scripts/ci.sh missing evidence compliance needle {needle}")

telemetry = completion.get("telemetry_primary")
required_telemetry_events: set[str] = set()
required_telemetry_fields: set[str] = set()
if isinstance(telemetry, dict):
    if telemetry.get("default_report_path") != "target/conformance/evidence_compliance_gate_completion_contract.report.json":
        err("telemetry_primary.default_report_path drifted")
    if telemetry.get("default_log_path") != "target/conformance/evidence_compliance_gate_completion_contract.log.jsonl":
        err("telemetry_primary.default_log_path drifted")
    required_telemetry_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    required_telemetry_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
else:
    err("completion_debt_evidence.telemetry_primary must be an object")

for event in [
    "evidence_compliance_gate_completion_contract_validated",
    "evidence_compliance_gate_completion_contract_failed",
]:
    if event not in required_telemetry_events:
        err(f"telemetry_primary.required_events missing {event}")
missing_telemetry_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_telemetry_fields)
if missing_telemetry_fields:
    err(f"telemetry_primary.required_fields missing {missing_telemetry_fields}")

source_commit = git_head()
status = "fail" if errors else "pass"
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    "crates/frankenlibc-harness/src/evidence_compliance.rs",
    "crates/frankenlibc-harness/src/bin/harness.rs",
    "crates/frankenlibc-harness/tests/evidence_compliance_test.rs",
    "scripts/check_evidence_compliance.sh",
]
report = {
    "schema_version": "evidence_compliance_gate_completion_contract.report.v1",
    "timestamp": now,
    "status": status,
    "bead_id": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "missing_items": missing_items_bound,
    "violation_codes": sorted(violation_codes),
    "proof_events": sorted(proof_events),
    "triage_fields": sorted(triage_fields),
    "required_telemetry_fields": sorted(required_telemetry_fields),
    "test_refs": test_refs_by_section,
    "artifact_refs": artifact_refs,
    "errors": errors,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_row = {
    "timestamp": now,
    "trace_id": f"{COMPLETION_BEAD}::evidence-compliance-contract::001",
    "level": "error" if errors else "info",
    "event": (
        "evidence_compliance_gate_completion_contract_failed"
        if errors
        else "evidence_compliance_gate_completion_contract_validated"
    ),
    "bead_id": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "stream": "conformance",
    "gate": "evidence_compliance_gate_completion_contract",
    "outcome": status,
    "violation_code_count": len(violation_codes),
    "triage_fields": sorted(triage_fields),
    "artifact_refs": artifact_refs,
    "failure_signature": "none" if not errors else "; ".join(errors),
    "mode": "strict",
    "runtime_mode": "strict",
    "api_family": "evidence",
    "symbol": "evidence_compliance",
    "decision_path": "contract->evidence_compliance->artifact_index->triage",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 1,
}
LOG.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    for message in errors:
        print(f"error: {message}", file=sys.stderr)
    sys.exit(1)

print(
    "evidence compliance completion contract validated: "
    f"missing_items={len(missing_items_bound)} violation_codes={len(violation_codes)} "
    f"proof_events={len(proof_events)} triage_fields={len(triage_fields)}"
)
PY
