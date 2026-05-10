#!/usr/bin/env bash
# check_validation_pipeline_stage_coverage_contract.sh — bd-32e.5.1 completion-debt evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_VALIDATION_PIPELINE_CONTRACT:-${ROOT}/tests/conformance/validation_pipeline_stage_coverage_contract.v1.json}"
REPORT="${FRANKENLIBC_VALIDATION_PIPELINE_REPORT:-${ROOT}/target/conformance/validation_pipeline_stage_coverage_contract.report.json}"
LOG="${FRANKENLIBC_VALIDATION_PIPELINE_LOG:-${ROOT}/target/conformance/validation_pipeline_stage_coverage_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

COMPLETION_DEBT_BEAD = "bd-32e.5.1"
ORIGINAL_BEAD = "bd-32e.5"
PASS_EVENT = "validation_pipeline_stage_coverage_contract_validated"
FAIL_EVENT = "validation_pipeline_stage_coverage_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "property_primary": "tests.property.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_STAGE_LABELS = {
    "null_check",
    "tls_cache",
    "bloom",
    "arena_lookup",
    "fingerprint",
    "canary",
    "bounds",
}
REQUIRED_STAGE_PATHS = {
    "pipeline::stage1::null_check",
    "pipeline::stage2::tls_cache",
    "pipeline::stage3::bloom",
    "pipeline::stage4::arena",
    "pipeline::stage5::fingerprint",
    "pipeline::stage6::canary",
    "pipeline::stage7::bounds",
}
REQUIRED_OUTCOMES = {
    "Null",
    "Foreign",
    "Validated",
    "CachedValid",
    "TemporalViolation",
    "Invalid",
    "Denied",
}
REQUIRED_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "test_refs",
    "required_stage_labels",
    "required_stage_paths",
    "required_outcomes",
    "artifact_refs",
    "failure_signature",
}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path, errors):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}


def read_source(path_text, source_name, errors):
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"test_sources.{source_name} missing")
        return ""
    path = root / path_text
    if not path.is_file():
        errors.append(f"test_sources.{source_name} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"test_sources.{source_name} unreadable: {path_text}: {exc}")
        return ""


def file_line_ref_exists(ref, errors):
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"invalid file-line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"invalid file-line ref line: {ref}")
        return
    path = root / path_text
    if line_no <= 0 or not path.is_file():
        errors.append(f"file-line ref missing path or positive line: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        errors.append(f"file-line ref outside file: {ref}")


def function_exists(source_text, name):
    return f"fn {name}" in source_text


def require_string_set(values, required, label, errors):
    if not isinstance(values, list):
        errors.append(f"{label} must be an array")
        return set()
    actual = {value for value in values if isinstance(value, str)}
    missing = sorted(required - actual)
    if missing:
        errors.append(f"{label} missing {','.join(missing)}")
    return actual


errors = []
contract = load_json(contract_path, errors)
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "validation_pipeline_stage_coverage_contract.v1":
    errors.append("schema_version drifted")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if evidence.get("next_audit_score_threshold", 0) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

for ref in evidence.get("implementation_refs", []):
    file_line_ref_exists(ref, errors)

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}
validator_text = source_texts.get("ptr_validator_unit", "")

stage = evidence.get("stage_coverage", {})
if not isinstance(stage, dict):
    errors.append("stage_coverage must be an object")
    stage = {}
stage_labels = require_string_set(
    stage.get("required_stage_labels"),
    REQUIRED_STAGE_LABELS,
    "stage_coverage.required_stage_labels",
    errors,
)
stage_paths = require_string_set(
    stage.get("required_stage_paths"),
    REQUIRED_STAGE_PATHS,
    "stage_coverage.required_stage_paths",
    errors,
)
outcomes = require_string_set(
    stage.get("required_outcomes"),
    REQUIRED_OUTCOMES,
    "stage_coverage.required_outcomes",
    errors,
)
for label in sorted(REQUIRED_STAGE_LABELS):
    if label not in validator_text:
        errors.append(f"ptr_validator source missing stage label {label}")
for path in sorted(REQUIRED_STAGE_PATHS):
    if path not in validator_text:
        errors.append(f"ptr_validator source missing stage path {path}")
for outcome in sorted(REQUIRED_OUTCOMES):
    if f"ValidationOutcome::{outcome}" not in validator_text and outcome not in validator_text:
        errors.append(f"ptr_validator source missing outcome {outcome}")

test_refs = []
for section, missing_item_id in REQUIRED_SECTIONS.items():
    block = evidence.get(section)
    if not isinstance(block, dict):
        errors.append(f"{section} missing")
        continue
    if block.get("missing_item_id") != missing_item_id:
        errors.append(f"{section}.missing_item_id must be {missing_item_id}")
    refs = block.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section}.required_test_refs missing")
        continue
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{section}.required_test_refs entry must be object")
            continue
        source_key = ref.get("source")
        name = ref.get("name")
        if not isinstance(source_key, str) or source_key not in source_texts:
            errors.append(f"{section} references undeclared source {source_key!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_texts[source_key], name):
            errors.append(f"{section} references missing test {source_key}::{name}")
            continue
        test_refs.append(f"{source_key}::{name}")

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

telemetry = evidence.get("telemetry_primary", {})
events = telemetry.get("required_events")
required_events = {PASS_EVENT, FAIL_EVENT, "validation_stage", "validation_terminal", "validation_order_rewrite"}
if not isinstance(events, list) or not required_events <= {event for event in events if isinstance(event, str)}:
    errors.append("telemetry_primary.required_events missing required events")
fields = telemetry.get("required_fields")
if not isinstance(fields, list) or not REQUIRED_FIELDS <= {field for field in fields if isinstance(field, str)}:
    errors.append("telemetry_primary.required_fields missing required keys")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
event = PASS_EVENT if not errors else FAIL_EVENT
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:validation_pipeline_stage_coverage",
    "event": event,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "test_refs": sorted(set(test_refs)),
    "required_stage_labels": sorted(stage_labels),
    "required_stage_paths": sorted(stage_paths),
    "required_outcomes": sorted(outcomes),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "validation_pipeline_stage_coverage_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "test_refs": sorted(set(test_refs)),
    "required_stage_labels": sorted(stage_labels),
    "required_stage_paths": sorted(stage_paths),
    "required_outcomes": sorted(outcomes),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    sys.exit(1)
PY
