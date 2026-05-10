#!/usr/bin/env bash
# check_canonical_evidence_schema_v2_completion_contract.sh - bd-33p.1.1 completion-debt gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_CANONICAL_EVIDENCE_SCHEMA_CONTRACT:-${ROOT}/tests/conformance/canonical_evidence_schema_v2_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_CANONICAL_EVIDENCE_SCHEMA_REPORT:-${ROOT}/target/conformance/canonical_evidence_schema_v2_completion_contract.report.json}"
LOG="${FRANKENLIBC_CANONICAL_EVIDENCE_SCHEMA_LOG:-${ROOT}/target/conformance/canonical_evidence_schema_v2_completion_contract.log.jsonl}"
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

COMPLETION_DEBT_BEAD = "bd-33p.1.1"
ORIGINAL_BEAD = "bd-33p.1"
PASS_EVENT = "canonical_evidence_schema_v2_completion_contract_validated"
FAIL_EVENT = "canonical_evidence_schema_v2_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_FIELDS = {"timestamp", "trace_id", "level", "event"}
REQUIRED_STREAMS = {"unit", "conformance", "e2e", "perf", "release"}
REQUIRED_OPTIONAL_GROUPS = {
    "workflow_fields": {"stream", "gate"},
    "span_profile_fields": {"span_id", "parent_span_id", "profile"},
    "decision_explainability_fields": {
        "controller_id",
        "decision_id",
        "policy_id",
        "evidence_seqno",
        "decision_action",
        "risk_inputs",
    },
    "artifact_failure_fields": {
        "source_commit",
        "target_dir",
        "failure_signature",
        "artifact_refs",
    },
}
REQUIRED_BUILDERS = {
    "with_stream",
    "with_gate",
    "with_span",
    "with_profile",
    "with_controller_id",
    "with_join_keys",
    "with_decision_action",
    "with_risk_inputs",
    "with_decision_explainability",
    "with_source_commit",
    "with_target_dir",
    "with_failure_signature",
    "with_artifacts",
}
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "schema_version",
    "required_fields",
    "optional_fields",
    "test_refs",
    "artifact_refs",
    "failure_signature",
}
REQUIRED_TELEMETRY_EVENTS = {
    PASS_EVENT,
    FAIL_EVENT,
    "runtime_decision",
    "validation_pass",
}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path, errors, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
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


def as_string_set(values, label, errors):
    if not isinstance(values, list):
        errors.append(f"{label} must be an array")
        return set()
    actual = {value for value in values if isinstance(value, str)}
    if len(actual) != len(values):
        errors.append(f"{label} must contain only strings")
    return actual


def require_set(values, required, label, errors):
    actual = as_string_set(values, label, errors)
    missing = sorted(required - actual)
    if missing:
        errors.append(f"{label} missing {','.join(missing)}")
    return actual


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


errors = []
contract = load_json(contract_path, errors, "contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "canonical_evidence_schema_v2_completion_contract.v1":
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

schema_artifact = evidence.get("schema_artifact")
if not isinstance(schema_artifact, str):
    errors.append("schema_artifact missing")
    log_schema = {}
else:
    log_schema = load_json(root / schema_artifact, errors, "log_schema")
if log_schema.get("schema_version", 0) < 2:
    errors.append("log_schema.schema_version must be >= 2")

schema_required = log_schema.get("required_fields", {})
if not isinstance(schema_required, dict):
    errors.append("log_schema.required_fields must be an object")
    schema_required = {}
schema_optional = log_schema.get("optional_fields", {})
if not isinstance(schema_optional, dict):
    errors.append("log_schema.optional_fields must be an object")
    schema_optional = {}

canonical = evidence.get("canonical_fields", {})
if not isinstance(canonical, dict):
    errors.append("canonical_fields must be an object")
    canonical = {}
required_fields = require_set(
    canonical.get("required_fields"),
    REQUIRED_FIELDS,
    "canonical_fields.required_fields",
    errors,
)
required_streams = require_set(
    canonical.get("required_streams"),
    REQUIRED_STREAMS,
    "canonical_fields.required_streams",
    errors,
)
builder_methods = require_set(
    canonical.get("required_builder_methods"),
    REQUIRED_BUILDERS,
    "canonical_fields.required_builder_methods",
    errors,
)

for field in sorted(REQUIRED_FIELDS):
    if field not in schema_required:
        errors.append(f"log_schema.required_fields missing {field}")

optional_fields = set()
for group, required in REQUIRED_OPTIONAL_GROUPS.items():
    values = require_set(canonical.get(group), required, f"canonical_fields.{group}", errors)
    optional_fields.update(values)
    for field in sorted(required):
        if field not in schema_optional:
            errors.append(f"log_schema.optional_fields missing {field}")

stream_meta = schema_optional.get("stream", {})
if isinstance(stream_meta, dict):
    stream_enum = set(stream_meta.get("enum", []))
    missing_streams = sorted(REQUIRED_STREAMS - stream_enum)
    if missing_streams:
        errors.append(f"log_schema.optional_fields.stream.enum missing {','.join(missing_streams)}")
else:
    errors.append("log_schema.optional_fields.stream must be an object")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}
structured_log_text = source_texts.get("structured_log", "")

for field in sorted(required_fields | optional_fields):
    if f"pub {field}:" not in structured_log_text:
        errors.append(f"structured_log LogEntry missing field {field}")
for method in sorted(builder_methods):
    if f"pub fn {method}" not in structured_log_text:
        errors.append(f"structured_log LogEntry missing builder {method}")

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

artifacts = evidence.get("conformance_primary", {}).get("required_artifacts", [])
for artifact in artifacts:
    if not isinstance(artifact, str) or not (root / artifact).is_file():
        errors.append(f"conformance_primary.required_artifacts missing {artifact!r}")

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

telemetry = evidence.get("telemetry_primary", {})
events = telemetry.get("required_events")
if not isinstance(events, list) or not REQUIRED_TELEMETRY_EVENTS <= {
    event for event in events if isinstance(event, str)
}:
    errors.append("telemetry_primary.required_events missing required events")
fields = telemetry.get("required_fields")
if not isinstance(fields, list) or not REQUIRED_TELEMETRY_FIELDS <= {
    field for field in fields if isinstance(field, str)
}:
    errors.append("telemetry_primary.required_fields missing required keys")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
event = PASS_EVENT if not errors else FAIL_EVENT
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_DEBT_BEAD}:canonical_evidence_schema_v2",
    "event": event,
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "schema_version": "canonical_evidence_schema_v2_completion_contract.v1",
    "required_fields": sorted(required_fields),
    "optional_fields": sorted(optional_fields),
    "required_streams": sorted(required_streams),
    "builder_methods": sorted(builder_methods),
    "test_refs": sorted(set(test_refs)),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": "canonical_evidence_schema_v2_completion_contract.report.v1",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "schema_artifact": schema_artifact,
    "required_fields": sorted(required_fields),
    "optional_fields": sorted(optional_fields),
    "required_streams": sorted(required_streams),
    "builder_methods": sorted(builder_methods),
    "test_refs": sorted(set(test_refs)),
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
