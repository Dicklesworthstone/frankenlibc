#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_CONTRACT:-$ROOT/tests/conformance/universal_evidence_schema_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_REPORT:-$OUT_DIR/universal_evidence_schema_completion_contract.report.json}"
LOG="${FRANKENLIBC_UNIVERSAL_EVIDENCE_SCHEMA_COMPLETION_LOG:-$OUT_DIR/universal_evidence_schema_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
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
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "universal_evidence_schema_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "universal_evidence_schema_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-bp8fl.7.5"
COMPLETION_BEAD = "bd-bp8fl.7.5.1"

BASE_REQUIRED_FIELDS = {"timestamp", "trace_id", "level", "event"}
REQUIRED_UNIVERSAL_FIELDS = {
    "bead_id",
    "scenario_id",
    "mode",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "decision_path",
    "healing_action",
    "latency_ns",
    "source_commit",
    "target_dir",
    "failure_signature",
    "artifact_refs",
}
REQUIRED_STREAMS = {"unit", "conformance", "e2e"}
REQUIRED_SCHEMA_EXAMPLES = {"ambition_evidence", "artifact_index", "test_failure"}
REQUIRED_TELEMETRY_EVENTS = {
    "universal_evidence_schema_completion_summary",
    "universal_evidence_schema_source_bindings",
    "universal_evidence_schema_compliance_bindings",
    "universal_evidence_schema_completion_contract_pass",
    "universal_evidence_schema_completion_contract_fail",
}
PASS_EVENT = "universal_evidence_schema_completion_contract_pass"
FAIL_EVENT = "universal_evidence_schema_completion_contract_fail"

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


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


def source_text(path_text: str, label: str) -> str:
    try:
        return (ROOT / path_text).read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {path_text}: {exc}")
        return ""


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


def require_set(values: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(values, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
for artifact_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{artifact_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {artifact_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

required_universal_fields = require_set(
    evidence.get("required_universal_fields"),
    REQUIRED_UNIVERSAL_FIELDS,
    "completion_debt_evidence.required_universal_fields",
)
required_streams = require_set(
    evidence.get("required_streams"),
    REQUIRED_STREAMS,
    "completion_debt_evidence.required_streams",
)
required_schema_examples = require_set(
    evidence.get("required_schema_examples"),
    REQUIRED_SCHEMA_EXAMPLES,
    "completion_debt_evidence.required_schema_examples",
)

log_schema_path = source_artifacts.get("log_schema")
log_schema = load_json(ROOT / str(log_schema_path), "log_schema") if isinstance(log_schema_path, str) else {}
schema_required = log_schema.get("required_fields", {})
schema_optional = log_schema.get("optional_fields", {})
schema_examples = log_schema.get("examples", {})
if not isinstance(schema_required, dict):
    err("log_schema.required_fields must be an object")
    schema_required = {}
if not isinstance(schema_optional, dict):
    err("log_schema.optional_fields must be an object")
    schema_optional = {}
if not isinstance(schema_examples, dict):
    err("log_schema.examples must be an object")
    schema_examples = {}
for field in sorted(BASE_REQUIRED_FIELDS):
    require(field in schema_required, f"log_schema.required_fields missing {field}")
for field in sorted(required_universal_fields):
    require(field in schema_optional, f"log_schema.optional_fields missing {field}")
for example in sorted(required_schema_examples):
    require(example in schema_examples, f"log_schema.examples missing {example}")
ambition_example = schema_examples.get("ambition_evidence", {})
if isinstance(ambition_example, dict):
    for field in sorted(required_universal_fields):
        require(field in ambition_example, f"log_schema ambition_evidence example missing {field}")
else:
    err("log_schema.examples.ambition_evidence must be an object")
stream_meta = schema_optional.get("stream", {})
if isinstance(stream_meta, dict):
    require(required_streams.issubset(set(stream_meta.get("enum", []))), "log_schema stream enum missing unit/conformance/e2e")
else:
    err("log_schema.optional_fields.stream must be an object")

source_texts: dict[str, str] = {}
for artifact_id, path_text in source_artifacts.items():
    if isinstance(path_text, str) and path_text.endswith((".rs", ".sh", ".json")) and (ROOT / path_text).is_file():
        source_texts[artifact_id] = source_text(path_text, artifact_id)

for ref in evidence.get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} is missing path")
        continue
    text = source_text(path_text, str(ref.get("id", "implementation_ref")))
    for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id')}.required_text"):
        require(needle in text, f"implementation ref {ref.get('id')} missing required text {needle!r} in {path_text}")

structured_log = source_texts.get("structured_log_source", "")
for field in sorted(required_universal_fields):
    if field not in {"expected", "actual"}:
        require(f"pub {field}:" in structured_log, f"LogEntry missing field {field}")
for method in [
    "with_runtime_mode",
    "with_replacement_level",
    "with_api",
    "with_oracle_kind",
    "with_expected_actual",
    "with_errno",
    "with_decision_path",
    "with_healing_action",
    "with_latency_ns",
    "with_source_commit",
    "with_target_dir",
    "with_failure_signature",
    "with_artifacts",
]:
    require(f"pub fn {method}" in structured_log, f"LogEntry missing builder {method}")
for anchor in [
    "runtime_mode",
    "is_ambition_evidence_event",
    "ambition_evidence events must include non-empty string artifact_refs array",
    "failing ambition_evidence events must include a concrete failure_signature",
]:
    require(anchor in structured_log, f"structured_log.rs missing validator anchor {anchor}")

evidence_compliance = source_texts.get("evidence_compliance_source", "")
for anchor in [
    "validate_evidence_bundle",
    "validate_failure_artifact_refs",
    "failure_event.missing_artifact_refs",
    "evidence_compliance.failure_event_missing_artifact_refs",
    "evidence_compliance.proof_summary",
]:
    require(anchor in evidence_compliance, f"evidence_compliance.rs missing anchor {anchor}")

test_refs: list[str] = []
test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
    test_sources = {}
for source_id, spec in test_sources.items():
    if not isinstance(spec, dict):
        err(f"test source {source_id} must be an object")
        continue
    path_text = spec.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"test source {source_id} must include path")
        continue
    text = source_text(path_text, source_id)
    for test_ref in as_string_list(spec.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
        require(function_exists(text, test_ref), f"test source {source_id} missing required test ref {test_ref}")
        test_refs.append(f"{source_id}::{test_ref}")

bindings = manifest.get("missing_item_bindings", [])
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
binding_ids = {binding.get("id") for binding in bindings if isinstance(binding, dict)}
for missing_item in ["tests.unit.primary", "tests.e2e.primary", "tests.conformance.primary", "telemetry.primary"]:
    require(missing_item in binding_ids, f"missing_item_bindings missing {missing_item}")
for binding in bindings:
    if not isinstance(binding, dict):
        err("missing_item_bindings entries must be objects")
        continue
    if binding.get("id") == "tests.conformance.primary":
        artifacts = binding.get("required_artifacts")
        for artifact in as_string_list(artifacts, "tests.conformance.primary.required_artifacts"):
            require((ROOT / artifact).is_file(), f"conformance artifact missing: {artifact}")
    else:
        refs = as_string_list(binding.get("required_test_refs"), f"{binding.get('id')}.required_test_refs")
        for ref in refs:
            require(any(ref in recorded for recorded in test_refs), f"{binding.get('id')} references missing test ref {ref}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
required_log_fields = as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
required_report_fields = as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields")
declared_events = require_set(telemetry.get("required_events"), REQUIRED_TELEMETRY_EVENTS, "telemetry_contract.required_events")
for event in sorted(declared_events - REQUIRED_TELEMETRY_EVENTS):
    err(f"telemetry_contract.required_events declares unimplemented event {event}")
row_field_names = {
    "timestamp",
    "trace_id",
    "event",
    "bead_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "outcome",
    "source_commit",
    "schema_version",
    "required_universal_fields",
    "test_refs",
    "artifact_refs",
    "failure_signature",
    "stream",
    "gate",
    "details",
}
report_field_names = {
    "schema_version",
    "manifest_id",
    "source_bead",
    "completion_debt_bead",
    "status",
    "source_commit",
    "summary",
    "required_universal_fields",
    "source_artifacts",
    "test_refs",
    "events",
    "errors",
}
for field in required_log_fields:
    require(field in row_field_names, f"checker telemetry row missing required log field {field}")
for field in required_report_fields:
    require(field in report_field_names, f"checker report missing required report field {field}")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
source_commit = git_head()
status = "pass" if not errors else "fail"
outcome = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(CONTRACT), rel(REPORT), rel(LOG)]

events = [
    {
        "event": "universal_evidence_schema_completion_summary",
        "stream": "conformance",
        "gate": "universal_evidence_schema_completion_contract",
        "details": {
            "required_universal_field_count": len(required_universal_fields),
            "source_artifact_count": len(source_artifacts),
            "test_ref_count": len(set(test_refs)),
        },
    },
    {
        "event": "universal_evidence_schema_source_bindings",
        "stream": "unit",
        "gate": "universal_evidence_schema_completion_contract",
        "details": {
            "required_universal_fields": sorted(required_universal_fields),
            "schema_examples": sorted(required_schema_examples),
            "required_streams": sorted(required_streams),
        },
    },
    {
        "event": "universal_evidence_schema_compliance_bindings",
        "stream": "e2e",
        "gate": "universal_evidence_schema_completion_contract",
        "details": {
            "test_refs": sorted(set(test_refs)),
            "compliance_script": source_artifacts.get("evidence_compliance_checker"),
        },
    },
    {
        "event": PASS_EVENT if not errors else FAIL_EVENT,
        "stream": "release",
        "gate": "universal_evidence_schema_completion_contract",
        "details": {
            "required_report_fields": required_report_fields,
            "required_log_fields": required_log_fields,
            "declared_events": sorted(declared_events),
        },
    },
]

rows: list[dict[str, Any]] = []
for seq, event in enumerate(events, start=1):
    row = {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_BEAD}::universal-evidence-schema-completion::{seq:03d}",
        "event": event["event"],
        "bead_id": COMPLETION_BEAD,
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": outcome,
        "source_commit": source_commit,
        "schema_version": EXPECTED_SCHEMA,
        "required_universal_fields": sorted(required_universal_fields),
        "test_refs": sorted(set(test_refs)),
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature,
        "stream": event["stream"],
        "gate": event["gate"],
        "details": event["details"],
    }
    rows.append(row)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "required_universal_fields": len(required_universal_fields),
        "source_artifacts": len(source_artifacts),
        "test_refs": len(set(test_refs)),
        "missing_item_bindings": len(binding_ids),
        "telemetry_events": len(declared_events),
    },
    "required_universal_fields": sorted(required_universal_fields),
    "source_artifacts": source_artifacts,
    "test_refs": sorted(set(test_refs)),
    "events": [row["event"] for row in rows],
    "errors": errors,
}
if errors and FAIL_EVENT not in report["events"]:
    err(f"failure telemetry must include {FAIL_EVENT}")

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    raise SystemExit(1)
PY
