#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_CONTRACT:-$ROOT/tests/conformance/math_production_set_policy_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_REPORT:-$OUT_DIR/math_production_set_policy_completion_contract.report.json}"
LOG="${FRANKENLIBC_MATH_PRODUCTION_POLICY_COMPLETION_LOG:-$OUT_DIR/math_production_set_policy_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "math_production_set_policy_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "math_production_set_policy_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-25pf"
COMPLETION_BEAD = "bd-25pf.1"
PASS_EVENT = "math_production_set_policy_completion_contract_pass"
FAIL_EVENT = "math_production_set_policy_completion_contract_fail"
REQUIRED_SOURCE_ARTIFACTS = {
    "production_set_policy",
    "production_set_policy_gate",
    "source_harness_test",
    "production_manifest",
    "governance",
    "linkage",
    "value_proof",
    "retirement_policy",
    "admission_report",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_TELEMETRY_EVENTS = {
    "math_production_set_policy_completion_summary",
    "math_production_set_policy_source_bindings",
    "math_production_set_policy_test_bindings",
    PASS_EVENT,
    FAIL_EVENT,
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


def read_text(path_text: str, label: str) -> str:
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


def require_set(value: Any, required: set[str], context: str) -> set[str]:
    actual = set(as_string_list(value, context))
    missing = sorted(required - actual)
    if missing:
        err(f"{context} missing {','.join(missing)}")
    return actual


def function_exists(source: str, name: str) -> bool:
    return f"fn {name}" in source


def positive_int(value: Any, context: str) -> int:
    try:
        parsed = int(value)
    except Exception:
        err(f"{context} must be an integer")
        return -1
    if parsed <= 0:
        err(f"{context} must be positive")
    return parsed


def run_source_gate(script_path: str, expected_stdout: str) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    output = subprocess.run(
        ["bash", script_path],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    transcript = f"stdout:\n{output.stdout}\nstderr:\n{output.stderr}"
    require(output.returncode == 0, f"source policy gate failed with exit {output.returncode}: {transcript}")
    require(expected_stdout in output.stdout, f"source policy gate stdout missing {expected_stdout!r}")
    source_report = load_json(ROOT / "target/conformance/math_production_set_policy.report.json", "source_policy_report")
    rows: list[dict[str, Any]] = []
    log_path = ROOT / "target/conformance/math_production_set_policy.log.jsonl"
    try:
        for index, line in enumerate(log_path.read_text(encoding="utf-8").splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except Exception as exc:
                err(f"source policy log line {index} is not JSON: {exc}")
                continue
            if isinstance(row, dict):
                rows.append(row)
            else:
                err(f"source policy log line {index} must be an object")
    except Exception as exc:
        err(f"source policy log unreadable: {rel(log_path)}: {exc}")
    return source_report, rows, transcript


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
missing_sources = sorted(REQUIRED_SOURCE_ARTIFACTS - set(source_artifacts))
if missing_sources:
    err(f"source_artifacts missing {','.join(missing_sources)}")
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
policy_contract = evidence.get("required_policy_contract", {})
if not isinstance(policy_contract, dict):
    err("completion_debt_evidence.required_policy_contract must be an object")
    policy_contract = {}
require(policy_contract.get("schema_version") == 1, "required policy schema_version must be 1")
require(policy_contract.get("bead") == ORIGINAL_BEAD, f"required policy bead must be {ORIGINAL_BEAD}")
expected_summary = policy_contract.get("summary", {})
if not isinstance(expected_summary, dict):
    err("required_policy_contract.summary must be an object")
    expected_summary = {}
expected_change_gate = policy_contract.get("change_gate", {})
if not isinstance(expected_change_gate, dict):
    err("required_policy_contract.change_gate must be an object")
    expected_change_gate = {}
required_log_fields = require_set(
    policy_contract.get("required_source_log_fields"),
    {
        "timestamp",
        "trace_id",
        "mode",
        "symbol",
        "outcome",
        "errno",
        "timing_ns",
        "gate",
        "classification",
        "linkage_status",
        "reasons",
    },
    "required_policy_contract.required_source_log_fields",
)

source_policy_path = source_artifacts.get("production_set_policy")
source_policy = load_json(ROOT / str(source_policy_path), "production_set_policy") if isinstance(source_policy_path, str) else {}
require(source_policy.get("schema_version") == 1, "production set policy schema mismatch")
require(source_policy.get("bead") == ORIGINAL_BEAD, "production set policy bead mismatch")
policy_summary = source_policy.get("summary", {})
if not isinstance(policy_summary, dict):
    err("production set policy summary must be an object")
    policy_summary = {}
for field, expected in expected_summary.items():
    require(policy_summary.get(field) == expected, f"production set policy summary.{field} mismatch")
change_gate = source_policy.get("policy", {}).get("change_gate", {}) if isinstance(source_policy.get("policy"), dict) else {}
if not isinstance(change_gate, dict):
    err("production set policy change_gate must be an object")
    change_gate = {}
for field, expected in expected_change_gate.items():
    require(change_gate.get(field) == expected, f"production set policy change_gate.{field} mismatch")
requirements = set(as_string_list(source_policy.get("policy", {}).get("admission_requirements") if isinstance(source_policy.get("policy"), dict) else None, "production_set_policy.policy.admission_requirements"))
required_requirements = set(as_string_list(policy_contract.get("required_admission_requirements"), "required_policy_contract.required_admission_requirements"))
missing_requirements = sorted(required_requirements - requirements)
if missing_requirements:
    err(f"production set policy admission_requirements missing {','.join(missing_requirements)}")
source_paths = policy_contract.get("source_paths", {})
if not isinstance(source_paths, dict):
    err("required_policy_contract.source_paths must be an object")
    source_paths = {}
require(source_policy.get("sources") == source_paths, "production set policy sources mismatch")

manifest_doc = load_json(ROOT / str(source_artifacts.get("production_manifest", "")), "production_manifest")
production_modules = manifest_doc.get("production_modules", [])
if not isinstance(production_modules, list):
    err("production_manifest.production_modules must be an array")
    production_modules = []
require(len(production_modules) == int(expected_summary.get("total_production_modules", -1)), "production module count mismatch")
admission_report = load_json(ROOT / str(source_artifacts.get("admission_report", "")), "admission_report")
admission_summary = admission_report.get("summary", {}) if isinstance(admission_report.get("summary"), dict) else {}
require(admission_summary.get("admitted") == int(expected_summary.get("total_production_modules", -1)), "admission_report.summary.admitted mismatch")
require(admission_summary.get("blocked") == 0, "admission_report.summary.blocked must be zero")

source_gate_report: dict[str, Any] = {}
source_gate_rows: list[dict[str, Any]] = []
source_gate_transcript = ""
gate_path = source_artifacts.get("production_set_policy_gate")
expected_stdout = policy_contract.get("required_source_gate_stdout")
if isinstance(gate_path, str) and isinstance(expected_stdout, str):
    source_gate_report, source_gate_rows, source_gate_transcript = run_source_gate(gate_path, expected_stdout)
else:
    err("source gate path/stdout contract missing")

require(source_gate_report.get("ok") is True, "source policy report ok must be true")
require(source_gate_report.get("failure_count") == 0, "source policy report failure_count must be zero")
source_gate_summary = source_gate_report.get("summary", {}) if isinstance(source_gate_report.get("summary"), dict) else {}
for field, expected in expected_summary.items():
    require(source_gate_summary.get(field) == expected, f"source gate report summary.{field} mismatch")
require(len(source_gate_rows) == int(expected_summary.get("total_production_modules", -1)), "source policy log row count mismatch")
for row in source_gate_rows:
    missing = sorted(required_log_fields - set(row))
    if missing:
        err(f"source policy log row missing {','.join(missing)}")
    require(row.get("mode") == "policy", "source policy log mode must be policy")
    require(row.get("outcome") == "pass", "source policy log outcome must be pass")
    require(row.get("errno") == 0, "source policy log errno must be zero")
    reasons = row.get("reasons")
    require(isinstance(reasons, list) and not reasons, "source policy log reasons must be an empty array")

for ref in evidence.get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} missing path")
        continue
    text = read_text(path_text, str(ref.get("id", "implementation_ref")))
    for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id')}.required_text"):
        require(needle in text, f"implementation ref {ref.get('id')} missing {needle!r} in {path_text}")

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
        err(f"test source {source_id} missing path")
        continue
    text = read_text(path_text, source_id)
    for test_ref in as_string_list(spec.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
        require(function_exists(text, test_ref), f"test source {source_id} missing required test ref {test_ref}")
        test_refs.append(f"{source_id}::{test_ref}")

bindings = manifest.get("missing_item_bindings", [])
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
binding_by_id = {str(item.get("id")): item for item in bindings if isinstance(item, dict)}
unit_binding = binding_by_id.get("tests.unit.primary")
if not isinstance(unit_binding, dict):
    err("missing_item_bindings missing tests.unit.primary")
else:
    for artifact in as_string_list(unit_binding.get("required_artifacts"), "tests.unit.primary.required_artifacts"):
        require((ROOT / artifact).exists(), f"tests.unit.primary artifact missing: {artifact}")
    for ref in as_string_list(unit_binding.get("required_test_refs"), "tests.unit.primary.required_test_refs"):
        require(any(ref in recorded for recorded in test_refs), f"tests.unit.primary references missing test ref {ref}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}
completion_required_log_fields = as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
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
    "artifact_refs",
    "test_refs",
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
    "source_artifacts",
    "required_policy_contract",
    "test_refs",
    "events",
    "errors",
}
for field in completion_required_log_fields:
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
        "event": "math_production_set_policy_completion_summary",
        "stream": "runtime-math",
        "gate": "math_production_set_policy_completion_contract",
        "details": {
            "production_modules": len(production_modules),
            "source_gate_rows": len(source_gate_rows),
            "source_gate_report_ok": source_gate_report.get("ok"),
        },
    },
    {
        "event": "math_production_set_policy_source_bindings",
        "stream": "governance",
        "gate": "math_production_set_policy_completion_contract",
        "details": {
            "source_artifacts": sorted(source_artifacts),
            "source_gate_transcript_contains_pass": bool(expected_stdout and expected_stdout in source_gate_transcript),
        },
    },
    {
        "event": "math_production_set_policy_test_bindings",
        "stream": "unit",
        "gate": "math_production_set_policy_completion_contract",
        "details": {
            "test_refs": sorted(set(test_refs)),
            "missing_item_bindings": ["tests.unit.primary"],
        },
    },
    {
        "event": PASS_EVENT if not errors else FAIL_EVENT,
        "stream": "release",
        "gate": "math_production_set_policy_completion_contract",
        "details": {
            "declared_events": sorted(declared_events),
            "required_report_fields": required_report_fields,
            "required_log_fields": completion_required_log_fields,
        },
    },
]

rows: list[dict[str, Any]] = []
for seq, event in enumerate(events, start=1):
    rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_BEAD}::math-production-set-policy-completion::{seq:03d}",
            "event": event["event"],
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": outcome,
            "source_commit": source_commit,
            "schema_version": EXPECTED_SCHEMA,
            "artifact_refs": artifact_refs,
            "test_refs": sorted(set(test_refs)),
            "failure_signature": failure_signature,
            "stream": event["stream"],
            "gate": event["gate"],
            "details": event["details"],
        }
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "source_artifacts": len(source_artifacts),
        "production_modules": len(production_modules),
        "source_gate_rows": len(source_gate_rows),
        "source_gate_failure_count": source_gate_report.get("failure_count"),
        "test_refs": len(set(test_refs)),
        "telemetry_events": len(declared_events),
    },
    "source_artifacts": source_artifacts,
    "required_policy_contract": policy_contract,
    "test_refs": sorted(set(test_refs)),
    "events": [row["event"] for row in rows],
    "errors": errors,
}

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
