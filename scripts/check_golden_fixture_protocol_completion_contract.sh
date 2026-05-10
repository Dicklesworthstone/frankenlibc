#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_CONTRACT:-$ROOT/tests/conformance/golden_fixture_protocol_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_REPORT:-$OUT_DIR/golden_fixture_protocol_completion_contract.report.json}"
LOG="${FRANKENLIBC_GOLDEN_FIXTURE_COMPLETION_LOG:-$OUT_DIR/golden_fixture_protocol_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import hashlib
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

EXPECTED_SCHEMA = "golden_fixture_protocol_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "golden_fixture_protocol_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-15n.3"
COMPLETION_BEAD = "bd-15n.3.1"
SOURCE_SCHEMA = "v1"
PASS_EVENT = "golden_fixture_protocol_completion_contract_pass"
FAIL_EVENT = "golden_fixture_protocol_completion_contract_fail"
REQUIRED_SOURCE_ARTIFACTS = {
    "golden_fixture_protocol",
    "conformance_coverage_gate",
    "conformance_coverage_wrapper",
    "conformance_coverage_harness_test",
    "coverage_baseline",
    "coverage_snapshot",
    "golden_gate",
    "golden_update_script",
    "golden_sha256s",
    "golden_markdown",
    "golden_json",
    "golden_suite_json",
    "completion_checker",
    "completion_harness_test",
}
REQUIRED_REGRESSION_RULES = {
    "Fixture file count must not decrease",
    "Total case count must not decrease",
    "Symbol coverage percentage must not decrease",
    "Per-module covered symbol count must not decrease",
    "No fixture file may be removed without approval",
}
REQUIRED_CI_GATES = {
    "conformance_golden_gate",
    "conformance_coverage_gate",
    "claim_reconciliation_gate",
}
REQUIRED_TELEMETRY_EVENTS = {
    "golden_fixture_protocol_completion_summary",
    "golden_fixture_protocol_source_bindings",
    "golden_fixture_protocol_test_bindings",
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


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except Exception as exc:
        err(f"sha256 read failed for {rel(path)}: {exc}")
        return ""
    return digest.hexdigest()


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


def nested(obj: dict[str, Any], path: list[str], default: Any) -> Any:
    value: Any = obj
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return default
        value = value[part]
    return value


def parse_sha256s(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        err(f"sha256 manifest unreadable: {rel(path)}: {exc}")
        return values
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 64:
            err(f"sha256 manifest line {index} is malformed")
            continue
        values[parts[1]] = parts[0]
    return values


def positive_int(value: Any, context: str) -> int:
    try:
        parsed = int(value)
    except Exception:
        err(f"{context} must be an integer")
        return -1
    if parsed <= 0:
        err(f"{context} must be positive")
    return parsed


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

protocol_contract = evidence.get("required_protocol_contract", {})
if not isinstance(protocol_contract, dict):
    err("completion_debt_evidence.required_protocol_contract must be an object")
    protocol_contract = {}
require(protocol_contract.get("schema_version") == SOURCE_SCHEMA, f"required protocol schema must be {SOURCE_SCHEMA}")
require(protocol_contract.get("generated_by_bead") == ORIGINAL_BEAD, f"required protocol bead must be {ORIGINAL_BEAD}")
require(protocol_contract.get("capture_command") == "scripts/update_conformance_golden.sh", "capture command mismatch")
require(protocol_contract.get("fixed_timestamp") == "1970-01-01T00:00:00Z", "fixed timestamp mismatch")
require(protocol_contract.get("verification_command") == "scripts/conformance_golden_gate.sh", "verification command mismatch")
require(protocol_contract.get("coverage_command") == "scripts/check_conformance_coverage.sh", "coverage command mismatch")
require(protocol_contract.get("coverage_baseline") == "tests/conformance/conformance_coverage_baseline.v1.json", "coverage baseline path mismatch")
require(protocol_contract.get("coverage_snapshot") == "tests/conformance/conformance_coverage_snapshot.v1.json", "coverage snapshot path mismatch")
required_outputs = set(as_string_list(protocol_contract.get("required_golden_outputs"), "required_protocol_contract.required_golden_outputs"))
sha_checked_outputs = set(as_string_list(protocol_contract.get("sha256_checked_outputs"), "required_protocol_contract.sha256_checked_outputs"))
required_rules = require_set(protocol_contract.get("required_regression_rules"), REQUIRED_REGRESSION_RULES, "required_protocol_contract.required_regression_rules")
required_ci_gates = require_set(protocol_contract.get("required_ci_gates"), REQUIRED_CI_GATES, "required_protocol_contract.required_ci_gates")

protocol_path = source_artifacts.get("golden_fixture_protocol")
protocol = load_json(ROOT / str(protocol_path), "golden_fixture_protocol") if isinstance(protocol_path, str) else {}
require(protocol.get("schema_version") == SOURCE_SCHEMA, "golden fixture protocol schema mismatch")
require(protocol.get("bead") == ORIGINAL_BEAD, "golden fixture protocol bead mismatch")
require(nested(protocol, ["protocol", "capture", "command"], None) == protocol_contract.get("capture_command"), "protocol capture command mismatch")
require(nested(protocol, ["protocol", "capture", "fixed_timestamp"], None) == protocol_contract.get("fixed_timestamp"), "protocol fixed timestamp mismatch")
protocol_outputs = set(as_string_list(nested(protocol, ["protocol", "capture", "outputs"], []), "protocol.capture.outputs"))
missing_protocol_outputs = sorted(required_outputs - protocol_outputs)
if missing_protocol_outputs:
    err(f"protocol capture outputs missing {','.join(missing_protocol_outputs)}")
require(nested(protocol, ["protocol", "verification", "command"], None) == protocol_contract.get("verification_command"), "protocol verification command mismatch")
require(nested(protocol, ["protocol", "coverage_regression", "command"], None) == protocol_contract.get("coverage_command"), "protocol coverage command mismatch")
require(nested(protocol, ["protocol", "coverage_regression", "baseline"], None) == protocol_contract.get("coverage_baseline"), "protocol coverage baseline mismatch")
require(nested(protocol, ["protocol", "coverage_regression", "snapshot"], None) == protocol_contract.get("coverage_snapshot"), "protocol coverage snapshot mismatch")
protocol_rules = set(as_string_list(nested(protocol, ["protocol", "coverage_regression", "regression_rules"], []), "protocol.coverage_regression.regression_rules"))
missing_protocol_rules = sorted(required_rules - protocol_rules)
if missing_protocol_rules:
    err(f"protocol regression_rules missing {','.join(missing_protocol_rules)}")
ci_gate_rows = nested(protocol, ["ci_integration", "gates"], [])
if not isinstance(ci_gate_rows, list):
    err("protocol ci_integration.gates must be an array")
    ci_gate_rows = []
protocol_ci_gates = {str(row.get("name")) for row in ci_gate_rows if isinstance(row, dict)}
missing_ci_gates = sorted(required_ci_gates - protocol_ci_gates)
if missing_ci_gates:
    err(f"protocol ci gates missing {','.join(missing_ci_gates)}")

for output in sorted(required_outputs):
    require((ROOT / output).is_file(), f"golden output missing: {output}")

sha_manifest = parse_sha256s(ROOT / str(source_artifacts.get("golden_sha256s", "")))
for filename in sorted(sha_checked_outputs):
    expected = sha_manifest.get(filename)
    if not expected:
        err(f"sha256 manifest missing {filename}")
        continue
    path = ROOT / "tests" / "conformance" / "golden" / filename
    require(path.is_file(), f"sha256 checked file missing: {rel(path)}")
    require(sha256_file(path) == expected, f"sha256 mismatch for {filename}")

baseline = load_json(ROOT / str(source_artifacts.get("coverage_baseline", "")), "coverage_baseline")
snapshot = load_json(ROOT / str(source_artifacts.get("coverage_snapshot", "")), "coverage_snapshot")
for label, doc in [("coverage_baseline", baseline), ("coverage_snapshot", snapshot)]:
    require(doc.get("schema_version") == SOURCE_SCHEMA, f"{label} schema mismatch")
    require(doc.get("bead") == ORIGINAL_BEAD, f"{label} bead mismatch")
    summary = doc.get("summary", {})
    if not isinstance(summary, dict):
        err(f"{label}.summary must be an object")
        summary = {}
    for field in [
        "total_symbols",
        "symbols_with_fixtures",
        "coverage_pct",
        "total_fixture_files",
        "total_fixture_cases",
        "total_families",
    ]:
        positive_int(summary.get(field), f"{label}.summary.{field}")
    fixtures = doc.get("fixtures", {})
    if isinstance(fixtures, dict):
        require(len(fixtures) == int(summary.get("total_fixture_files", -1)), f"{label} fixture count must match summary")
    else:
        err(f"{label}.fixtures must be an object")

baseline_summary = baseline.get("summary", {}) if isinstance(baseline.get("summary"), dict) else {}
snapshot_summary = snapshot.get("summary", {}) if isinstance(snapshot.get("summary"), dict) else {}
for field in ["coverage_pct", "total_fixture_files", "total_fixture_cases", "total_families"]:
    try:
        require(int(snapshot_summary.get(field, -1)) >= int(baseline_summary.get(field, -1)), f"coverage snapshot {field} is below baseline")
    except Exception:
        err(f"coverage summary {field} comparison failed")

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
required_binding_ids = {"tests.unit.primary", "tests.e2e.primary", "tests.golden.primary", "tests.conformance.primary"}
binding_by_id = {str(item.get("id")): item for item in bindings if isinstance(item, dict)}
for binding_id in sorted(required_binding_ids):
    binding = binding_by_id.get(binding_id)
    if not isinstance(binding, dict):
        err(f"missing_item_bindings missing {binding_id}")
        continue
    for artifact in as_string_list(binding.get("required_artifacts"), f"{binding_id}.required_artifacts"):
        require((ROOT / artifact).is_file(), f"{binding_id} artifact missing: {artifact}")
    for ref in as_string_list(binding.get("required_test_refs"), f"{binding_id}.required_test_refs"):
        require(any(ref in recorded for recorded in test_refs), f"{binding_id} references missing test ref {ref}")

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
    "required_protocol_contract",
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
        "event": "golden_fixture_protocol_completion_summary",
        "stream": "release",
        "gate": "golden_fixture_protocol_completion_contract",
        "details": {
            "required_source_artifacts": len(REQUIRED_SOURCE_ARTIFACTS),
            "required_outputs": len(required_outputs),
            "test_ref_count": len(set(test_refs)),
        },
    },
    {
        "event": "golden_fixture_protocol_source_bindings",
        "stream": "golden",
        "gate": "golden_fixture_protocol_completion_contract",
        "details": {
            "sha256_checked_outputs": sorted(sha_checked_outputs),
            "snapshot_fixture_cases": snapshot_summary.get("total_fixture_cases"),
            "baseline_fixture_cases": baseline_summary.get("total_fixture_cases"),
        },
    },
    {
        "event": "golden_fixture_protocol_test_bindings",
        "stream": "conformance",
        "gate": "golden_fixture_protocol_completion_contract",
        "details": {
            "missing_item_bindings": sorted(required_binding_ids),
            "test_refs": sorted(set(test_refs)),
        },
    },
    {
        "event": PASS_EVENT if not errors else FAIL_EVENT,
        "stream": "release",
        "gate": "golden_fixture_protocol_completion_contract",
        "details": {
            "declared_events": sorted(declared_events),
            "required_report_fields": required_report_fields,
            "required_log_fields": required_log_fields,
        },
    },
]

rows: list[dict[str, Any]] = []
for seq, event in enumerate(events, start=1):
    rows.append(
        {
            "timestamp": timestamp,
            "trace_id": f"{COMPLETION_BEAD}::golden-fixture-protocol-completion::{seq:03d}",
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
        "required_outputs": len(required_outputs),
        "test_refs": len(set(test_refs)),
        "coverage_baseline_cases": baseline_summary.get("total_fixture_cases"),
        "coverage_snapshot_cases": snapshot_summary.get("total_fixture_cases"),
        "telemetry_events": len(declared_events),
    },
    "source_artifacts": source_artifacts,
    "required_protocol_contract": protocol_contract,
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
