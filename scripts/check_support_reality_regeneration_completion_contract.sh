#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_CONTRACT:-$ROOT/tests/conformance/support_reality_regeneration_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_REPORT:-$OUT_DIR/support_reality_regeneration_completion_contract.report.json}"
LOG="${FRANKENLIBC_SUPPORT_REALITY_REGEN_COMPLETION_LOG:-$OUT_DIR/support_reality_regeneration_completion_contract.log.jsonl}"

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
import shlex
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "support_reality_regeneration_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "support_reality_regeneration_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-0agsk.3"
COMPLETION_BEAD = "bd-0agsk.3.1"
SOURCE_SCHEMA = "support_reality_regeneration.v1"
PASS_EVENT = "support_reality_regeneration_completion_contract_pass"
FAIL_EVENT = "support_reality_regeneration_completion_contract_fail"
REQUIRED_PAIR_IDS = {"support_matrix", "reality_report"}
REQUIRED_CHECKS = {
    "contract_schema_valid",
    "paired_artifacts_present",
    "artifact_sha256s_current",
    "reality_report_matches_harness_generation",
    "support_reality_counts_match",
    "single_artifact_write_modes_rejected",
}
REQUIRED_TELEMETRY_EVENTS = {
    "support_reality_regeneration_completion_summary",
    "support_reality_regeneration_source_bindings",
    "support_reality_regeneration_conformance_bindings",
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


def source_text(path_text: str, label: str) -> str:
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


def command_contract_failures(command: str) -> list[str]:
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return [f"command is not shell-tokenizable: {command}: {exc}"]
    if "cargo" not in tokens:
        return []
    failures: list[str] = []
    cargo_index = tokens.index("cargo")
    try:
        rch_index = tokens.index("rch")
    except ValueError:
        failures.append(f"cargo command must run through rch exec: {command}")
        return failures
    if rch_index > cargo_index:
        failures.append(f"rch must appear before cargo: {command}")
        return failures
    if "RCH_REQUIRE_REMOTE=1" not in tokens[:rch_index]:
        failures.append(f"cargo command must set RCH_REQUIRE_REMOTE=1 before rch: {command}")
    if tokens[rch_index + 1 : rch_index + 3] != ["exec", "--"]:
        failures.append(f"cargo command must use 'rch exec --': {command}")
    payload = tokens[rch_index + 3 : cargo_index]
    if not payload or payload[0] != "env":
        failures.append(f"cargo command must place env assignments inside rch payload: {command}")
    if not any(token.startswith("CARGO_TARGET_DIR=") for token in payload[1:]):
        failures.append(f"cargo command must set CARGO_TARGET_DIR inside rch env payload: {command}")
    return failures


def validate_required_commands(binding: dict[str, Any]) -> None:
    commands = as_string_list(binding.get("required_commands"), "tests.conformance.primary.required_commands")
    cargo_command_count = 0
    for command in commands:
        failures = command_contract_failures(command)
        if failures:
            for failure in failures:
                err(f"required command contract failed: {failure}")
        try:
            tokens = shlex.split(command)
        except ValueError:
            tokens = []
        if "cargo" in tokens:
            cargo_command_count += 1
    require(cargo_command_count == 2, f"tests.conformance.primary must bind exactly 2 cargo proof commands, got {cargo_command_count}")


manifest = load_json(CONTRACT, "contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")

source_artifacts = manifest.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    err("source_artifacts must be a non-empty object")
    source_artifacts = {}
for source_id, path_text in source_artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{source_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact {source_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

pair_contract = evidence.get("required_pair_contract", {})
if not isinstance(pair_contract, dict):
    err("completion_debt_evidence.required_pair_contract must be an object")
    pair_contract = {}
require(pair_contract.get("schema_version") == SOURCE_SCHEMA, f"required pair schema must be {SOURCE_SCHEMA}")
require(pair_contract.get("generated_by_bead") == ORIGINAL_BEAD, f"required pair bead must be {ORIGINAL_BEAD}")
require(pair_contract.get("mode") == "validate_only", "required pair mode must be validate_only")
require(pair_contract.get("canonical_command") == "scripts/check_support_reality_regeneration.sh --validate-only", "required pair canonical command mismatch")
required_pair_ids = require_set(pair_contract.get("required_artifact_ids"), REQUIRED_PAIR_IDS, "required_pair_contract.required_artifact_ids")
required_checks = require_set(pair_contract.get("required_checks"), REQUIRED_CHECKS, "required_pair_contract.required_checks")
require(pair_contract.get("single_artifact_update") == "forbidden", "single_artifact_update must be forbidden")

source_contract_path = source_artifacts.get("source_contract")
source_contract = load_json(ROOT / str(source_contract_path), "source_contract") if isinstance(source_contract_path, str) else {}
require(source_contract.get("schema_version") == SOURCE_SCHEMA, "source contract schema_version mismatch")
require(source_contract.get("generated_by_bead") == ORIGINAL_BEAD, "source contract generated_by_bead mismatch")
require(source_contract.get("mode") == "validate_only", "source contract mode mismatch")
require(source_contract.get("canonical_command") == pair_contract.get("canonical_command"), "source contract canonical_command mismatch")
source_policy = source_contract.get("paired_update_policy", {})
if not isinstance(source_policy, dict):
    err("source contract paired_update_policy must be an object")
    source_policy = {}
require(source_policy.get("single_artifact_update") == "forbidden", "source contract single_artifact_update mismatch")
require(source_policy.get("canonical_artifact_writes") == "forbidden_in_validate_only", "source contract write policy mismatch")
require_set(source_policy.get("required_artifact_ids"), REQUIRED_PAIR_IDS, "source_contract.paired_update_policy.required_artifact_ids")
source_checks = set(as_string_list(source_contract.get("checks"), "source_contract.checks"))
missing_source_checks = sorted(required_checks - source_checks)
if missing_source_checks:
    err(f"source contract checks missing {','.join(missing_source_checks)}")

output_rows = source_contract.get("output_artifacts", [])
if not isinstance(output_rows, list):
    err("source contract output_artifacts must be an array")
    output_rows = []
outputs_by_id = {str(row.get("id")): row for row in output_rows if isinstance(row, dict)}
for artifact_id in sorted(required_pair_ids):
    row = outputs_by_id.get(artifact_id)
    if not isinstance(row, dict):
        err(f"source contract output_artifacts missing {artifact_id}")
        continue
    path_text = row.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"source contract {artifact_id} path missing")
        continue
    artifact_path = ROOT / path_text
    require(artifact_path.is_file(), f"paired artifact file missing: {path_text}")
    current_sha = sha256_file(artifact_path)
    require(row.get("sha256") == current_sha, f"source contract {artifact_id} sha256 mismatch")

support_matrix = load_json(ROOT / str(source_artifacts.get("support_matrix", "")), "support_matrix")
reality_report = load_json(ROOT / str(source_artifacts.get("reality_report", "")), "reality_report")
support_summary = support_matrix.get("summary", {}) if isinstance(support_matrix.get("summary"), dict) else {}
support_counts = {
    "implemented": int(support_summary.get("implemented", support_matrix.get("counts", {}).get("implemented", 0))),
    "raw_syscall": int(support_summary.get("raw_syscall", support_matrix.get("counts", {}).get("raw_syscall", 0))),
    "wraps_host_libc": int(support_summary.get("wraps_host_libc", support_matrix.get("counts", {}).get("wraps_host_libc", 0))),
    "glibc_call_through": int(support_summary.get("glibc_call_through", support_matrix.get("counts", {}).get("glibc_call_through", 0))),
    "stub": int(support_summary.get("stub", support_matrix.get("counts", {}).get("stub", 0))),
}
reality_counts = {key: int(value) for key, value in (reality_report.get("counts", {}) or {}).items()}
require(support_counts == reality_counts, "support_matrix summary counts differ from reality_report counts")
support_total = int(support_matrix.get("total_exported", -1))
reality_total = int(reality_report.get("total_exported", -2))
symbol_count = len(support_matrix.get("symbols", []))
require(support_total == reality_total == symbol_count, "support/reality totals or symbol count differ")
require(support_matrix.get("generated_at_utc") == reality_report.get("generated_at_utc"), "support/reality generated_at_utc mismatch")

texts: dict[str, str] = {}
for source_id, path_text in source_artifacts.items():
    if isinstance(path_text, str) and (ROOT / path_text).is_file():
        texts[source_id] = source_text(path_text, source_id)

for ref in evidence.get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} missing path")
        continue
    text = source_text(path_text, str(ref.get("id", "implementation_ref")))
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
    text = source_text(path_text, source_id)
    for test_ref in as_string_list(spec.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
        require(function_exists(text, test_ref), f"test source {source_id} missing required test ref {test_ref}")
        test_refs.append(f"{source_id}::{test_ref}")

bindings = manifest.get("missing_item_bindings", [])
if not isinstance(bindings, list) or not bindings:
    err("missing_item_bindings must be a non-empty array")
    bindings = []
binding = next((item for item in bindings if isinstance(item, dict) and item.get("id") == "tests.conformance.primary"), None)
if not isinstance(binding, dict):
    err("missing_item_bindings missing tests.conformance.primary")
    binding = {}
for artifact in as_string_list(binding.get("required_artifacts"), "tests.conformance.primary.required_artifacts"):
    require((ROOT / artifact).is_file(), f"conformance artifact missing: {artifact}")
for ref in as_string_list(binding.get("required_test_refs"), "tests.conformance.primary.required_test_refs"):
    require(any(ref in recorded for recorded in test_refs), f"tests.conformance.primary references missing test ref {ref}")
validate_required_commands(binding)

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
    "required_checks",
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
    "source_artifacts",
    "required_checks",
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
        "event": "support_reality_regeneration_completion_summary",
        "stream": "conformance",
        "gate": "support_reality_regeneration_completion_contract",
        "details": {
            "required_check_count": len(required_checks),
            "source_artifact_count": len(source_artifacts),
            "test_ref_count": len(set(test_refs)),
        },
    },
    {
        "event": "support_reality_regeneration_source_bindings",
        "stream": "conformance",
        "gate": "support_reality_regeneration_completion_contract",
        "details": {
            "required_pair_ids": sorted(required_pair_ids),
            "support_total": support_total,
            "reality_total": reality_total,
            "generated_at_utc": support_matrix.get("generated_at_utc"),
        },
    },
    {
        "event": "support_reality_regeneration_conformance_bindings",
        "stream": "conformance",
        "gate": "support_reality_regeneration_completion_contract",
        "details": {
            "required_checks": sorted(required_checks),
            "test_refs": sorted(set(test_refs)),
        },
    },
    {
        "event": PASS_EVENT if not errors else FAIL_EVENT,
        "stream": "release",
        "gate": "support_reality_regeneration_completion_contract",
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
            "trace_id": f"{COMPLETION_BEAD}::support-reality-regeneration-completion::{seq:03d}",
            "event": event["event"],
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": outcome,
            "source_commit": source_commit,
            "schema_version": EXPECTED_SCHEMA,
            "required_checks": sorted(required_checks),
            "test_refs": sorted(set(test_refs)),
            "artifact_refs": artifact_refs,
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
        "required_checks": len(required_checks),
        "source_artifacts": len(source_artifacts),
        "test_refs": len(set(test_refs)),
        "support_total": support_total,
        "reality_total": reality_total,
        "telemetry_events": len(declared_events),
    },
    "source_artifacts": source_artifacts,
    "required_checks": sorted(required_checks),
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
