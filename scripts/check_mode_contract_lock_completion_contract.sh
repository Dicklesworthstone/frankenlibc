#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_CONTRACT:-$ROOT/tests/conformance/mode_contract_lock_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_REPORT:-$OUT_DIR/mode_contract_lock_completion_contract.report.json}"
LOG="${FRANKENLIBC_MODE_CONTRACT_LOCK_COMPLETION_LOG:-$OUT_DIR/mode_contract_lock_completion_contract.log.jsonl}"
RUNTIME_EVIDENCE_REPORT="${FRANKENLIBC_MODE_CONTRACT_LOCK_RUNTIME_EVIDENCE_REPORT:-$OUT_DIR/runtime_mode_evidence_logging_coverage.report.json}"
RUNTIME_EVIDENCE_LOG="${FRANKENLIBC_MODE_CONTRACT_LOCK_RUNTIME_EVIDENCE_LOG:-$OUT_DIR/runtime_mode_evidence_logging_coverage.log.jsonl}"
MODE_LOCK_REPORT="$ROOT/target/conformance/mode_contract_lock.report.json"
MODE_LOCK_LOG="$ROOT/target/conformance/mode_contract_lock.log.jsonl"

mkdir -p \
  "$(dirname "$REPORT")" \
  "$(dirname "$LOG")" \
  "$(dirname "$RUNTIME_EVIDENCE_REPORT")" \
  "$(dirname "$RUNTIME_EVIDENCE_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
RUNTIME_EVIDENCE_REPORT="$RUNTIME_EVIDENCE_REPORT" \
RUNTIME_EVIDENCE_LOG="$RUNTIME_EVIDENCE_LOG" \
MODE_LOCK_REPORT="$MODE_LOCK_REPORT" \
MODE_LOCK_LOG="$MODE_LOCK_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
RUNTIME_EVIDENCE_REPORT = pathlib.Path(os.environ["RUNTIME_EVIDENCE_REPORT"])
RUNTIME_EVIDENCE_LOG = pathlib.Path(os.environ["RUNTIME_EVIDENCE_LOG"])
MODE_LOCK_REPORT = pathlib.Path(os.environ["MODE_LOCK_REPORT"])
MODE_LOCK_LOG = pathlib.Path(os.environ["MODE_LOCK_LOG"])

EXPECTED_SCHEMA = "mode_contract_lock_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "mode_contract_lock_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-w2c3.3.3"
COMPLETION_BEAD = "bd-w2c3.3.3.1"

errors: list[str] = []
command_outputs: dict[str, dict[str, Any]] = {}


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


def json_lines(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return []
    records: list[dict[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except Exception as exc:
            err(f"{label}:{index} is not valid JSON: {exc}")
            continue
        if not isinstance(value, dict):
            err(f"{label}:{index} must be a JSON object")
            continue
        records.append(value)
    return records


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


def source_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {path_text}: {exc}")
        return ""


def run_command(command: list[str], env: dict[str, str] | None, label: str) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=merged,
        check=False,
    )
    command_outputs[label] = {
        "command": " ".join(command),
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }
    if proc.returncode != 0:
        err(
            f"{label} failed: exit={proc.returncode} "
            f"stdout={proc.stdout[:1600]!r} stderr={proc.stderr[:1600]!r}"
        )


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    except Exception:
        return "unknown"


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
    if not (ROOT / path_text).exists():
        err(f"source artifact {artifact_id} missing: {path_text}")

evidence = manifest.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}

for ref in evidence.get("implementation_refs", []):
    if not isinstance(ref, dict):
        err("implementation_refs entries must be objects")
        continue
    path_text = ref.get("path")
    if not isinstance(path_text, str) or not path_text:
        err(f"implementation ref {ref.get('id')} is missing path")
        continue
    text = source_text(path_text, ref.get("id", "implementation_ref"))
    for needle in as_string_list(ref.get("required_text"), f"implementation_refs.{ref.get('id')}.required_text"):
        require(needle in text, f"implementation ref {ref.get('id')} missing required text {needle!r} in {path_text}")

test_sources = evidence.get("test_sources", {})
all_test_text = ""
if not isinstance(test_sources, dict) or not test_sources:
    err("completion_debt_evidence.test_sources must be a non-empty object")
else:
    for source_id, source in test_sources.items():
        if not isinstance(source, dict):
            err(f"test source {source_id} must be an object")
            continue
        path_text = source.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"test source {source_id} must include path")
            continue
        text = source_text(path_text, source_id)
        all_test_text += text + "\n"
        for test_ref in as_string_list(source.get("required_test_refs"), f"test_sources.{source_id}.required_test_refs"):
            require(
                f"fn {test_ref}" in text or test_ref in text,
                f"test source {source_id} missing required test ref {test_ref}",
            )

required = manifest.get("required_source_contract", {})
if not isinstance(required, dict):
    err("required_source_contract must be an object")
    required = {}

mode_contract = load_json(ROOT / str(source_artifacts.get("mode_contract_lock", "")), "mode_contract_lock")
env_contract = mode_contract.get("env_contract", {}) if isinstance(mode_contract.get("env_contract"), dict) else {}
allowed_values = as_string_list(required.get("allowed_values"), "required_source_contract.allowed_values")
provenance_fields = as_string_list(required.get("required_provenance_fields"), "required_source_contract.required_provenance_fields")
startup_anchor_names = as_string_list(required.get("startup_anchor_names"), "required_source_contract.startup_anchor_names")
require(mode_contract.get("bead") == ORIGINAL_BEAD, "mode contract bead mismatch")
require(env_contract.get("env_key") == required.get("env_key"), "mode contract env_key mismatch")
require(env_contract.get("allowed_values") == allowed_values, "mode contract allowed_values mismatch")
require(env_contract.get("default_value") == required.get("default_value"), "mode contract default_value mismatch")
require(env_contract.get("unknown_value_behavior") == required.get("unknown_value_behavior"), "mode contract unknown_value_behavior mismatch")
require(env_contract.get("selection_timing") == required.get("selection_timing"), "mode contract selection_timing mismatch")
require(str(required.get("required_mutability_substring", "")).lower() in str(env_contract.get("mutability", "")).lower(), "mode contract mutability must mention immutable")

declared_provenance = mode_contract.get("required_provenance_fields", [])
require(declared_provenance == provenance_fields, "mode contract required_provenance_fields mismatch")
anchors = mode_contract.get("startup_reentrant_test_anchors", [])
if not isinstance(anchors, list):
    err("mode contract startup_reentrant_test_anchors must be an array")
    anchors = []
anchor_names = [anchor.get("name") for anchor in anchors if isinstance(anchor, dict)]
require(anchor_names == startup_anchor_names, "mode contract startup anchor names mismatch")
summary = mode_contract.get("summary", {}) if isinstance(mode_contract.get("summary"), dict) else {}
require(summary.get("allowed_value_count") == len(allowed_values), "mode contract summary.allowed_value_count mismatch")
require(summary.get("required_provenance_field_count") == len(provenance_fields), "mode contract summary.required_provenance_field_count mismatch")
require(summary.get("startup_reentrant_anchor_count") == len(startup_anchor_names), "mode contract summary.startup_reentrant_anchor_count mismatch")

runtime_inv = load_json(ROOT / str(source_artifacts.get("runtime_env_inventory", "")), "runtime_env_inventory")
runtime_rows = runtime_inv.get("inventory", [])
mode_row = next((row for row in runtime_rows if isinstance(row, dict) and row.get("env_key") == required.get("env_key")), None) if isinstance(runtime_rows, list) else None
require(mode_row is not None, "runtime env inventory missing FRANKENLIBC_MODE row")
metadata = mode_row.get("metadata", {}) if isinstance(mode_row, dict) and isinstance(mode_row.get("metadata"), dict) else {}
runtime_allowed_values = {str(value) for value in metadata.get("allowed_values", [])}
require(set(allowed_values).issubset(runtime_allowed_values), "runtime env inventory allowed_values must include strict+hardened")
for forbidden in ["off", "none", "disabled"]:
    require(forbidden not in runtime_allowed_values, f"runtime env inventory allowed_values must not expose {forbidden}")
require(metadata.get("default_value") == required.get("default_value"), "runtime env inventory default_value mismatch")
require("unknown values resolve to strict" in str(metadata.get("parse_rule", "")).lower(), "runtime env inventory parse_rule mismatch")
require("immutable" in str(metadata.get("mutability", "")).lower(), "runtime env inventory mutability mismatch")

docs_inv = load_json(ROOT / str(source_artifacts.get("docs_env_inventory", "")), "docs_env_inventory")
docs_rows = docs_inv.get("keys", [])
docs_mode = next((row for row in docs_rows if isinstance(row, dict) and row.get("env_key") == required.get("env_key")), None) if isinstance(docs_rows, list) else None
require(docs_mode is not None, "docs env inventory missing FRANKENLIBC_MODE row")
docs_mentions = docs_mode.get("mentions", []) if isinstance(docs_mode, dict) else []
joined_snippets = "\n".join(str(hit.get("snippet", "")) for hit in docs_mentions if isinstance(hit, dict))
for mode in allowed_values:
    require(mode in joined_snippets, f"docs env inventory FRANKENLIBC_MODE mentions missing {mode}")

config_rs = source_text(str(source_artifacts.get("membrane_config", "")), "membrane_config")
for anchor_name in startup_anchor_names:
    require(f"fn {anchor_name}" in config_rs, f"config.rs missing startup/reentrant anchor {anchor_name}")
parse_fn_match = re.search(
    r"fn\s+parse_runtime_mode_env\s*\(.*?\)\s*->\s*SafetyLevel\s*\{(?P<body>.*?)\n\}",
    config_rs,
    flags=re.S,
)
if parse_fn_match is None:
    err("parse_runtime_mode_env function not found in config.rs")
else:
    parse_body = parse_fn_match.group("body")
    require('"strict"' in parse_body and "SafetyLevel::Strict" in parse_body, "parse_runtime_mode_env must explicitly handle strict")
    require('"hardened"' in parse_body and "SafetyLevel::Hardened" in parse_body, "parse_runtime_mode_env must explicitly handle hardened")
    require(not ("off" in parse_body and "SafetyLevel::Off" in parse_body), "parse_runtime_mode_env must not map env values to SafetyLevel::Off")

runtime_evidence = load_json(ROOT / str(source_artifacts.get("runtime_mode_evidence_logging_coverage", "")), "runtime_mode_evidence_logging_coverage")
policy = runtime_evidence.get("coverage_policy", {}) if isinstance(runtime_evidence.get("coverage_policy"), dict) else {}
runtime_policy = required.get("runtime_evidence_policy", {}) if isinstance(required.get("runtime_evidence_policy"), dict) else {}
require(policy.get("env_key") == required.get("env_key"), "runtime evidence policy env_key mismatch")
require(set(policy.get("allowed_modes", [])) == set(runtime_policy.get("allowed_modes", [])), "runtime evidence policy allowed_modes mismatch")
for field in [
    "process_immutable_after_startup",
    "subprocess_rows_must_override_inherited_mode",
    "startup_evidence_required",
    "trace_id_required",
    "ambient_tz_dependency_allowed",
    "mismatch_behavior_required",
]:
    require(policy.get(field) == runtime_policy.get(field), f"runtime evidence policy {field} mismatch")
coverage_rows = runtime_evidence.get("coverage_rows", [])
require(isinstance(coverage_rows, list) and len(coverage_rows) == runtime_policy.get("coverage_row_count"), "runtime evidence coverage row count mismatch")

run_command(["bash", str(ROOT / "scripts/check_mode_contract_lock.sh")], None, "scripts/check_mode_contract_lock.sh")
run_command(["bash", str(ROOT / "scripts/check_mode_semantics.sh")], None, "scripts/check_mode_semantics.sh")
run_command(
    ["bash", str(ROOT / "scripts/check_runtime_mode_evidence_logging_coverage.sh"), "--validate-only"],
    {
        "RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_REPORT": str(RUNTIME_EVIDENCE_REPORT),
        "RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_LOG": str(RUNTIME_EVIDENCE_LOG),
    },
    "scripts/check_runtime_mode_evidence_logging_coverage.sh",
)

mode_report = load_json(MODE_LOCK_REPORT, "mode_contract_lock_report")
mode_events = json_lines(MODE_LOCK_LOG, "mode_contract_lock_log")
for check_id in as_string_list(required.get("required_mode_lock_checks"), "required_source_contract.required_mode_lock_checks"):
    require(mode_report.get("checks", {}).get(check_id) == "pass", f"mode contract lock check {check_id} did not pass")
mode_report_summary = mode_report.get("summary", {}) if isinstance(mode_report.get("summary"), dict) else {}
require(mode_report_summary.get("allowed_values") == allowed_values, "mode contract lock report allowed_values mismatch")
require(mode_report_summary.get("required_provenance_fields") == len(provenance_fields), "mode contract lock report provenance count mismatch")
require(mode_report_summary.get("startup_reentrant_anchors") == len(startup_anchor_names), "mode contract lock report anchor count mismatch")
for event in mode_events:
    for field in provenance_fields:
        require(field in event, f"mode contract lock log row missing provenance field {field}")

runtime_report = load_json(RUNTIME_EVIDENCE_REPORT, "runtime_mode_evidence_report")
runtime_events = json_lines(RUNTIME_EVIDENCE_LOG, "runtime_mode_evidence_log")
require(runtime_report.get("outcome") == "pass", "runtime mode evidence report outcome must be pass")
runtime_summary = runtime_report.get("summary", {}) if isinstance(runtime_report.get("summary"), dict) else {}
require(runtime_summary.get("coverage_rows") == runtime_policy.get("coverage_row_count"), "runtime mode evidence report coverage_rows mismatch")
require(runtime_summary.get("startup_evidence_rows") == runtime_policy.get("coverage_row_count"), "runtime mode evidence report startup_evidence_rows mismatch")
require(
    any(event.get("event") == "runtime_mode_evidence_logging_coverage_validated" for event in runtime_events),
    "runtime mode evidence log missing validated event",
)

for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    for test_ref in as_string_list(item.get("required_test_refs"), f"missing_item_bindings.{item_id}.required_test_refs"):
        require(test_ref in all_test_text or test_ref in config_rs, f"missing item {item_id} lacks test ref {test_ref}")
    for command in as_string_list(item.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands"):
        require("cargo " not in command or "rch exec -- cargo " in command, f"required command must use rch: {command}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}

source_commit = git_head()
timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
events = [
    {
        "timestamp": timestamp,
        "event": "mode_contract_lock_completion_summary",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "summary",
        "source_commit": source_commit,
        "env_key": required.get("env_key"),
        "allowed_values": allowed_values,
        "default_value": required.get("default_value"),
        "artifact_refs": [rel(CONTRACT), str(source_artifacts.get("mode_contract_lock")), str(source_artifacts.get("membrane_config"))],
    },
    {
        "timestamp": timestamp,
        "event": "mode_contract_lock_source_gate_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "source_gates",
        "source_commit": source_commit,
        "mode_contract_lock_report": rel(MODE_LOCK_REPORT),
        "mode_contract_lock_log": rel(MODE_LOCK_LOG),
        "mode_semantics_gate_exit": command_outputs.get("scripts/check_mode_semantics.sh", {}).get("exit_code"),
        "source_log_row_count": len(mode_events),
        "artifact_refs": [
            str(source_artifacts.get("mode_contract_lock")),
            rel(MODE_LOCK_REPORT),
            rel(MODE_LOCK_LOG),
            str(source_artifacts.get("mode_semantics_matrix")),
        ],
    },
    {
        "timestamp": timestamp,
        "event": "mode_contract_lock_runtime_evidence_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "runtime_evidence",
        "source_commit": source_commit,
        "runtime_mode_evidence_report": rel(RUNTIME_EVIDENCE_REPORT),
        "runtime_mode_evidence_log": rel(RUNTIME_EVIDENCE_LOG),
        "source_log_row_count": len(runtime_events),
        "artifact_refs": [
            str(source_artifacts.get("runtime_mode_evidence_logging_coverage")),
            rel(RUNTIME_EVIDENCE_REPORT),
            rel(RUNTIME_EVIDENCE_LOG),
        ],
    },
    {
        "timestamp": timestamp,
        "event": "mode_contract_lock_completion_contract_pass",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "pass" if status == "pass" else "fail",
        "source_commit": source_commit,
        "artifact_refs": [rel(REPORT), rel(LOG)],
    },
]

event_names = {event["event"] for event in events}
for event_name in as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"):
    require(event_name in event_names, f"required telemetry event {event_name} was not emitted")
for event in events:
    for field in as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"):
        require(field in event, f"telemetry event {event.get('event')} missing field {field}")

status = "pass" if not errors else "fail"
for event in events:
    event["status"] = status
    if event["event"] == "mode_contract_lock_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": {
        "env_key": required.get("env_key"),
        "allowed_values": allowed_values,
        "default_value": required.get("default_value"),
        "unknown_value_behavior": required.get("unknown_value_behavior"),
        "required_provenance_fields": len(provenance_fields),
        "startup_reentrant_anchors": len(startup_anchor_names),
        "runtime_evidence_coverage_rows": runtime_summary.get("coverage_rows"),
    },
    "mode_contract_lock_report": rel(MODE_LOCK_REPORT),
    "mode_contract_lock_log": rel(MODE_LOCK_LOG),
    "runtime_mode_evidence_report": rel(RUNTIME_EVIDENCE_REPORT),
    "runtime_mode_evidence_log": rel(RUNTIME_EVIDENCE_LOG),
    "source_gate_outputs": command_outputs,
    "source_log_row_counts": {
        "mode_contract_lock": len(mode_events),
        "runtime_mode_evidence": len(runtime_events),
    },
    "events": [event["event"] for event in events],
    "errors": errors,
}

for field in as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields"):
    if field not in report:
        err(f"completion report missing required field {field}")

status = "pass" if not errors else "fail"
report["status"] = status
for event in events:
    event["status"] = status
    if event["event"] == "mode_contract_lock_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if status == "pass":
    print(
        "PASS: mode-contract-lock completion contract "
        f"(allowed={allowed_values}, provenance_fields={len(provenance_fields)}, report={rel(REPORT)})"
    )
else:
    print(f"FAIL: mode-contract-lock completion contract ({len(errors)} errors)")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)
PY
