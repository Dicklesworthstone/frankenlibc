#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_CONTRACT:-$ROOT/tests/conformance/l1_hardened_interpose_graduation_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_REPORT:-$OUT_DIR/l1_hardened_interpose_graduation_completion_contract.report.json}"
LOG="${FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_COMPLETION_LOG:-$OUT_DIR/l1_hardened_interpose_graduation_completion_contract.log.jsonl}"
SOURCE_REPORT="${FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_SOURCE_REPORT:-$OUT_DIR/replacement_levels_l1_gate.source.report.json}"
SOURCE_LOG="${FRANKENLIBC_L1_HARDENED_INTERPOSE_GRADUATION_SOURCE_LOG:-$OUT_DIR/replacement_levels_l1_gate.source.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$SOURCE_REPORT")" "$(dirname "$SOURCE_LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
SOURCE_REPORT="$SOURCE_REPORT" \
SOURCE_LOG="$SOURCE_LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
SOURCE_LOG = pathlib.Path(os.environ["SOURCE_LOG"])

EXPECTED_SCHEMA = "l1_hardened_interpose_graduation_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "l1_hardened_interpose_graduation_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-gtf.4"
COMPLETION_BEAD = "bd-gtf.4.1"

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


def run_source_checker(source_checker: str) -> None:
    env = os.environ.copy()
    env["FLC_REPLACEMENT_LEVELS_REPORT_PATH"] = str(SOURCE_REPORT)
    env["FLC_REPLACEMENT_LEVELS_LOG_PATH"] = str(SOURCE_LOG)
    env.setdefault("SOURCE_COMMIT", "current")
    proc = subprocess.run(
        ["bash", source_checker],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        err(
            "source replacement levels checker failed: "
            f"exit={proc.returncode} stdout={proc.stdout[:1600]!r} stderr={proc.stderr[:1600]!r}"
        )


def object_by_key(items: Any, key: str) -> dict[str, dict[str, Any]]:
    if not isinstance(items, list):
        return {}
    result = {}
    for item in items:
        if isinstance(item, dict) and isinstance(item.get(key), str):
            result[item[key]] = item
    return result


manifest = load_json(CONTRACT, "contract")

require(manifest.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
require(manifest.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
require(
    manifest.get("completion_debt_bead") == COMPLETION_BEAD,
    f"completion_debt_bead must be {COMPLETION_BEAD}",
)

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

for ref in manifest.get("completion_debt_evidence", {}).get("implementation_refs", []):
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

test_sources = manifest.get("completion_debt_evidence", {}).get("test_sources", {})
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

levels_path = ROOT / str(source_artifacts.get("replacement_levels", ""))
levels = load_json(levels_path, "replacement_levels")
level_map = object_by_key(levels.get("levels"), "level")
l1_entry = level_map.get("L1", {})
objective_gate = l1_entry.get("objective_gate", {}) if isinstance(l1_entry, dict) else {}
obligations = objective_gate.get("obligations", []) if isinstance(objective_gate, dict) else []
obligation_by_id = object_by_key(obligations, "id")

require(levels.get("current_level") == required.get("current_level"), "current_level mismatch")
release_level = levels.get("release_tag_policy", {}).get("current_release_level")
require(release_level == required.get("current_release_level"), "release_tag_policy.current_release_level mismatch")
require(objective_gate.get("status") == required.get("l1_objective_status"), "L1 objective_gate.status mismatch")
require(len(obligations) == required.get("objective_obligation_count"), "L1 objective obligation count mismatch")
objective_outcomes = Counter(
    obligation.get("outcome", "unknown") for obligation in obligations if isinstance(obligation, dict)
)
for outcome, expected_count in required.get("objective_outcomes", {}).items():
    require(objective_outcomes.get(outcome, 0) == expected_count, f"objective outcome {outcome} count mismatch")
require(
    objective_gate.get("required_log_fields") == required.get("required_log_fields"),
    "objective_gate.required_log_fields mismatch",
)
generated_report = objective_gate.get("generated_report", {}) if isinstance(objective_gate, dict) else {}
require(
    generated_report.get("gate_script") == source_artifacts.get("source_checker"),
    "objective_gate.generated_report.gate_script mismatch",
)

for obligation_id in as_string_list(required.get("required_objective_obligations"), "required_source_contract.required_objective_obligations"):
    require(obligation_id in obligation_by_id, f"required objective obligation missing: {obligation_id}")
for artifact_ref in as_string_list(required.get("required_evidence_artifacts"), "required_source_contract.required_evidence_artifacts"):
    require(artifact_ref in objective_gate.get("evidence_bundle", {}).get("artifact_refs", []), f"required evidence artifact missing from objective gate: {artifact_ref}")
    require((ROOT / artifact_ref).exists(), f"required evidence artifact missing on disk: {artifact_ref}")

l1_crt_path = ROOT / str(source_artifacts.get("l1_crt_startup_tls_matrix", ""))
l1_crt = load_json(l1_crt_path, "l1_crt_startup_tls_matrix")
l1_summary = l1_crt.get("summary", {}) if isinstance(l1_crt.get("summary"), dict) else {}
require(len(l1_crt.get("proof_rows", [])) == required.get("l1_crt_proof_row_count"), "L1 CRT proof row count mismatch")
require(l1_summary.get("satisfied_row_count") == required.get("l1_crt_satisfied_row_count"), "L1 CRT satisfied row count mismatch")
require(l1_summary.get("blocked_row_count") == required.get("l1_crt_blocked_row_count"), "L1 CRT blocked row count mismatch")
expected_l1_crt_status = required.get("l1_crt_current_gate_status", "blocked")
require(
    l1_summary.get("current_gate_status") == expected_l1_crt_status,
    f"L1 CRT current_gate_status must be {expected_l1_crt_status}",
)

source_checker = source_artifacts.get("source_checker")
if isinstance(source_checker, str) and source_checker:
    run_source_checker(source_checker)
else:
    err("source_checker artifact path is missing")

source_report = load_json(SOURCE_REPORT, "source_gate_report")
source_events = json_lines(SOURCE_LOG, "source_gate_log")

for field in as_string_list(required.get("required_report_fields"), "required_source_contract.required_report_fields"):
    require(field in source_report, f"source gate report missing field {field}")
require(source_report.get("status") == "pass", "source gate report status must be pass")
require(source_report.get("bead_id") == ORIGINAL_BEAD, f"source gate report bead_id must be {ORIGINAL_BEAD}")
require(source_report.get("gate_id") == "replacement_levels_l1_gate", "source gate report gate_id mismatch")
require(source_report.get("current_level") == required.get("current_level"), "source gate report current_level mismatch")
require(source_report.get("objective_gate_status") == required.get("l1_objective_status"), "source gate report objective_gate_status mismatch")

summary = source_report.get("summary", {}) if isinstance(source_report.get("summary"), dict) else {}
require(summary.get("script_check_count") == required.get("script_check_count"), "source summary.script_check_count mismatch")
require(summary.get("script_failure_count") == required.get("script_failure_count"), "source summary.script_failure_count mismatch")
require(summary.get("objective_obligation_count") == required.get("objective_obligation_count"), "source summary.objective_obligation_count mismatch")
require(summary.get("l1_crt_proof_row_count") == required.get("l1_crt_proof_row_count"), "source summary.l1_crt_proof_row_count mismatch")
for outcome, expected_count in required.get("objective_outcomes", {}).items():
    require(
        summary.get("objective_outcomes", {}).get(outcome) == expected_count,
        f"source summary objective_outcomes.{outcome} mismatch",
    )

script_check_ids = {
    check.get("id")
    for check in source_report.get("script_checks", [])
    if isinstance(check, dict) and isinstance(check.get("id"), str)
}
for check_id in as_string_list(required.get("required_script_checks"), "required_source_contract.required_script_checks"):
    require(check_id in script_check_ids, f"required source script check missing: {check_id}")

source_counts = Counter(record.get("source", "unknown") for record in source_events)
for source in as_string_list(required.get("required_source_log_sources"), "required_source_contract.required_source_log_sources"):
    require(source_counts.get(source, 0) > 0, f"source gate log missing source={source}")
expected_log_rows = (
    int(summary.get("script_check_count", 0))
    + int(summary.get("objective_obligation_count", 0))
    + int(summary.get("l1_crt_proof_row_count", 0)) * 2
)
require(len(source_events) == expected_log_rows, f"source gate log row count expected {expected_log_rows}, got {len(source_events)}")
for record in source_events[: min(len(source_events), 16)]:
    if record.get("source") in {"script_check", "objective_gate"}:
        for field in required.get("required_log_fields", []):
            require(field in record, f"source gate log row missing required objective field {field}")

for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    for test_ref in as_string_list(item.get("required_test_refs"), f"missing_item_bindings.{item_id}.required_test_refs"):
        require(test_ref in all_test_text, f"missing item {item_id} lacks test ref {test_ref}")
    for command in as_string_list(item.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands"):
        require("cargo " not in command or "rch exec -- cargo " in command, f"required command must use rch: {command}")

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
events = [
    {
        "timestamp": timestamp,
        "event": "l1_hardened_interpose_completion_summary",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "summary",
        "current_level": levels.get("current_level"),
        "objective_gate_status": objective_gate.get("status"),
        "objective_obligation_count": len(obligations),
        "l1_crt_proof_row_count": len(l1_crt.get("proof_rows", [])),
    },
    {
        "timestamp": timestamp,
        "event": "l1_hardened_interpose_source_gate_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "source_gate",
        "source_gate_report": rel(SOURCE_REPORT),
        "source_gate_log": rel(SOURCE_LOG),
        "source_log_row_count": len(source_events),
        "script_check_count": summary.get("script_check_count"),
    },
    {
        "timestamp": timestamp,
        "event": "l1_hardened_interpose_objective_gate_bindings",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "objective_gate",
        "objective_outcomes": dict(objective_outcomes),
        "required_log_fields": objective_gate.get("required_log_fields"),
    },
    {
        "timestamp": timestamp,
        "event": "l1_hardened_interpose_completion_contract_pass",
        "bead_id": manifest.get("manifest_id"),
        "source_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "status": status,
        "outcome": "pass" if status == "pass" else "fail",
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
    if event["event"] == "l1_hardened_interpose_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "summary": {
        "current_level": levels.get("current_level"),
        "current_release_level": release_level,
        "objective_gate_status": objective_gate.get("status"),
        "objective_obligation_count": len(obligations),
        "objective_outcomes": dict(objective_outcomes),
        "l1_crt_proof_row_count": len(l1_crt.get("proof_rows", [])),
        "l1_crt_satisfied_row_count": l1_summary.get("satisfied_row_count"),
        "l1_crt_blocked_row_count": l1_summary.get("blocked_row_count"),
        "source_script_check_count": summary.get("script_check_count"),
        "source_script_failure_count": summary.get("script_failure_count"),
    },
    "source_gate_report": rel(SOURCE_REPORT),
    "source_gate_log": rel(SOURCE_LOG),
    "source_log_row_count": len(source_events),
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
    if event["event"] == "l1_hardened_interpose_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as handle:
    for event in events:
        handle.write(json.dumps(event, sort_keys=True) + "\n")

if status == "pass":
    print(
        "PASS: l1 hardened interpose graduation completion contract "
        f"(objective_obligations={len(obligations)}, source_log_rows={len(source_events)}, report={rel(REPORT)})"
    )
else:
    print(f"FAIL: l1 hardened interpose graduation completion contract ({len(errors)} errors)")
    for message in errors:
        print(f"  - {message}")
    raise SystemExit(1)
PY
