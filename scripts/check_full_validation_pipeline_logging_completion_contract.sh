#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_CONTRACT:-$ROOT/tests/conformance/full_validation_pipeline_logging_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_REPORT:-$OUT_DIR/full_validation_pipeline_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_FULL_VALIDATION_PIPELINE_LOGGING_LOG:-$OUT_DIR/full_validation_pipeline_logging_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import re
import stat
import subprocess
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "full_validation_pipeline_logging_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "full_validation_pipeline_logging_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-2icq.14"
COMPLETION_BEAD = "bd-2icq.14.1"
TRACE_ID = "bd-2icq-14-1-full-validation-pipeline-logging-completion-v1"
PASS_EVENT = "full_validation_pipeline_logging_completion_contract_validated"
FAIL_EVENT = "full_validation_pipeline_logging_completion_contract_failed"
EXPECTED_SCENARIOS = {
    "single_package": "test_single_package.sh",
    "build_wave": "test_build_wave.sh",
    "test_suite": "test_test_suite.sh",
    "full_pipeline": "test_full_pipeline.sh",
    "failure_recovery": "test_failure_recovery.sh",
    "progress_reporting": "test_progress_reporting.sh",
}
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.e2e.primary",
    "telemetry.primary",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "stream",
    "gate",
    "scenario_id",
    "runtime_mode",
    "replacement_level",
    "api_family",
    "symbol",
    "oracle_kind",
    "expected",
    "actual",
    "source_commit",
    "target_dir",
    "failure_signature",
    "artifact_refs",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "original_bead",
    "completion_debt_bead",
    "trace_id",
    "source_commit",
    "status",
    "scenario_contracts",
    "run_all_contract",
    "common_logging_contract",
    "missing_item_bindings",
    "summary",
    "artifact_refs",
    "errors",
}
REQUIRED_EVENTS = {
    "full_validation_pipeline_logging_source_gate",
    "full_validation_pipeline_logging_run_all_gate",
    "full_validation_pipeline_logging_common_gate",
    PASS_EVENT,
    FAIL_EVENT,
}

errors: list[str] = []
log_rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


COMMIT = source_commit()


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


def as_list(value: Any, context: str, allow_empty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    return value


def string_set(value: Any, context: str, allow_empty: bool = False) -> set[str]:
    result: set[str] = set()
    for index, item in enumerate(as_list(value, context, allow_empty=allow_empty)):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} unreadable: {path_text}: {exc}")
        return ""


def is_executable(path: pathlib.Path) -> bool:
    try:
        mode = path.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def file_line_ref_exists(ref: Any) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        err(f"invalid file-line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        err(f"invalid file-line ref line: {ref}")
        return
    path = ROOT / path_text
    if line_no <= 0 or not path.is_file():
        err(f"file-line ref missing path or positive line: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        err(f"file-line ref outside file: {ref}")


def shell_syntax(path_text: str) -> dict[str, Any]:
    proc = subprocess.run(
        ["bash", "-n", path_text],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return {
        "path": path_text,
        "exit_status": proc.returncode,
        "stdout_prefix": proc.stdout[:300],
        "stderr_prefix": proc.stderr[:300],
    }


def emit_row(event: str, gate: str, scenario_id: str, symbol: str, expected: Any, actual: Any, ok: bool) -> None:
    log_rows.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_BEAD}::full_validation_pipeline_logging::{scenario_id}",
            "level": "info" if ok else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "stream": "e2e" if gate in {"scenario", "run_all"} else "conformance",
            "gate": gate,
            "scenario_id": scenario_id,
            "runtime_mode": "hardened",
            "replacement_level": "L1",
            "api_family": "gentoo_e2e",
            "symbol": symbol,
            "oracle_kind": "static_contract_and_syntax_gate",
            "expected": expected,
            "actual": actual,
            "source_commit": COMMIT,
            "target_dir": rel(OUT_DIR),
            "failure_signature": "none" if ok else "contract_drift",
            "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
        }
    )


def validate_common_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    contract = manifest.get("common_logging_contract")
    if not isinstance(contract, dict):
        err("common_logging_contract must be an object")
        return {}
    script = contract.get("script")
    if not isinstance(script, str):
        err("common_logging_contract.script must be a string")
        return {}
    text = read_text(script, "common_logging_contract.script")
    actual = shell_syntax(script)
    ok = actual["exit_status"] == 0
    if not ok:
        err(f"common logging library has bash syntax errors: {actual['stderr_prefix']}")

    function_results: dict[str, bool] = {}
    for fn_name in string_set(contract.get("required_functions"), "common_logging_contract.required_functions"):
        found = re.search(rf"(^|\n){re.escape(fn_name)}\s*\(\)\s*\{{", text) is not None
        function_results[fn_name] = found
        if not found:
            err(f"common_logging_contract missing function {fn_name}")

    for needle in string_set(contract.get("required_needles"), "common_logging_contract.required_needles"):
        if needle not in text:
            err(f"common_logging_contract missing needle {needle!r}")

    for field in string_set(contract.get("required_summary_fields"), "common_logging_contract.required_summary_fields"):
        if f'"{field}"' not in text:
            err(f"common_logging_contract missing summary field {field}")

    actual.update(
        {
            "function_results": function_results,
            "required_needle_count": len(contract.get("required_needles", [])),
            "summary_field_count": len(contract.get("required_summary_fields", [])),
        }
    )
    emit_row(
        "full_validation_pipeline_logging_common_gate",
        "common",
        "common_logging_library",
        script,
        {"functions": sorted(function_results), "syntax_exit_status": 0},
        actual,
        not any(value is False for value in function_results.values()) and ok,
    )
    return actual


def validate_run_all_contract(manifest: dict[str, Any]) -> dict[str, Any]:
    contract = manifest.get("run_all_contract")
    if not isinstance(contract, dict):
        err("run_all_contract must be an object")
        return {}
    script = contract.get("script")
    if not isinstance(script, str):
        err("run_all_contract.script must be a string")
        return {}
    text = read_text(script, "run_all_contract.script")
    actual = shell_syntax(script)
    ok = actual["exit_status"] == 0
    if not ok:
        err(f"run_all_e2e has bash syntax errors: {actual['stderr_prefix']}")

    all_tests = string_set(contract.get("required_all_tests"), "run_all_contract.required_all_tests")
    fast_tests = string_set(contract.get("required_fast_tests"), "run_all_contract.required_fast_tests")
    for entry in sorted(all_tests):
        if f'"{entry}"' not in text:
            err(f"run_all_contract missing ALL_TESTS entry {entry}")
    for entry in sorted(fast_tests):
        if f'"{entry}"' not in text:
            err(f"run_all_contract missing FAST_TESTS entry {entry}")
    for field in string_set(contract.get("required_summary_fields"), "run_all_contract.required_summary_fields"):
        if f'"{field}"' not in text:
            err(f"run_all_contract missing summary field {field}")

    actual.update(
        {
            "all_tests": sorted(all_tests),
            "fast_tests": sorted(fast_tests),
            "summary_path": contract.get("summary_path"),
        }
    )
    emit_row(
        "full_validation_pipeline_logging_run_all_gate",
        "run_all",
        "run_all_e2e",
        script,
        {"all_test_count": len(EXPECTED_SCENARIOS), "syntax_exit_status": 0},
        actual,
        ok and EXPECTED_SCENARIOS.keys() <= {entry.split(":", 1)[0] for entry in all_tests},
    )
    return actual


def validate_scenario_contracts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    contracts = manifest.get("scenario_contracts")
    if not isinstance(contracts, list) or not contracts:
        err("scenario_contracts must be a non-empty array")
        return []
    by_id: dict[str, dict[str, Any]] = {}
    for contract in contracts:
        if not isinstance(contract, dict):
            err("scenario_contracts entries must be objects")
            continue
        scenario_id = contract.get("id")
        if not isinstance(scenario_id, str) or not scenario_id:
            err("scenario_contracts entry missing id")
            continue
        by_id[scenario_id] = contract

    missing = sorted(set(EXPECTED_SCENARIOS) - set(by_id))
    if missing:
        err(f"scenario_contracts missing {','.join(missing)}")

    duplicate_ids = [scenario_id for scenario_id in by_id if sum(1 for item in contracts if isinstance(item, dict) and item.get("id") == scenario_id) > 1]
    if duplicate_ids:
        err(f"scenario_contracts duplicate ids {sorted(set(duplicate_ids))}")

    results: list[dict[str, Any]] = []
    for scenario_id, expected_script_name in EXPECTED_SCENARIOS.items():
        contract = by_id.get(scenario_id)
        if not contract:
            continue
        script = contract.get("script")
        if not isinstance(script, str) or not script.endswith(expected_script_name):
            err(f"scenario {scenario_id} script must end with {expected_script_name}")
            script = str(script)
        path = ROOT / script
        require(path.is_file(), f"scenario {scenario_id} script missing: {script}")
        require(is_executable(path), f"scenario {scenario_id} script must be executable: {script}")
        text = read_text(script, f"scenario {scenario_id}")
        syntax = shell_syntax(script)
        if syntax["exit_status"] != 0:
            err(f"scenario {scenario_id} has bash syntax errors: {syntax['stderr_prefix']}")
        for base_needle in ["source \"${SCRIPT_DIR}/lib/common.sh\"", "e2e_init", "log_step", "e2e_finish"]:
            if base_needle not in text:
                err(f"scenario {scenario_id} missing base needle {base_needle!r}")
        e2e_name = contract.get("e2e_name")
        if isinstance(e2e_name, str) and f'e2e_init "{e2e_name}"' not in text:
            err(f"scenario {scenario_id} missing e2e_init name {e2e_name}")
        step_count = contract.get("step_count")
        if isinstance(step_count, int) and f'e2e_init "{e2e_name}" {step_count}' not in text:
            err(f"scenario {scenario_id} missing e2e_init step count {step_count}")
        for needle in string_set(contract.get("required_needles"), f"scenario_contracts.{scenario_id}.required_needles"):
            if needle not in text:
                err(f"scenario {scenario_id} missing needle {needle!r}")
        artifact_paths = string_set(contract.get("artifact_paths"), f"scenario_contracts.{scenario_id}.artifact_paths")
        require(bool(artifact_paths), f"scenario {scenario_id} must bind artifact paths")
        runtime = contract.get("runtime_target_minutes")
        if not isinstance(runtime, int) or runtime <= 0 or runtime > 30:
            err(f"scenario {scenario_id} runtime_target_minutes must be 1..30")
        result = {
            "id": scenario_id,
            "script": script,
            "syntax_exit_status": syntax["exit_status"],
            "runtime_target_minutes": runtime,
            "artifact_paths": sorted(artifact_paths),
            "required_needle_count": len(contract.get("required_needles", [])),
        }
        results.append(result)
        emit_row(
            "full_validation_pipeline_logging_source_gate",
            "scenario",
            scenario_id,
            script,
            {"script": expected_script_name, "syntax_exit_status": 0, "artifact_paths_non_empty": True},
            result,
            syntax["exit_status"] == 0 and path.is_file(),
        )
    return results


manifest = load_json(CONTRACT, "completion contract")
if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("original_bead") != ORIGINAL_BEAD:
    err(f"original_bead must be {ORIGINAL_BEAD}")
if manifest.get("completion_debt_bead") != COMPLETION_BEAD:
    err(f"completion_debt_bead must be {COMPLETION_BEAD}")
if manifest.get("trace_id") != TRACE_ID:
    err(f"trace_id must be {TRACE_ID}")

audit = manifest.get("audit_reference", {})
if not isinstance(audit, dict):
    err("audit_reference must be an object")
else:
    if audit.get("score_threshold", 0) < 800:
        err("audit_reference.score_threshold must be >= 800")

for ref in as_list(manifest.get("implementation_refs"), "implementation_refs"):
    file_line_ref_exists(ref)

artifacts = manifest.get("source_artifacts")
if not isinstance(artifacts, dict) or not artifacts:
    err("source_artifacts must be a non-empty object")
    artifacts = {}
for artifact_id, path_text in artifacts.items():
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{artifact_id} must be a non-empty string")
        continue
    require((ROOT / path_text).exists(), f"source artifact missing: {artifact_id}: {path_text}")

common_result = validate_common_contract(manifest)
run_all_result = validate_run_all_contract(manifest)
scenario_results = validate_scenario_contracts(manifest)

item_ids = set()
for item in as_list(manifest.get("missing_item_bindings"), "missing_item_bindings"):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    if isinstance(item_id, str):
        item_ids.add(item_id)
    refs = item.get("evidence_refs")
    if not isinstance(refs, list) or not refs:
        err(f"missing_item_bindings.{item_id}.evidence_refs must be a non-empty array")
missing_items = sorted(EXPECTED_MISSING_ITEMS - item_ids)
if missing_items:
    err(f"missing_item_bindings missing {','.join(missing_items)}")

evidence = manifest.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
report_fields = string_set(evidence.get("required_report_fields"), "completion_debt_evidence.required_report_fields")
log_fields = string_set(evidence.get("required_log_fields"), "completion_debt_evidence.required_log_fields")
events = string_set(evidence.get("required_events"), "completion_debt_evidence.required_events")
if not REQUIRED_REPORT_FIELDS <= report_fields:
    err(f"completion_debt_evidence.required_report_fields missing {sorted(REQUIRED_REPORT_FIELDS - report_fields)}")
if not REQUIRED_LOG_FIELDS <= log_fields:
    err(f"completion_debt_evidence.required_log_fields missing {sorted(REQUIRED_LOG_FIELDS - log_fields)}")
if not REQUIRED_EVENTS <= events:
    err(f"completion_debt_evidence.required_events missing {sorted(REQUIRED_EVENTS - events)}")

test_source_path = ROOT / "crates/frankenlibc-harness/tests/full_validation_pipeline_logging_completion_contract_test.rs"
test_source = test_source_path.read_text(encoding="utf-8") if test_source_path.is_file() else ""
for test_ref in string_set(evidence.get("required_test_refs"), "completion_debt_evidence.required_test_refs"):
    if f"fn {test_ref}" not in test_source:
        err(f"completion_debt_evidence.required_test_refs missing test fn {test_ref}")

status = "pass" if not errors else "fail"
summary_event = PASS_EVENT if not errors else FAIL_EVENT
summary_row = {
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_BEAD}::full_validation_pipeline_logging::summary",
    "level": "info" if not errors else "error",
    "event": summary_event,
    "bead_id": COMPLETION_BEAD,
    "stream": "conformance",
    "gate": "completion_contract",
    "scenario_id": "summary",
    "runtime_mode": "hardened",
    "replacement_level": "L1",
    "api_family": "gentoo_e2e",
    "symbol": rel(CONTRACT),
    "oracle_kind": "completion_debt_contract",
    "expected": {
        "scenario_count": len(EXPECTED_SCENARIOS),
        "missing_items": sorted(EXPECTED_MISSING_ITEMS),
    },
    "actual": {
        "scenario_count": len(scenario_results),
        "error_count": len(errors),
    },
    "source_commit": COMMIT,
    "target_dir": rel(OUT_DIR),
    "failure_signature": "none" if not errors else ";".join(errors[:8]),
    "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
}
log_rows.append(summary_row)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "trace_id": TRACE_ID,
    "source_commit": COMMIT,
    "status": status,
    "scenario_contracts": scenario_results,
    "run_all_contract": run_all_result,
    "common_logging_contract": common_result,
    "missing_item_bindings": sorted(item_ids),
    "summary": {
        "scenario_count": len(scenario_results),
        "expected_scenario_count": len(EXPECTED_SCENARIOS),
        "missing_item_count": len(item_ids),
        "log_row_count": len(log_rows),
        "source_artifact_count": len(artifacts),
        "required_report_field_count": len(report_fields),
        "required_log_field_count": len(log_fields),
    },
    "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
    "errors": errors,
}

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("\n".join(json.dumps(row, sort_keys=True) for row in log_rows) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"SCENARIO_COUNT={len(scenario_results)}")
print(f"LOG_ROWS={len(log_rows)}")
print(f"REPORT={rel(REPORT)}")
print(f"LOG={rel(LOG)}")
for message in errors:
    print(f"ERROR: {message}")

if errors:
    raise SystemExit(1)
PY
