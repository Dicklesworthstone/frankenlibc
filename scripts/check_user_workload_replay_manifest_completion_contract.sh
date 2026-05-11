#!/usr/bin/env bash
# Completion gate for bd-b92jd.3.1.1 workload replay manifest evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${1:-$ROOT/tests/conformance/user_workload_replay_manifest_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_USER_WORKLOAD_REPLAY_MANIFEST_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="$OUT_DIR/user_workload_replay_manifest_completion_contract.report.json"
LOG="$OUT_DIR/user_workload_replay_manifest_completion_contract.log.jsonl"
SOURCE_REPORT="$OUT_DIR/user_workload_replay_manifest_completion_contract.source.report.json"
SOURCE_LOG="$OUT_DIR/user_workload_replay_manifest_completion_contract.source.log.jsonl"
SOURCE_TARGET="$OUT_DIR/user_workload_replay_manifest_completion_source_target"

mkdir -p "$OUT_DIR"

ROOT="$ROOT" CONTRACT="$CONTRACT" REPORT="$REPORT" LOG="$LOG" SOURCE_REPORT="$SOURCE_REPORT" SOURCE_LOG="$SOURCE_LOG" SOURCE_TARGET="$SOURCE_TARGET" python3 - <<'PY'
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
SOURCE_REPORT = pathlib.Path(os.environ["SOURCE_REPORT"])
SOURCE_LOG = pathlib.Path(os.environ["SOURCE_LOG"])
SOURCE_TARGET = pathlib.Path(os.environ["SOURCE_TARGET"])

EXPECTED_SCHEMA = "user_workload_replay_manifest_completion_contract.v1"
COMPLETION_BEAD = "bd-b92jd.3.1.1"
ORIGINAL_BEAD = "bd-b92jd.3.1"
TRACE_ID = "bd-b92jd.3.1.1::user-workload-replay-manifest::v1"
EXPECTED_ITEMS = {"tests.unit.primary", "tests.conformance.primary", "telemetry.primary"}
EXPECTED_MODES = ["baseline", "strict", "hardened"]
EXPECTED_CATEGORIES = {"coreutils", "shell_pipeline", "dynamic_runtime", "c_fixture", "optional_tool"}
EXPECTED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "workload_id",
    "category",
    "runtime_mode",
    "command_kind",
    "command_argv",
    "env_overlay",
    "timeout_ms",
    "expected_exit",
    "expected_stdout_kind",
    "optional",
    "skip_reason",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
EXPECTED_FAILURE_SIGNATURES = {
    "workload_replay_invalid_command_argv",
    "workload_replay_invalid_env_overlay",
    "workload_replay_timeout_policy_invalid",
    "workload_replay_optional_skip_missing",
    "workload_replay_stale_source_commit",
}

errors: list[dict[str, str]] = []
events: list[dict[str, Any]] = []


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


SOURCE_COMMIT = git_head()


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def add_error(signature: str, message: str) -> None:
    errors.append({"signature": signature, "message": message})


def emit(name: str, status: str, expected: Any, observed: Any) -> None:
    events.append(
        {
            "timestamp": timestamp(),
            "event": name,
            "status": status,
            "bead_id": COMPLETION_BEAD,
            "trace_id": TRACE_ID,
            "source_commit": SOURCE_COMMIT,
            "expected": expected,
            "observed": observed,
            "artifact_refs": [rel(REPORT), rel(LOG), rel(SOURCE_REPORT), rel(SOURCE_LOG)],
        }
    )


def load_json(path: pathlib.Path, signature: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_error(signature, f"{rel(path)} is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        add_error(signature, f"{rel(path)} must be a JSON object")
        return {}
    return value


def load_jsonl(path: pathlib.Path, signature: str) -> list[dict[str, Any]]:
    try:
        rows = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except Exception as exc:
        add_error(signature, f"{rel(path)} is not valid JSONL: {exc}")
        return []
    result: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            add_error(signature, f"{rel(path)} row {index} must be an object")
            continue
        result.append(row)
    return result


def string_set(value: Any, context: str, signature: str) -> set[str]:
    if not isinstance(value, list):
        add_error(signature, f"{context} must be an array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            add_error(signature, f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_source(path_text: Any, context: str) -> str:
    if not isinstance(path_text, str) or not path_text:
        add_error("missing_source_artifact", f"{context} must be a path string")
        return ""
    path = ROOT / path_text
    if not path.is_file():
        add_error("missing_source_artifact", f"{context} missing file {path_text}")
        return ""
    return path.read_text(encoding="utf-8")


def validate_header(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != EXPECTED_SCHEMA:
        add_error("contract_header_drift", "schema_version mismatch")
    if manifest.get("bead") != COMPLETION_BEAD:
        add_error("contract_header_drift", "bead mismatch")
    if manifest.get("original_bead") != ORIGINAL_BEAD:
        add_error("contract_header_drift", "original_bead mismatch")
    if manifest.get("trace_id") != TRACE_ID:
        add_error("contract_header_drift", "trace_id mismatch")
    threshold = manifest.get("completion_debt_evidence", {}).get("next_audit_score_threshold", 0)
    if int(threshold or 0) < 800:
        add_error("contract_header_drift", "next audit score threshold must be at least 800")


def validate_source_artifacts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts = manifest.get("source_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        add_error("missing_source_artifact", "source_artifacts must be a non-empty array")
        emit("source_artifacts_validated", "fail", "source artifact files", [])
        return []
    observed: list[str] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            add_error("missing_source_artifact", f"source_artifacts[{index}] must be an object")
            continue
        path_text = artifact.get("path")
        if not isinstance(path_text, str) or not path_text:
            add_error("missing_source_artifact", f"source_artifacts[{index}].path is invalid")
            continue
        observed.append(path_text)
        if not (ROOT / path_text).is_file():
            add_error("missing_source_artifact", f"missing source artifact {path_text}")
    status = "fail" if any(error["signature"] == "missing_source_artifact" for error in errors) else "pass"
    emit("source_artifacts_validated", status, "all source artifacts exist", observed)
    return [artifact for artifact in artifacts if isinstance(artifact, dict)]


def validate_bindings(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    evidence = manifest.get("completion_debt_evidence")
    if not isinstance(evidence, dict):
        add_error("missing_completion_binding", "completion_debt_evidence must be an object")
        emit("completion_bindings_validated", "fail", sorted(EXPECTED_ITEMS), [])
        return []
    bindings = evidence.get("missing_item_bindings")
    if not isinstance(bindings, list):
        add_error("missing_completion_binding", "missing_item_bindings must be an array")
        emit("completion_bindings_validated", "fail", sorted(EXPECTED_ITEMS), [])
        return []
    specs = {binding.get("spec_item") for binding in bindings if isinstance(binding, dict)}
    if specs != EXPECTED_ITEMS:
        add_error("missing_completion_binding", f"expected {sorted(EXPECTED_ITEMS)} but saw {sorted(str(spec) for spec in specs)}")
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            add_error("missing_completion_binding", f"missing_item_bindings[{index}] must be an object")
            continue
        for key in ("implementation_refs", "test_refs", "required_positive_tests", "required_negative_tests", "required_commands"):
            if not string_set(binding.get(key), f"missing_item_bindings[{index}].{key}", "missing_completion_binding"):
                add_error("missing_completion_binding", f"missing_item_bindings[{index}].{key} must be non-empty")
    status = "fail" if any(error["signature"] == "missing_completion_binding" for error in errors) else "pass"
    emit("completion_bindings_validated", status, sorted(EXPECTED_ITEMS), sorted(str(spec) for spec in specs))
    return [binding for binding in bindings if isinstance(binding, dict)]


def validate_contract_runtime(runtime: dict[str, Any]) -> None:
    if runtime.get("source_bead") != ORIGINAL_BEAD:
        add_error("manifest_contract_drift", "source_bead mismatch")
    if runtime.get("required_modes") != EXPECTED_MODES:
        add_error("manifest_contract_drift", "required_modes mismatch")
    categories = string_set(runtime.get("required_categories"), "required_categories", "manifest_contract_drift")
    if categories != EXPECTED_CATEGORIES:
        add_error("manifest_contract_drift", "required_categories mismatch")
    if runtime.get("expected_workload_count") != 5:
        add_error("manifest_contract_drift", "expected_workload_count mismatch")
    if runtime.get("expected_matrix_row_count") != 15:
        add_error("manifest_contract_drift", "expected_matrix_row_count mismatch")
    if runtime.get("expected_optional_workload_count") != 1:
        add_error("manifest_contract_drift", "expected_optional_workload_count mismatch")
    log_fields = list(runtime.get("required_log_fields", []))
    if log_fields != EXPECTED_LOG_FIELDS:
        add_error("telemetry_contract_drift", "required_log_fields mismatch")
    signatures = string_set(runtime.get("required_failure_signatures"), "required_failure_signatures", "unit_binding_drift")
    if signatures != EXPECTED_FAILURE_SIGNATURES:
        add_error("unit_binding_drift", "required failure signatures drifted")

    source_test = read_source(runtime.get("source_harness_test_path"), "source_harness_test_path")
    for test_name in string_set(runtime.get("required_unit_tests"), "required_unit_tests", "unit_binding_drift"):
        if f"fn {test_name}" not in source_test:
            add_error("unit_binding_drift", f"missing source harness test {test_name}")
    for signature in EXPECTED_FAILURE_SIGNATURES:
        if signature not in source_test:
            add_error("unit_binding_drift", f"source harness missing failure signature {signature}")


def run_source_gate(runtime: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    checker_path = ROOT / str(runtime.get("source_checker_path", ""))
    manifest_path = ROOT / str(runtime.get("source_manifest_path", ""))
    if not checker_path.is_file() or not manifest_path.is_file():
        add_error("source_gate_failed", "source checker or manifest path is missing")
        emit("source_gate_replayed", "fail", "source checker pass", "missing source files")
        return {}, []
    env = os.environ.copy()
    env.update(
        {
            "USER_WORKLOAD_REPLAY_MANIFEST": str(manifest_path),
            "USER_WORKLOAD_REPLAY_REPORT": str(SOURCE_REPORT),
            "USER_WORKLOAD_REPLAY_LOG": str(SOURCE_LOG),
            "USER_WORKLOAD_REPLAY_TARGET_DIR": str(SOURCE_TARGET),
        }
    )
    output = subprocess.run(
        ["bash", str(checker_path), "--dry-run"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if output.returncode != 0:
        add_error("source_gate_failed", f"source checker failed stdout={output.stdout} stderr={output.stderr}")
    source_report = load_json(SOURCE_REPORT, "source_gate_failed")
    source_rows = load_jsonl(SOURCE_LOG, "telemetry_contract_drift")
    if source_report.get("status") != "pass":
        add_error("source_gate_failed", "source report status is not pass")
    if source_report.get("bead") != ORIGINAL_BEAD:
        add_error("source_gate_failed", "source report bead mismatch")
    if source_report.get("workload_count") != 5:
        add_error("source_gate_failed", "source report workload_count mismatch")
    if source_report.get("matrix_row_count") != 15:
        add_error("source_gate_failed", "source report matrix_row_count mismatch")
    if source_report.get("optional_workload_count") != 1:
        add_error("source_gate_failed", "source report optional_workload_count mismatch")
    coverage = set((source_report.get("required_category_coverage") or {}).keys())
    if coverage != EXPECTED_CATEGORIES:
        add_error("source_gate_failed", "source report category coverage mismatch")
    for check_name in runtime.get("required_source_checks", []):
        if source_report.get("checks", {}).get(check_name) != "pass":
            add_error("source_gate_failed", f"source check {check_name} did not pass")
    status = "fail" if any(error["signature"] == "source_gate_failed" for error in errors) else "pass"
    emit(
        "source_gate_replayed",
        status,
        {"workloads": 5, "rows": 15, "categories": sorted(EXPECTED_CATEGORIES)},
        {"workloads": source_report.get("workload_count"), "rows": source_report.get("matrix_row_count"), "categories": sorted(coverage)},
    )
    return source_report, source_rows


def validate_telemetry_rows(rows: list[dict[str, Any]]) -> None:
    if len(rows) != 15:
        add_error("telemetry_contract_drift", f"expected 15 telemetry rows, saw {len(rows)}")
    modes = {row.get("runtime_mode") for row in rows}
    if list(sorted(modes)) != sorted(EXPECTED_MODES):
        add_error("telemetry_contract_drift", f"runtime modes drifted: {sorted(str(mode) for mode in modes)}")
    categories = {row.get("category") for row in rows}
    if categories != EXPECTED_CATEGORIES:
        add_error("telemetry_contract_drift", f"telemetry categories drifted: {sorted(str(category) for category in categories)}")
    for index, row in enumerate(rows):
        missing = [field for field in EXPECTED_LOG_FIELDS if field not in row]
        if missing:
            add_error("telemetry_contract_drift", f"source log row {index} missing fields {missing}")
    optional_rows = [
        row
        for row in rows
        if row.get("workload_id") == "optional_sqlite_version_probe"
        and row.get("skip_reason") == "optional_tool_missing:sqlite3"
    ]
    if len(optional_rows) != 3:
        add_error("telemetry_contract_drift", "optional sqlite rows must carry deterministic skip reason in all modes")
    status = "fail" if any(error["signature"] == "telemetry_contract_drift" for error in errors) else "pass"
    emit(
        "telemetry_rows_validated",
        status,
        {"rows": 15, "fields": EXPECTED_LOG_FIELDS},
        {"rows": len(rows), "fields": sorted(rows[0].keys()) if rows else []},
    )


def main() -> int:
    manifest = load_json(CONTRACT, "invalid_contract_json")
    validate_header(manifest)
    artifacts = validate_source_artifacts(manifest)
    bindings = validate_bindings(manifest)
    runtime = manifest.get("user_workload_replay_manifest_contract")
    if not isinstance(runtime, dict):
        add_error("manifest_contract_drift", "user_workload_replay_manifest_contract must be an object")
        runtime = {}
    validate_contract_runtime(runtime)
    source_report, source_rows = run_source_gate(runtime)
    validate_telemetry_rows(source_rows)

    status = "fail" if errors else "pass"
    if status == "pass":
        emit(
            "user_workload_replay_manifest_completion_contract_pass",
            "pass",
            "source manifest, unit, conformance, and telemetry bindings",
            {"workloads": source_report.get("workload_count"), "rows": len(source_rows)},
        )
    else:
        emit(
            "user_workload_replay_manifest_completion_contract_failed",
            "fail",
            "source manifest, unit, conformance, and telemetry bindings",
            [error["signature"] for error in errors],
        )

    report = {
        "schema_version": EXPECTED_SCHEMA,
        "bead_id": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": SOURCE_COMMIT,
        "status": status,
        "summary": {
            "binding_count": len(bindings),
            "workload_count": source_report.get("workload_count", 0),
            "matrix_row_count": source_report.get("matrix_row_count", 0),
            "telemetry_row_count": len(source_rows),
            "failure_signature_count": len(EXPECTED_FAILURE_SIGNATURES),
        },
        "source_artifacts": artifacts,
        "missing_item_bindings": bindings,
        "artifact_refs": [rel(REPORT), rel(LOG), rel(SOURCE_REPORT), rel(SOURCE_LOG)],
        "errors": errors,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LOG.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in events), encoding="utf-8")
    if status == "pass":
        print(
            "PASS user_workload_replay_manifest_completion_contract "
            f"bindings={len(bindings)} workloads={source_report.get('workload_count', 0)} "
            f"matrix_rows={source_report.get('matrix_row_count', 0)} telemetry_rows={len(source_rows)} "
            f"report={rel(REPORT)} log={rel(LOG)}"
        )
        return 0
    print(
        "FAIL user_workload_replay_manifest_completion_contract "
        + ", ".join(error["signature"] for error in errors),
        file=sys.stderr,
    )
    return 1


sys.exit(main())
PY
