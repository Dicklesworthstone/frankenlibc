#!/usr/bin/env bash
# Validate the deterministic contributor gate quickstart contract.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${CONTRIBUTOR_GATE_QUICKSTART_CONTRACT:-${ROOT}/tests/conformance/contributor_gate_quickstart.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${CONTRIBUTOR_GATE_QUICKSTART_REPORT:-${OUT_DIR}/contributor_gate_quickstart.report.json}"
LOG="${CONTRIBUTOR_GATE_QUICKSTART_LOG:-${OUT_DIR}/contributor_gate_quickstart.log.jsonl}"
MODE="validate-only"

if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:$1"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:$1"
fi

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${MODE}" <<'PY'
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "contributor_gate_quickstart.v1"
EXPECTED_BEAD = "bd-0agsk.15"
EXPECTED_TODOS = {"TODO-1004"}
EXPECTED_COMMAND = "scripts/check_contributor_gate_quickstart.sh --validate-only"
TARGET_DIR = pathlib.Path("target/conformance")
REQUIRED_WORKFLOWS = [
    ("architecture_ledger_reconciliation", "scripts/check_architecture_todo_reconciliation.sh"),
    ("support_reality_regeneration", "scripts/check_support_reality_regeneration.sh --validate-only"),
    ("fixture_schema_validation", "scripts/check_fixture_schema_validation.sh --validate-only"),
    ("replacement_guard", "scripts/check_replacement_guard.sh interpose"),
    ("runtime_mode_evidence", "scripts/check_runtime_mode_evidence_logging_coverage.sh --validate-only"),
    ("hardened_coverage_inventory", "scripts/check_hardened_mode_coverage_inventory.sh --validate-only"),
]
NEGATIVE_SIGNATURES = {
    "workflow_set_drift",
    "referenced_script_missing",
    "primary_artifact_missing",
    "failure_signature_unanchored",
}


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "contributor_gate_quickstart.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"contributor-gate-quickstart-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}",
        "source_commit": git_head(),
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": rel(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        json.dumps(
            {
                "timestamp": now_utc(),
                "event": "contributor_gate_quickstart_validated"
                if outcome == "pass"
                else "contributor_gate_quickstart_failed",
                "bead": EXPECTED_BEAD,
                "outcome": outcome,
                "failure_signature": signature,
                "contract": rel(contract_path),
                "summary": summary,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if outcome != "pass":
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary):
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary):
    if not condition:
        fail(signature, message, **summary)


def require_rel_path(raw, field: str) -> pathlib.Path:
    require(isinstance(raw, str) and raw.strip(), "field_missing", f"{field} must be a non-empty string", field=field)
    path = pathlib.Path(raw)
    require(not path.is_absolute(), "absolute_path_declared", f"{field} must be project-relative", field=field, path=raw)
    require(".." not in path.parts, "parent_path_declared", f"{field} must not contain parent traversal", field=field, path=raw)
    return path


def require_existing(raw, field: str) -> pathlib.Path:
    path = require_rel_path(raw, field)
    abs_path = root / path
    require(abs_path.exists(), "primary_artifact_missing", f"{field} missing: {path}", field=field, path=path.as_posix())
    return path


def command_tokens(command: str, field: str) -> list[str]:
    require(isinstance(command, str) and command.strip(), "field_missing", f"{field} must be a non-empty command", field=field)
    try:
        tokens = shlex.split(command)
    except ValueError as err:
        fail("command_parse_error", f"{field} could not be parsed: {err}", field=field, command=command)
    require(tokens, "command_parse_error", f"{field} parsed to no tokens", field=field, command=command)
    return tokens


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

require(contract_path.is_file(), "contract_missing", f"contract file missing: {contract_path}")
contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(set(contract.get("source_todo_ids", [])) == EXPECTED_TODOS, "todo_set_drift", "source TODO ids drifted", actual=contract.get("source_todo_ids"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical command", actual=contract.get("canonical_command"))

runner_policy = contract.get("runner_policy", {})
require(runner_policy.get("default_execution_host") == "local", "runner_policy_drift", "default execution host must stay local")
require(runner_policy.get("rch_required") is False, "runner_policy_drift", "quickstart shell gates must not require rch")
require(runner_policy.get("cargo_target_dir") == "not_applicable", "runner_policy_drift", "cargo target dir must be not_applicable")
require(runner_policy.get("report_target_dir") == TARGET_DIR.as_posix(), "runner_policy_drift", "report target dir drifted")

rows = contract.get("required_workflows")
require(isinstance(rows, list), "workflow_rows_missing", "required_workflows must be an array")
actual_ids = [row.get("id") for row in rows if isinstance(row, dict)]
expected_ids = [row_id for row_id, _ in REQUIRED_WORKFLOWS]
require(actual_ids == expected_ids, "workflow_set_drift", "required workflow ids or order drifted", expected=expected_ids, actual=actual_ids)

all_reports = []
all_logs = []
for index, ((workflow_id, expected_command), row) in enumerate(zip(REQUIRED_WORKFLOWS, rows), start=1):
    prefix = f"required_workflows[{index - 1}]"
    require(row.get("order") == index, "workflow_order_drift", f"{workflow_id}: order must be {index}", workflow_id=workflow_id, actual=row.get("order"))
    require(row.get("command") == expected_command, "workflow_command_drift", f"{workflow_id}: command drifted", workflow_id=workflow_id, expected=expected_command, actual=row.get("command"))
    require(row.get("execution_host") == "local", "workflow_execution_host_drift", f"{workflow_id}: execution_host must be local", workflow_id=workflow_id)
    command = row.get("command")
    tokens = command_tokens(command, f"{prefix}.command")
    script = require_rel_path(row.get("script"), f"{prefix}.script")
    require(tokens[0] == script.as_posix(), "workflow_command_drift", f"{workflow_id}: command must start with script path", workflow_id=workflow_id, command=command, script=script.as_posix())
    script_path = root / script
    require(script_path.is_file(), "referenced_script_missing", f"{workflow_id}: script missing: {script}", workflow_id=workflow_id, script=script.as_posix())
    require(os.access(script_path, os.X_OK), "referenced_script_not_executable", f"{workflow_id}: script is not executable: {script}", workflow_id=workflow_id, script=script.as_posix())
    script_text = script_path.read_text(encoding="utf-8")

    artifacts = row.get("primary_artifacts")
    require(isinstance(artifacts, list) and artifacts, "primary_artifacts_missing", f"{workflow_id}: primary_artifacts must be non-empty", workflow_id=workflow_id)
    for artifact_index, artifact in enumerate(artifacts):
        require_existing(artifact, f"{prefix}.primary_artifacts[{artifact_index}]")

    reports = row.get("expected_reports")
    require(isinstance(reports, list) and reports, "expected_reports_missing", f"{workflow_id}: expected_reports must be non-empty", workflow_id=workflow_id)
    for report_index, report in enumerate(reports):
        report_path_rel = require_rel_path(report, f"{prefix}.expected_reports[{report_index}]")
        require(report_path_rel.parent == TARGET_DIR, "report_target_dir_drift", f"{workflow_id}: report must live under {TARGET_DIR}", workflow_id=workflow_id, report=report_path_rel.as_posix())
        require(report_path_rel.suffix == ".json", "report_suffix_drift", f"{workflow_id}: report must be JSON", workflow_id=workflow_id, report=report_path_rel.as_posix())
        all_reports.append(report_path_rel.as_posix())

    logs = row.get("expected_logs")
    require(isinstance(logs, list) and logs, "expected_logs_missing", f"{workflow_id}: expected_logs must be non-empty", workflow_id=workflow_id)
    for log_index, log in enumerate(logs):
        log_path_rel = require_rel_path(log, f"{prefix}.expected_logs[{log_index}]")
        require(log_path_rel.parent == TARGET_DIR, "log_target_dir_drift", f"{workflow_id}: log must live under {TARGET_DIR}", workflow_id=workflow_id, log=log_path_rel.as_posix())
        require(log_path_rel.suffix == ".jsonl", "log_suffix_drift", f"{workflow_id}: log must be JSONL", workflow_id=workflow_id, log=log_path_rel.as_posix())
        all_logs.append(log_path_rel.as_posix())

    target_dir = require_rel_path(row.get("target_dir"), f"{prefix}.target_dir")
    require(target_dir == TARGET_DIR, "target_dir_drift", f"{workflow_id}: target_dir must be {TARGET_DIR}", workflow_id=workflow_id, target_dir=target_dir.as_posix())

    signatures = row.get("failure_signatures")
    require(isinstance(signatures, list) and signatures, "failure_signatures_missing", f"{workflow_id}: failure_signatures must be non-empty", workflow_id=workflow_id)
    for signature_index, signature in enumerate(signatures):
        require(isinstance(signature, str) and signature.strip(), "failure_signatures_missing", f"{workflow_id}: signature must be non-empty", workflow_id=workflow_id, signature_index=signature_index)
        require(signature in script_text, "failure_signature_unanchored", f"{workflow_id}: signature not found in script: {signature}", workflow_id=workflow_id, declared_signature=signature)

validation_commands = contract.get("validation_commands")
require(isinstance(validation_commands, list) and validation_commands, "validation_commands_missing", "validation_commands must be non-empty")
for idx, command in enumerate(validation_commands):
    tokens = command_tokens(command, f"validation_commands[{idx}]")
    if tokens[0].startswith("scripts/"):
        path = root / require_rel_path(tokens[0], f"validation_commands[{idx}].script")
        require(path.is_file(), "validation_command_path_missing", f"validation command script missing: {tokens[0]}", command=command)
    if tokens[0] == "jq":
        require(len(tokens) >= 3, "validation_command_path_missing", "jq validation command must name an artifact", command=command)
        require_existing(tokens[-1], f"validation_commands[{idx}].artifact")

negative_tests = contract.get("negative_tests")
require(isinstance(negative_tests, list) and negative_tests, "negative_tests_missing", "negative_tests must be non-empty")
actual_negative = {
    test.get("expected_failure_signature")
    for test in negative_tests
    if isinstance(test, dict)
}
require(NEGATIVE_SIGNATURES.issubset(actual_negative), "negative_test_missing", "negative tests missing required signatures", expected=sorted(NEGATIVE_SIGNATURES), actual=sorted(actual_negative))

summary = contract.get("summary", {})
require(summary.get("workflow_count") == len(REQUIRED_WORKFLOWS), "summary_count_drift", "workflow_count drifted", declared=summary.get("workflow_count"))
require(summary.get("local_command_count") == len(REQUIRED_WORKFLOWS), "summary_count_drift", "local_command_count drifted", declared=summary.get("local_command_count"))
require(summary.get("rch_command_count") == 0, "summary_count_drift", "rch_command_count must remain zero for shell quickstart", declared=summary.get("rch_command_count"))
require(summary.get("expected_report_count") == len(all_reports), "summary_count_drift", "expected_report_count drifted", declared=summary.get("expected_report_count"), actual=len(all_reports))
require(summary.get("expected_log_count") == len(all_logs), "summary_count_drift", "expected_log_count drifted", declared=summary.get("expected_log_count"), actual=len(all_logs))

finish(
    "pass",
    "none",
    "contributor gate quickstart validated",
    workflow_ids=expected_ids,
    reports=all_reports,
    logs=all_logs,
)
PY

echo "PASS: contributor gate quickstart validated"
