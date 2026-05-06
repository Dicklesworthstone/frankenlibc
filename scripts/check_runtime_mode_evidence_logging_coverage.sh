#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_CONTRACT:-$ROOT/tests/conformance/runtime_mode_evidence_logging_coverage.v1.json}"
REPORT="${RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_REPORT:-$ROOT/target/conformance/runtime_mode_evidence_logging_coverage.report.json}"
LOG="${RUNTIME_MODE_EVIDENCE_LOGGING_COVERAGE_LOG:-$ROOT/target/conformance/runtime_mode_evidence_logging_coverage.log.jsonl}"
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

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$MODE" <<'PY'
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "runtime_mode_evidence_logging_coverage.v1"
EXPECTED_BEAD = "bd-0agsk.11"
EXPECTED_COMMAND = "scripts/check_runtime_mode_evidence_logging_coverage.sh --validate-only"
EXPECTED_TODOS = {"TODO-0701", "TODO-0702", "TODO-0703"}
REQUIRED_CAMPAIGNS = {
    "harness_conformance_matrix_isolated",
    "harness_kernel_regression_report",
    "shadow_run_candidate_replay",
    "standalone_link_run_smoke",
    "c_fixture_suite",
    "ld_preload_smoke",
    "e2e_suite",
}


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "runtime_mode_evidence_logging_coverage.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"runtime-mode-evidence-logging-coverage-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{id(summary)}",
        "source_commit": git_head(),
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": str(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        json.dumps(
            {
                "timestamp": now_utc(),
                "event": "runtime_mode_evidence_logging_coverage_validated"
                if outcome == "pass"
                else "runtime_mode_evidence_logging_coverage_failed",
                "bead": EXPECTED_BEAD,
                "outcome": outcome,
                "failure_signature": signature,
                "contract": str(contract_path),
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


def as_non_empty_string(value, field: str) -> str:
    require(isinstance(value, str) and value.strip(), "field_missing", f"{field} must be a non-empty string", field=field)
    return value


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

require(contract_path.is_file(), "contract_missing", f"missing contract: {contract_path}")
contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(set(contract.get("source_todo_ids", [])) == EXPECTED_TODOS, "todo_set_drift", "source TODO ids drifted", actual=contract.get("source_todo_ids"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical_command", actual=contract.get("canonical_command"))

for rel in contract.get("input_artifacts", []):
    require((root / rel).is_file(), "input_artifact_missing", f"input artifact missing: {rel}", artifact=rel)

policy = contract.get("coverage_policy", {})
require(policy.get("env_key") == "FRANKENLIBC_MODE", "policy_env_key", "coverage policy must target FRANKENLIBC_MODE")
require(set(policy.get("allowed_modes", [])) == {"strict", "hardened"}, "policy_allowed_modes", "allowed modes must be strict+hardened")
require(policy.get("process_immutable_after_startup") is True, "policy_immutability", "process immutability must be explicit")
require(policy.get("subprocess_rows_must_override_inherited_mode") is True, "policy_override", "subprocess override policy must be explicit")
require(policy.get("startup_evidence_required") is True, "policy_startup_evidence", "startup evidence policy must be explicit")
require(policy.get("trace_id_required") is True, "policy_trace_id", "trace id policy must be explicit")
require(policy.get("ambient_tz_dependency_allowed") is False, "policy_tz", "ambient TZ dependency must be forbidden")
require(policy.get("mismatch_behavior_required") is True, "policy_mismatch", "mismatch behavior policy must be explicit")

rows = contract.get("coverage_rows")
require(isinstance(rows, list) and rows, "coverage_rows_missing", "coverage_rows must be non-empty")
campaign_ids = [as_non_empty_string(row.get("campaign_id"), f"coverage_rows[{idx}].campaign_id") for idx, row in enumerate(rows)]
require(set(campaign_ids) == REQUIRED_CAMPAIGNS, "campaign_set_drift", "coverage campaign set drifted", declared=campaign_ids, expected=sorted(REQUIRED_CAMPAIGNS))
require(len(campaign_ids) == len(set(campaign_ids)), "duplicate_campaign", "coverage campaign ids must be unique", declared=campaign_ids)

for idx, row in enumerate(rows):
    prefix = f"coverage_rows[{idx}]"
    campaign_id = as_non_empty_string(row.get("campaign_id"), f"{prefix}.campaign_id")
    as_non_empty_string(row.get("launch_surface"), f"{prefix}.launch_surface")
    as_non_empty_string(row.get("subprocess_launcher"), f"{prefix}.subprocess_launcher")
    as_non_empty_string(row.get("startup_evidence_event"), f"{prefix}.startup_evidence_event")
    mismatch = as_non_empty_string(row.get("mismatch_behavior"), f"{prefix}.mismatch_behavior")
    trace_template = as_non_empty_string(row.get("evidence_trace_id_template"), f"{prefix}.evidence_trace_id_template")
    require(row.get("sets_frankenlibc_mode") is True, "mode_env_not_set", f"{campaign_id}: FRANKENLIBC_MODE must be set before subprocess launch", campaign_id=campaign_id)
    require(row.get("logs_startup_mode") is True, "startup_evidence_missing", f"{campaign_id}: startup-mode evidence is required", campaign_id=campaign_id)
    require("mode" in trace_template or "runtime_mode" in trace_template or "{seq}" in trace_template, "trace_id_mode_blind", f"{campaign_id}: trace id template must include mode/runtime/seq join key", campaign_id=campaign_id, trace_template=trace_template)
    require(mismatch != "none", "mismatch_behavior_missing", f"{campaign_id}: mismatch behavior must be explicit", campaign_id=campaign_id)

    controls = row.get("ambient_env_controls", {})
    require(controls.get("tz_dependency") is False, "ambient_tz_dependency", f"{campaign_id}: runtime-mode coverage must not depend on ambient TZ", campaign_id=campaign_id)
    require(controls.get("inherited_frankenlibc_mode_is_overridden") is True, "inherited_mode_not_overridden", f"{campaign_id}: inherited FRANKENLIBC_MODE must be overridden", campaign_id=campaign_id)

    source_checks = row.get("source_checks")
    require(isinstance(source_checks, list) and source_checks, "source_checks_missing", f"{campaign_id}: source_checks must be non-empty", campaign_id=campaign_id)
    for check_idx, check in enumerate(source_checks):
        rel = as_non_empty_string(check.get("path"), f"{prefix}.source_checks[{check_idx}].path")
        path = root / rel
        require(path.is_file(), "source_path_missing", f"{campaign_id}: source path missing: {rel}", campaign_id=campaign_id, path=rel)
        text = path.read_text(encoding="utf-8")
        tokens = check.get("tokens")
        require(isinstance(tokens, list) and tokens, "source_tokens_missing", f"{campaign_id}: source tokens must be non-empty", campaign_id=campaign_id, path=rel)
        for token in tokens:
            token = as_non_empty_string(token, f"{prefix}.source_checks[{check_idx}].token")
            require(token in text, "source_token_missing", f"{campaign_id}: source token missing in {rel}: {token}", campaign_id=campaign_id, path=rel, token=token)

summary = contract.get("summary", {})
require(summary.get("coverage_row_count") == len(rows), "summary_row_count", "summary coverage_row_count drifted", declared=summary.get("coverage_row_count"), actual=len(rows))
require(summary.get("subprocess_row_count") == len(rows), "summary_subprocess_count", "summary subprocess_row_count drifted", declared=summary.get("subprocess_row_count"), actual=len(rows))
require(summary.get("startup_evidence_row_count") == len(rows), "summary_startup_count", "summary startup_evidence_row_count drifted", declared=summary.get("startup_evidence_row_count"), actual=len(rows))
require(summary.get("ambient_tz_dependent_row_count") == 0, "summary_tz_count", "summary ambient_tz_dependent_row_count must stay zero", declared=summary.get("ambient_tz_dependent_row_count"))
require(summary.get("mismatch_behavior_row_count") == len(rows), "summary_mismatch_count", "summary mismatch_behavior_row_count drifted", declared=summary.get("mismatch_behavior_row_count"), actual=len(rows))

negative_signatures = {
    test.get("expected_failure_signature")
    for test in contract.get("negative_tests", [])
    if isinstance(test, dict)
}
for signature in ["startup_evidence_missing", "ambient_tz_dependency", "source_token_missing"]:
    require(signature in negative_signatures, "negative_test_missing", f"missing negative test declaration for {signature}", expected_signature=signature)

finish(
    "pass",
    "none",
    "runtime-mode evidence logging coverage validated",
    coverage_rows=len(rows),
    campaigns=sorted(campaign_ids),
    startup_evidence_rows=summary.get("startup_evidence_row_count"),
)
PY

echo "PASS: runtime-mode evidence logging coverage validated"
