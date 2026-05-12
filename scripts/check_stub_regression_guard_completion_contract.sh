#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_STUB_REGRESSION_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/stub_regression_guard_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_STUB_REGRESSION_COMPLETION_REPORT:-${ROOT}/target/conformance/stub_regression_guard_completion_contract.report.json}"
LOG="${FRANKENLIBC_STUB_REGRESSION_COMPLETION_LOG:-${ROOT}/target/conformance/stub_regression_guard_completion_contract.log.jsonl}"
RUN_GUARD="${FRANKENLIBC_STUB_REGRESSION_COMPLETION_RUN_GUARD:-1}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$RUN_GUARD" <<'PY'
import json
import os
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
run_guard = sys.argv[5].lower() not in {"0", "false", "no"}
start_ns = time.time_ns()

EXPECTED_SCHEMA = "stub_regression_guard_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "stub_regression_guard_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-1p5v"
EXPECTED_COMPLETION_BEAD = "bd-1p5v.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "guard_script",
    "waiver_policy",
    "census",
    "census_generator",
    "priority_ranking",
    "wave_plan",
    "guard_harness",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
EXPECTED_GUARD_CHECKS = [
    "artifact_current",
    "waiver_schema_valid",
    "symbol_coverage_valid",
    "matrix_stub_policy_valid",
    "stale_waivers_absent",
    "waiver_evidence_valid",
    "burn_down_thresholds_valid",
    "downgrade_evidence_valid",
]
EXPECTED_ZERO_SUMMARY_FIELDS = [
    "active_forbidden_symbols",
    "waiver_count",
    "stale_waiver_count",
    "symbol_violations",
    "matrix_violations",
    "waiver_evidence_violations",
    "burn_down_threshold_violations",
    "downgrade_evidence_violations",
    "downgraded_symbol_count",
]
EXPECTED_ZERO_BURN_DOWN_FIELDS = [
    "total_non_implemented",
    "symbols_unscheduled",
    "unscheduled_waves",
    "unscheduled_share_pct",
]
PASS_EVENTS = [
    "stub_regression_guard_completion.unit_binding",
    "stub_regression_guard_completion.telemetry_contract",
    "stub_regression_guard_completion.validated",
]
FAIL_EVENT = "stub_regression_guard_completion.failed"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root))
    except ValueError:
        return str(path)


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_log(records: list[dict]) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(
        "".join(json.dumps(record, sort_keys=True) + "\n" for record in records),
        encoding="utf-8",
    )


def fail(signature: str, message: str, **details):
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
        "source_commit": git_head(),
        "status": "fail",
        "failure_signature": signature,
        "message": message,
        "contract": rel(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "details": details,
    }
    write_json(report_path, report)
    write_log(
        [
            {
                "timestamp": now_utc(),
                "event": FAIL_EVENT,
                "status": "fail",
                "failure_signature": signature,
                "message": message,
                "details": details,
            }
        ]
    )
    raise SystemExit(f"FAIL[{signature}]: {message}")


def require(condition: bool, signature: str, message: str, **details) -> None:
    if not condition:
        fail(signature, message, **details)


def load_json(path: pathlib.Path):
    require(path.is_file(), "json_missing", f"missing json artifact: {rel(path)}", path=rel(path))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        fail("json_invalid", f"invalid json artifact: {rel(path)}", path=rel(path), error=str(err))


def source_text(source_artifacts: dict, key: str) -> str:
    value = source_artifacts.get(key)
    require(isinstance(value, str) and value, "source_artifact_missing", f"missing source artifact {key}", key=key)
    path = root / value
    require(path.is_file(), "source_path_missing", f"source artifact missing: {value}", key=key, path=value)
    return path.read_text(encoding="utf-8")


def validate_source_artifacts(contract: dict) -> dict:
    source_artifacts = contract.get("source_artifacts")
    require(isinstance(source_artifacts, dict), "source_artifacts_shape", "source_artifacts must be an object")
    require(
        set(source_artifacts) == EXPECTED_SOURCE_KEYS,
        "source_artifact_key_drift",
        "source_artifacts keys drifted",
        declared=sorted(source_artifacts),
        expected=sorted(EXPECTED_SOURCE_KEYS),
    )
    for key, path in source_artifacts.items():
        require(isinstance(path, str) and path, "source_artifact_value", f"{key} must point at a path", key=key)
        require((root / path).is_file(), "source_path_missing", f"source artifact missing: {path}", key=key, path=path)
    return source_artifacts


def validate_source_anchors(contract: dict, source_artifacts: dict) -> int:
    anchors = contract.get("source_anchors")
    require(isinstance(anchors, dict), "source_anchors_shape", "source_anchors must be an object")
    total = 0
    for key, needles in anchors.items():
        require(key in source_artifacts, "source_anchor_unknown_key", f"unknown source anchor key: {key}", key=key)
        require(isinstance(needles, list) and needles, "source_anchor_list", f"{key} anchors must be non-empty", key=key)
        text = source_text(source_artifacts, key)
        for needle in needles:
            require(isinstance(needle, str) and needle, "source_anchor_empty", f"{key} source anchor must be non-empty", key=key)
            require(
                needle in text,
                "source_anchor_missing",
                f"{key} is missing a required source anchor",
                key=key,
                path=source_artifacts[key],
                needle=needle,
            )
            total += 1
    return total


def validate_line_ref(ref: str) -> str:
    require(isinstance(ref, str) and ref, "line_ref_empty", "line ref must be a non-empty string")
    path_text, sep, line_text = ref.rpartition(":")
    require(sep == ":" and line_text.isdigit(), "line_ref_shape", "line ref must be path:line", ref=ref)
    line_no = int(line_text)
    require(line_no > 0, "line_ref_line", "line number must be positive", ref=ref)
    path = root / path_text
    require(path.is_file(), "line_ref_path_missing", "line ref path is missing", ref=ref)
    lines = path.read_text(encoding="utf-8").splitlines()
    require(line_no <= len(lines), "line_ref_out_of_range", "line ref is beyond end of file", ref=ref, line_count=len(lines))
    require(lines[line_no - 1].strip() != "", "line_ref_blank", "line ref points at a blank line", ref=ref)
    return ref


def validate_missing_items(contract: dict) -> list[dict]:
    bindings = contract.get("missing_item_bindings")
    require(isinstance(bindings, list), "missing_item_bindings_shape", "missing_item_bindings must be an array")
    actual = {}
    for binding in bindings:
        require(isinstance(binding, dict), "missing_item_shape", "missing item binding must be an object")
        item_id = binding.get("id")
        kind = binding.get("kind")
        require(isinstance(item_id, str) and item_id, "missing_item_id", "missing item id must be non-empty")
        require(isinstance(kind, str) and kind, "missing_item_kind", "missing item kind must be non-empty", item_id=item_id)
        actual[item_id] = kind
        require(binding.get("next_audit_threshold") == 900, "next_audit_threshold", "each missing item must pin threshold 900", item_id=item_id)
        for key in ("implementation_refs", "test_refs"):
            refs = binding.get(key)
            require(isinstance(refs, list) and refs, f"{key}_missing", f"{item_id} must cite {key}", item_id=item_id)
            for ref in refs:
                validate_line_ref(ref)
        if item_id == "telemetry.primary":
            refs = binding.get("telemetry_refs")
            require(isinstance(refs, list) and refs, "telemetry_refs_missing", "telemetry.primary must cite telemetry refs")
            for ref in refs:
                validate_line_ref(ref)
            require(binding.get("required_events") == PASS_EVENTS, "required_events_drift", "telemetry required events drifted")
        commands = binding.get("required_commands")
        require(isinstance(commands, list) and commands, "required_commands_missing", f"{item_id} commands must be non-empty", item_id=item_id)
        for command in commands:
            require(isinstance(command, str) and command, "command_empty", "required command must be non-empty", item_id=item_id)
            if " cargo " in f" {command} ":
                require("rch exec -- cargo" in command, "cargo_not_rch", "cargo validation must run through rch", command=command)
    require(actual == EXPECTED_MISSING_ITEMS, "missing_item_set_drift", "completion-debt missing item set drifted", actual=actual, expected=EXPECTED_MISSING_ITEMS)
    return bindings


def validate_contract_details(contract: dict) -> dict:
    details = contract.get("stub_regression_guard_completion_contract")
    require(isinstance(details, dict), "contract_details_shape", "stub regression completion contract must be an object")
    require(details.get("required_guard_checks") == EXPECTED_GUARD_CHECKS, "required_guard_checks", "required guard check list drifted", actual=details.get("required_guard_checks"))
    require(details.get("required_guard_event") == "stub_regression_guard", "required_guard_event", "required guard event drifted")
    require(details.get("required_zero_summary_fields") == EXPECTED_ZERO_SUMMARY_FIELDS, "required_zero_summary_fields", "required zero summary fields drifted")
    require(details.get("required_zero_burn_down_fields") == EXPECTED_ZERO_BURN_DOWN_FIELDS, "required_zero_burn_down_fields", "required zero burn-down fields drifted")
    require(details.get("next_audit_threshold") == 900, "contract_audit_threshold", "contract must pin threshold 900")
    return details


def validate_policy(source_artifacts: dict) -> dict:
    policy = load_json(root / source_artifacts["waiver_policy"])
    require(policy.get("schema_version") == "v1", "policy_schema", "waiver policy schema drifted")
    require(policy.get("bead") == "bd-1p5v", "policy_bead", "waiver policy bead drifted", actual=policy.get("bead"))
    policy_obj = policy.get("policy")
    require(isinstance(policy_obj, dict), "policy_shape", "waiver policy must contain policy object")
    require(policy_obj.get("default_decision") == "deny", "policy_default_decision", "waiver policy default decision must be deny")
    forbidden = policy_obj.get("forbidden_without_waiver")
    require(isinstance(forbidden, dict), "policy_forbidden_shape", "forbidden_without_waiver must be an object")
    require(set(forbidden.get("risk_tiers", [])) == {"critical", "high"}, "policy_risk_tiers", "risk tiers must be critical+high")
    require(set(forbidden.get("source_debt_scopes", [])) == {"critical_non_exported_debt", "exported_shadow_debt"}, "policy_scopes", "source debt scopes drifted")
    require(set(forbidden.get("matrix_statuses", [])) == {"Stub"}, "policy_matrix_statuses", "matrix statuses must gate Stub")
    thresholds = policy_obj.get("burn_down_thresholds")
    require(isinstance(thresholds, dict), "policy_thresholds_shape", "burn_down_thresholds must be an object")
    for key in ("max_total_non_implemented", "max_symbols_unscheduled", "max_unscheduled_waves", "max_unscheduled_share_pct"):
        require(float(thresholds.get(key, -1)) == 0.0, "policy_threshold_nonzero", "burn-down threshold must be zero", key=key, actual=thresholds.get(key))
    require(policy.get("waivers") == [], "policy_waivers_nonempty", "waiver policy must have no active waivers")
    require(policy.get("matrix_waivers") == [], "policy_matrix_waivers_nonempty", "matrix waivers must be empty")
    summary = policy.get("summary")
    require(isinstance(summary, dict), "policy_summary_shape", "waiver policy summary must be an object")
    for key in ("waiver_count", "critical_waiver_count", "high_waiver_count", "matrix_waiver_count"):
        require(int(summary.get(key, -1)) == 0, "policy_summary_nonzero", "waiver policy summary count must be zero", key=key, actual=summary.get(key))
    return summary


def validate_census(source_artifacts: dict) -> dict:
    census = load_json(root / source_artifacts["census"])
    require(census.get("schema_version") == "v1", "census_schema", "census schema drifted")
    exported = census.get("exported_taxonomy_view")
    require(isinstance(exported, dict), "census_exported_shape", "exported taxonomy view must be an object")
    require(exported.get("stub_symbols") == [], "census_stub_symbols", "census stub symbols must be empty")
    require(exported.get("non_implemented_exported_symbols") == [], "census_non_implemented", "census non-implemented exported symbols must be empty")
    require(census.get("risk_ranked_debt") == [], "census_risk_ranked_debt", "risk ranked debt must be empty")
    reconciliation = census.get("reconciliation")
    require(isinstance(reconciliation, dict), "census_reconciliation_shape", "reconciliation must be an object")
    for key in ("exported_stub_count", "exported_non_implemented_count", "replacement_blocker_count", "interpose_unapproved_callthrough_count", "critical_non_exported_todo_count", "critical_exported_shadow_todo_count"):
        require(int(reconciliation.get(key, -1)) == 0, "census_reconciliation_nonzero", "census reconciliation count must be zero", key=key, actual=reconciliation.get(key))
    require(reconciliation.get("matrix_summary_deltas") == [], "census_matrix_deltas", "matrix summary deltas must be empty")
    summary = census.get("summary")
    require(isinstance(summary, dict), "census_summary_shape", "census summary must be an object")
    for key in ("priority_item_count", "replacement_blocker_count", "interpose_unapproved_callthrough_count", "nonzero_matrix_delta_count"):
        require(int(summary.get(key, -1)) == 0, "census_summary_nonzero", "census summary count must be zero", key=key, actual=summary.get(key))
    return summary


def validate_ranking_and_wave(source_artifacts: dict) -> dict:
    ranking = load_json(root / source_artifacts["priority_ranking"])
    require(ranking.get("schema_version") == 1, "ranking_schema", "priority ranking schema drifted")
    burn_down = ranking.get("burn_down")
    require(isinstance(burn_down, dict), "ranking_burn_down_shape", "ranking burn_down must be an object")
    for key in ("total_non_implemented", "symbols_unscheduled", "waves_in_progress", "symbols_in_progress", "symbols_planned"):
        require(int(burn_down.get(key, -1)) == 0, "ranking_burn_down_nonzero", "ranking burn-down count must be zero", key=key, actual=burn_down.get(key))
    require(burn_down.get("wave_plan") == [], "ranking_wave_plan_nonempty", "ranking wave plan must be empty")
    wave_plan = load_json(root / source_artifacts["wave_plan"])
    require(wave_plan.get("schema_version") == "v1", "wave_plan_schema", "wave plan schema drifted")
    downgrade = wave_plan.get("downgrade_policy")
    require(isinstance(downgrade, dict), "wave_downgrade_shape", "wave downgrade policy must be an object")
    require(downgrade.get("default_decision") == "deny", "wave_default_decision", "wave downgrade default decision must be deny")
    require(downgrade.get("waived_symbols") == [], "wave_waived_symbols", "wave waived symbols must be empty")
    require(int(downgrade.get("waived_symbol_count", -1)) == 0, "wave_waived_count", "wave waived symbol count must be zero")
    return {"ranking": burn_down, "wave_plan": downgrade}


def run_stub_guard() -> None:
    if not run_guard:
        return
    command = [str(root / "scripts/check_stub_regression_guard.sh")]
    proc = subprocess.run(command, cwd=root, text=True, capture_output=True, env=os.environ.copy())
    if proc.returncode != 0:
        fail(
            "stub_guard_failed",
            "stub regression guard failed",
            command=" ".join(command),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )


def validate_guard_report_and_log() -> dict:
    guard_report_path = root / "target/conformance/stub_regression_guard.report.json"
    guard_log_path = root / "target/conformance/stub_regression_guard.log.jsonl"
    guard_report = load_json(guard_report_path)
    require(guard_report.get("schema_version") == "v1", "guard_report_schema", "guard report schema drifted")
    require(guard_report.get("bead") == "bd-1x3.3", "guard_report_bead", "guard report bead drifted")
    require(guard_report.get("uplift_bead") == "bd-1p5v", "guard_report_uplift", "guard report uplift bead drifted")
    checks = guard_report.get("checks")
    require(isinstance(checks, dict), "guard_checks_shape", "guard report checks must be an object")
    for check in EXPECTED_GUARD_CHECKS:
        require(checks.get(check) == "pass", "guard_check_not_pass", "guard check must pass", check=check, actual=checks.get(check))
    for key in ("violations", "symbol_violations", "matrix_violations", "stale_waivers", "waiver_evidence_violations", "burn_down_threshold_violations", "downgrade_evidence_violations"):
        require(guard_report.get(key) == [], "guard_violation_list_nonempty", "guard violation list must be empty", key=key, actual=guard_report.get(key))
    summary = guard_report.get("summary")
    require(isinstance(summary, dict), "guard_summary_shape", "guard report summary must be an object")
    for key in EXPECTED_ZERO_SUMMARY_FIELDS:
        require(float(summary.get(key, -1)) == 0.0, "guard_summary_nonzero", "guard summary field must be zero", key=key, actual=summary.get(key))
    burn_down = summary.get("burn_down_snapshot")
    require(isinstance(burn_down, dict), "guard_burn_down_shape", "guard burn-down snapshot must be an object")
    for key in EXPECTED_ZERO_BURN_DOWN_FIELDS:
        require(float(burn_down.get(key, -1)) == 0.0, "guard_burn_down_nonzero", "guard burn-down field must be zero", key=key, actual=burn_down.get(key))

    require(guard_log_path.is_file(), "guard_log_missing", "guard log is missing", path=rel(guard_log_path))
    records = [
        json.loads(line)
        for line in guard_log_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    require(len(records) == 1, "guard_log_record_count", "guard log must contain exactly one record", count=len(records))
    event = records[0]
    require(event.get("event") == "stub_regression_guard", "guard_log_event", "guard log event drifted", actual=event.get("event"))
    require(event.get("outcome") == "pass", "guard_log_outcome", "guard log outcome must pass", actual=event.get("outcome"))
    require(int(event.get("errno", -1)) == 0, "guard_log_errno", "guard log errno must be zero", actual=event.get("errno"))
    details = event.get("details")
    require(isinstance(details, dict), "guard_log_details_shape", "guard log details must be an object")
    require(int(details.get("violation_count", -1)) == 0, "guard_log_violation_count", "guard log violation count must be zero", actual=details.get("violation_count"))
    return {"report": guard_report, "event": event, "report_path": guard_report_path, "log_path": guard_log_path}


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected contract schema", actual=contract.get("schema_version"))
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "unexpected original bead", actual=contract.get("original_bead"))
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_debt_bead", "unexpected completion-debt bead", actual=contract.get("completion_debt_bead"))

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
bindings = validate_missing_items(contract)
validate_contract_details(contract)
policy_summary = validate_policy(source_artifacts)
census_summary = validate_census(source_artifacts)
ranking_wave_summary = validate_ranking_and_wave(source_artifacts)

run_stub_guard()
guard = validate_guard_report_and_log()
guard_summary = guard["report"]["summary"]

records = [
    {
        "timestamp": now_utc(),
        "event": PASS_EVENTS[0],
        "status": "pass",
        "bead_id": EXPECTED_COMPLETION_BEAD,
        "details": {
            "missing_item": "tests.unit.primary",
            "guard_check_count": len(EXPECTED_GUARD_CHECKS),
            "harness_tests": [
                "waiver_policy_has_required_shape",
                "guard_script_passes_with_current_policy",
                "guard_script_fails_when_stale_waiver_injected",
                "guard_script_fails_when_burn_down_threshold_is_too_strict",
            ],
        },
    },
    {
        "timestamp": now_utc(),
        "event": PASS_EVENTS[1],
        "status": "pass",
        "bead_id": EXPECTED_COMPLETION_BEAD,
        "details": {
            "missing_item": "telemetry.primary",
            "guard_report": rel(guard["report_path"]),
            "guard_log": rel(guard["log_path"]),
            "guard_event": guard["event"].get("event"),
            "violation_count": guard["event"].get("details", {}).get("violation_count"),
        },
    },
    {
        "timestamp": now_utc(),
        "event": PASS_EVENTS[2],
        "status": "pass",
        "bead_id": EXPECTED_COMPLETION_BEAD,
        "details": {
            "missing_item_count": len(bindings),
            "source_anchor_count": anchor_count,
            "next_audit_threshold": 900,
            "run_guard": run_guard,
        },
    },
]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": "pass",
    "failure_signature": "none",
    "contract": rel(contract_path),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "summary": {
        "missing_item_count": len(bindings),
        "source_anchor_count": anchor_count,
        "guard_check_count": len(EXPECTED_GUARD_CHECKS),
        "next_audit_threshold": 900,
        "policy_waiver_count": int(policy_summary["waiver_count"]),
        "census_priority_item_count": int(census_summary["priority_item_count"]),
        "guard_active_forbidden_symbols": int(guard_summary["active_forbidden_symbols"]),
        "guard_waiver_count": int(guard_summary["waiver_count"]),
        "guard_stale_waiver_count": int(guard_summary["stale_waiver_count"]),
        "guard_symbol_violations": int(guard_summary["symbol_violations"]),
        "guard_matrix_violations": int(guard_summary["matrix_violations"]),
        "guard_downgraded_symbol_count": int(guard_summary["downgraded_symbol_count"]),
        "ranking_total_non_implemented": int(ranking_wave_summary["ranking"]["total_non_implemented"]),
        "wave_waived_symbol_count": int(ranking_wave_summary["wave_plan"]["waived_symbol_count"]),
    },
    "artifact_refs": [
        rel(guard["report_path"]),
        rel(guard["log_path"]),
        rel(log_path),
    ],
}

write_json(report_path, report)
write_log(records)
print(
    "stub_regression_guard_completion_contract: PASS "
    f"checks={len(EXPECTED_GUARD_CHECKS)} waivers={report['summary']['guard_waiver_count']} "
    f"violations={report['summary']['guard_symbol_violations'] + report['summary']['guard_matrix_violations']}"
)
PY
