#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_AARCH64_CONFORMANCE_PERF_CONTRACT:-${ROOT}/tests/conformance/aarch64_conformance_perf_matrix_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_AARCH64_CONFORMANCE_PERF_REPORT:-${ROOT}/target/conformance/aarch64_conformance_perf_matrix_completion_contract.report.json}"
LOG="${FRANKENLIBC_AARCH64_CONFORMANCE_PERF_LOG:-${ROOT}/target/conformance/aarch64_conformance_perf_matrix_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" <<'PY'
import json
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
start_ns = time.time_ns()

EXPECTED_SCHEMA = "aarch64_conformance_perf_matrix_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "aarch64_conformance_perf_matrix_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-1gg.4"
EXPECTED_COMPLETION_BEAD = "bd-1gg.4.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
    "tests.fuzz.primary": "fuzz",
    "tests.conformance.primary": "conformance",
    "telemetry.primary": "telemetry",
}
EXPECTED_SOURCE_KEYS = {
    "aarch64_crosscompile_gate",
    "user_environment_matrix",
    "user_environment_gate",
    "user_environment_harness",
    "conformance_matrix",
    "conformance_matrix_gate",
    "conformance_matrix_harness",
    "perf_regression_prevention",
    "perf_regression_gate",
    "perf_regression_harness",
    "perf_budget_policy",
    "fuzz_harness_architecture",
    "fuzz_harness_gate",
    "fuzz_harness_test",
    "raw_syscall_tls_contract",
    "completion_contract",
    "completion_gate",
    "completion_harness",
}
PASS_EVENTS = [
    "aarch64_conformance_perf_matrix_completion.unit_binding",
    "aarch64_conformance_perf_matrix_completion.e2e_binding",
    "aarch64_conformance_perf_matrix_completion.fuzz_binding",
    "aarch64_conformance_perf_matrix_completion.conformance_binding",
    "aarch64_conformance_perf_matrix_completion.telemetry_contract",
    "aarch64_conformance_perf_matrix_completion.validated",
]
FAIL_EVENT = "aarch64_conformance_perf_matrix_completion.failed"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
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
    require(set(anchors) <= set(source_artifacts), "source_anchor_unknown_key", "source anchors contain unknown keys")
    total = 0
    for key, needles in anchors.items():
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
        require(binding.get("next_audit_threshold") == 900, "next_audit_threshold", "each item must pin threshold 900", item_id=item_id)
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


def validate_contract_details(contract: dict, source_artifacts: dict) -> dict:
    details = contract.get("aarch64_conformance_perf_matrix_contract")
    require(isinstance(details, dict), "contract_details_shape", "aarch64 conformance/perf contract must be an object")
    require(details.get("required_target") == "aarch64-unknown-linux-gnu", "required_target", "required aarch64 target drifted")
    require(set(details.get("required_crosscompile_checks") or []) == {"frankenlibc-core", "frankenlibc-abi"}, "crosscompile_checks_drift", "crosscompile checks drifted")
    require(set(details.get("required_architectures") or []) == {"x86_64", "aarch64"}, "architecture_contract_drift", "architecture contract drifted")
    require(details.get("required_aarch64_reason_code") == "aarch64_bringup_missing", "aarch64_reason_drift", "aarch64 reason code drifted")
    require(details.get("required_support_claim_allowed") is False, "support_claim_contract_drift", "support claim policy drifted")
    require(details.get("next_audit_threshold") == 900, "contract_audit_threshold", "contract must pin threshold 900")

    cross_gate = source_text(source_artifacts, "aarch64_crosscompile_gate")
    for needle in [
        'TARGET="aarch64-unknown-linux-gnu"',
        'cargo check --target "${TARGET}" -p frankenlibc-core',
        'cargo check --target "${TARGET}" -p frankenlibc-abi',
        'target/conformance/aarch64_crosscompile.report.json',
    ]:
        require(needle in cross_gate, "crosscompile_gate_missing", "aarch64 crosscompile gate lost required wiring", needle=needle)

    env_matrix = load_json(root / source_artifacts["user_environment_matrix"])
    rows = env_matrix.get("rows")
    require(isinstance(rows, list) and rows, "environment_rows_shape", "environment matrix rows must be a non-empty array")
    coverage = env_matrix.get("coverage_requirements", {})
    require(set(coverage.get("architectures") or []) >= {"x86_64", "aarch64"}, "environment_architecture_coverage", "environment matrix must require x86_64 and aarch64")
    aarch64_rows = [row for row in rows if isinstance(row, dict) and row.get("architecture") == "aarch64"]
    require(aarch64_rows, "aarch64_environment_missing", "environment matrix must include an aarch64 row")
    for row in aarch64_rows:
        require(row.get("reason_code") == "aarch64_bringup_missing", "aarch64_reason_missing", "aarch64 rows must keep bring-up reason", row=row.get("environment_id"))
        require(row.get("support_claim_allowed") is False, "aarch64_support_claim_allowed", "aarch64 rows must not claim support", row=row.get("environment_id"))

    conformance = load_json(root / source_artifacts["conformance_matrix"])
    summary = conformance.get("summary", {})
    for key, expected in details.get("required_conformance_summary", {}).items():
        require(summary.get(key) == expected, "conformance_summary_drift", "conformance matrix summary drifted", key=key, expected=expected, actual=summary.get(key))

    perf = load_json(root / source_artifacts["perf_regression_prevention"])
    perf_summary = perf.get("summary", {})
    for key, expected in details.get("required_perf_summary", {}).items():
        require(perf_summary.get(key) == expected, "perf_summary_drift", "perf regression summary drifted", key=key, expected=expected, actual=perf_summary.get(key))
    features = perf.get("gate_wiring", {}).get("features", {})
    for feature in details.get("required_perf_gate_features") or []:
        require(features.get(feature) is True, "perf_gate_feature_missing", "perf gate feature missing", feature=feature)

    budget = load_json(root / source_artifacts["perf_budget_policy"])
    require(budget.get("budgets", {}).get("strict_hotpath", {}).get("strict_mode_ns") == 20, "strict_budget_drift", "strict hotpath budget drifted")
    require(budget.get("budgets", {}).get("strict_hotpath", {}).get("hardened_mode_ns") == 200, "hardened_budget_drift", "hardened hotpath budget drifted")
    require(budget.get("regression_policy", {}).get("max_regression_pct") == 15, "regression_budget_drift", "max regression budget drifted")

    fuzz = load_json(root / source_artifacts["fuzz_harness_architecture"])
    fuzz_summary = fuzz.get("summary", {})
    for key, expected in details.get("required_fuzz_summary", {}).items():
        require(fuzz_summary.get(key) == expected, "fuzz_summary_drift", "fuzz architecture summary drifted", key=key, expected=expected, actual=fuzz_summary.get(key))
    return {
        "environment_row_count": len(rows),
        "aarch64_row_count": len(aarch64_rows),
        "perf_suite_count": perf_summary.get("total_suites_in_spec"),
        "fuzz_target_count": fuzz_summary.get("total_targets"),
        "conformance_pass_rate_percent": summary.get("pass_rate_percent"),
    }


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "schema_version drifted")
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "original bead drifted")
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_bead", "completion bead drifted")

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
bindings = validate_missing_items(contract)
details_summary = validate_contract_details(contract, source_artifacts)

summary = {
    "missing_item_count": len(bindings),
    "source_artifact_count": len(source_artifacts),
    "source_anchor_count": anchor_count,
    **details_summary,
}
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": "pass",
    "failure_signature": "none",
    "contract": rel(contract_path),
    "report": rel(report_path),
    "log": rel(log_path),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "summary": summary,
}
write_json(report_path, report)
write_log(
    [
        {
            "timestamp": now_utc(),
            "event": event,
            "status": "pass",
            "original_bead": EXPECTED_ORIGINAL_BEAD,
            "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
            "source_commit": report["source_commit"],
            "summary": summary,
            "artifact_refs": {
                "contract": rel(contract_path),
                "report": rel(report_path),
                "log": rel(log_path),
            },
        }
        for event in PASS_EVENTS
    ]
)
print(
    "PASS: aarch64 conformance perf matrix completion contract "
    f"items={summary['missing_item_count']} env_rows={summary['environment_row_count']} "
    f"aarch64_rows={summary['aarch64_row_count']} fuzz_targets={summary['fuzz_target_count']} "
    f"conformance_pass_rate={summary['conformance_pass_rate_percent']}"
)
PY
