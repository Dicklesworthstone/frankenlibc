#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_RUNTIME_MODE_STARTUP_SELECTION_COMPLETION_CONTRACT:-$ROOT/tests/conformance/runtime_mode_startup_selection_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_RUNTIME_MODE_STARTUP_SELECTION_COMPLETION_REPORT:-$ROOT/target/conformance/runtime_mode_startup_selection_completion_contract.report.json}"
LOG="${FRANKENLIBC_RUNTIME_MODE_STARTUP_SELECTION_COMPLETION_LOG:-$ROOT/target/conformance/runtime_mode_startup_selection_completion_contract.log.jsonl}"

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

EXPECTED_SCHEMA = "runtime_mode_startup_selection_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "runtime_mode_startup_selection_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-oai.1"
EXPECTED_COMPLETION_BEAD = "bd-oai.1.1"
EXPECTED_MISSING_ITEMS = {
    "tests.unit.primary": "unit",
    "tests.e2e.primary": "e2e",
}
REQUIRED_SOURCE_KEYS = {
    "runtime_policy",
    "harness_bin",
    "runtime_mode_evidence_contract",
    "runtime_mode_evidence_checker",
    "runtime_mode_evidence_source_test",
    "mode_contract_lock_contract",
    "mode_contract_lock_checker",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_GATE_EVENTS = [
    "runtime_mode_startup_selection_contract_validated",
    "runtime_mode_startup_selection_unit_bindings",
    "runtime_mode_startup_selection_e2e_bindings",
    "runtime_mode_startup_selection_summary",
]


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def fail(signature: str, message: str, **details):
    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
        "source_commit": git_head(),
        "status": "fail",
        "failure_signature": signature,
        "message": message,
        "contract": str(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "details": details,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        json.dumps(
            {
                "timestamp": now_utc(),
                "event": "runtime_mode_startup_selection_failed",
                "status": "fail",
                "failure_signature": signature,
                "message": message,
                "details": details,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    raise SystemExit(f"FAIL[{signature}]: {message}")


def require(condition: bool, signature: str, message: str, **details):
    if not condition:
        fail(signature, message, **details)


def load_json(path: pathlib.Path):
    require(path.is_file(), "json_missing", f"missing json artifact: {path}", path=str(path))
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        fail("json_invalid", f"invalid json: {path}: {err}", path=str(path), error=str(err))


def source_text(source_artifacts: dict, key: str) -> str:
    rel = source_artifacts.get(key)
    require(isinstance(rel, str) and rel, "source_artifact_missing", f"missing source artifact key {key}", key=key)
    path = root / rel
    require(path.is_file(), "source_path_missing", f"source artifact path missing: {rel}", key=key, path=rel)
    return path.read_text(encoding="utf-8")


def require_text_contains(text: str, needle: str, signature: str, message: str, **details):
    require(isinstance(needle, str) and needle, "anchor_empty", "source anchor must be a non-empty string", **details)
    require(needle in text, signature, message, needle=needle, **details)


def validate_source_artifacts(contract: dict):
    source_artifacts = contract.get("source_artifacts")
    require(isinstance(source_artifacts, dict), "source_artifacts_shape", "source_artifacts must be an object")
    require(
        set(source_artifacts) == REQUIRED_SOURCE_KEYS,
        "source_artifact_key_drift",
        "source_artifacts keys drifted",
        declared=sorted(source_artifacts),
        expected=sorted(REQUIRED_SOURCE_KEYS),
    )
    for key, rel in source_artifacts.items():
        require(isinstance(rel, str) and rel, "source_artifact_value", f"{key} must point at a path", key=key)
        path = root / rel
        require(path.is_file(), "source_path_missing", f"source artifact missing: {rel}", key=key, path=rel)
    return source_artifacts


def validate_source_anchors(contract: dict, source_artifacts: dict):
    anchors = contract.get("source_anchors")
    require(isinstance(anchors, dict), "source_anchors_shape", "source_anchors must be an object")
    for key, needles in anchors.items():
        require(key in source_artifacts, "source_anchor_unknown_key", f"unknown source anchor key: {key}", key=key)
        require(isinstance(needles, list) and needles, "source_anchor_list", f"{key} anchors must be non-empty", key=key)
        text = source_text(source_artifacts, key)
        for needle in needles:
            require_text_contains(
                text,
                needle,
                "source_anchor_missing",
                f"{key} is missing a required source anchor",
                key=key,
                path=source_artifacts[key],
            )
    return sum(len(needles) for needles in anchors.values())


def validate_startup_contract(contract: dict):
    policy = contract.get("startup_mode_contract")
    require(isinstance(policy, dict), "startup_contract_shape", "startup_mode_contract must be an object")
    require(policy.get("env_key") == "FRANKENLIBC_MODE", "startup_env_key", "startup contract must target FRANKENLIBC_MODE")
    require(set(policy.get("allowed_modes", [])) == {"strict", "hardened"}, "startup_allowed_modes", "allowed modes must be strict+hardened")
    require(set(policy.get("strict_aliases", [])) >= {"strict", "default", "abi"}, "strict_aliases", "strict aliases drifted")
    require(set(policy.get("hardened_aliases", [])) >= {"hardened", "repair", "tsm", "full"}, "hardened_aliases", "hardened aliases drifted")
    require(policy.get("unknown_value_behavior") == "strict", "unknown_fallback", "unknown mode values must fall back to strict")
    require(policy.get("unset_behavior") == "strict", "unset_fallback", "unset mode must default to strict")
    require(policy.get("resolution_scope") == "process", "resolution_scope", "runtime mode selection must be process-scoped")
    require(policy.get("immutable_after_first_resolution") is True, "immutability", "runtime mode must be immutable after first resolution")
    require(policy.get("global_cache_state") == "MODE_STATE", "global_cache", "global cache must be MODE_STATE")
    require(policy.get("thread_local_cache_state") == "MODE_THREAD_LOCAL_CACHE", "tls_cache", "thread-local cache must be declared")
    require(policy.get("thread_local_cache_fast_path_required") is True, "tls_fast_path", "thread-local fast path is required")
    require(policy.get("reentrant_resolution_behavior") == "strict", "reentrant_behavior", "reentrant resolution must return strict")
    require(policy.get("switch_attempt_event") == "runtime_mode_switch_attempt", "switch_event", "switch attempt event drifted")
    require(policy.get("decision_path") == "mode->cache->immutable", "decision_path", "mode decision path drifted")
    require(policy.get("subprocess_evidence_event") == "conformance.runtime_mode_startup", "startup_event", "startup evidence event drifted")
    require(policy.get("subprocess_env_override_required") is True, "subprocess_override", "subprocess FRANKENLIBC_MODE override is required")
    require(policy.get("ambient_tz_dependency_allowed") is False, "ambient_tz", "ambient TZ dependency must stay forbidden")
    return policy


def validate_missing_items(contract: dict):
    bindings = contract.get("missing_item_bindings")
    require(isinstance(bindings, list), "missing_item_bindings_shape", "missing_item_bindings must be an array")
    actual = {}
    for item in bindings:
        require(isinstance(item, dict), "missing_item_shape", "missing item binding must be an object")
        item_id = item.get("id")
        kind = item.get("kind")
        require(isinstance(item_id, str) and item_id, "missing_item_id", "missing item id must be non-empty")
        require(isinstance(kind, str) and kind, "missing_item_kind", "missing item kind must be non-empty", item_id=item_id)
        actual[item_id] = kind
        refs = item.get("required_test_refs")
        commands = item.get("required_commands")
        require(isinstance(refs, list) and refs, "missing_item_test_refs", f"{item_id} test refs must be non-empty", item_id=item_id)
        require(isinstance(commands, list) and commands, "missing_item_commands", f"{item_id} commands must be non-empty", item_id=item_id)
        for command in commands:
            require(isinstance(command, str) and command, "command_empty", "required command must be non-empty", item_id=item_id)
            if "cargo" in command:
                require("rch exec -- cargo" in command, "cargo_not_rch", "cargo validation must run through rch", command=command)
                require("CARGO_TARGET_DIR=" in command, "target_dir_missing", "rch cargo command must name an isolated CARGO_TARGET_DIR", command=command)
    require(actual == EXPECTED_MISSING_ITEMS, "missing_item_set_drift", "completion-debt missing item set drifted", actual=actual, expected=EXPECTED_MISSING_ITEMS)
    return bindings


def validate_test_refs(contract: dict, source_artifacts: dict):
    coverage = contract.get("completion_coverage")
    require(isinstance(coverage, dict), "coverage_shape", "completion_coverage must be an object")
    unit = coverage.get("unit")
    e2e = coverage.get("e2e")
    require(isinstance(unit, dict), "unit_coverage_shape", "unit coverage must be an object")
    require(isinstance(e2e, dict), "e2e_coverage_shape", "e2e coverage must be an object")

    runtime_policy = source_text(source_artifacts, "runtime_policy")
    completion_harness = source_text(source_artifacts, "completion_harness")
    runtime_mode_evidence_test = source_text(source_artifacts, "runtime_mode_evidence_source_test")
    completion_checker = source_text(source_artifacts, "completion_checker")
    runtime_mode_evidence_checker = source_text(source_artifacts, "runtime_mode_evidence_checker")

    for name in unit.get("runtime_policy_inline_tests", []):
        require_text_contains(runtime_policy, f"fn {name}", "unit_test_ref_missing", "runtime_policy inline test missing", test=name, path=source_artifacts["runtime_policy"])
    for name in unit.get("completion_harness_tests", []):
        require_text_contains(completion_harness, f"fn {name}", "unit_test_ref_missing", "completion harness test missing", test=name, path=source_artifacts["completion_harness"])
    for name in e2e.get("runtime_mode_evidence_harness_tests", []):
        require_text_contains(runtime_mode_evidence_test, f"fn {name}", "e2e_test_ref_missing", "runtime mode evidence test missing", test=name, path=source_artifacts["runtime_mode_evidence_source_test"])
    for name in e2e.get("completion_checker_tests", []):
        require_text_contains(completion_harness, f"fn {name}", "e2e_test_ref_missing", "completion checker test missing", test=name, path=source_artifacts["completion_harness"])

    for token in [
        "coverage policy must target FRANKENLIBC_MODE",
        "process immutability must be explicit",
        "FRANKENLIBC_MODE must be set before subprocess launch",
        "inherited FRANKENLIBC_MODE must be overridden",
    ]:
        require_text_contains(runtime_mode_evidence_checker, token, "evidence_gate_token_missing", "runtime-mode evidence gate token missing", token=token)
    for event in REQUIRED_GATE_EVENTS:
        require_text_contains(completion_checker, event, "completion_event_missing", "completion checker event token missing", event=event)

    unit_refs = len(unit.get("runtime_policy_inline_tests", [])) + len(unit.get("completion_harness_tests", []))
    e2e_refs = len(e2e.get("runtime_mode_evidence_harness_tests", [])) + len(e2e.get("completion_checker_tests", []))
    require(unit_refs == 9, "unit_ref_count", "unit test ref count drifted", count=unit_refs)
    require(e2e_refs == 4, "e2e_ref_count", "e2e test ref count drifted", count=e2e_refs)
    return unit_refs, e2e_refs


def validate_runtime_mode_evidence_contract(source_artifacts: dict):
    evidence = load_json(root / source_artifacts["runtime_mode_evidence_contract"])
    policy = evidence.get("coverage_policy", {})
    require(policy.get("env_key") == "FRANKENLIBC_MODE", "evidence_env_key", "runtime evidence contract env key drifted")
    require(policy.get("process_immutable_after_startup") is True, "evidence_immutability", "runtime evidence contract must preserve immutability")
    require(policy.get("subprocess_rows_must_override_inherited_mode") is True, "evidence_subprocess_override", "runtime evidence contract must require subprocess override")
    require(policy.get("ambient_tz_dependency_allowed") is False, "evidence_ambient_tz", "runtime evidence contract must forbid ambient TZ dependency")
    summary = evidence.get("summary", {})
    require(summary.get("startup_evidence_row_count") == 7, "evidence_startup_count", "startup evidence row count drifted", summary=summary)
    require(summary.get("ambient_tz_dependent_row_count") == 0, "evidence_tz_count", "ambient TZ dependent row count must stay zero", summary=summary)
    return summary


contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("original_bead") == EXPECTED_ORIGINAL_BEAD, "original_bead", "unexpected original bead", actual=contract.get("original_bead"))
require(contract.get("completion_debt_bead") == EXPECTED_COMPLETION_BEAD, "completion_bead", "unexpected completion-debt bead", actual=contract.get("completion_debt_bead"))

source_artifacts = validate_source_artifacts(contract)
anchor_count = validate_source_anchors(contract, source_artifacts)
startup_policy = validate_startup_contract(contract)
missing_bindings = validate_missing_items(contract)
unit_refs, e2e_refs = validate_test_refs(contract, source_artifacts)
evidence_summary = validate_runtime_mode_evidence_contract(source_artifacts)

declared_events = contract.get("required_gate_events")
require(declared_events == REQUIRED_GATE_EVENTS, "gate_event_drift", "required gate events drifted", declared=declared_events)

events = [
    {
        "timestamp": now_utc(),
        "event": "runtime_mode_startup_selection_contract_validated",
        "status": "pass",
        "original_bead": EXPECTED_ORIGINAL_BEAD,
        "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
        "contract": str(contract_path),
    },
    {
        "timestamp": now_utc(),
        "event": "runtime_mode_startup_selection_unit_bindings",
        "status": "pass",
        "unit_test_refs": unit_refs,
    },
    {
        "timestamp": now_utc(),
        "event": "runtime_mode_startup_selection_e2e_bindings",
        "status": "pass",
        "e2e_test_refs": e2e_refs,
        "startup_evidence_rows": evidence_summary.get("startup_evidence_row_count"),
    },
    {
        "timestamp": now_utc(),
        "event": "runtime_mode_startup_selection_summary",
        "status": "pass",
        "env_key": startup_policy.get("env_key"),
        "allowed_modes": startup_policy.get("allowed_modes"),
        "source_anchor_count": anchor_count,
        "missing_item_count": len(missing_bindings),
    },
]

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": "pass",
    "failure_signature": "none",
    "contract": str(contract_path),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "events": events,
    "summary": {
        "env_key": startup_policy.get("env_key"),
        "allowed_modes": startup_policy.get("allowed_modes"),
        "global_cache_state": startup_policy.get("global_cache_state"),
        "thread_local_cache_state": startup_policy.get("thread_local_cache_state"),
        "missing_item_count": len(missing_bindings),
        "unit_test_ref_count": unit_refs,
        "e2e_test_ref_count": e2e_refs,
        "source_anchor_count": anchor_count,
        "source_anchor_group_count": len(contract.get("source_anchors", {})),
        "startup_evidence_row_count": evidence_summary.get("startup_evidence_row_count"),
        "ambient_tz_dependent_row_count": evidence_summary.get("ambient_tz_dependent_row_count"),
    },
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("\n".join(json.dumps(event, sort_keys=True) for event in events) + "\n", encoding="utf-8")
PY

echo "PASS: runtime-mode startup selection completion contract validated"
