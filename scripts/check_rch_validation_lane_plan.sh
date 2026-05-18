#!/usr/bin/env bash
# Gate for bd-juvqm.9: rch-aware validation lane plan.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MANIFEST="${RCH_VALIDATION_LANE_PLAN_MANIFEST:-$ROOT/tests/conformance/rch_validation_lane_plan.v1.json}"
REPORT="${RCH_VALIDATION_LANE_PLAN_REPORT:-$ROOT/target/conformance/rch_validation_lane_plan.report.json}"
LOG="${RCH_VALIDATION_LANE_PLAN_LOG:-$ROOT/target/conformance/rch_validation_lane_plan.log.jsonl}"
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

python3 - "$ROOT" "$MANIFEST" "$REPORT" "$LOG" "$MODE" <<'PY'
from __future__ import annotations

import json
import pathlib
import shlex
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
manifest_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "v1"
EXPECTED_MANIFEST = "rch-validation-lane-plan"
EXPECTED_BEAD = "bd-juvqm.9"
EXPECTED_CHECKER = "scripts/check_rch_validation_lane_plan.sh --validate-only"
REQUIRED_LOG_FIELDS = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "latency_ns",
    "artifact_refs",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "bead",
    "trace_id",
    "mode",
    "source_commit",
    "outcome",
    "failure_signature",
    "message",
    "manifest",
    "duration_ms",
    "summary",
    "report_path",
    "log_path",
    "report_contract_fields",
    "contract_status",
    "contract_errors",
}
REPORT_CONTRACT_FIELDS: list[str] = []
CONTRACT_ERRORS: list[str] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return "unknown"


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def finish(outcome: str, signature: str, message: str, **summary) -> None:
    duration_ns = time.time_ns() - start_ns
    trace_id = f"rch-validation-lane-plan-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    report = {
        "schema_version": "rch_validation_lane_plan.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": trace_id,
        "mode": mode,
        "source_commit": git_head(),
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "manifest": rel(manifest_path),
        "duration_ms": duration_ns // 1_000_000,
        "summary": summary,
        "report_path": rel(report_path),
        "log_path": rel(log_path),
        "report_contract_fields": REPORT_CONTRACT_FIELDS,
        "contract_status": "pending",
        "contract_errors": [],
    }
    contract_errors = list(CONTRACT_ERRORS)
    missing_report_fields = [field for field in REPORT_CONTRACT_FIELDS if field not in report]
    if missing_report_fields:
        contract_errors.append(f"missing_report_field:{','.join(missing_report_fields)}")
    report["contract_status"] = "pass" if not contract_errors else "fail"
    report["contract_errors"] = contract_errors
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_row = {
        "timestamp": now_utc(),
        "event": "rch_validation_lane_plan_validated"
        if outcome == "pass"
        else "rch_validation_lane_plan_failed",
        "trace_id": trace_id,
        "mode": mode,
        "api_family": "validation",
        "symbol": "rch_validation_lane_plan",
        "decision_path": outcome,
        "latency_ns": duration_ns,
        "artifact_refs": [rel(manifest_path), rel(report_path)],
        "bead": EXPECTED_BEAD,
        "failure_signature": signature,
    }
    log_path.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")
    if outcome != "pass" or contract_errors:
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary) -> None:
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary) -> None:
    if not condition:
        fail(signature, message, **summary)


def load_manifest() -> dict:
    require(manifest_path.is_file(), "input_missing", f"manifest missing: {manifest_path}")
    try:
        return json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        fail("json_parse", f"manifest is not valid JSON: {err}")
    raise AssertionError("unreachable")


def as_string(value: dict, key: str, context: str) -> str:
    item = value.get(key)
    require(isinstance(item, str) and item, "missing_string", f"{context}.{key} must be a non-empty string")
    return item


def as_list(value: dict, key: str, context: str) -> list:
    item = value.get(key)
    require(isinstance(item, list), "missing_array", f"{context}.{key} must be an array")
    return item


def report_contract_field_list(manifest: dict) -> list[str]:
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(manifest: dict) -> list[str]:
    errors: list[str] = []
    report_contract = manifest.get("report_contract")
    if not isinstance(report_contract, dict):
        return ["report_contract_not_object"]
    if report_contract.get("output_path") != rel(report_path):
        errors.append("report_contract_output_path_mismatch")
    if report_contract.get("log_path") != rel(log_path):
        errors.append("report_contract_log_path_mismatch")
    fields = set(report_contract_field_list(manifest))
    missing = sorted(REQUIRED_REPORT_FIELDS - fields)
    if missing:
        errors.append(f"report_contract_missing_required_field:{','.join(missing)}")
    return errors


def shell_words(command: str) -> list[str]:
    cleaned = command.replace("...", "ELLIPSIS")
    try:
        return shlex.split(cleaned)
    except ValueError:
        return command.split()


def split_env_assignments(words: list[str]) -> tuple[dict[str, str], list[str]]:
    env: dict[str, str] = {}
    index = 0
    while index < len(words):
        word = words[index]
        if "=" not in word or word.startswith("-"):
            break
        key, value = word.split("=", 1)
        if not key or not key.replace("_", "").isalnum() or key[0].isdigit():
            break
        env[key] = value
        index += 1
    return env, words[index:]


def command_mentions_cargo(command: str) -> bool:
    return any(word == "cargo" or word.startswith("cargo ") for word in shell_words(command))


def require_no_bash_wrapped_cargo(surface_id: str, field: str, command: str, words: list[str]) -> None:
    shell_words_seen = {"bash", "sh", "zsh"}
    if words and pathlib.Path(words[0]).name in shell_words_seen and "cargo" in words:
        fail(
            "bash_wrapped_cargo_lane",
            f"{surface_id}.{field} wraps cargo in a shell; use a directly classified rch cargo lane",
            surface_id=surface_id,
            field=field,
            command=command,
        )
    if any(word in {"bash", "sh", "zsh"} for word in words[:3]) and "-c" in words and "cargo" in command:
        fail(
            "bash_wrapped_cargo_lane",
            f"{surface_id}.{field} wraps cargo in a shell; use a directly classified rch cargo lane",
            surface_id=surface_id,
            field=field,
            command=command,
        )


def validate_cargo_command(surface_id: str, field: str, command: str, target_dir_pattern: str) -> bool:
    words = shell_words(command)
    if not words or not command_mentions_cargo(command):
        return False
    env, words = split_env_assignments(words)
    require_no_bash_wrapped_cargo(surface_id, field, command, words)

    if words[0] == "scripts/" or command.startswith("scripts/"):
        return False

    require(
        len(words) >= 2 and words[0] == "rch" and words[1] == "cargo",
        "bare_cargo_command",
        f"{surface_id}.{field} must start with `rch cargo`, not local cargo",
        surface_id=surface_id,
        field=field,
        command=command,
    )
    require(
        env.get("RCH_FORCE_REMOTE") == "true",
        "missing_remote_force",
        f"{surface_id}.{field} must set RCH_FORCE_REMOTE=true for remote-only validation evidence",
        surface_id=surface_id,
        field=field,
        command=command,
    )
    require(
        "--workspace" not in words,
        "workspace_gate_forbidden",
        f"{surface_id}.{field} uses a workspace-wide gate inside a focused surface lane",
        surface_id=surface_id,
        field=field,
        command=command,
    )
    require(
        "-p" in words or "--package" in words,
        "missing_package_selector",
        f"{surface_id}.{field} must choose a focused package with -p/--package",
        surface_id=surface_id,
        field=field,
        command=command,
    )
    require(
        "CARGO_TARGET_DIR" in target_dir_pattern or ".cargo-target" in target_dir_pattern,
        "missing_cargo_target_dir",
        f"{surface_id} must document isolated CARGO_TARGET_DIR guidance",
        surface_id=surface_id,
        target_dir_pattern=target_dir_pattern,
    )
    require(
        "<agent" in target_dir_pattern and "<bead" in target_dir_pattern,
        "target_pattern_not_isolated",
        f"{surface_id} target_dir_pattern must be per-agent and per-bead",
        surface_id=surface_id,
        target_dir_pattern=target_dir_pattern,
    )
    return True


def validate() -> None:
    global CONTRACT_ERRORS, REPORT_CONTRACT_FIELDS
    if mode != "validate-only":
        fail("unknown_mode", f"only --validate-only is supported; got {mode}")

    manifest = load_manifest()
    REPORT_CONTRACT_FIELDS = report_contract_field_list(manifest)
    CONTRACT_ERRORS = validate_report_contract(manifest)
    if CONTRACT_ERRORS:
        fail(
            "report_contract",
            "report_contract must bind output/log paths and required report fields",
            contract_errors=CONTRACT_ERRORS,
        )
    require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version")
    require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id", "unexpected manifest_id")
    require(manifest.get("bead") == EXPECTED_BEAD, "bead", "unexpected bead")
    require(manifest.get("canonical_checker") == EXPECTED_CHECKER, "canonical_checker", "unexpected canonical_checker")
    require(
        len(as_string(manifest, "regeneration_note", "manifest")) >= 40,
        "regeneration_note_missing",
        "regeneration_note must explain how future agents update the plan",
    )

    rules = manifest.get("rules")
    require(isinstance(rules, dict), "missing_rules", "rules must be an object")
    require(rules.get("all_cargo_through_rch") is True, "rch_rule_disabled", "all_cargo_through_rch must be true")
    require(
        rules.get("remote_only_force_required") is True,
        "remote_force_rule_disabled",
        "remote_only_force_required must be true",
    )
    fallback_policy = as_string(rules, "local_fallback_is_invalid_proof", "rules")
    require(
        "[RCH] local" in fallback_policy and "invalid" in fallback_policy.lower(),
        "local_fallback_policy_missing",
        "local_fallback_is_invalid_proof must reject [RCH] local fallback as validation evidence",
    )
    target_pattern = as_string(rules, "target_dir_isolation_pattern", "rules")
    require(
        "<agent" in target_pattern and "<bead" in target_pattern,
        "target_pattern_not_isolated",
        "target_dir_isolation_pattern must be per-agent and per-bead",
        target_dir_isolation_pattern=target_pattern,
    )
    require(
        "FORBIDDEN" in as_string(rules, "broad_workspace_gate_policy", "rules"),
        "broad_policy_not_fail_closed",
        "broad workspace policy must be explicitly fail-closed",
    )
    require(
        "exit=0" in as_string(rules, "post_remote_exit_hang_policy", "rules"),
        "missing_rch_hang_policy",
        "post_remote_exit_hang_policy must cover remote exit=0 retrieval stalls",
    )

    validation_requirements = manifest.get("validation_requirements")
    require(isinstance(validation_requirements, dict), "missing_validation_requirements", "validation_requirements must be an object")
    required_surface_ids = {
        item for item in as_list(validation_requirements, "required_surface_ids", "validation_requirements") if isinstance(item, str)
    }
    require(required_surface_ids, "missing_required_surfaces", "required_surface_ids must not be empty")
    actual_log_fields = {
        item for item in as_list(validation_requirements, "structured_log_fields", "validation_requirements") if isinstance(item, str)
    }
    require(
        REQUIRED_LOG_FIELDS.issubset(actual_log_fields),
        "missing_structured_log_fields",
        "structured_log_fields must include the standard trace fields",
        missing=sorted(REQUIRED_LOG_FIELDS - actual_log_fields),
    )

    surfaces = as_list(manifest, "surfaces", "manifest")
    surface_ids: set[str] = set()
    cargo_lane_count = 0
    for index, surface in enumerate(surfaces):
        require(isinstance(surface, dict), "surface_not_object", f"surfaces[{index}] must be an object")
        surface_id = as_string(surface, "surface_id", f"surfaces[{index}]")
        require(surface_id not in surface_ids, "duplicate_surface_id", f"duplicate surface_id {surface_id}")
        surface_ids.add(surface_id)
        as_string(surface, "scope", surface_id)
        as_string(surface, "owning_bead", surface_id)
        target_dir_pattern = as_string(surface, "target_dir_pattern", surface_id)
        test_cmd = as_string(surface, "minimal_test_cmd", surface_id)
        clippy_cmd = as_string(surface, "minimal_clippy_cmd", surface_id)

        if validate_cargo_command(surface_id, "minimal_test_cmd", test_cmd, target_dir_pattern):
            cargo_lane_count += 1
        if clippy_cmd != "n/a (shell scripts)" and validate_cargo_command(
            surface_id, "minimal_clippy_cmd", clippy_cmd, target_dir_pattern
        ):
            cargo_lane_count += 1

        if command_mentions_cargo(test_cmd) and test_cmd.startswith("scripts/"):
            require(
                "invoked by the script itself" in test_cmd,
                "script_cargo_contract_missing",
                f"{surface_id} script lane must state that rch is invoked internally",
                surface_id=surface_id,
            )

    missing_surfaces = required_surface_ids - surface_ids
    require(
        not missing_surfaces,
        "missing_surface",
        "manifest is missing required surface rows",
        missing_surfaces=sorted(missing_surfaces),
    )

    allowlist = as_list(manifest, "broad_gate_allowlist", "manifest")
    for index, row in enumerate(allowlist):
        require(isinstance(row, dict), "allowlist_row_not_object", f"broad_gate_allowlist[{index}] must be an object")
        command = as_string(row, "command", f"broad_gate_allowlist[{index}]")
        rationale = as_string(row, "rationale", f"broad_gate_allowlist[{index}]")
        env, words = split_env_assignments(shell_words(command))
        require(
            env.get("RCH_FORCE_REMOTE") == "true",
            "missing_remote_force",
            "broad allowlist commands must force remote execution",
            command=command,
        )
        require(
            len(words) >= 3 and words[0] == "rch" and words[1] == "cargo" and "--workspace" in words,
            "bad_broad_allowlist_command",
            "broad allowlist commands must be explicit rch cargo workspace gates",
            command=command,
        )
        require(
            "only" in rationale.lower() and len(rationale) >= 40,
            "allowlist_rationale_missing",
            "broad allowlist rows must explain the narrow condition",
            command=command,
        )

    runbook = as_list(manifest, "post_remote_exit_hang_runbook", "manifest")
    joined_runbook = "\n".join(str(item) for item in runbook)
    require(len(runbook) >= 5, "runbook_too_short", "post_remote_exit_hang_runbook must have at least five steps")
    require("exit=0" in joined_runbook, "runbook_missing_exit_zero", "runbook must mention remote exit=0 evidence")
    require("CARGO_TARGET_DIR" in joined_runbook, "runbook_missing_target_dir", "runbook must cover target-dir isolation on rerun")
    require("did NOT land" in joined_runbook or "do NOT re-run" in joined_runbook, "runbook_missing_no_rerun", "runbook must prevent blind reruns")

    finish(
        "pass",
        "none",
        "rch validation lane plan is internally consistent",
        surfaces=len(surfaces),
        required_surfaces=len(required_surface_ids),
        cargo_lanes=cargo_lane_count,
        broad_allowlist=len(allowlist),
        runbook_steps=len(runbook),
    )


validate()
PY
