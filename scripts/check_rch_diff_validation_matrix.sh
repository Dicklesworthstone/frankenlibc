#!/usr/bin/env bash
# Validate and emit a path-to-RCH validation matrix without running cargo.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_RCH_DIFF_MATRIX_CONTRACT:-${ROOT}/tests/conformance/rch_diff_validation_matrix.v1.json}"
LANE_PLAN="${FRANKENLIBC_RCH_VALIDATION_LANE_PLAN:-${ROOT}/tests/conformance/rch_validation_lane_plan.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_RCH_DIFF_MATRIX_REPORT:-${OUT_DIR}/rch_diff_validation_matrix.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${CONTRACT}" "${LANE_PLAN}" "${REPORT}" <<'PY'
import copy
import fnmatch
import json
import shlex
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
contract_path = Path(sys.argv[2])
lane_plan_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
for name in ["contract_path", "lane_plan_path", "report_path"]:
    path = locals()[name]
    if not path.is_absolute():
        locals()[name] = root / path

errors = []


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{path}: {exc}")
        return {}


def current_commit():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def current_diff_entries(ignore_globs, include_untracked):
    def ignored(path):
        return any(fnmatch.fnmatchcase(path, pattern) for pattern in ignore_globs)

    entries = []
    seen = set()

    def add_path(path, status):
        if not path or ignored(path) or path in seen:
            return
        seen.add(path)
        entries.append({"path": path, "status": status})

    try:
        tracked_out = subprocess.check_output(
            ["git", "diff", "--name-only"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        tracked_out = ""
    for line in tracked_out.splitlines():
        add_path(line.strip(), "tracked_modified")

    if include_untracked:
        try:
            untracked_out = subprocess.check_output(
                ["git", "ls-files", "--others", "--exclude-standard"],
                cwd=root,
                text=True,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            untracked_out = ""
        for line in untracked_out.splitlines():
            add_path(line.strip(), "untracked")

    return entries


def is_hex_commit(value):
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def source_commit_current(value, head):
    return value == "current" or (head != "unknown" and value == head)


def repo_path(value, context):
    if not isinstance(value, str) or not value:
        errors.append(f"{context}: must be a non-empty repo-relative path")
        return
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context}: path must stay repo-relative: {value}")
        return
    if not (root / path).exists():
        errors.append(f"{context}: missing path {value}")


def string_list(value, context, *, min_len=1):
    if not isinstance(value, list) or len(value) < min_len:
        errors.append(f"{context}: must be a list with at least {min_len} entries")
        return []
    result = []
    for idx, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{context}[{idx}]: must be a non-empty string")
        else:
            result.append(item)
    return result


def command_words(command):
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def split_env(words):
    env = {}
    index = 0
    while index < len(words):
        word = words[index]
        if "=" not in word or word.startswith("-"):
            break
        key, value = word.split("=", 1)
        if not key or key[0].isdigit() or not key.replace("_", "").isalnum():
            break
        env[key] = value
        index += 1
    return env, words[index:]


def command_mentions_cargo(command):
    return any(word == "cargo" for word in command_words(command))


def validate_command(command, context, policy, *, record_global=True):
    local_errors = []
    words = command_words(command)
    env, body = split_env(words)
    if command_mentions_cargo(command):
        if body and body[0] == "cargo":
            local_errors.append("bare_cargo_command")
        if "--workspace" in body:
            local_errors.append("workspace_wide_command")
        remote_markers = set(policy.get("remote_env_markers", []))
        env_tokens = {f"{key}={value}" for key, value in env.items()}
        if not (remote_markers & env_tokens):
            local_errors.append("missing_remote_marker")
        if "[RCH] local" in command:
            local_errors.append("local_fallback_marker")
    if record_global:
        for error in local_errors:
            errors.append(f"{context}: {error}")
    return local_errors


def rule_matches(path, rule):
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in rule.get("path_globs", []))


def expand_path_placeholders(command, path):
    test_name = Path(path).stem
    return command.replace("{path}", path).replace("{test_name}", test_name)


def build_matrix(paths, contract, lane_surfaces, *, label, record_global=True):
    matrix = []
    local_errors = []
    rules = contract.get("path_rules", [])
    if not isinstance(rules, list):
        local_errors.append("path_rules_not_array")
        rules = []
    policy = contract.get("policy", {})
    for path in paths:
        matched = [rule for rule in rules if isinstance(rule, dict) and rule_matches(path, rule)]
        if not matched:
            local_errors.append(f"unmapped_path:{path}")
            continue
        rule_rows = []
        for rule in matched:
            rule_id = rule.get("rule_id", "<missing>")
            context = f"{label}.{path}.{rule_id}"
            cargo_required = rule.get("cargo_required", True) is not False
            surfaces = string_list(rule.get("surface_ids"), f"{context}.surface_ids")
            for surface in surfaces:
                if surface not in lane_surfaces:
                    local_errors.append(f"unknown_surface:{surface}")
            static_checks = [
                expand_path_placeholders(command, path)
                for command in string_list(rule.get("static_checks"), f"{context}.static_checks")
            ]
            preflights = [
                expand_path_placeholders(command, path)
                for command in string_list(
                    rule.get("remote_preflight_commands"),
                    f"{context}.remote_preflight_commands",
                    min_len=1 if cargo_required else 0,
                )
            ]
            remote_commands = [
                expand_path_placeholders(command, path)
                for command in string_list(
                    rule.get("remote_cargo_commands"),
                    f"{context}.remote_cargo_commands",
                    min_len=1 if cargo_required else 0,
                )
            ]
            for idx, command in enumerate(preflights):
                local_errors.extend(
                    validate_command(
                        command,
                        f"{context}.remote_preflight_commands[{idx}]",
                        policy,
                        record_global=record_global,
                    )
                )
            for idx, command in enumerate(remote_commands):
                local_errors.extend(
                    validate_command(
                        command,
                        f"{context}.remote_cargo_commands[{idx}]",
                        policy,
                        record_global=record_global,
                    )
                )
            rule_rows.append(
                {
                    "rule_id": rule_id,
                    "surface_ids": surfaces,
                    "static_checks": static_checks,
                    "remote_preflight_commands": preflights,
                    "remote_cargo_commands": remote_commands,
                    "cargo_required": cargo_required,
                    "notes": rule.get("notes"),
                }
            )
        matrix.append({"path": path, "rules": rule_rows})
    return matrix, local_errors


def collect_commands(matrix, field):
    seen = []
    for row in matrix:
        for rule in row.get("rules", []):
            for command in rule.get(field, []):
                if command not in seen:
                    seen.append(command)
    return seen


head = current_commit()
contract = load_json(contract_path)
lane_plan = load_json(lane_plan_path)

if contract.get("schema_version") != "v1":
    errors.append("contract schema_version must be v1")
if contract.get("manifest_id") != "rch_diff_validation_matrix":
    errors.append("contract manifest_id mismatch")
if contract.get("bead") != "bd-5ci21":
    errors.append("contract bead must be bd-5ci21")
source_commit = contract.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("contract source_commit must be current or 40-hex")
elif not source_commit_current(source_commit, head):
    errors.append("contract source_commit is stale")

expected_inputs = {
    "rch_validation_lane_plan": "tests/conformance/rch_validation_lane_plan.v1.json",
    "rch_remote_admissibility_preflight": "scripts/check_rch_remote_admissibility.sh",
    "standalone_tls_model_checker": "scripts/check_standalone_tls_model_startup_experiment.sh",
    "standalone_owned_tls_surface_checker": "scripts/check_standalone_owned_tls_startup_surface.sh",
    "standalone_blocker_rollup_checker": "scripts/check_standalone_blocker_burndown_progress_rollup.sh",
}
if contract.get("inputs") != expected_inputs:
    errors.append("contract inputs mismatch")
for key, value in expected_inputs.items():
    repo_path(contract.get("inputs", {}).get(key), f"inputs.{key}")

lane_surfaces = {
    row.get("surface_id")
    for row in lane_plan.get("surfaces", [])
    if isinstance(row, dict) and isinstance(row.get("surface_id"), str)
}
if not lane_surfaces:
    errors.append("lane plan must expose surfaces")

sample_paths = string_list(contract.get("sample_paths"), "sample_paths")
sample_matrix, sample_errors = build_matrix(sample_paths, contract, lane_surfaces, label="sample")
errors.extend(sample_errors)

policy = contract.get("policy", {})
ignore_globs = policy.get("current_diff_ignored_globs", [])
if not isinstance(ignore_globs, list) or not all(isinstance(item, str) and item for item in ignore_globs):
    errors.append("policy.current_diff_ignored_globs must be a list of non-empty strings")
    ignore_globs = []
if policy.get("include_untracked_current_diff") is not True:
    errors.append("policy.include_untracked_current_diff must be true")
allowed_statuses = policy.get("current_diff_statuses", [])
if sorted(allowed_statuses) != ["tracked_modified", "untracked"]:
    errors.append("policy.current_diff_statuses must be tracked_modified/untracked")
current_entries = current_diff_entries(ignore_globs, include_untracked=True)
current_paths = [entry["path"] for entry in current_entries]
current_matrix, current_errors = build_matrix(current_paths, contract, lane_surfaces, label="current_diff")
if current_errors and not contract.get("policy", {}).get("current_diff_is_informational"):
    errors.extend(current_errors)

negative_results = []
for control in contract.get("negative_controls", []):
    if not isinstance(control, dict):
        errors.append("negative control row must be an object")
        continue
    control_id = control.get("control_id")
    expected_error = control.get("expected_error")
    mutated = copy.deepcopy(contract)
    if control_id == "unknown_path_fails":
        mutated.setdefault("sample_paths", []).append("src/unknown_surface.rs")
    elif control_id == "untracked_unknown_path_fails":
        mutated.setdefault("sample_paths", []).append(
            "crates/frankenlibc-harness/tests/new_unmapped_contract_test.rs"
        )
    elif control_id == "bare_cargo_command_fails":
        mutated["path_rules"][0]["remote_cargo_commands"][0] = "cargo check -p frankenlibc-abi"
    elif control_id == "workspace_command_fails":
        mutated["path_rules"][0]["remote_cargo_commands"].append(
            "RCH_REQUIRE_REMOTE=1 rch exec -- cargo check --workspace"
        )
    else:
        errors.append(f"unknown negative control {control_id}")
        continue
    _, observed_errors = build_matrix(
        mutated.get("sample_paths", []),
        mutated,
        lane_surfaces,
        label=f"negative.{control_id}",
        record_global=False,
    )
    flattened = ",".join(observed_errors)
    passed = expected_error in flattened
    if not passed:
        errors.append(f"negative_control_failed:{control_id}: expected {expected_error}")
    negative_results.append(
        {
            "control_id": control_id,
            "expected_error": expected_error,
            "observed_errors": observed_errors,
            "status": "pass" if passed else "fail",
        }
    )

sample_static = collect_commands(sample_matrix, "static_checks")
sample_preflights = collect_commands(sample_matrix, "remote_preflight_commands")
sample_remote = collect_commands(sample_matrix, "remote_cargo_commands")
current_static = collect_commands(current_matrix, "static_checks")
current_preflights = collect_commands(current_matrix, "remote_preflight_commands")
current_remote = collect_commands(current_matrix, "remote_cargo_commands")
report = {
    "schema_version": "rch_diff_validation_matrix.report.v1",
    "bead": "bd-5ci21",
    "follow_up_bead": contract.get("follow_up_bead"),
    "status": "pass" if not errors else "fail",
    "source_commit": source_commit,
    "current_head": head,
    "sample_paths": sample_paths,
    "sample_matrix": sample_matrix,
    "current_diff_entries": current_entries,
    "current_diff_paths": current_paths,
    "current_diff_matrix": current_matrix,
    "current_diff_errors": current_errors,
    "current_diff_untracked_count": sum(1 for entry in current_entries if entry.get("status") == "untracked"),
    "current_static_checks": current_static,
    "current_remote_preflight_commands": current_preflights,
    "current_remote_cargo_commands": current_remote,
    "static_checks": sample_static,
    "remote_preflight_commands": sample_preflights,
    "remote_cargo_commands": sample_remote,
    "negative_controls": negative_results,
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
