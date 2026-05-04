#!/usr/bin/env bash
# check_user_workload_replay_manifest.sh -- CI gate for bd-b92jd.3.1
#
# Validates the safe user workload replay manifest and emits deterministic
# JSON/JSONL artifacts for every workload x baseline/strict/hardened row.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${USER_WORKLOAD_REPLAY_MANIFEST:-$ROOT/tests/conformance/user_workload_replay_manifest.v1.json}"
REPORT="${USER_WORKLOAD_REPLAY_REPORT:-$ROOT/target/conformance/user_workload_replay_manifest.report.json}"
LOG="${USER_WORKLOAD_REPLAY_LOG:-$ROOT/target/conformance/user_workload_replay_manifest.log.jsonl}"
TARGET_DIR="${USER_WORKLOAD_REPLAY_TARGET_DIR:-$ROOT/target/conformance}"
MODE="${1:---dry-run}"

case "${MODE}" in
  --dry-run|--validate-only)
    ;;
  *)
    echo "usage: $0 [--dry-run|--validate-only]" >&2
    exit 2
    ;;
esac

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${TARGET_DIR}" "${MODE}" <<'PY'
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
target_dir = Path(sys.argv[5])
mode = sys.argv[6]

REQUIRED_MODES = ["baseline", "strict", "hardened"]
REQUIRED_CATEGORIES = {
    "coreutils",
    "shell_pipeline",
    "dynamic_runtime",
    "c_fixture",
    "optional_tool",
}
REQUIRED_LOG_FIELDS = [
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
COMMAND_KINDS = {"argv", "pipeline", "dynamic_runtime", "c_fixture"}
STDOUT_KINDS = {"exact", "contains", "nonempty"}
STDERR_KINDS = {"empty", "empty_or_diagnostic"}
ALLOWED_ENV_KEYS = {"LD_PRELOAD", "FRANKENLIBC_MODE"}

errors = []
failure_signatures = []
checks = {}
log_rows = []


def fail(message, signature):
    errors.append(message)
    failure_signatures.append(signature)


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"{path}: {exc}", "workload_replay_manifest_unreadable")
        return None


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


def repo_relative(path_text):
    path = Path(path_text)
    if path.is_absolute():
        return None
    parts = path.parts
    if ".." in parts:
        return None
    return root / path


def validate_argv(argv, context):
    if not isinstance(argv, list) or not argv:
        fail(f"{context}: argv must be a non-empty list", "workload_replay_invalid_command_argv")
        return []
    normalized = []
    for index, item in enumerate(argv):
        if not isinstance(item, str) or not item or "\0" in item:
            fail(
                f"{context}: argv[{index}] must be a non-empty string without NUL",
                "workload_replay_invalid_command_argv",
            )
            continue
        normalized.append(item)
    return normalized


def flattened_command_argv(command, workload_id):
    kind = command.get("kind")
    if kind in {"argv", "dynamic_runtime"}:
        return validate_argv(command.get("argv"), f"{workload_id}.command")
    if kind == "pipeline":
        stages = command.get("stages")
        if not isinstance(stages, list) or len(stages) < 2:
            fail(
                f"{workload_id}: pipeline command requires at least two stages",
                "workload_replay_invalid_command_argv",
            )
            return []
        flattened = []
        for stage_index, stage in enumerate(stages):
            if not isinstance(stage, dict):
                fail(
                    f"{workload_id}: pipeline stage {stage_index} must be an object",
                    "workload_replay_invalid_command_argv",
                )
                continue
            argv = validate_argv(stage.get("argv"), f"{workload_id}.stages[{stage_index}]")
            if argv:
                if flattened:
                    flattened.append("|")
                flattened.extend(argv)
        return flattened
    if kind == "c_fixture":
        source = command.get("source")
        source_path = repo_relative(source) if isinstance(source, str) else None
        if source_path is None or not source_path.is_file():
            fail(f"{workload_id}: C fixture source missing: {source}", "workload_replay_artifact_ref_missing")
        build_argv = validate_argv(command.get("build_argv"), f"{workload_id}.build_argv")
        run_argv = validate_argv(command.get("argv"), f"{workload_id}.argv")
        return build_argv + ["--"] + run_argv
    fail(f"{workload_id}: unknown command kind {kind!r}", "workload_replay_invalid_command_argv")
    return []


def validate_env_overlay(workload_id, runtime_mode, env_overlay, runtime_policy):
    if not isinstance(env_overlay, dict):
        fail(f"{workload_id}.{runtime_mode}: env_overlay must be an object", "workload_replay_invalid_env_overlay")
        return {}
    for key, value in env_overlay.items():
        if key not in ALLOWED_ENV_KEYS or "=" in key:
            fail(
                f"{workload_id}.{runtime_mode}: env_overlay contains invalid key {key!r}",
                "workload_replay_invalid_env_overlay",
            )
        if not isinstance(value, str) or value == "":
            fail(
                f"{workload_id}.{runtime_mode}: env_overlay value for {key!r} must be non-empty string",
                "workload_replay_invalid_env_overlay",
            )
    forbidden = set(runtime_policy.get("baseline_env_forbidden", []))
    if runtime_mode == "baseline" and forbidden.intersection(env_overlay):
        fail(
            f"{workload_id}: baseline env_overlay must not set {sorted(forbidden.intersection(env_overlay))}",
            "workload_replay_invalid_env_overlay",
        )
    if runtime_mode in {"strict", "hardened"}:
        required = runtime_policy.get(f"{runtime_mode}_env_required", {})
        for key, expected in required.items():
            if env_overlay.get(key) != expected:
                fail(
                    f"{workload_id}.{runtime_mode}: env_overlay must set {key}={expected}",
                    "workload_replay_invalid_env_overlay",
                )
    return env_overlay


def validate_expected(workload_id, runtime_mode, expected):
    if not isinstance(expected, dict):
        fail(f"{workload_id}.{runtime_mode}: expected must be object", "workload_replay_invalid_command_argv")
        return 0, "missing"
    exit_code = expected.get("exit_code")
    if not isinstance(exit_code, int) or exit_code < 0 or exit_code > 255:
        fail(
            f"{workload_id}.{runtime_mode}: expected.exit_code must be 0..255",
            "workload_replay_invalid_command_argv",
        )
    stdout = expected.get("stdout")
    stderr = expected.get("stderr")
    if not isinstance(stdout, dict) or stdout.get("kind") not in STDOUT_KINDS:
        fail(
            f"{workload_id}.{runtime_mode}: stdout.kind must be one of {sorted(STDOUT_KINDS)}",
            "workload_replay_invalid_command_argv",
        )
        stdout_kind = "missing"
    else:
        stdout_kind = stdout.get("kind")
        if stdout_kind in {"exact", "contains"} and not isinstance(stdout.get("value"), str):
            fail(
                f"{workload_id}.{runtime_mode}: stdout.value is required for {stdout_kind}",
                "workload_replay_invalid_command_argv",
            )
    if not isinstance(stderr, dict) or stderr.get("kind") not in STDERR_KINDS:
        fail(
            f"{workload_id}.{runtime_mode}: stderr.kind must be one of {sorted(STDERR_KINDS)}",
            "workload_replay_invalid_command_argv",
        )
    return exit_code if isinstance(exit_code, int) else 0, stdout_kind


def validate_artifact_refs(workload_id, artifact_refs):
    if not isinstance(artifact_refs, list) or not artifact_refs:
        fail(f"{workload_id}: artifact_refs must be non-empty", "workload_replay_artifact_ref_missing")
        return []
    normalized = []
    for artifact_ref in artifact_refs:
        if not isinstance(artifact_ref, str) or not artifact_ref:
            fail(f"{workload_id}: artifact ref must be non-empty string", "workload_replay_artifact_ref_missing")
            continue
        path = repo_relative(artifact_ref)
        if path is None:
            fail(f"{workload_id}: unsafe artifact ref {artifact_ref}", "workload_replay_artifact_ref_missing")
            continue
        if not artifact_ref.startswith("target/") and not path.exists():
            fail(f"{workload_id}: artifact ref does not exist: {artifact_ref}", "workload_replay_artifact_ref_missing")
        normalized.append(artifact_ref)
    return normalized


source_commit = current_commit()
manifest = load_json(manifest_path)
checks["json_parse"] = "pass" if isinstance(manifest, dict) else "fail"
if not isinstance(manifest, dict):
    manifest = {}

if manifest.get("schema_version") == "v1" and manifest.get("bead") == "bd-b92jd.3.1":
    checks["top_level_shape"] = "pass"
else:
    checks["top_level_shape"] = "fail"
    fail("manifest must declare schema_version=v1 and bead=bd-b92jd.3.1", "workload_replay_bad_manifest")

if manifest.get("required_log_fields") == REQUIRED_LOG_FIELDS:
    checks["required_log_fields"] = "pass"
else:
    checks["required_log_fields"] = "fail"
    fail("required_log_fields must match the workload replay log contract", "workload_replay_log_contract_missing")

runtime_policy = manifest.get("runtime_mode_policy", {})
if runtime_policy.get("required_modes") == REQUIRED_MODES:
    checks["runtime_mode_policy"] = "pass"
else:
    checks["runtime_mode_policy"] = "fail"
    fail("runtime mode policy must require baseline, strict, hardened", "workload_replay_missing_mode")

freshness = manifest.get("freshness_policy", {})
if freshness.get("source_commit") in {"current", source_commit}:
    checks["artifact_freshness"] = "pass"
else:
    checks["artifact_freshness"] = "fail"
    fail(
        f"freshness_policy.source_commit={freshness.get('source_commit')!r} is not current {source_commit}",
        freshness.get("stale_failure_signature", "workload_replay_stale_source_commit"),
    )

timeout_policy = manifest.get("timeout_policy", {})
max_timeout = timeout_policy.get("max_timeout_ms", 0)
if not isinstance(max_timeout, int) or max_timeout <= 0:
    fail("timeout_policy.max_timeout_ms must be a positive integer", "workload_replay_timeout_policy_invalid")

workload_contract = manifest.get("workload_contract", {})
if set(workload_contract.get("required_categories", [])) == REQUIRED_CATEGORIES:
    checks["required_categories"] = "pass"
else:
    checks["required_categories"] = "fail"
    fail("workload_contract.required_categories does not match required set", "workload_replay_missing_category")

workloads = manifest.get("workloads", [])
workload_ids = [workload.get("workload_id") for workload in workloads if isinstance(workload, dict)]
if not isinstance(workloads, list) or not workloads or len(workload_ids) != len(set(workload_ids)):
    fail("workloads must be a non-empty list with unique workload_id values", "workload_replay_bad_workload_rows")

coverage = Counter()
optional_count = 0
matrix_row_count = 0

for workload in workloads if isinstance(workloads, list) else []:
    if not isinstance(workload, dict):
        fail("workload row must be an object", "workload_replay_bad_workload_rows")
        continue
    workload_id = workload.get("workload_id", "<missing workload_id>")
    category = workload.get("category")
    if category not in REQUIRED_CATEGORIES:
        fail(f"{workload_id}: unknown or missing category {category!r}", "workload_replay_missing_category")
    else:
        coverage[category] += 1

    command = workload.get("command")
    if not isinstance(command, dict):
        fail(f"{workload_id}: command must be an object", "workload_replay_invalid_command_argv")
        command = {}
    command_kind = command.get("kind")
    if command_kind not in COMMAND_KINDS:
        fail(f"{workload_id}: command.kind must be one of {sorted(COMMAND_KINDS)}", "workload_replay_invalid_command_argv")
    command_argv = flattened_command_argv(command, workload_id)

    timeout_ms = workload.get("timeout_ms")
    if not isinstance(timeout_ms, int) or timeout_ms <= 0 or timeout_ms > max_timeout:
        fail(
            f"{workload_id}: timeout_ms must be between 1 and {max_timeout}",
            timeout_policy.get("timeout_failure_signature", "workload_replay_timeout_policy_invalid"),
        )

    optional = workload.get("optional")
    if not isinstance(optional, bool):
        fail(f"{workload_id}: optional must be boolean", "workload_replay_optional_skip_missing")
        optional = False

    skip_reason = "none"
    if optional:
        optional_count += 1
        skip_policy = workload.get("skip_policy")
        if not isinstance(skip_policy, dict) or not skip_policy.get("tool") or not skip_policy.get("deterministic_skip_reason"):
            fail(f"{workload_id}: optional workloads require skip_policy.tool and deterministic_skip_reason", "workload_replay_optional_skip_missing")
        else:
            prefix = workload_contract.get("optional_skip_prefix", "optional_tool_missing")
            skip_reason = skip_policy.get("deterministic_skip_reason")
            if skip_reason != f"{prefix}:{skip_policy.get('tool')}":
                fail(f"{workload_id}: deterministic skip reason must be {prefix}:<tool>", "workload_replay_optional_skip_missing")
    elif workload.get("skip_policy") is not None:
        fail(f"{workload_id}: non-optional workload must not define skip_policy", "workload_replay_optional_skip_missing")

    artifact_refs = validate_artifact_refs(workload_id, workload.get("artifact_refs"))

    if workload.get("source_commit_state") not in {"current", source_commit}:
        fail(f"{workload_id}: source_commit_state is stale", "workload_replay_stale_source_commit")

    expectations = workload.get("mode_expectations")
    if not isinstance(expectations, dict):
        fail(f"{workload_id}: mode_expectations must be object", "workload_replay_missing_mode")
        expectations = {}
    for runtime_mode in REQUIRED_MODES:
        expectation = expectations.get(runtime_mode)
        if not isinstance(expectation, dict):
            fail(f"{workload_id}: missing mode_expectations.{runtime_mode}", "workload_replay_missing_mode")
            expectation = {}
        env_overlay = validate_env_overlay(
            workload_id,
            runtime_mode,
            expectation.get("env_overlay"),
            runtime_policy,
        )
        expected_exit, stdout_kind = validate_expected(workload_id, runtime_mode, expectation.get("expected"))
        matrix_row_count += 1
        log_rows.append(
            {
                "trace_id": f"bd-b92jd.3.1::{workload_id}::{runtime_mode}",
                "bead_id": "bd-b92jd.3.1",
                "workload_id": workload_id,
                "category": category,
                "runtime_mode": runtime_mode,
                "command_kind": command_kind,
                "command_argv": command_argv,
                "env_overlay": env_overlay,
                "timeout_ms": timeout_ms,
                "expected_exit": expected_exit,
                "expected_stdout_kind": stdout_kind,
                "optional": optional,
                "skip_reason": skip_reason,
                "artifact_refs": artifact_refs,
                "source_commit": source_commit,
                "target_dir": str(target_dir),
                "failure_signature": "none",
            }
        )

missing_categories = sorted(REQUIRED_CATEGORIES - set(coverage))
if missing_categories:
    fail(f"missing required workload categories: {missing_categories}", "workload_replay_missing_category")

checks["workload_rows"] = "pass" if not any(sig in failure_signatures for sig in {
    "workload_replay_bad_workload_rows",
    "workload_replay_invalid_command_argv",
    "workload_replay_missing_category",
    "workload_replay_missing_mode",
}) else "fail"
checks["timeout_policy"] = "pass" if "workload_replay_timeout_policy_invalid" not in failure_signatures else "fail"
checks["optional_skip_policy"] = "pass" if "workload_replay_optional_skip_missing" not in failure_signatures else "fail"
checks["category_coverage"] = "pass" if not missing_categories else "fail"

summary = manifest.get("summary", {})
summary_ok = (
    summary.get("workload_count") == len(workloads)
    and summary.get("mode_count") == len(REQUIRED_MODES)
    and summary.get("matrix_row_count") == matrix_row_count
    and summary.get("optional_workload_count") == optional_count
    and summary.get("required_category_coverage") == dict(sorted(coverage.items()))
    and summary.get("negative_test_count") == len(manifest.get("negative_tests", []))
)
checks["summary_counts"] = "pass" if summary_ok else "fail"
if not summary_ok:
    fail("summary counts do not match workloads, modes, optional count, categories, or negatives", "workload_replay_summary_mismatch")

for row in log_rows:
    missing = [field for field in REQUIRED_LOG_FIELDS if field not in row]
    if missing:
        fail(f"log row missing fields {missing}", "workload_replay_log_contract_missing")

checks["structured_log_rows"] = "pass" if "workload_replay_log_contract_missing" not in failure_signatures else "fail"

status = "pass" if not errors else "fail"
artifact_refs = [
    "tests/conformance/user_workload_replay_manifest.v1.json",
    "scripts/check_user_workload_replay_manifest.sh",
    "target/conformance/user_workload_replay_manifest.report.json",
    "target/conformance/user_workload_replay_manifest.log.jsonl",
]
report = {
    "schema_version": "v1",
    "bead": "bd-b92jd.3.1",
    "status": status,
    "mode": mode.removeprefix("--"),
    "checks": checks,
    "errors": errors,
    "failure_signatures": sorted(set(failure_signatures)),
    "source_commit": source_commit,
    "workload_count": len(workloads) if isinstance(workloads, list) else 0,
    "matrix_row_count": matrix_row_count,
    "optional_workload_count": optional_count,
    "required_category_coverage": dict(sorted(coverage.items())),
    "missing_required_categories": missing_categories,
    "required_runtime_modes": REQUIRED_MODES,
    "log_row_count": len(log_rows),
    "artifact_refs": artifact_refs,
    "target_dir": str(target_dir),
}

report_path.parent.mkdir(parents=True, exist_ok=True)
log_path.parent.mkdir(parents=True, exist_ok=True)
target_dir.mkdir(parents=True, exist_ok=True)

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)

print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if status == "pass" else 1)
PY
