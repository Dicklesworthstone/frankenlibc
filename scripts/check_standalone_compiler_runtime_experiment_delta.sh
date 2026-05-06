#!/usr/bin/env bash
# check_standalone_compiler_runtime_experiment_delta.sh -- CI gate for bd-zyck1.96
#
# Validates the report-only panic-abort compiler-runtime experiment delta and
# emits a materialized report that keeps the partial improvement claim-bounded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DELTA="${FRANKENLIBC_STANDALONE_COMPILER_RUNTIME_DELTA:-${ROOT}/tests/conformance/standalone_compiler_runtime_experiment_delta.v1.json}"
EXPERIMENT="${FRANKENLIBC_STANDALONE_COMPILER_RUNTIME_EXPERIMENT:-${ROOT}/tests/conformance/standalone_compiler_runtime_experiment.v1.json}"
OWNED_UNWINDER="${FRANKENLIBC_STANDALONE_OWNED_UNWINDER_SURFACE:-${ROOT}/tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json}"
VERSION_BURNDOWN="${FRANKENLIBC_STANDALONE_VERSION_BURNDOWN:-${ROOT}/tests/conformance/standalone_host_version_requirement_burndown.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_COMPILER_RUNTIME_DELTA_REPORT:-${OUT_DIR}/standalone_compiler_runtime_experiment_delta.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${DELTA}" "${EXPERIMENT}" "${OWNED_UNWINDER}" "${VERSION_BURNDOWN}" "${REPORT}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
delta_path = Path(sys.argv[2])
experiment_path = Path(sys.argv[3])
owned_path = Path(sys.argv[4])
version_path = Path(sys.argv[5])
report_path = Path(sys.argv[6])
for name in ["delta_path", "experiment_path", "owned_path", "version_path", "report_path"]:
    path = locals()[name]
    if not path.is_absolute():
        locals()[name] = root / path

BEAD_ID = "bd-zyck1.96"
EXPECTED_INPUTS = {
    "standalone_compiler_runtime_experiment": "tests/conformance/standalone_compiler_runtime_experiment.v1.json",
    "standalone_owned_unwinder_symbol_surface": "tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json",
    "standalone_host_version_requirement_burndown": "tests/conformance/standalone_host_version_requirement_burndown.v1.json",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_compiler_runtime_experiment_delta",
    "delta_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_compiler_runtime_experiment_delta",
}
EXPECTED_REPORT_POLICY = {
    "report_only": True,
    "promotion_allowed": False,
    "replacement_level_change_allowed": False,
    "default_forge_path_change_allowed": False,
    "default_build_profile_change_allowed": False,
    "panic_strategy_change_allowed": False,
    "experiment_delta_claim_status": "report_only",
    "standalone_claim_status_until_all_blockers_exit": "claim_blocked",
    "partial_improvement_is_not_standalone_evidence": True,
    "missing_removed_symbol_result": "fail_closed",
    "remaining_symbol_drift_result": "fail_closed",
    "version_requirement_delta_result": "fail_closed",
    "needed_library_delta_result": "fail_closed",
}
EXPECTED_REMOVED_UNWIND = {
    "_Unwind_DeleteException@GCC_3.0",
    "_Unwind_RaiseException@GCC_3.0",
}
EXPECTED_NEEDED_LIBRARIES = {"ld-linux-x86-64.so.2", "libgcc_s.so.1"}
EXPECTED_REMAINING_BLOCKING_REASONS = {
    "host_needed_libraries_present",
    "host_direct_needed_libraries_present",
    "host_resolved_libraries_present",
    "host_loader_dependency",
    "host_libc_dependency",
    "libgcc_runtime_dependency",
    "undefined_unwind_symbols",
    "undefined_glibc_symbols",
    "undefined_tls_symbols",
    "host_version_requirements",
}

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


def is_hex_commit(value):
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(ch in "0123456789abcdefABCDEF" for ch in value)
    )


def source_commit_marker_is_current(value, head):
    return value == "current" or (head != "unknown" and value == head)


def object_value(value, context):
    if not isinstance(value, dict):
        errors.append(f"{context}: must be an object")
        return {}
    return value


def string_list(value, context, *, min_len=0):
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


def repo_path(ref, context):
    if not isinstance(ref, str) or not ref:
        errors.append(f"{context}: path must be a non-empty string")
        return
    path = Path(ref)
    if path.is_absolute() or ".." in path.parts:
        errors.append(f"{context}: path must stay repo-relative: {ref}")
        return
    if not (root / path).exists():
        errors.append(f"{context}: path does not exist: {ref}")


def nested(value, context, *segments):
    current = value
    walked = []
    for segment in segments:
        walked.append(segment)
        if not isinstance(current, dict) or segment not in current:
            errors.append(f"{context}: missing {'.'.join(walked)}")
            return {}
        current = current[segment]
    return current


head = current_commit()
delta = load_json(delta_path)
experiment = load_json(experiment_path)
owned = load_json(owned_path)
version = load_json(version_path)
for value_name in ["delta", "experiment", "owned", "version"]:
    if not isinstance(locals()[value_name], dict):
        locals()[value_name] = {}

if delta.get("schema_version") != "v1" or delta.get("bead") != BEAD_ID:
    errors.append("delta must declare schema_version=v1 and bead=bd-zyck1.96")
if delta.get("manifest_id") != "standalone-compiler-runtime-experiment-delta":
    errors.append("manifest_id must be standalone-compiler-runtime-experiment-delta")
source_commit = delta.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("delta source_commit must be 'current' or a 40-hex commit")
elif not source_commit_marker_is_current(source_commit, head):
    errors.append("delta source_commit must be 'current' or match current git HEAD")
if delta.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match compiler-runtime delta stale-source contract")
if delta.get("inputs") != EXPECTED_INPUTS:
    errors.append("inputs must match compiler-runtime delta input contract")
for key, ref in EXPECTED_INPUTS.items():
    repo_path(delta.get("inputs", {}).get(key), f"inputs.{key}")
if delta.get("report_policy") != EXPECTED_REPORT_POLICY:
    errors.append("report_policy must match report-only partial-improvement contract")

experiment_summary = object_value(experiment.get("summary"), "experiment.summary")
observation = object_value(delta.get("observation"), "observation")
if observation.get("baseline_lane") != experiment_summary.get("baseline_lane"):
    errors.append("observation.baseline_lane must match experiment summary")
if observation.get("experiment_lane") != experiment_summary.get("experiment_lane"):
    errors.append("observation.experiment_lane must match experiment summary")
if observation.get("experiment_env") != {"CARGO_PROFILE_RELEASE_PANIC": "abort"}:
    errors.append("observation.experiment_env must pin panic-abort lane env")
if observation.get("delta_classification") != "improvement":
    errors.append("observation.delta_classification must be improvement")

owned_rows = owned.get("symbol_rows", [])
if not isinstance(owned_rows, list):
    errors.append("owned unwinder symbol_rows must be an array")
    owned_rows = []
owned_symbols = {
    row.get("symbol")
    for row in owned_rows
    if isinstance(row, dict) and isinstance(row.get("symbol"), str)
}
if len(owned_symbols) != 12:
    errors.append("owned unwinder surface must expose twelve baseline symbols")

removed = set(string_list(observation.get("removed_undefined_unwind_symbols"), "observation.removed_undefined_unwind_symbols", min_len=2))
remaining = set(string_list(observation.get("remaining_undefined_unwind_symbols"), "observation.remaining_undefined_unwind_symbols", min_len=10))
added_unwind = set(string_list(observation.get("added_undefined_unwind_symbols"), "observation.added_undefined_unwind_symbols"))
if removed != EXPECTED_REMOVED_UNWIND:
    errors.append("observation.removed_undefined_unwind_symbols must record only the two observed panic-abort removals")
if added_unwind:
    errors.append("observation.added_undefined_unwind_symbols must be empty")
if not removed.issubset(owned_symbols):
    errors.append("removed unwind symbols must be present in owned unwinder baseline surface")
if remaining != owned_symbols - removed:
    errors.append("remaining_undefined_unwind_symbols must equal owned unwinder baseline symbols minus removed symbols")

version_rows = version.get("version_requirement_matrix", [])
if not isinstance(version_rows, list):
    errors.append("version_requirement_matrix must be an array")
    version_rows = []
all_requirements = {
    row.get("requirement_id")
    for row in version_rows
    if isinstance(row, dict) and isinstance(row.get("requirement_id"), str)
}
still_versions = set(string_list(observation.get("version_requirements_still_present"), "observation.version_requirements_still_present", min_len=4))
if set(string_list(observation.get("removed_version_requirements"), "observation.removed_version_requirements")):
    errors.append("observation.removed_version_requirements must stay empty")
if set(string_list(observation.get("added_version_requirements"), "observation.added_version_requirements")):
    errors.append("observation.added_version_requirements must stay empty")
if still_versions != all_requirements:
    errors.append("version_requirements_still_present must match the full current version requirement matrix")

needed_still = set(string_list(observation.get("needed_libraries_still_present"), "observation.needed_libraries_still_present", min_len=2))
if set(string_list(observation.get("removed_needed_libraries"), "observation.removed_needed_libraries")):
    errors.append("observation.removed_needed_libraries must stay empty")
if set(string_list(observation.get("added_needed_libraries"), "observation.added_needed_libraries")):
    errors.append("observation.added_needed_libraries must stay empty")
if needed_still != EXPECTED_NEEDED_LIBRARIES:
    errors.append("needed_libraries_still_present must remain ld-linux plus libgcc")

remaining_reasons = set(string_list(observation.get("remaining_blocking_reasons"), "observation.remaining_blocking_reasons", min_len=10))
if remaining_reasons != EXPECTED_REMAINING_BLOCKING_REASONS:
    errors.append("remaining_blocking_reasons must retain all ten current blocker reasons")

summary = object_value(delta.get("summary"), "summary")
summary_expectations = {
    "baseline_unwind_symbol_count": len(owned_symbols),
    "removed_unwind_symbol_count": len(removed),
    "remaining_unwind_symbol_count": len(remaining),
    "removed_needed_library_count": 0,
    "remaining_needed_library_count": len(needed_still),
    "removed_version_requirement_count": 0,
    "remaining_version_requirement_count": len(still_versions),
}
for field, expected in summary_expectations.items():
    if summary.get(field) != expected:
        errors.append(f"summary.{field} mismatch")
if summary.get("delta_classification") != "improvement":
    errors.append("summary.delta_classification must be improvement")
if summary.get("claim_status") != "report_only":
    errors.append("summary.claim_status must be report_only")
if summary.get("standalone_claim_status") != "claim_blocked":
    errors.append("summary.standalone_claim_status must be claim_blocked")
if summary.get("promotion_allowed") is not False:
    errors.append("summary.promotion_allowed must be false")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": status,
    "source_commit": source_commit,
    "current_head": head,
    "claim_status": "report_only",
    "standalone_claim_status": "claim_blocked",
    "delta_classification": observation.get("delta_classification"),
    "removed_undefined_unwind_symbols": sorted(removed),
    "remaining_undefined_unwind_symbols": sorted(remaining),
    "needed_libraries_still_present": sorted(needed_still),
    "version_requirements_still_present": sorted(still_versions),
    "remaining_blocking_reasons": sorted(remaining_reasons),
    "summary": {
        **summary_expectations,
        "promotion_allowed": False,
        "partial_improvement_is_not_standalone_evidence": True,
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    for error in errors:
        print(f"compiler-runtime-delta error: {error}", file=sys.stderr)
    sys.exit(1)
print(
    "compiler-runtime-delta: pass "
    f"removed_unwind={len(removed)} remaining_unwind={len(remaining)} "
    f"remaining_versions={len(still_versions)} report={report_path}"
)
PY
