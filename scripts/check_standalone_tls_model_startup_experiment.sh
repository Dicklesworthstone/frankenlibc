#!/usr/bin/env bash
# check_standalone_tls_model_startup_experiment.sh -- CI gate for bd-84m77
#
# Validates the report-only TLS model/startup experiment record and emits a
# materialized report that keeps profile-only TLS changes claim-bounded.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPERIMENT="${FRANKENLIBC_STANDALONE_TLS_MODEL_EXPERIMENT:-${ROOT}/tests/conformance/standalone_tls_model_startup_experiment.v1.json}"
TLS_DIAGNOSTIC="${FRANKENLIBC_STANDALONE_TLS_DIAGNOSTIC:-${ROOT}/tests/conformance/standalone_tls_blocker_diagnostics.v1.json}"
VERSION_BURNDOWN="${FRANKENLIBC_STANDALONE_VERSION_BURNDOWN:-${ROOT}/tests/conformance/standalone_host_version_requirement_burndown.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_TLS_MODEL_EXPERIMENT_REPORT:-${OUT_DIR}/standalone_tls_model_startup_experiment.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${EXPERIMENT}" "${TLS_DIAGNOSTIC}" "${VERSION_BURNDOWN}" "${REPORT}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
experiment_path = Path(sys.argv[2])
diagnostic_path = Path(sys.argv[3])
version_path = Path(sys.argv[4])
report_path = Path(sys.argv[5])
for name in ["experiment_path", "diagnostic_path", "version_path", "report_path"]:
    path = locals()[name]
    if not path.is_absolute():
        locals()[name] = root / path

BEAD_ID = "bd-84m77"
TLS_SYMBOL = "__tls_get_addr@GLIBC_2.3"
TLS_VERSION_REQUIREMENT = "ld-linux-x86-64.so.2:GLIBC_2.3"
EXPECTED_INPUTS = {
    "standalone_replacement_artifact": "tests/conformance/standalone_replacement_artifact.v1.json",
    "standalone_tls_blocker_diagnostics": "tests/conformance/standalone_tls_blocker_diagnostics.v1.json",
    "standalone_host_version_requirement_burndown": "tests/conformance/standalone_host_version_requirement_burndown.v1.json",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_standalone_tls_model_startup_experiment",
    "experiment_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_standalone_tls_model_startup_experiment",
}
EXPECTED_REPORT_POLICY = {
    "report_only": True,
    "promotion_allowed": False,
    "replacement_level_change_allowed": False,
    "default_forge_path_change_allowed": False,
    "default_tls_model_change_allowed": False,
    "source_rewrite_allowed": False,
    "initial_exec_unchanged_result": "claim_blocked",
    "local_exec_build_failure_result": "not_viable_for_cdylib_lane",
    "missing_tls_symbol_absence_result": "fail_closed",
    "version_need_overclaim_result": "fail_closed",
    "local_exec_promotion_claim_result": "fail_closed",
    "required_followup_before_clearance": "owned TLS startup/runtime change plus current nm/readelf absence proof",
}
EXPECTED_ABSENCE_CONTROLS = {
    "artifact_state.dependency_breakdown.undefined_tls_symbols is empty",
    "nm -D reports no undefined __tls_get_addr symbol",
    "readelf -Ws reports no undefined __tls_get_addr symbol",
    "readelf --version-info has no ld-linux-x86-64.so.2:GLIBC_2.3 need",
}
EXPECTED_LANE_IDS = {
    "baseline-reference-from-tls-diagnostic",
    "initial-exec-tls-model-probe",
    "local-exec-tls-model-probe",
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
experiment = load_json(experiment_path)
diagnostic = load_json(diagnostic_path)
version = load_json(version_path)
for value_name in ["experiment", "diagnostic", "version"]:
    if not isinstance(locals()[value_name], dict):
        locals()[value_name] = {}

if experiment.get("schema_version") != "v1" or experiment.get("bead") != BEAD_ID:
    errors.append("experiment must declare schema_version=v1 and bead=bd-84m77")
if experiment.get("manifest_id") != "standalone-tls-model-startup-experiment":
    errors.append("manifest_id must be standalone-tls-model-startup-experiment")
source_commit = experiment.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("experiment source_commit must be 'current' or a 40-hex commit")
elif not source_commit_marker_is_current(source_commit, head):
    errors.append("experiment source_commit must be 'current' or match current git HEAD")
if experiment.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match TLS model stale-source contract")
if experiment.get("inputs") != EXPECTED_INPUTS:
    errors.append("inputs must match TLS model experiment input contract")
for key, ref in EXPECTED_INPUTS.items():
    repo_path(experiment.get("inputs", {}).get(key), f"inputs.{key}")
if experiment.get("report_policy") != EXPECTED_REPORT_POLICY:
    errors.append("report_policy must match report-only TLS model contract")

diagnostic_summary = object_value(diagnostic.get("summary"), "diagnostic.summary")
if diagnostic.get("manifest_id") != "standalone-tls-blocker-diagnostics":
    errors.append("TLS diagnostic input must be standalone-tls-blocker-diagnostics")
if diagnostic_summary.get("undefined_tls_symbol_count") != 1:
    errors.append("TLS diagnostic must keep exactly one undefined TLS symbol positive control")
diagnostic_symbols = set(
    string_list(
        nested(diagnostic, "diagnostic", "current_forge_evidence", "observed_artifact_symbols").get("undefined_tls_symbols"),
        "diagnostic.current_forge_evidence.observed_artifact_symbols.undefined_tls_symbols",
        min_len=1,
    )
)
if diagnostic_symbols != {TLS_SYMBOL}:
    errors.append("TLS diagnostic current forge evidence must keep __tls_get_addr@GLIBC_2.3")
diagnostic_hash = nested(diagnostic, "diagnostic", "current_forge_evidence").get("latest_probe_artifact_sha256")

version_rows = version.get("version_requirement_matrix", [])
if not isinstance(version_rows, list):
    errors.append("version_requirement_matrix must be an array")
    version_rows = []
tls_version_rows = [
    row for row in version_rows
    if isinstance(row, dict) and row.get("requirement_id") == TLS_VERSION_REQUIREMENT
]
if len(tls_version_rows) != 1:
    errors.append("version burndown must keep one ld-linux GLIBC_2.3 TLS row")
elif TLS_SYMBOL not in string_list(tls_version_rows[0].get("observed_symbols"), "tls_version_row.observed_symbols", min_len=1):
    errors.append("version burndown TLS row must point at __tls_get_addr@GLIBC_2.3")

controls = object_value(experiment.get("artifact_controls"), "artifact_controls")
required_absence = set(
    string_list(
        controls.get("required_absence_before_clearance"),
        "artifact_controls.required_absence_before_clearance",
        min_len=4,
    )
)
if required_absence != EXPECTED_ABSENCE_CONTROLS:
    errors.append("artifact_controls must require nm/readelf absence before clearance")
if "cannot promote" not in str(controls.get("claim_guard", "")) and "may promote" not in str(controls.get("claim_guard", "")):
    errors.append("artifact_controls.claim_guard must block profile-only promotion")

negative_gate_conditions = set(
    string_list(
        nested(diagnostic, "diagnostic", "negative_control_gate").get("future_pass_conditions"),
        "diagnostic.negative_control_gate.future_pass_conditions",
        min_len=4,
    )
)
if not any("no undefined __tls_get_addr" in condition for condition in negative_gate_conditions):
    errors.append("negative control gate must require no undefined __tls_get_addr before clearance")

lanes = experiment.get("experiment_lanes", [])
if not isinstance(lanes, list):
    errors.append("experiment_lanes must be an array")
    lanes = []
by_id = {
    lane.get("lane_id"): lane
    for lane in lanes
    if isinstance(lane, dict) and isinstance(lane.get("lane_id"), str)
}
if set(by_id) != EXPECTED_LANE_IDS:
    errors.append("experiment_lanes must contain exactly the baseline, initial-exec, and local-exec lanes")

baseline = object_value(by_id.get("baseline-reference-from-tls-diagnostic"), "baseline lane")
initial = object_value(by_id.get("initial-exec-tls-model-probe"), "initial-exec lane")
local = object_value(by_id.get("local-exec-tls-model-probe"), "local-exec lane")

if baseline.get("role") != "baseline_reference" or baseline.get("build_status") != "not_rerun":
    errors.append("baseline lane must be a not-rerun TLS diagnostic reference")
if baseline.get("artifact_sha256") != diagnostic_hash:
    errors.append("baseline lane artifact hash must match TLS diagnostic current forge hash")
if set(string_list(baseline.get("undefined_tls_symbols"), "baseline.undefined_tls_symbols", min_len=1)) != {TLS_SYMBOL}:
    errors.append("baseline lane must keep __tls_get_addr@GLIBC_2.3")

if initial.get("role") != "experiment" or initial.get("tls_model") != "initial-exec":
    errors.append("initial-exec lane must be the initial-exec TLS model experiment")
if initial.get("build_status") != "pass" or initial.get("build_exit_code") != 0:
    errors.append("initial-exec lane must record a passing build")
if initial.get("claim_status") != "report_only" or initial.get("artifact_claim_status") != "claim_blocked":
    errors.append("initial-exec lane must remain report_only and claim_blocked")
if set(string_list(initial.get("undefined_tls_symbols"), "initial.undefined_tls_symbols", min_len=1)) != {TLS_SYMBOL}:
    errors.append("initial-exec lane must keep __tls_get_addr@GLIBC_2.3 as an active blocker")
if set(string_list(initial.get("host_version_requirements"), "initial.host_version_requirements", min_len=1)) != {TLS_VERSION_REQUIREMENT}:
    errors.append("initial-exec lane must keep the ld-linux GLIBC_2.3 version requirement")
if nested(initial, "initial", "env").get("RUSTFLAGS") != "-Z tls-model=initial-exec":
    errors.append("initial-exec lane env must pin -Z tls-model=initial-exec")

if local.get("role") != "negative_experiment" or local.get("tls_model") != "local-exec":
    errors.append("local-exec lane must be the local-exec negative experiment")
if (
    local.get("build_status") != "fail"
    or local.get("build_exit_code") != 101
    or local.get("artifact_produced") is not False
    or local.get("failure_signature") != "non_pic_tls_relocation_in_shared_dependency"
):
    errors.append("local-exec lane must remain a failed cdylib-inapplicable negative control")
snippets = set(string_list(local.get("diagnostic_snippets"), "local.diagnostic_snippets", min_len=2))
if not {"relocation R_X86_64_TPOFF32", "cannot be used with -shared"}.issubset(snippets):
    errors.append("local-exec lane must preserve non-PIC shared relocation diagnostics")

comparison = object_value(experiment.get("comparison"), "comparison")
if comparison.get("baseline_lane") != "baseline-reference-from-tls-diagnostic":
    errors.append("comparison.baseline_lane mismatch")
if comparison.get("experiment_lane") != "initial-exec-tls-model-probe":
    errors.append("comparison.experiment_lane mismatch")
if comparison.get("negative_experiment_lane") != "local-exec-tls-model-probe":
    errors.append("comparison.negative_experiment_lane mismatch")
if set(string_list(comparison.get("removed_tls_symbols"), "comparison.removed_tls_symbols")):
    errors.append("comparison.removed_tls_symbols must stay empty")
if set(string_list(comparison.get("removed_tls_version_requirements"), "comparison.removed_tls_version_requirements")):
    errors.append("comparison.removed_tls_version_requirements must stay empty")
if comparison.get("initial_exec_delta_classification") != "unchanged":
    errors.append("comparison.initial_exec_delta_classification must be unchanged")
if comparison.get("local_exec_artifact_comparison") != "inapplicable_build_failed":
    errors.append("comparison.local_exec_artifact_comparison must be inapplicable_build_failed")
if comparison.get("standalone_claim_status") != "claim_blocked":
    errors.append("comparison.standalone_claim_status must be claim_blocked")

summary = object_value(experiment.get("summary"), "summary")
summary_expectations = {
    "lane_count": 3,
    "build_pass_count": 1,
    "build_fail_count": 1,
    "reference_lane_count": 1,
    "initial_exec_tls_symbol_count": 1,
    "initial_exec_tls_version_requirement_count": 1,
    "local_exec_artifact_produced": False,
}
for field, expected in summary_expectations.items():
    if summary.get(field) != expected:
        errors.append(f"summary.{field} mismatch")
if summary.get("initial_exec_delta_classification") != "unchanged":
    errors.append("summary.initial_exec_delta_classification must be unchanged")
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
    "lanes": lanes,
    "comparison": comparison,
    "summary": {
        "initial_exec_delta_classification": comparison.get("initial_exec_delta_classification"),
        "initial_exec_tls_symbols": initial.get("undefined_tls_symbols", []),
        "initial_exec_host_version_requirements": initial.get("host_version_requirements", []),
        "local_exec_failure_signature": local.get("failure_signature"),
        "promotion_allowed": False,
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    for error in errors:
        print(f"tls-model-experiment error: {error}", file=sys.stderr)
    sys.exit(1)
print(
    "tls-model-experiment: pass "
    f"initial_exec_tls={len(initial.get('undefined_tls_symbols', []))} "
    f"local_exec_status={local.get('build_status')} "
    f"report={report_path}"
)
PY
