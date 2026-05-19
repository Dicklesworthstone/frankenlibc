#!/usr/bin/env bash
# check_standalone_owned_unwinder_symbol_surface.sh -- CI gate for bd-zyck1.95
#
# Validates the report-only owned-unwinder symbol surface contract and emits a
# materialized report tying each current _Unwind_* blocker to its provider row.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURFACE="${FRANKENLIBC_STANDALONE_OWNED_UNWINDER_SURFACE:-${ROOT}/tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json}"
DIAGNOSTICS="${FRANKENLIBC_STANDALONE_COMPILER_RUNTIME_DIAGNOSTICS:-${ROOT}/tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json}"
PLAN="${FRANKENLIBC_STANDALONE_HOST_DEPENDENCY_PROBE_PLAN:-${ROOT}/tests/conformance/standalone_host_dependency_probe_plan.v1.json}"
VERSION_BURNDOWN="${FRANKENLIBC_STANDALONE_VERSION_BURNDOWN:-${ROOT}/tests/conformance/standalone_host_version_requirement_burndown.v1.json}"
OWNER_LEDGER="${FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER:-${ROOT}/tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json}"
ROLLUP="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP:-${ROOT}/tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_OWNED_UNWINDER_SURFACE_REPORT:-${OUT_DIR}/standalone_owned_unwinder_symbol_surface.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${SURFACE}" "${DIAGNOSTICS}" "${PLAN}" "${VERSION_BURNDOWN}" "${OWNER_LEDGER}" "${ROLLUP}" "${REPORT}" <<'PY'
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

root = Path(sys.argv[1]).resolve()
surface_path = Path(sys.argv[2])
diagnostics_path = Path(sys.argv[3])
plan_path = Path(sys.argv[4])
version_path = Path(sys.argv[5])
owner_path = Path(sys.argv[6])
rollup_path = Path(sys.argv[7])
report_path = Path(sys.argv[8])
for name in [
    "surface_path",
    "diagnostics_path",
    "plan_path",
    "version_path",
    "owner_path",
    "rollup_path",
    "report_path",
]:
    path = locals()[name]
    if not path.is_absolute():
        locals()[name] = root / path

BEAD_ID = "bd-zyck1.95"
EXPECTED_INPUTS = {
    "standalone_compiler_runtime_blocker_diagnostics": "tests/conformance/standalone_compiler_runtime_blocker_diagnostics.v1.json",
    "standalone_host_dependency_probe_plan": "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
    "standalone_host_version_requirement_burndown": "tests/conformance/standalone_host_version_requirement_burndown.v1.json",
    "standalone_forge_blocker_owner_action_ledger": "tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json",
    "standalone_blocker_burndown_progress_rollup": "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_owned_unwinder_symbol_surface",
    "owned_unwinder_surface_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_owned_unwinder_symbol_surface",
}
EXPECTED_REPORT_POLICY = {
    "report_only": True,
    "promotion_allowed": False,
    "replacement_level_change_allowed": False,
    "default_forge_path_change_allowed": False,
    "default_build_profile_change_allowed": False,
    "panic_strategy_change_allowed": False,
    "missing_symbol_result": "fail_closed",
    "extra_symbol_result": "fail_closed",
    "provider_version_drift_result": "fail_closed",
    "ready_claim_with_current_undefined_symbol_result": "fail_closed",
    "claim_status_until_all_symbols_exit": "claim_blocked",
}
EXPECTED_SOURCE_DIAGNOSTIC = (
    "standalone_compiler_runtime_blocker_diagnostics.current_forge_evidence."
    "evidence_command_results.nm_dynamic.observed_undefined_unwind_symbols"
)
EXPECTED_SOURCE_ACTION_ROW = (
    "standalone_host_dependency_probe_plan.current_forge_blocker_projection."
    "blocker_action_required_rows.undefined_unwind_symbols"
)
EXPECTED_SOURCE_VERSION_MATRIX = "standalone_host_version_requirement_burndown.version_requirement_matrix"
REQUIRED_SYMBOL_ROW_FIELDS = {
    "symbol",
    "bare_symbol",
    "provider_library",
    "version_node",
    "requirement_id",
    "blocking_reason",
    "owner_surface",
    "source_diagnostic",
    "source_version_matrix",
    "semantic_contract_class",
    "owned_substitute_strategy",
    "owned_surface_status",
    "evidence_commands",
    "exit_criteria",
    "status_until_exit",
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


def required_string(row, field, context):
    value = row.get(field)
    if not isinstance(value, str) or not value:
        errors.append(f"{context}.{field}: must be a non-empty string")
        return ""
    return value


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


def split_symbol_version(symbol):
    if "@" not in symbol:
        return symbol, ""
    bare, version = symbol.rsplit("@", 1)
    return bare, version


head = current_commit()
surface = load_json(surface_path)
diagnostics = load_json(diagnostics_path)
plan = load_json(plan_path)
version_burndown = load_json(version_path)
owner_ledger = load_json(owner_path)
rollup = load_json(rollup_path)
for value_name in ["surface", "diagnostics", "plan", "version_burndown", "owner_ledger", "rollup"]:
    if not isinstance(locals()[value_name], dict):
        locals()[value_name] = {}

if surface.get("schema_version") != "v1" or surface.get("bead") != BEAD_ID:
    errors.append("surface must declare schema_version=v1 and bead=bd-zyck1.95")
if surface.get("manifest_id") != "standalone-owned-unwinder-symbol-surface":
    errors.append("manifest_id must be standalone-owned-unwinder-symbol-surface")
source_commit = surface.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("surface source_commit must be 'current' or a 40-hex commit")
elif not source_commit_marker_is_current(source_commit, head):
    errors.append("surface source_commit must be 'current' or match current git HEAD")
if surface.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match owned-unwinder stale-source contract")
if surface.get("report_policy") != EXPECTED_REPORT_POLICY:
    errors.append("report_policy must match owned-unwinder fail-closed contract")
if surface.get("source_action_row") != EXPECTED_SOURCE_ACTION_ROW:
    errors.append("source_action_row must point at live undefined_unwind_symbols blocker action row")
inputs = object_value(surface.get("inputs"), "inputs")
if inputs != EXPECTED_INPUTS:
    errors.append("inputs must match owned-unwinder symbol surface input contract")
for key, ref in EXPECTED_INPUTS.items():
    repo_path(inputs.get(key), f"inputs.{key}")

declared_fields = set(string_list(surface.get("required_symbol_row_fields"), "required_symbol_row_fields"))
if declared_fields != REQUIRED_SYMBOL_ROW_FIELDS:
    errors.append("required_symbol_row_fields mismatch")

nm_symbols = set(
    string_list(
        nested(
            diagnostics,
            "diagnostics",
            "current_forge_evidence",
            "evidence_command_results",
            "nm_dynamic",
        ).get("observed_undefined_unwind_symbols"),
        "diagnostics.nm_dynamic.observed_undefined_unwind_symbols",
        min_len=12,
    )
)
mapping_symbols = set()
for mapping in diagnostics.get("blocker_mappings", []):
    if isinstance(mapping, dict) and mapping.get("blocking_reason") == "undefined_unwind_symbols":
        mapping_symbols.update(
            string_list(
                nested(mapping, "diagnostics.blocker_mappings.undefined_unwind_symbols", "observed_values").get(
                    "undefined_unwind_symbols"
                ),
                "diagnostics.blocker_mappings.undefined_unwind_symbols.observed_values.undefined_unwind_symbols",
                min_len=12,
            )
        )
if nm_symbols != mapping_symbols:
    errors.append("diagnostics nm_dynamic and blocker_mappings unwind symbol sets must match")
if len(nm_symbols) != 12:
    errors.append("current diagnostics must expose twelve unique undefined unwind symbols")

projection = object_value(plan.get("current_forge_blocker_projection"), "plan.current_forge_blocker_projection")
action_rows = object_value(
    projection.get("blocker_action_required_rows"),
    "plan.current_forge_blocker_projection.blocker_action_required_rows",
)
unwind_action = object_value(
    action_rows.get("undefined_unwind_symbols"),
    "plan.current_forge_blocker_projection.blocker_action_required_rows.undefined_unwind_symbols",
)
if unwind_action:
    expected_pairs = {
        "blocking_reason": "undefined_unwind_symbols",
        "owner_surface": "unwind_runtime",
        "primary_probe_id": "nm_dynamic_undefined_symbols",
    }
    for field, expected in expected_pairs.items():
        if unwind_action.get(field) != expected:
            errors.append(
                "plan.current_forge_blocker_projection.blocker_action_required_rows."
                f"undefined_unwind_symbols.{field} must be {expected}"
            )
    if unwind_action.get("promotion_allowed") is not False:
        errors.append(
            "plan.current_forge_blocker_projection.blocker_action_required_rows."
            "undefined_unwind_symbols.promotion_allowed must be false"
        )
action_values = set(
    string_list(
        unwind_action.get("current_blocker_values"),
        "plan.current_forge_blocker_projection.blocker_action_required_rows."
        "undefined_unwind_symbols.current_blocker_values",
        min_len=12,
    )
)
if action_values != nm_symbols:
    errors.append(
        "plan.current_forge_blocker_projection.blocker_action_required_rows."
        "undefined_unwind_symbols.current_blocker_values must match current diagnostics"
    )
action_exit_criteria = string_list(
    unwind_action.get("exit_criteria"),
    "plan.current_forge_blocker_projection.blocker_action_required_rows.undefined_unwind_symbols.exit_criteria",
    min_len=2,
)

owner_rows = owner_ledger.get("ledger_rows", [])
if not isinstance(owner_rows, list):
    errors.append("owner ledger ledger_rows must be an array")
    owner_rows = []
owner_unwind = next(
    (
        row
        for row in owner_rows
        if isinstance(row, dict) and row.get("blocking_reason") == "undefined_unwind_symbols"
    ),
    {},
)
if owner_unwind.get("owner_surface") != "unwind_runtime":
    errors.append("owner ledger undefined_unwind_symbols row must belong to unwind_runtime")

rollup_rows = rollup.get("progress_categories", [])
if not isinstance(rollup_rows, list):
    errors.append("rollup progress_categories must be an array")
    rollup_rows = []
rollup_unwind = next(
    (
        row
        for row in rollup_rows
        if isinstance(row, dict) and row.get("category_id") == "unwind_runtime"
    ),
    {},
)
rollup_reasons = set(string_list(rollup_unwind.get("source_blocking_reasons"), "rollup unwind source_blocking_reasons"))
if "undefined_unwind_symbols" not in rollup_reasons:
    errors.append("rollup unwind_runtime row must include undefined_unwind_symbols")
if rollup_unwind.get("last_known_value_count") != len(nm_symbols):
    errors.append("rollup unwind_runtime last_known_value_count must match current unwind symbol count")

version_rows = version_burndown.get("version_requirement_matrix", [])
if not isinstance(version_rows, list):
    errors.append("version_requirement_matrix must be an array")
    version_rows = []
symbol_to_version_row = {}
libgcc_requirement_ids = set()
for row in version_rows:
    if not isinstance(row, dict):
        errors.append("version requirement row must be an object")
        continue
    if row.get("provider_library") != "libgcc_s.so.1":
        continue
    secondary = set(string_list(row.get("secondary_blocking_reasons"), "version row secondary_blocking_reasons"))
    if "undefined_unwind_symbols" not in secondary:
        continue
    requirement_id = row.get("requirement_id")
    provider = row.get("provider_library")
    version = row.get("version_node")
    if requirement_id != f"{provider}:{version}":
        errors.append("libgcc unwind version row requirement_id must equal provider:version")
        continue
    libgcc_requirement_ids.add(requirement_id)
    for symbol in string_list(row.get("observed_symbols"), f"version row {requirement_id}.observed_symbols"):
        symbol_to_version_row[symbol] = row
if set(symbol_to_version_row) != nm_symbols:
    errors.append("version requirement matrix must map every current unwind symbol exactly once")

rows = surface.get("symbol_rows", [])
if not isinstance(rows, list):
    errors.append("symbol_rows must be an array")
    rows = []
seen_symbols = set()
materialized_rows = []
unresolved_count = 0
for row in rows:
    if not isinstance(row, dict):
        errors.append("symbol row must be an object")
        continue
    symbol = row.get("symbol")
    context = f"symbol_rows[{symbol or '<missing>'}]"
    for field in sorted(REQUIRED_SYMBOL_ROW_FIELDS - set(row)):
        errors.append(f"{context}: missing field {field}")
    symbol = required_string(row, "symbol", context)
    if not symbol:
        continue
    if symbol in seen_symbols:
        errors.append(f"duplicate symbol row {symbol}")
    seen_symbols.add(symbol)
    bare, version = split_symbol_version(symbol)
    if row.get("bare_symbol") != bare:
        errors.append(f"{context}.bare_symbol must equal symbol before version suffix")
    if row.get("version_node") != version:
        errors.append(f"{context}.version_node must equal symbol version suffix")
    version_row = symbol_to_version_row.get(symbol, {})
    if not version_row:
        errors.append(f"{context}: symbol is not present in current version matrix")
    else:
        for field in ["provider_library", "version_node", "requirement_id"]:
            if row.get(field) != version_row.get(field):
                errors.append(f"{context}.{field} must match version requirement matrix")
    if row.get("blocking_reason") != "undefined_unwind_symbols":
        errors.append(f"{context}.blocking_reason must be undefined_unwind_symbols")
    if row.get("owner_surface") != "unwind_runtime":
        errors.append(f"{context}.owner_surface must be unwind_runtime")
    if row.get("source_diagnostic") != EXPECTED_SOURCE_DIAGNOSTIC:
        errors.append(f"{context}.source_diagnostic mismatch")
    if row.get("source_version_matrix") != EXPECTED_SOURCE_VERSION_MATRIX:
        errors.append(f"{context}.source_version_matrix mismatch")
    required_string(row, "semantic_contract_class", context)
    required_string(row, "owned_substitute_strategy", context)
    evidence = string_list(row.get("evidence_commands"), f"{context}.evidence_commands", min_len=2)
    exit_criteria = string_list(row.get("exit_criteria"), f"{context}.exit_criteria", min_len=2)
    if row.get("owned_surface_status") != "unresolved":
        errors.append(f"{context}.owned_surface_status must remain unresolved while diagnostics still reports {symbol}")
    else:
        unresolved_count += 1
    if row.get("status_until_exit") != "claim_blocked":
        errors.append(f"{context}.status_until_exit must be claim_blocked")
    materialized_rows.append(
        {
            "symbol": symbol,
            "bare_symbol": bare,
            "provider_library": row.get("provider_library"),
            "version_node": row.get("version_node"),
            "requirement_id": row.get("requirement_id"),
            "owner_surface": row.get("owner_surface"),
            "semantic_contract_class": row.get("semantic_contract_class"),
            "owned_surface_status": row.get("owned_surface_status"),
            "evidence_commands": evidence,
            "exit_criteria": exit_criteria,
            "status_until_exit": "claim_blocked",
        }
    )
if seen_symbols != nm_symbols:
    errors.append("symbol_rows must cover every current undefined unwind symbol exactly")

summary = object_value(surface.get("summary"), "summary")
summary_expectations = {
    "current_unwind_symbol_count": len(nm_symbols),
    "provider_library_count": 1 if libgcc_requirement_ids else 0,
    "provider_version_requirement_count": len(libgcc_requirement_ids),
    "unresolved_symbol_count": len(nm_symbols),
}
for field, expected in summary_expectations.items():
    if summary.get(field) != expected:
        errors.append(f"summary.{field} mismatch")
if summary.get("owned_surface_ready") is not False:
    errors.append("summary.owned_surface_ready must remain false while current diagnostics reports unwind symbols")
if summary.get("promotion_allowed") is not False:
    errors.append("summary.promotion_allowed must be false")
if summary.get("claim_status_until_all_symbols_exit") != "claim_blocked":
    errors.append("summary.claim_status_until_all_symbols_exit must be claim_blocked")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": status,
    "source_commit": source_commit,
    "current_head": head,
    "claim_status": "claim_blocked",
    "owner_surface": "unwind_runtime",
    "source_action_row": EXPECTED_SOURCE_ACTION_ROW,
    "source_action_exit_criteria": action_exit_criteria,
    "provider_version_requirement_ids": sorted(libgcc_requirement_ids),
    "symbol_rows": materialized_rows,
    "summary": {
        **summary_expectations,
        "owned_surface_ready": False,
        "promotion_allowed": False,
        "claim_status_until_all_symbols_exit": "claim_blocked",
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    for error in errors:
        print(f"owned-unwinder-symbol-surface error: {error}", file=sys.stderr)
    sys.exit(1)
print(
    "owned-unwinder-symbol-surface: pass "
    f"symbols={len(nm_symbols)} provider_versions={len(libgcc_requirement_ids)} report={report_path}"
)
PY
