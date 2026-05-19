#!/usr/bin/env bash
# check_standalone_owned_tls_startup_surface.sh -- CI gate for bd-w1c58
#
# Validates the report-only owned TLS startup surface and emits a compact
# materialized report for the current __tls_get_addr blocker.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SURFACE="${FRANKENLIBC_STANDALONE_OWNED_TLS_SURFACE:-${ROOT}/tests/conformance/standalone_owned_tls_startup_surface.v1.json}"
TLS_DIAGNOSTIC="${FRANKENLIBC_STANDALONE_TLS_DIAGNOSTIC:-${ROOT}/tests/conformance/standalone_tls_blocker_diagnostics.v1.json}"
TLS_REMOVAL_EXPERIMENT="${FRANKENLIBC_STANDALONE_TLS_REMOVAL_EXPERIMENT:-${ROOT}/tests/conformance/standalone_tls_removal_experiment.v1.json}"
TLS_EXPERIMENT="${FRANKENLIBC_STANDALONE_TLS_MODEL_EXPERIMENT:-${ROOT}/tests/conformance/standalone_tls_model_startup_experiment.v1.json}"
PLAN="${FRANKENLIBC_STANDALONE_HOST_DEPENDENCY_PROBE_PLAN:-${ROOT}/tests/conformance/standalone_host_dependency_probe_plan.v1.json}"
VERSION_BURNDOWN="${FRANKENLIBC_STANDALONE_VERSION_BURNDOWN:-${ROOT}/tests/conformance/standalone_host_version_requirement_burndown.v1.json}"
OWNER_LEDGER="${FRANKENLIBC_STANDALONE_BLOCKER_OWNER_LEDGER:-${ROOT}/tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json}"
ROLLUP="${FRANKENLIBC_STANDALONE_BLOCKER_ROLLUP:-${ROOT}/tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_STANDALONE_OWNED_TLS_SURFACE_REPORT:-${OUT_DIR}/standalone_owned_tls_startup_surface.report.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")"

python3 - "${ROOT}" "${SURFACE}" "${TLS_DIAGNOSTIC}" "${TLS_REMOVAL_EXPERIMENT}" "${TLS_EXPERIMENT}" "${PLAN}" "${VERSION_BURNDOWN}" "${OWNER_LEDGER}" "${ROLLUP}" "${REPORT}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
surface_path = Path(sys.argv[2])
diagnostic_path = Path(sys.argv[3])
tls_removal_path = Path(sys.argv[4])
experiment_path = Path(sys.argv[5])
plan_path = Path(sys.argv[6])
version_path = Path(sys.argv[7])
owner_path = Path(sys.argv[8])
rollup_path = Path(sys.argv[9])
report_path = Path(sys.argv[10])

paths = [surface_path, diagnostic_path, tls_removal_path, experiment_path, plan_path, version_path, owner_path, rollup_path, report_path]
surface_path, diagnostic_path, tls_removal_path, experiment_path, plan_path, version_path, owner_path, rollup_path, report_path = [
    path if path.is_absolute() else root / path for path in paths
]

BEAD_ID = "bd-w1c58"
TLS_SYMBOL = "__tls_get_addr@GLIBC_2.3"
TLS_BARE_SYMBOL = "__tls_get_addr"
TLS_REQUIREMENT_ID = "ld-linux-x86-64.so.2:GLIBC_2.3"
TLS_PROVIDER = "ld-linux-x86-64.so.2"
TLS_VERSION = "GLIBC_2.3"
EXPECTED_INPUTS = {
    "standalone_tls_blocker_diagnostics": "tests/conformance/standalone_tls_blocker_diagnostics.v1.json",
    "standalone_tls_removal_experiment": "tests/conformance/standalone_tls_removal_experiment.v1.json",
    "standalone_tls_model_startup_experiment": "tests/conformance/standalone_tls_model_startup_experiment.v1.json",
    "standalone_host_dependency_probe_plan": "tests/conformance/standalone_host_dependency_probe_plan.v1.json",
    "standalone_host_version_requirement_burndown": "tests/conformance/standalone_host_version_requirement_burndown.v1.json",
    "standalone_forge_blocker_owner_action_ledger": "tests/conformance/standalone_forge_blocker_owner_action_ledger.v1.json",
    "standalone_blocker_burndown_progress_rollup": "tests/conformance/standalone_blocker_burndown_progress_rollup.v1.json",
}
EXPECTED_FRESHNESS_POLICY = {
    "recorded_source_commit_field": "source_commit",
    "comparison_target": "current git HEAD",
    "stale_result": "block_owned_tls_startup_surface",
    "owned_tls_surface_evidence_allowed_when_stale": False,
    "rejected_evidence_kind": "stale_owned_tls_startup_surface",
}
EXPECTED_REPORT_POLICY = {
    "report_only": True,
    "promotion_allowed": False,
    "replacement_level_change_allowed": False,
    "default_forge_path_change_allowed": False,
    "default_tls_model_change_allowed": False,
    "source_rewrite_claim_allowed": False,
    "missing_symbol_result": "fail_closed",
    "extra_symbol_result": "fail_closed",
    "provider_version_drift_result": "fail_closed",
    "ready_claim_with_current_tls_symbol_result": "fail_closed",
    "claim_status_until_symbol_exit": "claim_blocked",
}
REQUIRED_ROW_FIELDS = {
    "symbol",
    "bare_symbol",
    "provider_library",
    "version_node",
    "requirement_id",
    "blocking_reason",
    "provider_blocking_reason",
    "owner_surface",
    "provider_owner_surface",
    "source_diagnostic",
    "source_version_matrix",
    "source_tls_model_experiment",
    "source_owner_ledger",
    "semantic_contract_class",
    "owned_substitute_strategy",
    "owned_surface_status",
    "source_surface_hotspots",
    "evidence_commands",
    "exit_criteria",
    "status_until_exit",
}
EXPECTED_SOURCE_DIAGNOSTIC = (
    "standalone_tls_blocker_diagnostics.current_forge_evidence."
    "observed_artifact_symbols.undefined_tls_symbols"
)
EXPECTED_SOURCE_ACTION_ROW = (
    "standalone_host_dependency_probe_plan.current_forge_blocker_projection."
    "blocker_action_required_rows.undefined_tls_symbols"
)
EXPECTED_SOURCE_VERSION_MATRIX = "standalone_host_version_requirement_burndown.version_requirement_matrix"
EXPECTED_SOURCE_EXPERIMENT = "standalone_tls_model_startup_experiment.comparison.initial_exec_delta_classification"
EXPECTED_SOURCE_LEDGER = "standalone_forge_blocker_owner_action_ledger.ledger_rows.undefined_tls_symbols"

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


def require_string(row, field, context):
    value = row.get(field)
    if not isinstance(value, str) or not value:
        errors.append(f"{context}.{field}: must be a non-empty string")
        return ""
    return value


head = current_commit()
surface = load_json(surface_path)
diagnostic = load_json(diagnostic_path)
tls_removal = load_json(tls_removal_path)
experiment = load_json(experiment_path)
plan = load_json(plan_path)
version_burndown = load_json(version_path)
owner_ledger = load_json(owner_path)
rollup = load_json(rollup_path)
for name in ["surface", "diagnostic", "tls_removal", "experiment", "plan", "version_burndown", "owner_ledger", "rollup"]:
    if not isinstance(locals()[name], dict):
        locals()[name] = {}

if surface.get("schema_version") != "v1" or surface.get("bead") != BEAD_ID:
    errors.append("surface must declare schema_version=v1 and bead=bd-w1c58")
if surface.get("manifest_id") != "standalone-owned-tls-startup-surface":
    errors.append("manifest_id must be standalone-owned-tls-startup-surface")
source_commit = surface.get("source_commit")
if not (source_commit == "current" or is_hex_commit(source_commit)):
    errors.append("surface source_commit must be 'current' or a 40-hex commit")
elif not source_commit_marker_is_current(source_commit, head):
    errors.append("surface source_commit must be 'current' or match current git HEAD")
if surface.get("source_commit_freshness_policy") != EXPECTED_FRESHNESS_POLICY:
    errors.append("source_commit_freshness_policy must match owned TLS stale-source contract")
if surface.get("report_policy") != EXPECTED_REPORT_POLICY:
    errors.append("report_policy must match owned TLS fail-closed contract")
if surface.get("source_action_row") != EXPECTED_SOURCE_ACTION_ROW:
    errors.append("source_action_row must point at live undefined_tls_symbols blocker action row")
inputs = object_value(surface.get("inputs"), "inputs")
if inputs != EXPECTED_INPUTS:
    errors.append("inputs must match owned TLS surface input contract")
for key, ref in EXPECTED_INPUTS.items():
    repo_path(inputs.get(key), f"inputs.{key}")
if set(string_list(surface.get("required_symbol_row_fields"), "required_symbol_row_fields")) != REQUIRED_ROW_FIELDS:
    errors.append("required_symbol_row_fields mismatch")

if diagnostic.get("manifest_id") != "standalone-tls-blocker-diagnostics":
    errors.append("TLS diagnostic input must be standalone-tls-blocker-diagnostics")
diagnostic_symbols = set(
    string_list(
        nested(diagnostic, "diagnostic", "current_forge_evidence", "observed_artifact_symbols").get(
            "undefined_tls_symbols"
        ),
        "diagnostic.current_forge_evidence.observed_artifact_symbols.undefined_tls_symbols",
    )
)
nm_symbols = set(
    string_list(
        nested(diagnostic, "diagnostic", "current_forge_evidence", "evidence_command_results", "nm_dynamic").get(
            "observed_undefined_tls_symbols"
        ),
        "diagnostic.nm_dynamic.observed_undefined_tls_symbols",
    )
)
readelf_symbols = set(
    string_list(
        nested(diagnostic, "diagnostic", "current_forge_evidence", "evidence_command_results", "readelf_symbols").get(
            "observed_undefined_tls_symbols"
        ),
        "diagnostic.readelf_symbols.observed_undefined_tls_symbols",
    )
)
if diagnostic_symbols != {TLS_SYMBOL} or nm_symbols != {TLS_SYMBOL} or readelf_symbols != {TLS_SYMBOL}:
    errors.append("TLS diagnostic must keep exactly __tls_get_addr@GLIBC_2.3 in artifact, nm, and readelf controls")
version_needs = nested(
    diagnostic,
    "diagnostic",
    "current_forge_evidence",
    "evidence_command_results",
    "readelf_version",
).get("observed_tls_version_needs")
if not isinstance(version_needs, dict) or version_needs.get(TLS_PROVIDER) != [TLS_VERSION]:
    errors.append("TLS diagnostic readelf version control must keep ld-linux-x86-64.so.2:GLIBC_2.3")

artifact_probe = object_value(diagnostic.get("owned_tls_cache_artifact_probe"), "diagnostic.owned_tls_cache_artifact_probe")
descriptor_buckets = artifact_probe.get("tls_descriptor_buckets")
if not isinstance(descriptor_buckets, list):
    errors.append("diagnostic.owned_tls_cache_artifact_probe.tls_descriptor_buckets must be an array")
    descriptor_buckets = []
expected_hotspots = []
for index, bucket in enumerate(descriptor_buckets):
    if not isinstance(bucket, dict):
        errors.append(f"diagnostic tls_descriptor_buckets[{index}] must be an object")
        continue
    examples = string_list(
        bucket.get("observed_call_site_examples"),
        f"diagnostic.tls_descriptor_buckets[{index}].observed_call_site_examples",
    )
    expected_hotspots.extend(examples)
if len(expected_hotspots) != 6:
    errors.append("diagnostic residual std TLS descriptor buckets must expose exactly six call-site hotspots")

diagnostic_emitters = artifact_probe.get("residual_artifact_tls_emitters")
if not isinstance(diagnostic_emitters, list):
    errors.append("diagnostic owned TLS probe residual_artifact_tls_emitters must be an array")
    diagnostic_emitters = []
removal_emitters = tls_removal.get("residual_artifact_tls_emitters")
if not isinstance(removal_emitters, list):
    errors.append("standalone_tls_removal_experiment residual_artifact_tls_emitters must be an array")
    removal_emitters = []
diagnostic_emitter_symbols = {
    row.get("symbol")
    for row in diagnostic_emitters
    if isinstance(row, dict) and isinstance(row.get("symbol"), str)
}
removal_emitter_count = sum(1 for row in removal_emitters if isinstance(row, dict))
if len(diagnostic_emitter_symbols) != 6 or removal_emitter_count != 6:
    errors.append("diagnostic and TLS-removal residual artifact TLS emitter inventories must both contain six rows")
if any(
    not isinstance(row, dict)
    or row.get("crate") != "std"
    or row.get("claim_status_until_exit") != "claim_blocked"
    for row in diagnostic_emitters
):
    errors.append("diagnostic residual artifact TLS emitters must remain std claim_blocked rows")

projection = object_value(plan.get("current_forge_blocker_projection"), "plan.current_forge_blocker_projection")
action_rows = object_value(
    projection.get("blocker_action_required_rows"),
    "plan.current_forge_blocker_projection.blocker_action_required_rows",
)
tls_action = object_value(
    action_rows.get("undefined_tls_symbols"),
    "plan.current_forge_blocker_projection.blocker_action_required_rows.undefined_tls_symbols",
)
if tls_action:
    expected_pairs = {
        "blocking_reason": "undefined_tls_symbols",
        "owner_surface": "tls_startup",
        "primary_probe_id": "nm_dynamic_undefined_symbols",
    }
    for field, expected in expected_pairs.items():
        if tls_action.get(field) != expected:
            errors.append(
                "plan.current_forge_blocker_projection.blocker_action_required_rows."
                f"undefined_tls_symbols.{field} must be {expected}"
            )
    if tls_action.get("promotion_allowed") is not False:
        errors.append(
            "plan.current_forge_blocker_projection.blocker_action_required_rows."
            "undefined_tls_symbols.promotion_allowed must be false"
        )
action_values = set(
    string_list(
        tls_action.get("current_blocker_values"),
        "plan.current_forge_blocker_projection.blocker_action_required_rows."
        "undefined_tls_symbols.current_blocker_values",
    )
)
if action_values != {TLS_SYMBOL}:
    errors.append(
        "plan.current_forge_blocker_projection.blocker_action_required_rows."
        "undefined_tls_symbols.current_blocker_values must match current TLS diagnostic"
    )
action_exit_criteria = string_list(
    tls_action.get("exit_criteria"),
    "plan.current_forge_blocker_projection.blocker_action_required_rows.undefined_tls_symbols.exit_criteria",
    min_len=2,
)

if experiment.get("manifest_id") != "standalone-tls-model-startup-experiment":
    errors.append("TLS model experiment input must be standalone-tls-model-startup-experiment")
comparison = object_value(experiment.get("comparison"), "tls experiment comparison")
if comparison.get("initial_exec_delta_classification") != "unchanged":
    errors.append("TLS model experiment must still classify initial-exec as unchanged")
if comparison.get("local_exec_artifact_comparison") != "inapplicable_build_failed":
    errors.append("TLS model experiment must keep local-exec as inapplicable build failed")
if comparison.get("standalone_claim_status") != "claim_blocked":
    errors.append("TLS model experiment must keep standalone claim blocked")

version_rows = version_burndown.get("version_requirement_matrix", [])
if not isinstance(version_rows, list):
    errors.append("version_requirement_matrix must be an array")
    version_rows = []
tls_version_rows = [
    row for row in version_rows if isinstance(row, dict) and row.get("requirement_id") == TLS_REQUIREMENT_ID
]
if len(tls_version_rows) != 1:
    errors.append("version burndown must keep exactly one ld-linux GLIBC_2.3 TLS row")
    tls_version_row = {}
else:
    tls_version_row = tls_version_rows[0]
    if tls_version_row.get("provider_library") != TLS_PROVIDER or tls_version_row.get("version_node") != TLS_VERSION:
        errors.append("TLS version row provider/version mismatch")
    if tls_version_row.get("owner_surface") != "loader_tls_runtime":
        errors.append("TLS version row owner_surface must be loader_tls_runtime")
    if TLS_SYMBOL not in string_list(tls_version_row.get("observed_symbols"), "tls version row observed_symbols"):
        errors.append("TLS version row must observe __tls_get_addr@GLIBC_2.3")
    secondary = set(string_list(tls_version_row.get("secondary_blocking_reasons"), "tls version secondary_blocking_reasons"))
    if "undefined_tls_symbols" not in secondary:
        errors.append("TLS version row must include undefined_tls_symbols as a secondary blocker")

owner_rows = owner_ledger.get("ledger_rows", [])
if not isinstance(owner_rows, list):
    errors.append("owner ledger ledger_rows must be an array")
    owner_rows = []
owner_tls = next(
    (row for row in owner_rows if isinstance(row, dict) and row.get("blocking_reason") == "undefined_tls_symbols"),
    {},
)
if owner_tls.get("owner_surface") != "tls_startup":
    errors.append("owner ledger undefined_tls_symbols row must belong to tls_startup")

rollup_rows = rollup.get("progress_categories", [])
if not isinstance(rollup_rows, list):
    errors.append("rollup progress_categories must be an array")
    rollup_rows = []
rollup_tls = next((row for row in rollup_rows if isinstance(row, dict) and row.get("category_id") == "tls_startup"), {})
if set(string_list(rollup_tls.get("source_blocking_reasons"), "rollup tls source_blocking_reasons")) != {"undefined_tls_symbols"}:
    errors.append("rollup tls_startup row must only source undefined_tls_symbols")
if rollup_tls.get("last_known_value_count") != 1:
    errors.append("rollup tls_startup last_known_value_count must be 1")

rows = surface.get("symbol_rows", [])
if not isinstance(rows, list):
    errors.append("symbol_rows must be an array")
    rows = []
if len(rows) != 1:
    errors.append("symbol_rows must contain exactly one TLS row")

materialized_rows = []
unresolved_count = 0
seen_symbols = set()
for row in rows:
    if not isinstance(row, dict):
        errors.append("symbol row must be an object")
        continue
    context = f"symbol_rows[{row.get('symbol') or '<missing>'}]"
    for field in sorted(REQUIRED_ROW_FIELDS - set(row)):
        errors.append(f"{context}: missing field {field}")
    symbol = require_string(row, "symbol", context)
    seen_symbols.add(symbol)
    if symbol != TLS_SYMBOL:
        errors.append(f"{context}.symbol must be {TLS_SYMBOL}")
    if row.get("bare_symbol") != TLS_BARE_SYMBOL:
        errors.append(f"{context}.bare_symbol must be {TLS_BARE_SYMBOL}")
    expected_pairs = {
        "provider_library": TLS_PROVIDER,
        "version_node": TLS_VERSION,
        "requirement_id": TLS_REQUIREMENT_ID,
        "blocking_reason": "undefined_tls_symbols",
        "provider_blocking_reason": "host_version_requirements",
        "owner_surface": "tls_startup",
        "provider_owner_surface": "loader_tls_runtime",
        "source_diagnostic": EXPECTED_SOURCE_DIAGNOSTIC,
        "source_version_matrix": EXPECTED_SOURCE_VERSION_MATRIX,
        "source_tls_model_experiment": EXPECTED_SOURCE_EXPERIMENT,
        "source_owner_ledger": EXPECTED_SOURCE_LEDGER,
        "status_until_exit": "claim_blocked",
    }
    for field, expected in expected_pairs.items():
        if row.get(field) != expected:
            errors.append(f"{context}.{field} must be {expected}")
    for field in ["semantic_contract_class", "owned_substitute_strategy"]:
        require_string(row, field, context)
    hotspots = string_list(row.get("source_surface_hotspots"), f"{context}.source_surface_hotspots", min_len=6)
    if hotspots != expected_hotspots:
        errors.append(
            f"{context}.source_surface_hotspots must match live residual std TLS descriptor buckets"
        )
    if not all(hotspot.startswith("std::") for hotspot in hotspots):
        errors.append(f"{context}.source_surface_hotspots must now point at residual Rust std TLS surfaces")
    evidence = string_list(row.get("evidence_commands"), f"{context}.evidence_commands", min_len=4)
    if not any("nm -D" in command and TLS_BARE_SYMBOL in command for command in evidence):
        errors.append(f"{context}.evidence_commands must include nm -D TLS control")
    exit_criteria = string_list(row.get("exit_criteria"), f"{context}.exit_criteria", min_len=4)
    if not any("no undefined __tls_get_addr" in criterion for criterion in exit_criteria):
        errors.append(f"{context}.exit_criteria must include __tls_get_addr absence")
    if row.get("owned_surface_status") != "unresolved":
        errors.append(f"{context}.owned_surface_status must remain unresolved while diagnostics reports {TLS_SYMBOL}")
    else:
        unresolved_count += 1
    materialized_rows.append(
        {
            "symbol": symbol,
            "provider_library": row.get("provider_library"),
            "version_node": row.get("version_node"),
            "requirement_id": row.get("requirement_id"),
            "owner_surface": row.get("owner_surface"),
            "provider_owner_surface": row.get("provider_owner_surface"),
            "owned_surface_status": row.get("owned_surface_status"),
            "evidence_commands": evidence,
            "exit_criteria": exit_criteria,
            "status_until_exit": "claim_blocked",
        }
    )
if seen_symbols != {TLS_SYMBOL}:
    errors.append("symbol_rows must cover the current TLS diagnostic exactly")

summary = object_value(surface.get("summary"), "summary")
summary_expectations = {
    "current_tls_symbol_count": 1,
    "provider_library_count": 1,
    "provider_version_requirement_count": 1,
    "source_surface_hotspot_count": len(rows[0].get("source_surface_hotspots", [])) if rows and isinstance(rows[0], dict) else 0,
    "residual_artifact_tls_emitter_count": len(diagnostic_emitter_symbols),
    "unresolved_symbol_count": 1,
}
for field, expected in summary_expectations.items():
    if summary.get(field) != expected:
        errors.append(f"summary.{field} mismatch")
if summary.get("owned_surface_ready") is not False:
    errors.append("summary.owned_surface_ready must remain false while current diagnostics reports __tls_get_addr")
if summary.get("promotion_allowed") is not False:
    errors.append("summary.promotion_allowed must be false")
if summary.get("claim_status_until_symbol_exit") != "claim_blocked":
    errors.append("summary.claim_status_until_symbol_exit must be claim_blocked")

status = "pass" if not errors else "fail"
report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": status,
    "source_commit": source_commit,
    "current_head": head,
    "claim_status": "claim_blocked",
    "owner_surface": "tls_startup",
    "source_action_row": EXPECTED_SOURCE_ACTION_ROW,
    "source_action_exit_criteria": action_exit_criteria,
    "provider_version_requirement_ids": [TLS_REQUIREMENT_ID],
    "symbol_rows": materialized_rows,
    "summary": {
        **summary_expectations,
        "owned_surface_ready": False,
        "promotion_allowed": False,
        "claim_status_until_symbol_exit": "claim_blocked",
    },
    "errors": errors,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
if errors:
    for error in errors:
        print(f"owned-tls-startup-surface error: {error}", file=sys.stderr)
    sys.exit(1)
print(
    "owned-tls-startup-surface: pass "
    f"symbols=1 provider_versions=1 report={report_path}"
)
PY
