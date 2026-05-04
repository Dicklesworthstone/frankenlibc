#!/usr/bin/env bash
# check_crt_tls_atexit_direct_link_run_proof_fixtures.sh -- bd-b92jd.1.2 gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_CRT_TLS_PROOF_MANIFEST:-${ROOT}/tests/conformance/crt_tls_atexit_direct_link_run_proof_fixtures.v1.json}"
OUT_DIR="${FLC_CRT_TLS_PROOF_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_CRT_TLS_PROOF_REPORT:-${OUT_DIR}/crt_tls_atexit_direct_link_run_proof_fixtures.report.json}"
LOG="${FLC_CRT_TLS_PROOF_LOG:-${OUT_DIR}/crt_tls_atexit_direct_link_run_proof_fixtures.log.jsonl}"
TARGET_DIR="${FLC_CRT_TLS_PROOF_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1]).resolve()
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

BEAD_ID = "bd-b92jd.1.2"
GATE_ID = "crt-tls-atexit-direct-link-run-proof-fixtures-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "scenario_kind",
    "runtime_mode",
    "replacement_level",
    "execution_model",
    "expected_decision",
    "actual_decision",
    "expected_order",
    "actual_order",
    "source_commit",
    "target_dir",
    "artifact_refs",
    "failure_signature",
]
REQUIRED_SCENARIO_KINDS = {
    "crt_startup",
    "tls_initialization",
    "tls_destructor",
    "init_fini_ordering",
    "atexit_on_exit",
    "errno_tls_isolation",
    "env_ownership",
    "secure_mode_diagnostics",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_EXECUTION_MODELS = {"direct_link_run", "replace_mode_simulated"}
REQUIRED_ROW_FIELDS = [
    "fixture_id",
    "scenario_kind",
    "title",
    "replacement_level",
    "execution_model",
    "source_commit",
    "runtime_modes",
    "expected_order",
    "actual_order",
    "expected_status",
    "actual_status",
    "expected_decision",
    "actual_decision",
    "missing_evidence",
    "strict_expectation",
    "hardened_expectation",
    "source_artifacts",
    "target_artifacts",
    "artifact_refs",
    "failure_signature",
]
DIAGNOSTIC_SIGNATURES = {
    "missing_field",
    "replace_artifact_missing",
    "missing_source_commit",
    "stale_source_commit",
    "missing_artifact_refs",
    "missing_source_artifact",
    "missing_fixture_row",
    "strict_hardened_expectation_missing",
    "direct_link_claim_conflict",
}
errors = []
log_rows = []


def fail(signature, message):
    errors.append({"failure_signature": signature, "message": message})


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def rel(path):
    try:
        return Path(path).resolve().relative_to(root).as_posix()
    except Exception:
        return str(path)


def load_json(path, label):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def require_object(value, context):
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{context}: must be an object")
    return {}


def require_array(row, field, context):
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{context}.{field}: must be a non-empty array")
    return []


def require_string(row, field, context):
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{context}.{field}: must be a non-empty string")
    return ""


def repo_ref(path_text, context, *, must_exist):
    if not isinstance(path_text, str) or not path_text:
        fail("missing_source_artifact", f"{context}: path must be a non-empty string")
        return None
    path = Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        fail("missing_source_artifact", f"{context}: path must stay repo-relative: {path_text}")
        return None
    resolved = root / path
    if must_exist and not resolved.exists():
        fail("missing_source_artifact", f"{context}: missing path {path_text}")
    return resolved


def commit_is_current(commit_marker):
    return commit_marker in {"current", "unknown", source_commit}


manifest = require_object(load_json(resolve(manifest_path), "manifest"), "manifest")
if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match CRT/TLS proof log contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not commit_is_current(required_commit):
    fail(
        "stale_source_commit",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

sources = require_object(manifest.get("sources"), "sources")
for key, source_path in sources.items():
    if not isinstance(source_path, str) or not source_path:
        fail("missing_field", f"sources.{key}: must be a non-empty string")
    else:
        repo_ref(source_path, f"sources.{key}", must_exist=True)

policy = require_object(manifest.get("replacement_artifact_policy"), "replacement_artifact_policy")
replace_artifact_text = require_string(policy, "replace_artifact", "replacement_artifact_policy")
replace_artifact = repo_ref(
    replace_artifact_text,
    "replacement_artifact_policy.replace_artifact",
    must_exist=False,
)
replace_artifact_exists = bool(replace_artifact and replace_artifact.exists())
if policy.get("missing_artifact_result") != "claim_blocked":
    fail("missing_field", "missing_artifact_result must be claim_blocked")
if policy.get("missing_row_source_commit_result") != "claim_blocked":
    fail("missing_field", "missing_row_source_commit_result must be claim_blocked")
if policy.get("missing_row_artifact_refs_result") != "claim_blocked":
    fail("missing_field", "missing_row_artifact_refs_result must be claim_blocked")
if not policy.get("direct_link_evidence_cannot_be_inferred_from_ld_preload"):
    fail("direct_link_claim_conflict", "direct link evidence must not be inferred from LD_PRELOAD")

declared_scenarios = set(manifest.get("required_scenario_kinds", []))
declared_runtime_modes = set(manifest.get("required_runtime_modes", []))
declared_execution_models = set(manifest.get("required_execution_models", []))
if declared_scenarios != REQUIRED_SCENARIO_KINDS:
    fail("missing_fixture_row", "required_scenario_kinds must match CRT/TLS proof scope")
if declared_runtime_modes != REQUIRED_RUNTIME_MODES:
    fail("strict_hardened_expectation_missing", "required_runtime_modes must be strict+hardened")
if declared_execution_models != REQUIRED_EXECUTION_MODELS:
    fail("missing_field", "required_execution_models must include direct_link_run and replace_mode_simulated")

declared_diagnostics = {
    row.get("id")
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict)
}
for signature in DIAGNOSTIC_SIGNATURES:
    if signature not in declared_diagnostics:
        fail("missing_field", f"diagnostic_signatures missing {signature}")

negative_signatures = {
    row.get("failure_signature")
    for row in manifest.get("negative_claim_tests", [])
    if isinstance(row, dict)
}
for signature in [
    "replace_artifact_missing",
    "missing_source_commit",
    "stale_source_commit",
    "missing_artifact_refs",
    "missing_fixture_row",
    "strict_hardened_expectation_missing",
]:
    if signature not in negative_signatures:
        fail("missing_field", f"negative_claim_tests missing {signature}")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_row", "fixture_rows must be a non-empty array")
    rows = []

seen_ids = set()
scenario_counts = Counter()
decision_counts = Counter()
execution_counts = Counter()
mode_counts = Counter()

for row in rows:
    if not isinstance(row, dict):
        fail("missing_field", "fixture_rows entries must be objects")
        continue
    fixture_id = row.get("fixture_id", "<missing>")
    for field in REQUIRED_ROW_FIELDS:
        if field not in row:
            signature = {
                "source_commit": "missing_source_commit",
                "artifact_refs": "missing_artifact_refs",
                "strict_expectation": "strict_hardened_expectation_missing",
                "hardened_expectation": "strict_hardened_expectation_missing",
            }.get(field, "missing_field")
            fail(signature, f"{fixture_id}: missing field {field}")

    if fixture_id in seen_ids:
        fail("missing_field", f"{fixture_id}: duplicate fixture_id")
    seen_ids.add(fixture_id)

    scenario = require_string(row, "scenario_kind", fixture_id)
    if scenario not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_row", f"{fixture_id}: unknown scenario_kind {scenario}")
    else:
        scenario_counts[scenario] += 1

    execution_model = require_string(row, "execution_model", fixture_id)
    if execution_model not in REQUIRED_EXECUTION_MODELS:
        fail("missing_field", f"{fixture_id}: unknown execution_model {execution_model}")
    else:
        execution_counts[execution_model] += 1

    runtime_modes = set(require_array(row, "runtime_modes", fixture_id))
    if runtime_modes != REQUIRED_RUNTIME_MODES:
        fail("strict_hardened_expectation_missing", f"{fixture_id}: runtime_modes must be strict+hardened")
    for mode in runtime_modes:
        mode_counts[mode] += 1

    for expectation_field in ["strict_expectation", "hardened_expectation"]:
        expectation = require_object(row.get(expectation_field), f"{fixture_id}.{expectation_field}")
        if not expectation:
            fail("strict_hardened_expectation_missing", f"{fixture_id}: {expectation_field} missing")

    row_commit = row.get("source_commit")
    if not isinstance(row_commit, str) or not row_commit:
        fail("missing_source_commit", f"{fixture_id}: source_commit must be present")
    elif not commit_is_current(row_commit):
        fail("stale_source_commit", f"{fixture_id}: source_commit {row_commit!r} is stale")

    artifact_refs = row.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs:
        fail("missing_artifact_refs", f"{fixture_id}: artifact_refs must be non-empty")
        artifact_refs = []
    for artifact in artifact_refs:
        repo_ref(artifact, f"{fixture_id}.artifact_refs", must_exist=True)
    for artifact in row.get("source_artifacts", []):
        repo_ref(artifact, f"{fixture_id}.source_artifacts", must_exist=True)
    for artifact in row.get("target_artifacts", []):
        repo_ref(artifact, f"{fixture_id}.target_artifacts", must_exist=False)

    expected_decision = row.get("expected_decision")
    actual_decision = row.get("actual_decision")
    decision_counts[str(actual_decision)] += 1
    if expected_decision != actual_decision:
        fail(
            "direct_link_claim_conflict",
            f"{fixture_id}: expected_decision {expected_decision!r} differs from actual_decision {actual_decision!r}",
        )
    if not replace_artifact_exists and actual_decision != "claim_blocked":
        fail(
            "replace_artifact_missing",
            f"{fixture_id}: {replace_artifact_text} is missing but row actual_decision={actual_decision!r}",
        )

    expected_order = row.get("expected_order")
    if not isinstance(expected_order, list) or not expected_order:
        fail("missing_field", f"{fixture_id}: expected_order must be non-empty")
    actual_order = row.get("actual_order")
    if not isinstance(actual_order, list):
        fail("missing_field", f"{fixture_id}: actual_order must be an array")
    if actual_decision == "claim_blocked" and not row.get("missing_evidence"):
        fail("missing_field", f"{fixture_id}: claim_blocked rows must list missing_evidence")
    if row.get("failure_signature") in {"", None, "none"} and actual_decision == "claim_blocked":
        fail("missing_field", f"{fixture_id}: blocked row must provide failure_signature")

    for mode in sorted(runtime_modes):
        log_rows.append(
            {
                "trace_id": f"{BEAD_ID}::{fixture_id}::{mode}",
                "bead_id": BEAD_ID,
                "fixture_id": fixture_id,
                "scenario_kind": scenario,
                "runtime_mode": mode,
                "replacement_level": row.get("replacement_level"),
                "execution_model": execution_model,
                "expected_decision": expected_decision,
                "actual_decision": actual_decision,
                "expected_order": expected_order if isinstance(expected_order, list) else [],
                "actual_order": actual_order if isinstance(actual_order, list) else [],
                "source_commit": source_commit,
                "target_dir": target_dir,
                "artifact_refs": artifact_refs,
                "failure_signature": row.get("failure_signature"),
            }
        )

missing_scenarios = REQUIRED_SCENARIO_KINDS - set(scenario_counts)
if missing_scenarios:
    fail("missing_fixture_row", "missing scenario rows: " + ",".join(sorted(missing_scenarios)))
if mode_counts.get("strict", 0) != len(rows) or mode_counts.get("hardened", 0) != len(rows):
    fail("strict_hardened_expectation_missing", "every fixture row must cover strict and hardened")
for execution_model in REQUIRED_EXECUTION_MODELS:
    if execution_counts.get(execution_model, 0) == 0:
        fail("missing_field", f"missing execution_model {execution_model}")

summary = {
    "fixture_count": len(rows),
    "required_scenario_count": len(REQUIRED_SCENARIO_KINDS),
    "strict_hardened_mode_count": len(REQUIRED_RUNTIME_MODES),
    "claim_blocked_count": decision_counts.get("claim_blocked", 0),
    "decision_counts": dict(sorted(decision_counts.items())),
    "scenario_counts": dict(sorted(scenario_counts.items())),
    "execution_model_counts": dict(sorted(execution_counts.items())),
    "log_row_count": len(log_rows),
    "replace_artifact_exists": replace_artifact_exists,
}
declared_summary = manifest.get("summary", {})
if isinstance(declared_summary, dict):
    for key in ["fixture_count", "claim_blocked_count", "required_scenario_count", "strict_hardened_mode_count"]:
        if declared_summary.get(key) != summary.get(key):
            fail("stale_source_commit", f"summary.{key} drifted from computed value {summary.get(key)}")

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "manifest": rel(manifest_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "source_commit": source_commit,
    "target_dir": target_dir,
    "replacement_artifact": replace_artifact_text,
    "errors": errors,
    "required_log_fields": REQUIRED_LOG_FIELDS,
    "summary": summary,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in log_rows),
    encoding="utf-8",
)
print(json.dumps(report, indent=2, sort_keys=True))
if errors:
    sys.exit(1)
PY
