#!/usr/bin/env bash
# check_resolver_nss_hard_parts.sh -- bd-bp8fl.5.1 resolver/NSS fixture gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_RESOLVER_NSS_HARD_PARTS_MANIFEST:-${ROOT}/tests/conformance/resolver_nss_hard_parts.v1.json}"
OUT_DIR="${FLC_RESOLVER_NSS_HARD_PARTS_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_RESOLVER_NSS_HARD_PARTS_REPORT:-${OUT_DIR}/resolver_nss_hard_parts.report.json}"
LOG="${FLC_RESOLVER_NSS_HARD_PARTS_LOG:-${OUT_DIR}/resolver_nss_hard_parts.log.jsonl}"
TARGET_DIR="${FLC_RESOLVER_NSS_HARD_PARTS_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

BEAD_ID = "bd-bp8fl.5.1"
GATE_ID = "resolver-nss-hard-parts-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "query_kind",
    "network_state",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "h_errno",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_QUERY_KINDS = {
    "hosts_lookup",
    "dns_success",
    "dns_failure",
    "offline_resolver",
    "missing_nss_backend",
    "malformed_packet",
    "cache_consistency",
}
REQUIRED_INPUT_DATABASES = {"hosts", "passwd", "group", "services", "protocols", "dns", "nsswitch"}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_NSS_CLASSIFICATIONS = {
    "not_applicable",
    "files_backend_missing_record",
    "backend_unavailable",
    "unsupported_database",
    "cache_consistency_guard",
}
REQUIRED_DNS_MAPPINGS = {
    ("0", "NETDB_SUCCESS", "resolver_ok"),
    ("EAI_NONAME", "HOST_NOT_FOUND", "name_not_found"),
    ("EAI_FAIL", "NO_RECOVERY", "malformed_or_backend_failure"),
    ("ETIMEDOUT", "TRY_AGAIN", "timeout_or_offline"),
}
SIGNATURE_PRIORITY = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_case",
    "nss_backend_failure_classification",
    "dns_error_mapping",
    "environment_divergence",
    "oracle_mismatch",
]

errors: list[tuple[str, str]] = []
logs: list[dict] = []


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature: str, message: str) -> None:
    errors.append((signature, message))


def load_json(path: Path, label: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"{label}: cannot parse {path}: {exc}")
        return {}


def resolve(path_text) -> Path:
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def rel(path: Path) -> str:
    try:
        return str(Path(path).relative_to(root))
    except ValueError:
        return str(path)


def require_object(value, ctx: str) -> dict:
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_array(row: dict, field: str, ctx: str) -> list:
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def require_string(row: dict, field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_int(row: dict, field: str, ctx: str) -> int:
    value = row.get(field)
    if isinstance(value, int) and value >= 0:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-negative integer")
    return 0


def existing_path(path_text, ctx: str) -> None:
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def source_commit_ok(marker: str) -> bool:
    return marker in ("current", "unknown", source_commit)


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match resolver/NSS log contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

sources = require_object(manifest.get("sources"), "sources")
for key in [
    "resolver_fixture",
    "oracle_precedence_divergence",
    "support_matrix",
    "hard_parts_failure_replay_gate",
    "hard_parts_e2e_catalog",
]:
    source_path = sources.get(key)
    if not isinstance(source_path, str) or not source_path:
        fail("missing_field", f"sources.{key}: must be non-empty string")
    else:
        existing_path(source_path, f"sources.{key}")

oracle_doc = load_json(resolve(sources.get("oracle_precedence_divergence", "")), "oracle_precedence")
oracle_kinds = {
    str(row.get("id"))
    for row in oracle_doc.get("oracle_kinds", [])
    if isinstance(row, dict) and row.get("id")
}
divergence_classes = {
    str(row.get("id"))
    for row in oracle_doc.get("divergence_classifications", [])
    if isinstance(row, dict) and row.get("id")
}

resolver_fixture = load_json(resolve(sources.get("resolver_fixture", "")), "resolver_fixture")
resolver_case_names = {
    str(row.get("name"))
    for row in resolver_fixture.get("cases", [])
    if isinstance(row, dict) and row.get("name")
}

declared_diagnostics = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for required in SIGNATURE_PRIORITY:
    if required not in declared_diagnostics:
        fail("missing_field", f"diagnostic_signatures missing {required}")

required_manifest_query_kinds = set(str(kind) for kind in manifest.get("required_query_kinds", []))
required_manifest_databases = set(str(kind) for kind in manifest.get("required_input_databases", []))
if required_manifest_query_kinds != REQUIRED_QUERY_KINDS:
    fail("missing_field", "required_query_kinds must match resolver/NSS hard-parts coverage")
if required_manifest_databases != REQUIRED_INPUT_DATABASES:
    fail("missing_field", "required_input_databases must match resolver/NSS hard-parts coverage")

manifest_dns_mappings = {
    (
        str(row.get("errno")),
        str(row.get("h_errno")),
        str(row.get("reason_code")),
    )
    for row in manifest.get("required_dns_error_mappings", [])
    if isinstance(row, dict)
}
missing_dns_mappings = sorted(REQUIRED_DNS_MAPPINGS - manifest_dns_mappings)
if missing_dns_mappings:
    fail("dns_error_mapping", f"required_dns_error_mappings missing {missing_dns_mappings}")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_case", "fixture_rows must be a non-empty array")
    rows = []

seen_query_kinds: set[str] = set()
seen_databases: set[str] = set()
seen_runtime_modes: set[str] = set()
direct_runner_count = 0
isolated_runner_count = 0
allowed_environment_divergence_count = 0
blocked_or_degraded_count = 0

for index, value in enumerate(rows):
    row = require_object(value, f"fixture_rows[{index}]")
    ctx = f"fixture_rows[{index}]"
    fixture_id = require_string(row, "fixture_id", ctx)
    query_kind = require_string(row, "query_kind", ctx)
    input_database = require_string(row, "input_database", ctx)
    network_state = require_string(row, "network_state", ctx)
    nsswitch_config = require_string(row, "nsswitch_config", ctx)
    runtime_mode = require_string(row, "runtime_mode", ctx)
    replacement_level = require_string(row, "replacement_level", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    allowed_divergence = require_string(row, "allowed_divergence", ctx)
    timeout_ms = require_int(row, "timeout_ms", ctx)
    source_fixture_case = require_string(row, "source_fixture_case", ctx)

    if query_kind in REQUIRED_QUERY_KINDS:
        seen_query_kinds.add(query_kind)
    else:
        fail("missing_fixture_case", f"{ctx}.query_kind {query_kind!r} is not required coverage")
    if input_database in REQUIRED_INPUT_DATABASES:
        seen_databases.add(input_database)
    else:
        fail("missing_fixture_case", f"{ctx}.input_database {input_database!r} is not required coverage")
    if runtime_mode in REQUIRED_RUNTIME_MODES:
        seen_runtime_modes.add(runtime_mode)
    else:
        fail("missing_field", f"{ctx}.runtime_mode must be strict or hardened")
    if replacement_level not in {"L0", "L1", "L2", "L3"}:
        fail("missing_field", f"{ctx}.replacement_level must be L0/L1/L2/L3")
    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind {oracle_kind!r} is not declared")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence {allowed_divergence!r} is not declared")
    if source_fixture_case not in resolver_case_names:
        fail("missing_source_artifact", f"{ctx}.source_fixture_case {source_fixture_case!r} is absent from resolver fixture")

    expected = require_object(row.get("expected"), f"{ctx}.expected")
    for field in ["result", "errno", "h_errno", "status", "user_diagnostic"]:
        require_string(expected, field, f"{ctx}.expected")
    if expected.get("status") in {"blocked_claim", "degraded"}:
        blocked_or_degraded_count += 1

    cleanup = require_object(row.get("cleanup"), f"{ctx}.cleanup")
    if cleanup.get("required") is not True:
        fail("missing_field", f"{ctx}.cleanup.required must be true")
    cleanup_state = require_string(cleanup, "state", f"{ctx}.cleanup")

    nss_failure = require_object(row.get("nss_backend_failure"), f"{ctx}.nss_backend_failure")
    classification = require_string(nss_failure, "classification", f"{ctx}.nss_backend_failure")
    require_string(nss_failure, "user_diagnostic", f"{ctx}.nss_backend_failure")
    if classification not in REQUIRED_NSS_CLASSIFICATIONS:
        fail("nss_backend_failure_classification", f"{ctx}.nss_backend_failure.classification {classification!r} is unknown")
    if query_kind == "missing_nss_backend" and classification in {"not_applicable", "cache_consistency_guard"}:
        fail("nss_backend_failure_classification", f"{ctx}: missing_nss_backend requires backend failure classification")

    dns_mapping = require_object(row.get("dns_error_mapping"), f"{ctx}.dns_error_mapping")
    mapping_tuple = (
        require_string(dns_mapping, "errno", f"{ctx}.dns_error_mapping"),
        require_string(dns_mapping, "h_errno", f"{ctx}.dns_error_mapping"),
        require_string(dns_mapping, "reason_code", f"{ctx}.dns_error_mapping"),
    )
    if mapping_tuple not in REQUIRED_DNS_MAPPINGS:
        fail("dns_error_mapping", f"{ctx}.dns_error_mapping {mapping_tuple!r} is not a required mapping")
    dns_row = input_database in {"dns", "nsswitch"} or query_kind in {
        "dns_success",
        "dns_failure",
        "offline_resolver",
        "malformed_packet",
    }
    if dns_row and (expected.get("errno") != mapping_tuple[0] or expected.get("h_errno") != mapping_tuple[1]):
        fail("dns_error_mapping", f"{ctx}: expected errno/h_errno must match dns_error_mapping")

    env_divergence = require_object(row.get("environment_divergence"), f"{ctx}.environment_divergence")
    divergence_allowed = env_divergence.get("allowed")
    divergence_reason = require_string(env_divergence, "reason", f"{ctx}.environment_divergence")
    if divergence_allowed is True:
        allowed_environment_divergence_count += 1
    needs_divergence = (
        ("offline" in network_state and input_database not in {"hosts"})
        or "timeout" in network_state
        or "loopback_malformed" in network_state
        or input_database in {"passwd", "group", "services", "protocols", "nsswitch"}
        or allowed_divergence in {"flaky_environment", "unsupported_contract", "proof_gap"}
    )
    if needs_divergence and divergence_allowed is not True:
        fail("environment_divergence", f"{ctx}: host-dependent/offline row must allow environment divergence")
    if divergence_allowed is True and not divergence_reason:
        fail("environment_divergence", f"{ctx}: allowed environment divergence requires reason")
    if timeout_ms > 0 and "timeout" not in network_state and query_kind not in {"dns_failure", "malformed_packet"}:
        fail("environment_divergence", f"{ctx}: timeout_ms > 0 must be tied to timeout, DNS failure, or malformed packet")

    artifact_refs = [str(sources.get("resolver_fixture", "")), str(manifest_path)]
    for runner_field, expected_kind in [("direct_runner", "direct"), ("isolated_runner", "isolated")]:
        runner = require_object(row.get(runner_field), f"{ctx}.{runner_field}")
        runner_kind = require_string(runner, "runner_kind", f"{ctx}.{runner_field}")
        command = require_string(runner, "command", f"{ctx}.{runner_field}")
        refs = [str(ref) for ref in require_array(runner, "artifact_refs", f"{ctx}.{runner_field}")]
        if runner_kind != expected_kind:
            fail("missing_field", f"{ctx}.{runner_field}.runner_kind must be {expected_kind}")
        if runner_kind == "direct" and "rch exec -- cargo" in command and " -p frankenlibc-harness" not in command:
            fail("missing_field", f"{ctx}.{runner_field}.command must scope cargo to frankenlibc-harness")
        for artifact_ref in refs:
            existing_path(artifact_ref, f"{ctx}.{runner_field}.artifact_refs")
        artifact_refs.extend(refs)
        if runner_kind == "direct":
            direct_runner_count += 1
        if runner_kind == "isolated":
            isolated_runner_count += 1

    logs.append(
        {
            "timestamp": now(),
            "trace_id": f"{BEAD_ID}::{fixture_id}::{runtime_mode}",
            "bead_id": BEAD_ID,
            "fixture_id": fixture_id,
            "query_kind": query_kind,
            "network_state": network_state,
            "runtime_mode": runtime_mode,
            "replacement_level": replacement_level,
            "oracle_kind": oracle_kind,
            "expected": expected,
            "actual": {
                "verdict": "schema_and_source_fixture_validated",
                "input_database": input_database,
                "nsswitch_config": nsswitch_config,
                "source_fixture_case": source_fixture_case,
                "cleanup_state": cleanup_state,
            },
            "errno": expected.get("errno"),
            "h_errno": expected.get("h_errno"),
            "artifact_refs": sorted(set(artifact_refs)),
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": "ok",
        }
    )

missing_query_kinds = sorted(REQUIRED_QUERY_KINDS - seen_query_kinds)
if missing_query_kinds:
    fail("missing_fixture_case", f"missing query kinds {missing_query_kinds}")
missing_databases = sorted(REQUIRED_INPUT_DATABASES - seen_databases)
if missing_databases:
    fail("missing_fixture_case", f"missing input databases {missing_databases}")
missing_modes = sorted(REQUIRED_RUNTIME_MODES - seen_runtime_modes)
if missing_modes:
    fail("missing_fixture_case", f"missing runtime modes {missing_modes}")

summary = manifest.get("summary")
if isinstance(summary, dict):
    expected_summary = {
        "fixture_count": len(rows),
        "required_query_kind_count": len(REQUIRED_QUERY_KINDS),
        "required_input_database_count": len(REQUIRED_INPUT_DATABASES),
        "runtime_mode_count": len(seen_runtime_modes),
        "direct_runner_count": direct_runner_count,
        "isolated_runner_count": isolated_runner_count,
        "allowed_environment_divergence_count": allowed_environment_divergence_count,
        "blocked_or_degraded_count": blocked_or_degraded_count,
    }
    for key, expected_value in expected_summary.items():
        if int(summary.get(key, -1)) != expected_value:
            fail("stale_artifact", f"summary.{key}={summary.get(key)!r} does not match {expected_value}")
else:
    fail("missing_field", "summary must be object")

error_signatures = [signature for signature, _ in errors]
primary_signature = ""
for signature in SIGNATURE_PRIORITY:
    if signature in error_signatures:
        primary_signature = signature
        break

if errors:
    logs.append(
        {
            "timestamp": now(),
            "trace_id": f"{BEAD_ID}::gate::fail",
            "bead_id": BEAD_ID,
            "fixture_id": GATE_ID,
            "query_kind": "all",
            "network_state": "not_run",
            "runtime_mode": "strict+hardened",
            "replacement_level": "L0",
            "oracle_kind": "gate_validator",
            "expected": "resolver/NSS fixture manifest is current and complete",
            "actual": [message for _, message in errors],
            "errno": "0",
            "h_errno": "NETDB_INTERNAL",
            "artifact_refs": [rel(manifest_path)],
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": primary_signature or "gate_validation_failed",
        }
    )

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "source_commit": source_commit,
    "target_dir": target_dir,
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "summary": {
        "fixture_count": len(rows),
        "covered_query_kind_count": len(seen_query_kinds),
        "covered_input_database_count": len(seen_databases),
        "runtime_mode_count": len(seen_runtime_modes),
        "direct_runner_count": direct_runner_count,
        "isolated_runner_count": isolated_runner_count,
        "allowed_environment_divergence_count": allowed_environment_divergence_count,
        "blocked_or_degraded_count": blocked_or_degraded_count,
        "log_row_count": len(logs),
    },
    "covered_query_kinds": sorted(seen_query_kinds),
    "covered_input_databases": sorted(seen_databases),
    "runtime_modes": sorted(seen_runtime_modes),
    "diagnostic_signatures": sorted(declared_diagnostics),
    "errors": [{"failure_signature": signature, "message": message} for signature, message in errors],
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in logs),
    encoding="utf-8",
)

if errors:
    raise SystemExit(1)
PY
