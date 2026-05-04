#!/usr/bin/env bash
# check_loader_dlfcn_relocation_tls_audit.sh -- bd-bp8fl.5.4 loader/dlfcn fixture gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_LOADER_DLFCN_MANIFEST:-${ROOT}/tests/conformance/loader_dlfcn_relocation_tls_audit.v1.json}"
OUT_DIR="${FLC_LOADER_DLFCN_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_LOADER_DLFCN_REPORT:-${OUT_DIR}/loader_dlfcn_relocation_tls_audit.report.json}"
LOG="${FLC_LOADER_DLFCN_LOG:-${OUT_DIR}/loader_dlfcn_relocation_tls_audit.log.jsonl}"
TARGET_DIR="${FLC_LOADER_DLFCN_TARGET_DIR:-${OUT_DIR}}"
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

BEAD_ID = "bd-bp8fl.5.4"
GATE_ID = "loader-dlfcn-relocation-tls-audit-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "shared_object",
    "symbol",
    "version_node",
    "replacement_level",
    "runtime_mode",
    "oracle_kind",
    "expected_status",
    "actual_status",
    "loader_error",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_FIXTURE_KINDS = {
    "dlopen_success",
    "dlopen_failure",
    "dlsym_version_lookup",
    "tls_symbol_access",
    "relocation_startup",
    "missing_symbol",
    "audit_boundary",
    "dlclose_error",
}
REQUIRED_SYMBOLS = {
    "dlopen",
    "dlsym",
    "dlvsym",
    "dlclose",
    "dlerror",
    "__call_tls_dtors",
    "relocation_startup",
    "ld_audit",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_REPLACEMENT_LEVELS = {"L0"}
REQUIRED_LOADER_ERRORS = {
    "none",
    "object_not_found",
    "symbol_not_found",
    "invalid_handle",
    "unsupported_audit_boundary",
}
DIAGNOSTIC_SIGNATURES = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_kind",
    "symbol_version_classification",
    "loader_error_normalization",
    "unsupported_relocation_or_audit",
]

errors = []
logs = []


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fail(signature, message):
    errors.append({"failure_signature": signature, "message": message})


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        fail("missing_source_artifact", f"cannot parse {path}: {exc}")
        return {}


def resolve(path_text):
    path = Path(str(path_text))
    return path if path.is_absolute() else root / path


def require_object(value, ctx):
    if isinstance(value, dict):
        return value
    fail("missing_field", f"{ctx}: must be object")
    return {}


def require_array(row, field, ctx):
    value = row.get(field)
    if isinstance(value, list) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty array")
    return []


def require_string(row, field, ctx):
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def existing_path(path_text, ctx):
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def source_commit_ok(marker):
    return marker in ("current", "unknown", source_commit)


manifest = require_object(load_json(manifest_path), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match loader/dlfcn log contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

sources = require_object(manifest.get("sources"), "sources")
for key in [
    "dlfcn_abi",
    "version_script",
    "dlfcn_fixture",
    "dlfcn_boundary_policy",
    "oracle_precedence_divergence",
    "replacement_levels",
    "hard_parts_e2e_catalog",
]:
    path_text = sources.get(key)
    if isinstance(path_text, str) and path_text:
        existing_path(path_text, f"sources.{key}")
    else:
        fail("missing_field", f"sources.{key}: must be non-empty string")

declared_signatures = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for signature in DIAGNOSTIC_SIGNATURES:
    if signature not in declared_signatures:
        fail("missing_field", f"diagnostic_signatures missing {signature}")

if set(map(str, manifest.get("required_fixture_kinds", []))) != REQUIRED_FIXTURE_KINDS:
    fail("missing_fixture_kind", "required_fixture_kinds must match loader/dlfcn coverage")
if set(map(str, manifest.get("required_symbols", []))) != REQUIRED_SYMBOLS:
    fail("missing_fixture_kind", "required_symbols must match loader/dlfcn coverage")
if set(map(str, manifest.get("required_runtime_modes", []))) != REQUIRED_RUNTIME_MODES:
    fail("missing_fixture_kind", "required_runtime_modes must include strict and hardened")
if set(map(str, manifest.get("required_replacement_levels", []))) != REQUIRED_REPLACEMENT_LEVELS:
    fail("missing_fixture_kind", "required_replacement_levels must be L0")
if set(map(str, manifest.get("required_loader_error_classes", []))) != REQUIRED_LOADER_ERRORS:
    fail("loader_error_normalization", "required_loader_error_classes drifted")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_kind", "fixture_rows must be a non-empty array")
    rows = []

seen_kinds = set()
seen_symbols = set()
seen_modes = set()
seen_levels = set()
direct_runner_count = 0
isolated_runner_count = 0
blocked_or_failure_count = 0

for index, value in enumerate(rows):
    row = require_object(value, f"fixture_rows[{index}]")
    ctx = f"fixture_rows[{index}]"
    fixture_id = require_string(row, "fixture_id", ctx)
    fixture_kind = require_string(row, "fixture_kind", ctx)
    shared_object = require_string(row, "shared_object", ctx)
    symbol = require_string(row, "symbol", ctx)
    version_node = require_string(row, "version_node", ctx)
    relocation_kind = require_string(row, "relocation_kind", ctx)
    tls_use = require_string(row, "tls_use", ctx)
    dl_sequence = require_array(row, "dl_sequence", ctx)
    runtime_mode = require_string(row, "runtime_mode", ctx)
    replacement_level = require_string(row, "replacement_level", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    expected = require_object(row.get("expected"), f"{ctx}.expected")
    artifact_refs = require_array(row, "artifact_refs", ctx)
    source_commit_state = require_string(row, "source_commit_state", ctx)
    direct_runner = require_object(row.get("direct_runner"), f"{ctx}.direct_runner")
    isolated_runner = require_object(row.get("isolated_runner"), f"{ctx}.isolated_runner")

    seen_kinds.add(fixture_kind)
    seen_symbols.add(symbol)
    seen_modes.add(runtime_mode)
    seen_levels.add(replacement_level)

    if fixture_kind not in REQUIRED_FIXTURE_KINDS:
        fail("missing_fixture_kind", f"{fixture_id}: unknown fixture_kind {fixture_kind}")
    if symbol not in REQUIRED_SYMBOLS:
        fail("missing_fixture_kind", f"{fixture_id}: unknown symbol {symbol}")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_kind", f"{fixture_id}: runtime_mode must be strict or hardened")
    if replacement_level not in REQUIRED_REPLACEMENT_LEVELS:
        fail("missing_fixture_kind", f"{fixture_id}: replacement_level must be L0")
    if not source_commit_ok(source_commit_state):
        fail("stale_artifact", f"{fixture_id}: source_commit_state {source_commit_state!r} is stale")

    for field in ["status", "errno", "loader_error", "user_diagnostic"]:
        require_string(expected, field, f"{ctx}.expected")

    status = str(expected.get("status", ""))
    loader_error = str(expected.get("loader_error", ""))
    if loader_error not in REQUIRED_LOADER_ERRORS:
        fail("loader_error_normalization", f"{fixture_id}: unknown loader_error {loader_error}")
    if status == "pass" and loader_error != "none":
        fail("loader_error_normalization", f"{fixture_id}: pass rows must use loader_error none")
    if status in {"expected_failure", "blocked"} and loader_error == "none":
        fail("loader_error_normalization", f"{fixture_id}: error rows need a loader_error class")
    if status in {"expected_failure", "blocked"}:
        blocked_or_failure_count += 1

    if fixture_kind == "dlsym_version_lookup" and version_node in {"", "not_applicable"}:
        fail("symbol_version_classification", f"{fixture_id}: version lookup needs a version_node")
    if fixture_kind == "audit_boundary" and status != "blocked":
        fail("unsupported_relocation_or_audit", f"{fixture_id}: audit boundary must stay blocked")
    if fixture_kind == "relocation_startup" and relocation_kind == "none":
        fail("unsupported_relocation_or_audit", f"{fixture_id}: relocation startup needs relocation_kind")
    if not dl_sequence:
        fail("missing_field", f"{fixture_id}: dl_sequence cannot be empty")

    for ref in artifact_refs:
        existing_path(ref, f"{fixture_id}.artifact_refs")

    for runner_name, runner in [("direct_runner", direct_runner), ("isolated_runner", isolated_runner)]:
        runner_kind = require_string(runner, "runner_kind", f"{ctx}.{runner_name}")
        require_string(runner, "command", f"{ctx}.{runner_name}")
        refs = require_array(runner, "artifact_refs", f"{ctx}.{runner_name}")
        if runner_kind == "direct":
            direct_runner_count += 1
        if runner_kind == "isolated":
            isolated_runner_count += 1
        for ref in refs:
            existing_path(ref, f"{fixture_id}.{runner_name}.artifact_refs")

    log_row = {
        "trace_id": f"{BEAD_ID}::{fixture_id}",
        "bead_id": BEAD_ID,
        "fixture_id": fixture_id,
        "shared_object": shared_object,
        "symbol": symbol,
        "version_node": version_node,
        "replacement_level": replacement_level,
        "runtime_mode": runtime_mode,
        "oracle_kind": oracle_kind,
        "expected_status": status,
        "actual_status": status if not errors else "not_run",
        "loader_error": loader_error,
        "artifact_refs": artifact_refs,
        "source_commit": source_commit,
        "target_dir": target_dir,
        "failure_signature": "none",
        "relocation_kind": relocation_kind,
        "tls_use": tls_use,
    }
    logs.append(log_row)

missing_kinds = sorted(REQUIRED_FIXTURE_KINDS - seen_kinds)
missing_symbols = sorted(REQUIRED_SYMBOLS - seen_symbols)
missing_modes = sorted(REQUIRED_RUNTIME_MODES - seen_modes)
missing_levels = sorted(REQUIRED_REPLACEMENT_LEVELS - seen_levels)
if missing_kinds:
    fail("missing_fixture_kind", f"missing fixture kinds: {missing_kinds}")
if missing_symbols:
    fail("missing_fixture_kind", f"missing symbols: {missing_symbols}")
if missing_modes:
    fail("missing_fixture_kind", f"missing runtime modes: {missing_modes}")
if missing_levels:
    fail("missing_fixture_kind", f"missing replacement levels: {missing_levels}")

summary = {
    "fixture_row_count": len(rows),
    "covered_fixture_kind_count": len(seen_kinds),
    "covered_symbol_count": len(seen_symbols),
    "runtime_mode_count": len(seen_modes),
    "replacement_level_count": len(seen_levels),
    "direct_runner_count": direct_runner_count,
    "isolated_runner_count": isolated_runner_count,
    "blocked_or_failure_count": blocked_or_failure_count,
    "log_row_count": len(logs),
}

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "generated_at_utc": now(),
    "source_commit": source_commit,
    "target_dir": target_dir,
    "summary": summary,
    "errors": errors,
    "report_artifacts": {
        "manifest": str(manifest_path),
        "report": str(report_path),
        "log": str(log_path),
    },
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with log_path.open("w", encoding="utf-8") as handle:
    for row in logs:
        handle.write(json.dumps(row, sort_keys=True) + "\n")

print(json.dumps(report, sort_keys=True))
if errors:
    sys.exit(1)
PY
