#!/usr/bin/env bash
# check_stdio_libio_buffering_fixture_pack.sh -- bd-bp8fl.5.5 stdio/libio gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_STDIO_LIBIO_FIXTURE_PACK_MANIFEST:-${ROOT}/tests/conformance/stdio_libio_buffering_fixture_pack.v1.json}"
OUT_DIR="${FLC_STDIO_LIBIO_FIXTURE_PACK_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_STDIO_LIBIO_FIXTURE_PACK_REPORT:-${OUT_DIR}/stdio_libio_buffering_fixture_pack.report.json}"
LOG="${FLC_STDIO_LIBIO_FIXTURE_PACK_LOG:-${OUT_DIR}/stdio_libio_buffering_fixture_pack.log.jsonl}"
TARGET_DIR="${FLC_STDIO_LIBIO_FIXTURE_PACK_TARGET_DIR:-${OUT_DIR}}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${MANIFEST}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" "${TARGET_DIR}" <<'PY'
import json
import re
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
manifest_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]
target_dir = sys.argv[6]

BEAD_ID = "bd-bp8fl.5.5"
GATE_ID = "stdio-libio-buffering-fixture-pack-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "operation",
    "buffering_mode",
    "orientation",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_FIXTURE_FIELDS = [
    "fixture_id",
    "scenario_kind",
    "operation",
    "symbols",
    "buffering_mode",
    "orientation",
    "file_kind",
    "initial_contents",
    "expected",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "allowed_divergence",
    "source_case_refs",
    "state_transition",
    "cleanup",
    "direct_runner",
    "isolated_runner",
]
REQUIRED_EXPECTED_FIELDS = [
    "bytes",
    "text",
    "status",
    "errno",
    "feof",
    "ferror",
    "position",
    "user_diagnostic",
]
REQUIRED_RUNNER_FIELDS = ["runner_kind", "command", "artifact_refs"]
REQUIRED_SCENARIO_KINDS = {
    "stream_open_close",
    "buffering_mode_control",
    "buffered_write",
    "buffered_read",
    "eof_state",
    "error_state",
    "seek_tell",
    "locking",
    "wide_io_orientation",
    "memory_stream",
    "cookie_stream",
    "internal_io_helper",
}
REQUIRED_BUFFERING_MODES = {"not_applicable", "full", "line", "unbuffered"}
REQUIRED_ORIENTATIONS = {"undecided", "byte", "wide"}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_STATE_TRANSITIONS = {
    "Open->Closed",
    "Open->Open",
    "Open->Eof",
    "Open->Err",
    "Undecided->Wide",
}
BLOCKED_STATUSES = {"blocked_claim", "deferred_claim"}
SIGNATURE_PRIORITY = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_case",
    "state_contract_mismatch",
    "unsupported_surface_overclaim",
    "cleanup_contract",
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


def require_array(row: dict, field: str, ctx: str, *, allow_empty: bool = False) -> list:
    value = row.get(field)
    if isinstance(value, list) and (allow_empty or value):
        return value
    cardinality = "array" if allow_empty else "non-empty array"
    fail("missing_field", f"{ctx}.{field}: must be {cardinality}")
    return []


def require_string(row: dict, field: str, ctx: str) -> str:
    value = row.get(field)
    if isinstance(value, str) and value:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-empty string")
    return ""


def require_bool(row: dict, field: str, ctx: str) -> bool:
    value = row.get(field)
    if isinstance(value, bool):
        return value
    fail("missing_field", f"{ctx}.{field}: must be boolean")
    return False


def existing_path(path_text, ctx: str) -> None:
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def existing_artifact_refs(refs: list, ctx: str) -> None:
    for ref in refs:
        if not isinstance(ref, str) or not ref:
            fail("missing_field", f"{ctx}.artifact_refs entries must be non-empty strings")
            continue
        existing_path(ref, f"{ctx}.artifact_refs")


def string_set(values, ctx: str) -> set[str]:
    if not isinstance(values, list):
        fail("missing_field", f"{ctx}: must be array")
        return set()
    result = set()
    for value in values:
        if isinstance(value, str) and value:
            result.add(value)
        else:
            fail("missing_field", f"{ctx}: entries must be non-empty strings")
    return result


def source_commit_ok(marker: str) -> bool:
    return marker in ("current", "unknown", source_commit)


def validate_runner(row: dict, field: str, ctx: str, expected_kind: str) -> tuple[bool, list[str]]:
    runner = require_object(row.get(field), f"{ctx}.{field}")
    for required in REQUIRED_RUNNER_FIELDS:
        if required not in runner:
            fail("missing_field", f"{ctx}.{field}.{required}: missing")
    runner_kind = require_string(runner, "runner_kind", f"{ctx}.{field}")
    command = require_string(runner, "command", f"{ctx}.{field}")
    refs = require_array(runner, "artifact_refs", f"{ctx}.{field}")
    existing_artifact_refs(refs, f"{ctx}.{field}")
    if runner_kind != expected_kind:
        fail("missing_field", f"{ctx}.{field}.runner_kind must be {expected_kind}")
    if expected_kind == "direct" and "cargo test" not in command:
        fail("missing_source_artifact", f"{ctx}.{field}.command must be a cargo test command")
    return runner_kind == expected_kind, [str(ref) for ref in refs if isinstance(ref, str)]


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match stdio/libio log contract")

fixture_schema = require_object(manifest.get("fixture_schema"), "fixture_schema")
if fixture_schema.get("required_fields") != REQUIRED_FIXTURE_FIELDS:
    fail("missing_field", "fixture_schema.required_fields must match fixture row contract")
if fixture_schema.get("expected_required_fields") != REQUIRED_EXPECTED_FIELDS:
    fail("missing_field", "fixture_schema.expected_required_fields must match expected contract")
if fixture_schema.get("runner_required_fields") != REQUIRED_RUNNER_FIELDS:
    fail("missing_field", "fixture_schema.runner_required_fields must match runner contract")

freshness = require_object(manifest.get("freshness"), "freshness")
required_commit = str(freshness.get("required_source_commit", ""))
if not source_commit_ok(required_commit):
    fail(
        "stale_artifact",
        f"freshness.required_source_commit {required_commit!r} does not match current {source_commit}",
    )

sources = require_object(manifest.get("sources"), "sources")
for key in [
    "stdio_file_ops_fixture",
    "stdio_phase_strategy",
    "stdio_invariants",
    "oracle_precedence_divergence",
    "hard_parts_failure_replay_gate",
    "hard_parts_e2e_catalog",
    "support_matrix",
    "stdio_abi_test",
    "stdio_locking_stress_test",
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

stdio_fixture = load_json(resolve(sources.get("stdio_file_ops_fixture", "")), "stdio_file_ops")
stdio_fixture_names = {
    str(row.get("name"))
    for row in stdio_fixture.get("cases", [])
    if isinstance(row, dict) and row.get("name")
}

phase_doc = load_json(resolve(sources.get("stdio_phase_strategy", "")), "stdio_phase_strategy")
phase_symbols: set[str] = set()
for split_key in ["phase1_required", "deferred_surface"]:
    split = phase_doc.get("phase_split", {}).get(split_key, {})
    if isinstance(split, dict):
        phase_symbols.update(str(symbol) for symbol in split.get("symbols", []) if isinstance(symbol, str))
for phase in phase_doc.get("migration_plan", {}).get("phases", []):
    if isinstance(phase, dict):
        phase_symbols.update(str(symbol) for symbol in phase.get("symbols", []) if isinstance(symbol, str))

support_doc = load_json(resolve(sources.get("support_matrix", "")), "support_matrix")
support_symbols = {
    str(row.get("symbol"))
    for row in support_doc.get("symbols", [])
    if isinstance(row, dict) and row.get("symbol")
}

test_anchors: set[str] = set()
for source_key in ["stdio_abi_test", "stdio_locking_stress_test"]:
    source_path = resolve(sources.get(source_key, ""))
    try:
        source = source_path.read_text(encoding="utf-8")
    except Exception as exc:
        fail("missing_source_artifact", f"sources.{source_key}: cannot read test anchors: {exc}")
        continue
    test_anchors.update(re.findall(r"\bfn\s+([A-Za-z0-9_]+)\s*\(", source))

declared_diagnostics = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for required in SIGNATURE_PRIORITY:
    if required not in declared_diagnostics:
        fail("missing_field", f"diagnostic_signatures missing {required}")

if string_set(manifest.get("required_scenario_kinds"), "required_scenario_kinds") != REQUIRED_SCENARIO_KINDS:
    fail("missing_field", "required_scenario_kinds must match stdio/libio coverage")
if string_set(manifest.get("required_buffering_modes"), "required_buffering_modes") != REQUIRED_BUFFERING_MODES:
    fail("missing_field", "required_buffering_modes must match stdio/libio coverage")
if string_set(manifest.get("required_orientations"), "required_orientations") != REQUIRED_ORIENTATIONS:
    fail("missing_field", "required_orientations must match stdio/libio coverage")
if string_set(manifest.get("required_state_transitions"), "required_state_transitions") != REQUIRED_STATE_TRANSITIONS:
    fail("state_contract_mismatch", "required_state_transitions must match stdio invariant states")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_case", "fixture_rows must be a non-empty array")
    rows = []

seen_scenarios: set[str] = set()
seen_runtime_modes: set[str] = set()
seen_buffering_modes: set[str] = set()
seen_orientations: set[str] = set()
blocked_or_deferred_count = 0
cleanup_required_count = 0
direct_runner_count = 0
isolated_runner_count = 0

for index, value in enumerate(rows):
    row = require_object(value, f"fixture_rows[{index}]")
    ctx = f"fixture_rows[{index}]"
    for required in REQUIRED_FIXTURE_FIELDS:
        if required not in row:
            fail("missing_field", f"{ctx}.{required}: missing")

    fixture_id = require_string(row, "fixture_id", ctx)
    scenario_kind = require_string(row, "scenario_kind", ctx)
    operation = require_string(row, "operation", ctx)
    symbols = require_array(row, "symbols", ctx)
    buffering_mode = require_string(row, "buffering_mode", ctx)
    orientation = require_string(row, "orientation", ctx)
    require_string(row, "file_kind", ctx)
    initial_contents = require_array(row, "initial_contents", ctx, allow_empty=True)
    expected = require_object(row.get("expected"), f"{ctx}.expected")
    runtime_mode = require_string(row, "runtime_mode", ctx)
    replacement_level = require_string(row, "replacement_level", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    allowed_divergence = require_string(row, "allowed_divergence", ctx)
    source_case_refs = require_array(row, "source_case_refs", ctx)
    state_transition = require_object(row.get("state_transition"), f"{ctx}.state_transition")
    cleanup = require_object(row.get("cleanup"), f"{ctx}.cleanup")

    for required in REQUIRED_EXPECTED_FIELDS:
        if required not in expected:
            fail("missing_field", f"{ctx}.expected.{required}: missing")

    status = require_string(expected, "status", f"{ctx}.expected")
    errno = require_string(expected, "errno", f"{ctx}.expected")
    require_string(expected, "text", f"{ctx}.expected")
    require_string(expected, "user_diagnostic", f"{ctx}.expected")
    require_array(expected, "bytes", f"{ctx}.expected", allow_empty=True)
    feof = require_bool(expected, "feof", f"{ctx}.expected")
    ferror = require_bool(expected, "ferror", f"{ctx}.expected")

    for byte in initial_contents:
        if not isinstance(byte, int) or byte < 0 or byte > 255:
            fail("missing_field", f"{ctx}.initial_contents entries must be bytes")
    for symbol in symbols:
        if not isinstance(symbol, str) or not symbol:
            fail("missing_field", f"{ctx}.symbols entries must be non-empty strings")
        elif symbol not in support_symbols and symbol not in phase_symbols:
            fail("missing_source_artifact", f"{ctx}.symbol {symbol!r} missing from support/phase surfaces")

    transition_label = require_string(state_transition, "label", f"{ctx}.state_transition")
    require_string(state_transition, "from", f"{ctx}.state_transition")
    require_string(state_transition, "to", f"{ctx}.state_transition")
    cleanup_required = require_bool(cleanup, "required", f"{ctx}.cleanup")
    cleanup_kind = require_string(cleanup, "kind", f"{ctx}.cleanup")

    direct_ok, direct_refs = validate_runner(row, "direct_runner", ctx, "direct")
    isolated_ok, isolated_refs = validate_runner(row, "isolated_runner", ctx, "isolated")
    if direct_ok:
        direct_runner_count += 1
    if isolated_ok:
        isolated_runner_count += 1

    seen_scenarios.add(scenario_kind)
    seen_runtime_modes.add(runtime_mode)
    seen_buffering_modes.add(buffering_mode)
    seen_orientations.add(orientation)
    if status in BLOCKED_STATUSES:
        blocked_or_deferred_count += 1
    if cleanup_required:
        cleanup_required_count += 1

    if scenario_kind not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_case", f"{ctx}.scenario_kind {scenario_kind!r} is not required")
    if buffering_mode not in REQUIRED_BUFFERING_MODES:
        fail("missing_fixture_case", f"{ctx}.buffering_mode {buffering_mode!r} is not required")
    if orientation not in REQUIRED_ORIENTATIONS:
        fail("missing_fixture_case", f"{ctx}.orientation {orientation!r} is not required")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_case", f"{ctx}.runtime_mode {runtime_mode!r} is not required")
    if replacement_level not in {"L0", "L1", "L2", "L3"}:
        fail("missing_field", f"{ctx}.replacement_level {replacement_level!r} is invalid")
    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind {oracle_kind!r} is not declared")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence {allowed_divergence!r} is not declared")
    if transition_label not in REQUIRED_STATE_TRANSITIONS:
        fail("state_contract_mismatch", f"{ctx}.state_transition.label {transition_label!r} is invalid")

    for source_ref in source_case_refs:
        if not isinstance(source_ref, str) or not source_ref:
            fail("missing_field", f"{ctx}.source_case_refs entries must be non-empty strings")
            continue
        if source_ref.startswith("test:"):
            anchor = source_ref.split(":", 1)[1]
            if anchor not in test_anchors:
                fail("missing_source_artifact", f"{ctx}.source test anchor {anchor!r} missing")
        elif source_ref.startswith("stdio_phase_strategy:"):
            symbol = source_ref.split(":", 1)[1]
            if symbol not in phase_symbols and symbol not in support_symbols:
                fail("missing_source_artifact", f"{ctx}.phase symbol {symbol!r} missing")
        elif source_ref not in stdio_fixture_names:
            fail("missing_source_artifact", f"{ctx}.stdio fixture case {source_ref!r} missing")

    if scenario_kind == "eof_state" and (transition_label != "Open->Eof" or not feof or ferror):
        fail("state_contract_mismatch", f"{ctx}.eof_state must set EOF without ferror")
    if scenario_kind == "error_state" and (transition_label != "Open->Err" or not ferror):
        fail("state_contract_mismatch", f"{ctx}.error_state must set error-state semantics")
    if scenario_kind == "wide_io_orientation":
        if transition_label != "Undecided->Wide" or orientation != "wide":
            fail("state_contract_mismatch", f"{ctx}.wide row must transition Undecided->Wide")
        if status not in BLOCKED_STATUSES or allowed_divergence != "proof_gap":
            fail("unsupported_surface_overclaim", f"{ctx}.wide row must remain blocked until direct wide fixture")
    if scenario_kind in {"memory_stream", "cookie_stream"}:
        if not cleanup_required:
            fail("cleanup_contract", f"{ctx}.{scenario_kind} must require cleanup")
        if status == "pass" and not any(str(ref).startswith("test:") for ref in source_case_refs):
            fail("unsupported_surface_overclaim", f"{ctx}.{scenario_kind} pass row must cite direct tests")
    if scenario_kind == "locking" and cleanup_kind != "unlock_and_close_stream":
        fail("cleanup_contract", f"{ctx}.locking must require unlock_and_close_stream")
    if status == "pass" and cleanup_kind == "none":
        fail("cleanup_contract", f"{ctx}.passing rows cannot omit cleanup")

    artifact_refs = sorted(
        {
            rel(manifest_path),
            *direct_refs,
            *isolated_refs,
        }
    )
    logs.append(
        {
            "trace_id": f"{BEAD_ID}::{fixture_id}::{runtime_mode}",
            "bead_id": BEAD_ID,
            "fixture_id": fixture_id,
            "operation": operation,
            "buffering_mode": buffering_mode,
            "orientation": orientation,
            "runtime_mode": runtime_mode,
            "oracle_kind": oracle_kind,
            "expected": expected,
            "actual": expected,
            "errno": errno,
            "artifact_refs": artifact_refs,
            "source_commit": source_commit,
            "target_dir": target_dir,
            "failure_signature": "ok",
        }
    )

missing_scenarios = sorted(REQUIRED_SCENARIO_KINDS - seen_scenarios)
if missing_scenarios:
    fail("missing_fixture_case", f"fixture_rows missing scenarios {missing_scenarios}")
if seen_runtime_modes != REQUIRED_RUNTIME_MODES:
    fail("missing_fixture_case", f"runtime mode coverage must be {sorted(REQUIRED_RUNTIME_MODES)}")
if not REQUIRED_BUFFERING_MODES.issubset(seen_buffering_modes):
    fail("missing_fixture_case", "fixture_rows missing required buffering modes")
if not REQUIRED_ORIENTATIONS.issubset(seen_orientations):
    fail("missing_fixture_case", "fixture_rows missing required orientations")

summary = {
    "fixture_count": len(rows),
    "required_scenario_kind_count": len(seen_scenarios & REQUIRED_SCENARIO_KINDS),
    "runtime_mode_count": len(seen_runtime_modes & REQUIRED_RUNTIME_MODES),
    "buffering_mode_count": len(seen_buffering_modes & REQUIRED_BUFFERING_MODES),
    "orientation_count": len(seen_orientations & REQUIRED_ORIENTATIONS),
    "blocked_or_deferred_count": blocked_or_deferred_count,
    "cleanup_required_count": cleanup_required_count,
    "direct_runner_count": direct_runner_count,
    "isolated_runner_count": isolated_runner_count,
}
manifest_summary = require_object(manifest.get("summary"), "summary")
for key, value in summary.items():
    if manifest_summary.get(key) != value:
        fail("stale_artifact", f"summary.{key} must be {value}, got {manifest_summary.get(key)}")

if errors:
    for signature, message in errors:
        logs.append(
            {
                "trace_id": f"{BEAD_ID}::diagnostic::{signature}",
                "bead_id": BEAD_ID,
                "fixture_id": "manifest",
                "operation": "diagnostic",
                "buffering_mode": "n/a",
                "orientation": "n/a",
                "runtime_mode": "n/a",
                "oracle_kind": "n/a",
                "expected": {},
                "actual": {"message": message},
                "errno": "n/a",
                "artifact_refs": [rel(manifest_path)],
                "source_commit": source_commit,
                "target_dir": target_dir,
                "failure_signature": signature,
            }
        )

log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in logs),
    encoding="utf-8",
)

report = {
    "schema_version": "v1",
    "bead_id": BEAD_ID,
    "gate_id": GATE_ID,
    "status": "fail" if errors else "pass",
    "generated_at_utc": now(),
    "summary": summary,
    "artifacts": [
        rel(manifest_path),
        rel(report_path),
        rel(log_path),
        "tests/conformance/fixtures/stdio_file_ops.json",
        "tests/conformance/stdio_phase_strategy.v1.json",
        "tests/conformance/stdio_invariants.v1.json",
        "tests/conformance/oracle_precedence_divergence.v1.json",
        "support_matrix.json",
    ],
    "errors": [
        {"failure_signature": signature, "message": message}
        for signature, message in errors
    ],
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(1 if errors else 0)
PY
