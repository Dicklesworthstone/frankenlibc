#!/usr/bin/env bash
# check_math_fenv_softfp_fixture_pack.sh -- bd-bp8fl.5.7 math/fenv gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_MANIFEST:-${ROOT}/tests/conformance/math_fenv_softfp_fixture_pack.v1.json}"
OUT_DIR="${FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_REPORT:-${OUT_DIR}/math_fenv_softfp_fixture_pack.report.json}"
LOG="${FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_LOG:-${OUT_DIR}/math_fenv_softfp_fixture_pack.log.jsonl}"
TARGET_DIR="${FLC_MATH_FENV_SOFTFP_FIXTURE_PACK_TARGET_DIR:-${OUT_DIR}}"
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

BEAD_ID = "bd-bp8fl.5.7"
GATE_ID = "math-fenv-softfp-fixture-pack-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "function",
    "input_class",
    "rounding_mode",
    "expected_class",
    "actual_class",
    "errno",
    "fenv_flags",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_FIXTURE_FIELDS = [
    "fixture_id",
    "scenario_kind",
    "function",
    "symbols",
    "input_class",
    "inputs",
    "rounding_mode",
    "initial_fenv",
    "expected",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "allowed_divergence",
    "source_case_refs",
    "tolerance",
    "fenv_restoration",
    "direct_runner",
    "isolated_runner",
]
REQUIRED_EXPECTED_FIELDS = [
    "value_class",
    "errno",
    "fenv_flags",
    "status",
    "user_diagnostic",
]
REQUIRED_TOLERANCE_FIELDS = ["kind", "abs", "ulp", "nan_payload_policy"]
REQUIRED_RUNNER_FIELDS = ["runner_kind", "command", "artifact_refs"]
REQUIRED_SCENARIO_KINDS = {
    "domain_error",
    "range_error",
    "divide_by_zero",
    "overflow",
    "underflow",
    "inexact",
    "rounding_mode_sensitivity",
    "nan_propagation",
    "infinity_behavior",
    "subnormal_behavior",
    "soft_fp_arch_sensitive",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_EXCEPTION_FLAGS = {
    "FE_INVALID",
    "FE_DIVBYZERO",
    "FE_OVERFLOW",
    "FE_UNDERFLOW",
    "FE_INEXACT",
}
REQUIRED_VALUE_CLASSES = {
    "quiet_nan",
    "negative_infinity",
    "positive_infinity",
    "positive_zero",
    "finite_rounded",
    "rounding_mode_set",
    "exception_flag_set",
    "positive_subnormal",
    "finite_arch_sensitive",
}
REQUIRED_ROUNDING_MODES = {
    "FE_TONEAREST",
    "FE_DOWNWARD",
    "FE_UPWARD",
    "FE_TOWARDZERO",
}
TOLERANCE_KINDS = {"exact", "relative", "ulp", "nan_payload", "flag_only", "deferred"}
BLOCKED_STATUSES = {"blocked_claim", "deferred_claim"}
SIGNATURE_PRIORITY = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_case",
    "fenv_flag_mismatch",
    "rounding_mode_mismatch",
    "tolerance_policy_mismatch",
    "nan_classification_mismatch",
    "soft_fp_overclaim",
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
    fail("missing_field", "required_log_fields must match math/fenv log contract")

fixture_schema = require_object(manifest.get("fixture_schema"), "fixture_schema")
if fixture_schema.get("required_fields") != REQUIRED_FIXTURE_FIELDS:
    fail("missing_field", "fixture_schema.required_fields must match fixture row contract")
if fixture_schema.get("expected_required_fields") != REQUIRED_EXPECTED_FIELDS:
    fail("missing_field", "fixture_schema.expected_required_fields must match expected contract")
if fixture_schema.get("tolerance_required_fields") != REQUIRED_TOLERANCE_FIELDS:
    fail("missing_field", "fixture_schema.tolerance_required_fields must match tolerance contract")
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
    "math_ops_fixture",
    "oracle_precedence_divergence",
    "hard_parts_failure_replay_gate",
    "hard_parts_e2e_catalog",
    "support_matrix",
    "math_abi_test",
    "fenv_abi_test",
    "conformance_diff_math",
    "conformance_diff_fenv",
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

math_ops = load_json(resolve(sources.get("math_ops_fixture", "")), "math_ops")
math_case_names = {
    str(row.get("name"))
    for row in math_ops.get("cases", [])
    if isinstance(row, dict) and row.get("name")
}

support_doc = load_json(resolve(sources.get("support_matrix", "")), "support_matrix")
support_symbols = {
    str(row.get("symbol"))
    for row in support_doc.get("symbols", [])
    if isinstance(row, dict) and row.get("symbol")
}

test_anchors: set[str] = set()
for source_key in ["math_abi_test", "fenv_abi_test", "conformance_diff_math", "conformance_diff_fenv"]:
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
    fail("missing_field", "required_scenario_kinds must match math/fenv coverage")
if string_set(manifest.get("required_runtime_modes"), "required_runtime_modes") != REQUIRED_RUNTIME_MODES:
    fail("missing_field", "required_runtime_modes must match math/fenv coverage")
if string_set(manifest.get("required_exception_flags"), "required_exception_flags") != REQUIRED_EXCEPTION_FLAGS:
    fail("missing_field", "required_exception_flags must match fenv coverage")
if string_set(manifest.get("required_value_classes"), "required_value_classes") != REQUIRED_VALUE_CLASSES:
    fail("missing_field", "required_value_classes must match math classification coverage")

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_case", "fixture_rows must be a non-empty array")
    rows = []

seen_scenarios: set[str] = set()
seen_runtime_modes: set[str] = set()
seen_flags: set[str] = set()
seen_value_classes: set[str] = set()
blocked_or_deferred_count = 0
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
    function = require_string(row, "function", ctx)
    symbols = require_array(row, "symbols", ctx)
    input_class = require_string(row, "input_class", ctx)
    require_object(row.get("inputs"), f"{ctx}.inputs")
    rounding_mode = require_string(row, "rounding_mode", ctx)
    initial_fenv = require_object(row.get("initial_fenv"), f"{ctx}.initial_fenv")
    expected = require_object(row.get("expected"), f"{ctx}.expected")
    runtime_mode = require_string(row, "runtime_mode", ctx)
    replacement_level = require_string(row, "replacement_level", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    allowed_divergence = require_string(row, "allowed_divergence", ctx)
    source_case_refs = require_array(row, "source_case_refs", ctx)
    tolerance = require_object(row.get("tolerance"), f"{ctx}.tolerance")
    fenv_restoration = require_object(row.get("fenv_restoration"), f"{ctx}.fenv_restoration")

    for required in REQUIRED_EXPECTED_FIELDS:
        if required not in expected:
            fail("missing_field", f"{ctx}.expected.{required}: missing")
    for required in REQUIRED_TOLERANCE_FIELDS:
        if required not in tolerance:
            fail("missing_field", f"{ctx}.tolerance.{required}: missing")

    value_class = require_string(expected, "value_class", f"{ctx}.expected")
    errno = require_string(expected, "errno", f"{ctx}.expected")
    fenv_flags = require_array(expected, "fenv_flags", f"{ctx}.expected", allow_empty=True)
    status = require_string(expected, "status", f"{ctx}.expected")
    require_string(expected, "user_diagnostic", f"{ctx}.expected")
    tolerance_kind = require_string(tolerance, "kind", f"{ctx}.tolerance")
    nan_payload_policy = require_string(tolerance, "nan_payload_policy", f"{ctx}.tolerance")
    require_bool(fenv_restoration, "requires_restore", f"{ctx}.fenv_restoration")
    require_string(fenv_restoration, "restored_by", f"{ctx}.fenv_restoration")

    direct_ok, direct_refs = validate_runner(row, "direct_runner", ctx, "direct")
    isolated_ok, isolated_refs = validate_runner(row, "isolated_runner", ctx, "isolated")
    if direct_ok:
        direct_runner_count += 1
    if isolated_ok:
        isolated_runner_count += 1

    seen_scenarios.add(scenario_kind)
    seen_runtime_modes.add(runtime_mode)
    seen_value_classes.add(value_class)
    seen_flags.update(str(flag) for flag in fenv_flags if isinstance(flag, str))
    if status in BLOCKED_STATUSES:
        blocked_or_deferred_count += 1

    if scenario_kind not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_case", f"{ctx}.scenario_kind {scenario_kind!r} is not required")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_case", f"{ctx}.runtime_mode {runtime_mode!r} is not required")
    if rounding_mode not in REQUIRED_ROUNDING_MODES:
        fail("rounding_mode_mismatch", f"{ctx}.rounding_mode {rounding_mode!r} is invalid")
    if replacement_level not in {"L0", "L1", "L2", "L3"}:
        fail("missing_field", f"{ctx}.replacement_level {replacement_level!r} is invalid")
    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind {oracle_kind!r} is not declared")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence {allowed_divergence!r} is not declared")
    if value_class not in REQUIRED_VALUE_CLASSES:
        fail("missing_fixture_case", f"{ctx}.expected.value_class {value_class!r} is not required")
    if tolerance_kind not in TOLERANCE_KINDS:
        fail("tolerance_policy_mismatch", f"{ctx}.tolerance.kind {tolerance_kind!r} is invalid")
    if tolerance_kind == "nan_payload" and nan_payload_policy == "not_applicable":
        fail("nan_classification_mismatch", f"{ctx}.nan tolerance must name payload policy")

    for symbol in symbols:
        if not isinstance(symbol, str) or not symbol:
            fail("missing_field", f"{ctx}.symbols entries must be non-empty strings")
        elif symbol not in support_symbols:
            fail("missing_source_artifact", f"{ctx}.symbol {symbol!r} missing from support_matrix")

    for flag in fenv_flags:
        if not isinstance(flag, str) or flag not in REQUIRED_EXCEPTION_FLAGS:
            fail("fenv_flag_mismatch", f"{ctx}.expected.fenv_flags includes unknown flag {flag!r}")

    for source_ref in source_case_refs:
        if not isinstance(source_ref, str) or not source_ref:
            fail("missing_field", f"{ctx}.source_case_refs entries must be non-empty strings")
            continue
        if source_ref.startswith("test:"):
            anchor = source_ref.split(":", 1)[1]
            if anchor not in test_anchors:
                fail("missing_source_artifact", f"{ctx}.source test anchor {anchor!r} missing")
        elif source_ref.startswith("symbol:"):
            symbol = source_ref.split(":", 1)[1]
            if symbol not in support_symbols:
                fail("missing_source_artifact", f"{ctx}.source symbol {symbol!r} missing")
        elif source_ref.startswith("math_ops:"):
            case_name = source_ref.split(":", 1)[1]
            if case_name not in math_case_names:
                fail("missing_source_artifact", f"{ctx}.math_ops case {case_name!r} missing")
        else:
            fail("missing_source_artifact", f"{ctx}.source ref {source_ref!r} has unknown prefix")

    flag_set = set(str(flag) for flag in fenv_flags if isinstance(flag, str))
    if scenario_kind == "domain_error" and (errno != "EDOM" or "FE_INVALID" not in flag_set or value_class != "quiet_nan"):
        fail("fenv_flag_mismatch", f"{ctx}.domain_error must declare EDOM, FE_INVALID, and quiet_nan")
    if scenario_kind == "range_error" and (errno != "ERANGE" or "FE_DIVBYZERO" not in flag_set):
        fail("fenv_flag_mismatch", f"{ctx}.range_error must declare ERANGE and FE_DIVBYZERO")
    if scenario_kind == "divide_by_zero" and ("FE_DIVBYZERO" not in flag_set or value_class != "exception_flag_set"):
        fail("fenv_flag_mismatch", f"{ctx}.divide_by_zero must declare FE_DIVBYZERO flag evidence")
    if scenario_kind == "overflow" and (errno != "ERANGE" or not {"FE_OVERFLOW", "FE_INEXACT"}.issubset(flag_set)):
        fail("fenv_flag_mismatch", f"{ctx}.overflow must declare ERANGE, FE_OVERFLOW, and FE_INEXACT")
    if scenario_kind == "underflow" and (errno != "ERANGE" or not {"FE_UNDERFLOW", "FE_INEXACT"}.issubset(flag_set)):
        fail("fenv_flag_mismatch", f"{ctx}.underflow must declare ERANGE, FE_UNDERFLOW, and FE_INEXACT")
    if scenario_kind == "inexact" and ("FE_INEXACT" not in flag_set or tolerance_kind not in {"ulp", "relative"}):
        fail("fenv_flag_mismatch", f"{ctx}.inexact must declare FE_INEXACT and numeric tolerance")
    if scenario_kind == "rounding_mode_sensitivity":
        if rounding_mode == "FE_TONEAREST" or value_class != "rounding_mode_set":
            fail("rounding_mode_mismatch", f"{ctx}.rounding row must use non-default mode and rounding_mode_set class")
    if scenario_kind == "nan_propagation":
        if value_class != "quiet_nan" or tolerance_kind != "nan_payload" or nan_payload_policy == "not_applicable":
            fail("nan_classification_mismatch", f"{ctx}.NaN row must be quiet_nan with payload policy")
    if scenario_kind == "subnormal_behavior" and value_class != "positive_subnormal":
        fail("missing_fixture_case", f"{ctx}.subnormal row must classify positive_subnormal")
    if scenario_kind == "soft_fp_arch_sensitive":
        if status not in BLOCKED_STATUSES or allowed_divergence != "proof_gap" or tolerance_kind != "deferred":
            fail("soft_fp_overclaim", f"{ctx}.soft-fp row must remain blocked/deferred with proof_gap")

    artifact_refs = sorted({rel(manifest_path), *direct_refs, *isolated_refs})
    logs.append(
        {
            "trace_id": f"{BEAD_ID}::{fixture_id}::{runtime_mode}",
            "bead_id": BEAD_ID,
            "fixture_id": fixture_id,
            "function": function,
            "input_class": input_class,
            "rounding_mode": rounding_mode,
            "expected_class": value_class,
            "actual_class": value_class,
            "errno": errno,
            "fenv_flags": fenv_flags,
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
if not REQUIRED_EXCEPTION_FLAGS.issubset(seen_flags):
    fail("missing_fixture_case", f"exception flag coverage missing {sorted(REQUIRED_EXCEPTION_FLAGS - seen_flags)}")
if not REQUIRED_VALUE_CLASSES.issubset(seen_value_classes):
    fail("missing_fixture_case", f"value class coverage missing {sorted(REQUIRED_VALUE_CLASSES - seen_value_classes)}")

summary = {
    "fixture_count": len(rows),
    "required_scenario_kind_count": len(seen_scenarios & REQUIRED_SCENARIO_KINDS),
    "runtime_mode_count": len(seen_runtime_modes & REQUIRED_RUNTIME_MODES),
    "exception_flag_count": len(seen_flags & REQUIRED_EXCEPTION_FLAGS),
    "value_class_count": len(seen_value_classes & REQUIRED_VALUE_CLASSES),
    "blocked_or_deferred_count": blocked_or_deferred_count,
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
                "function": "diagnostic",
                "input_class": "n/a",
                "rounding_mode": "n/a",
                "expected_class": "n/a",
                "actual_class": "n/a",
                "errno": "n/a",
                "fenv_flags": [],
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
        "tests/conformance/fixtures/math_ops.json",
        "tests/conformance/oracle_precedence_divergence.v1.json",
        "support_matrix.json",
        "crates/frankenlibc-abi/tests/math_abi_test.rs",
        "crates/frankenlibc-abi/tests/fenv_abi_test.rs",
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
