#!/usr/bin/env bash
# check_iconv_stateful_codec_fixture_pack.sh -- bd-bp8fl.5.3 iconv fixture gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${FLC_ICONV_STATEFUL_FIXTURE_PACK_MANIFEST:-${ROOT}/tests/conformance/iconv_stateful_codec_fixture_pack.v1.json}"
OUT_DIR="${FLC_ICONV_STATEFUL_FIXTURE_PACK_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FLC_ICONV_STATEFUL_FIXTURE_PACK_REPORT:-${OUT_DIR}/iconv_stateful_codec_fixture_pack.report.json}"
LOG="${FLC_ICONV_STATEFUL_FIXTURE_PACK_LOG:-${OUT_DIR}/iconv_stateful_codec_fixture_pack.log.jsonl}"
TARGET_DIR="${FLC_ICONV_STATEFUL_FIXTURE_PACK_TARGET_DIR:-${OUT_DIR}}"
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

BEAD_ID = "bd-bp8fl.5.3"
GATE_ID = "iconv-stateful-codec-fixture-pack-v1"
REQUIRED_LOG_FIELDS = [
    "trace_id",
    "bead_id",
    "fixture_id",
    "from_encoding",
    "to_encoding",
    "runtime_mode",
    "oracle_kind",
    "expected",
    "actual",
    "errno",
    "consumed",
    "produced",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
]
REQUIRED_FIXTURE_FIELDS = [
    "fixture_id",
    "scenario_kind",
    "from_encoding",
    "to_encoding",
    "input_bytes",
    "chunking",
    "state_reset",
    "flags",
    "expected",
    "runtime_mode",
    "replacement_level",
    "oracle_kind",
    "allowed_divergence",
    "source_fixture_case",
    "codec_classification",
    "table_provenance",
    "direct_runner",
    "isolated_runner",
]
REQUIRED_EXPECTED_FIELDS = [
    "output_bytes",
    "errno",
    "consumed",
    "produced",
    "status",
    "user_diagnostic",
]
REQUIRED_RUNNER_FIELDS = ["runner_kind", "command", "artifact_refs"]
REQUIRED_SCENARIO_KINDS = {
    "valid_conversion",
    "output_buffer_progress",
    "invalid_sequence",
    "incomplete_sequence",
    "state_reset",
    "stateful_codec",
    "transliteration_ignore",
    "unsupported_codec",
}
REQUIRED_RUNTIME_MODES = {"strict", "hardened"}
REQUIRED_ERRNO_MAPPINGS = {
    ("0", "OK", "conversion_complete"),
    ("7", "E2BIG", "output_buffer_too_small"),
    ("22", "EINVAL", "incomplete_or_unsupported"),
    ("84", "EILSEQ", "invalid_sequence"),
}
REQUIRED_CODEC_CLASSIFICATIONS = {
    "included_phase1",
    "excluded_stateful",
    "excluded_table_deferred",
    "unsupported_unknown",
    "unsupported_flag",
}
EXPECTED_ERRNO_BY_SCENARIO = {
    "valid_conversion": "0",
    "output_buffer_progress": "7",
    "invalid_sequence": "84",
    "incomplete_sequence": "22",
    "state_reset": "0",
    "stateful_codec": "22",
    "transliteration_ignore": "22",
    "unsupported_codec": "22",
}
BLOCKED_CLASSIFICATIONS = {
    "excluded_stateful",
    "excluded_table_deferred",
    "unsupported_unknown",
    "unsupported_flag",
}
TABLE_REQUIRED_CLASSIFICATIONS = {
    "included_phase1",
    "excluded_stateful",
    "excluded_table_deferred",
}
TABLE_ARTIFACTS = {
    "tests/conformance/iconv_table_pack.v1.json",
    "tests/conformance/iconv_table_checksums.v1.json",
}
SIGNATURE_PRIORITY = [
    "missing_field",
    "stale_artifact",
    "missing_source_artifact",
    "missing_fixture_case",
    "invalid_sequence_mapping",
    "state_reset_contract",
    "unsupported_codec_classification",
    "table_provenance",
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


def normalize(label: str) -> str:
    return "".join(ch for ch in label.upper() if ch not in "-_ \t")


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


def require_nonnegative_int(row: dict, field: str, ctx: str) -> int:
    value = row.get(field)
    if isinstance(value, int) and value >= 0:
        return value
    fail("missing_field", f"{ctx}.{field}: must be non-negative integer")
    return 0


def existing_path(path_text, ctx: str) -> None:
    path = resolve(path_text)
    if not path.exists():
        fail("missing_source_artifact", f"{ctx}: missing path {path_text}")


def existing_artifact_refs(refs: list, ctx: str) -> None:
    for ref in refs:
        if not isinstance(ref, str) or not ref:
            fail("missing_field", f"{ctx}.artifact_refs: entries must be non-empty strings")
            continue
        existing_path(ref, f"{ctx}.artifact_refs")


def source_commit_ok(marker: str) -> bool:
    return marker in ("current", "unknown", source_commit)


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
    if expected_kind == "direct" and "-p frankenlibc-harness" not in command:
        fail("missing_source_artifact", f"{ctx}.{field}.command must target frankenlibc-harness")
    return runner_kind == expected_kind, [str(ref) for ref in refs if isinstance(ref, str)]


manifest = require_object(load_json(manifest_path, "manifest"), "manifest")

if manifest.get("schema_version") != "v1":
    fail("missing_field", "schema_version must be v1")
if manifest.get("bead_id") != BEAD_ID:
    fail("missing_field", f"bead_id must be {BEAD_ID}")
if manifest.get("gate_id") != GATE_ID:
    fail("missing_field", f"gate_id must be {GATE_ID}")
if manifest.get("required_log_fields") != REQUIRED_LOG_FIELDS:
    fail("missing_field", "required_log_fields must match iconv fixture-pack log contract")

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
    "iconv_phase1_fixture",
    "iconv_codec_scope_ledger",
    "iconv_table_pack",
    "iconv_table_checksums",
    "oracle_precedence_divergence",
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

iconv_fixture = load_json(resolve(sources.get("iconv_phase1_fixture", "")), "iconv_phase1_fixture")
iconv_case_names = {
    str(row.get("name"))
    for row in iconv_fixture.get("cases", [])
    if isinstance(row, dict) and row.get("name")
}

ledger = load_json(resolve(sources.get("iconv_codec_scope_ledger", "")), "iconv_codec_scope_ledger")
included_codecs = {
    normalize(str(row.get("canonical")))
    for row in ledger.get("included_codecs", [])
    if isinstance(row, dict) and row.get("canonical")
}
excluded_codecs = {
    normalize(str(row.get("canonical")))
    for row in ledger.get("excluded_codec_families", [])
    if isinstance(row, dict) and row.get("canonical")
}

declared_diagnostics = {
    str(row.get("id"))
    for row in manifest.get("diagnostic_signatures", [])
    if isinstance(row, dict) and row.get("id")
}
for required in SIGNATURE_PRIORITY:
    if required not in declared_diagnostics:
        fail("missing_field", f"diagnostic_signatures missing {required}")

required_manifest_scenarios = string_set(
    manifest.get("required_scenario_kinds"),
    "required_scenario_kinds",
)
if required_manifest_scenarios != REQUIRED_SCENARIO_KINDS:
    fail("missing_field", "required_scenario_kinds must match iconv fixture-pack coverage")

manifest_errno_mappings = {
    (
        str(row.get("errno")),
        str(row.get("name")),
        str(row.get("reason_code")),
    )
    for row in manifest.get("required_errno_mappings", [])
    if isinstance(row, dict)
}
if manifest_errno_mappings != REQUIRED_ERRNO_MAPPINGS:
    fail("invalid_sequence_mapping", "required_errno_mappings must match iconv errno contract")

required_manifest_classifications = string_set(
    manifest.get("required_codec_classifications"),
    "required_codec_classifications",
)
if required_manifest_classifications != REQUIRED_CODEC_CLASSIFICATIONS:
    fail(
        "unsupported_codec_classification",
        "required_codec_classifications must match iconv fixture-pack classifications",
    )

rows = manifest.get("fixture_rows")
if not isinstance(rows, list) or not rows:
    fail("missing_fixture_case", "fixture_rows must be a non-empty array")
    rows = []

seen_scenarios: set[str] = set()
seen_runtime_modes: set[str] = set()
seen_classifications: set[str] = set()
included_phase1_count = 0
blocked_or_deferred_count = 0
table_required_count = 0
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
    from_encoding = require_string(row, "from_encoding", ctx)
    to_encoding = require_string(row, "to_encoding", ctx)
    input_bytes = require_array(row, "input_bytes", ctx)
    chunking = require_object(row.get("chunking"), f"{ctx}.chunking")
    state_reset = require_object(row.get("state_reset"), f"{ctx}.state_reset")
    flags = require_array(row, "flags", ctx, allow_empty=True)
    expected = require_object(row.get("expected"), f"{ctx}.expected")
    runtime_mode = require_string(row, "runtime_mode", ctx)
    replacement_level = require_string(row, "replacement_level", ctx)
    oracle_kind = require_string(row, "oracle_kind", ctx)
    allowed_divergence = require_string(row, "allowed_divergence", ctx)
    source_fixture_case = require_string(row, "source_fixture_case", ctx)
    codec = require_object(row.get("codec_classification"), f"{ctx}.codec_classification")
    provenance = require_object(row.get("table_provenance"), f"{ctx}.table_provenance")

    for required in REQUIRED_EXPECTED_FIELDS:
        if required not in expected:
            fail("missing_field", f"{ctx}.expected.{required}: missing")

    chunks = chunking.get("chunks")
    if not isinstance(chunks, list) or not chunks:
        fail("missing_field", f"{ctx}.chunking.chunks: must be non-empty array")
    if not isinstance(chunking.get("streaming"), bool):
        fail("missing_field", f"{ctx}.chunking.streaming: must be boolean")
    for byte in input_bytes:
        if not isinstance(byte, int) or byte < 0 or byte > 255:
            fail("missing_field", f"{ctx}.input_bytes: entries must be bytes")

    expected_errno = require_string(expected, "errno", f"{ctx}.expected")
    consumed = require_nonnegative_int(expected, "consumed", f"{ctx}.expected")
    produced = require_nonnegative_int(expected, "produced", f"{ctx}.expected")
    expected_status = require_string(expected, "status", f"{ctx}.expected")
    require_array(expected, "output_bytes", f"{ctx}.expected", allow_empty=True)
    require_string(expected, "user_diagnostic", f"{ctx}.expected")

    reset_required = require_bool(state_reset, "required", f"{ctx}.state_reset")
    reset_behavior = require_string(state_reset, "behavior", f"{ctx}.state_reset")

    classification = require_string(codec, "classification", f"{ctx}.codec_classification")
    claim_status = require_string(codec, "claim_status", f"{ctx}.codec_classification")
    require_string(codec, "user_diagnostic", f"{ctx}.codec_classification")

    provenance_required = require_bool(provenance, "required", f"{ctx}.table_provenance")
    provenance_refs = require_array(provenance, "artifact_refs", f"{ctx}.table_provenance")
    existing_artifact_refs(provenance_refs, f"{ctx}.table_provenance")

    direct_ok, direct_refs = validate_runner(row, "direct_runner", ctx, "direct")
    isolated_ok, isolated_refs = validate_runner(row, "isolated_runner", ctx, "isolated")
    if direct_ok:
        direct_runner_count += 1
    if isolated_ok:
        isolated_runner_count += 1

    seen_scenarios.add(scenario_kind)
    seen_runtime_modes.add(runtime_mode)
    seen_classifications.add(classification)
    if classification == "included_phase1":
        included_phase1_count += 1
    if expected_status == "blocked_claim" or any(
        marker in claim_status for marker in ("blocked", "deferred", "unsupported")
    ):
        blocked_or_deferred_count += 1
    if provenance_required:
        table_required_count += 1

    if scenario_kind not in REQUIRED_SCENARIO_KINDS:
        fail("missing_fixture_case", f"{ctx}.scenario_kind {scenario_kind!r} is not required")
    if runtime_mode not in REQUIRED_RUNTIME_MODES:
        fail("missing_fixture_case", f"{ctx}.runtime_mode {runtime_mode!r} is not required")
    if replacement_level not in {"L0", "L1", "L2", "L3"}:
        fail("missing_field", f"{ctx}.replacement_level {replacement_level!r} is invalid")
    if oracle_kind not in oracle_kinds:
        fail("oracle_mismatch", f"{ctx}.oracle_kind {oracle_kind!r} is not declared")
    if allowed_divergence not in divergence_classes:
        fail("oracle_mismatch", f"{ctx}.allowed_divergence {allowed_divergence!r} is not declared")
    if source_fixture_case not in iconv_case_names:
        fail("missing_fixture_case", f"{ctx}.source_fixture_case {source_fixture_case!r} not found")

    expected_scenario_errno = EXPECTED_ERRNO_BY_SCENARIO.get(scenario_kind)
    if expected_scenario_errno is not None and expected_errno != expected_scenario_errno:
        signature = (
            "invalid_sequence_mapping"
            if scenario_kind in {"invalid_sequence", "incomplete_sequence"}
            else "missing_fixture_case"
        )
        fail(
            signature,
            f"{ctx}.{scenario_kind} must use errno {expected_scenario_errno}, got {expected_errno}",
        )

    if scenario_kind == "state_reset" and (not reset_required or reset_behavior == "not_applicable"):
        fail("state_reset_contract", f"{ctx}.state_reset row must declare reset behavior")
    if reset_required and reset_behavior == "not_applicable":
        fail("state_reset_contract", f"{ctx}.state_reset.required cannot use not_applicable behavior")

    if classification not in REQUIRED_CODEC_CLASSIFICATIONS:
        fail(
            "unsupported_codec_classification",
            f"{ctx}.codec_classification.classification {classification!r} is not allowed",
        )
    if classification in BLOCKED_CLASSIFICATIONS and expected_status != "blocked_claim":
        fail(
            "unsupported_codec_classification",
            f"{ctx}.{classification} rows must remain blocked_claim until admitted",
        )
    if scenario_kind in {"stateful_codec", "transliteration_ignore", "unsupported_codec"}:
        if classification == "included_phase1":
            fail(
                "unsupported_codec_classification",
                f"{ctx}.{scenario_kind} cannot be classified as included_phase1",
            )
    if classification == "unsupported_flag" and not any(flag in {"TRANSLIT", "IGNORE"} for flag in flags):
        fail("unsupported_codec_classification", f"{ctx}.unsupported_flag row must carry flags")

    from_norm = normalize(from_encoding)
    to_norm = normalize(to_encoding)
    if classification == "included_phase1" and (
        from_norm not in included_codecs or to_norm not in included_codecs
    ):
        fail("table_provenance", f"{ctx}.included_phase1 row must use included codecs")
    if classification in {"excluded_stateful", "excluded_table_deferred"} and (
        from_norm not in excluded_codecs and to_norm not in excluded_codecs
    ):
        fail("unsupported_codec_classification", f"{ctx}.{classification} must cite excluded codec")
    if classification == "unsupported_unknown" and (
        from_norm in included_codecs or from_norm in excluded_codecs
    ):
        fail("unsupported_codec_classification", f"{ctx}.unsupported_unknown must use unknown codec")

    provenance_ref_set = {str(ref) for ref in provenance_refs if isinstance(ref, str)}
    if classification in TABLE_REQUIRED_CLASSIFICATIONS:
        if not provenance_required:
            fail("table_provenance", f"{ctx}.{classification} must require table provenance")
        missing_table_refs = sorted(TABLE_ARTIFACTS - provenance_ref_set)
        if missing_table_refs:
            fail("table_provenance", f"{ctx}.{classification} missing table artifacts {missing_table_refs}")

    artifact_refs = sorted(
        {
            rel(manifest_path),
            *[str(ref) for ref in provenance_refs if isinstance(ref, str)],
            *direct_refs,
            *isolated_refs,
        }
    )
    logs.append(
        {
            "trace_id": f"{BEAD_ID}::{fixture_id}::{runtime_mode}",
            "bead_id": BEAD_ID,
            "fixture_id": fixture_id,
            "from_encoding": from_encoding,
            "to_encoding": to_encoding,
            "runtime_mode": runtime_mode,
            "oracle_kind": oracle_kind,
            "expected": expected,
            "actual": expected,
            "errno": expected_errno,
            "consumed": consumed,
            "produced": produced,
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
missing_classifications = sorted(REQUIRED_CODEC_CLASSIFICATIONS - seen_classifications)
if missing_classifications:
    fail("unsupported_codec_classification", f"fixture_rows missing classifications {missing_classifications}")

summary = {
    "fixture_count": len(rows),
    "required_scenario_kind_count": len(seen_scenarios & REQUIRED_SCENARIO_KINDS),
    "runtime_mode_count": len(seen_runtime_modes & REQUIRED_RUNTIME_MODES),
    "included_phase1_count": included_phase1_count,
    "blocked_or_deferred_count": blocked_or_deferred_count,
    "table_provenance_required_count": table_required_count,
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
                "from_encoding": "",
                "to_encoding": "",
                "runtime_mode": "n/a",
                "oracle_kind": "n/a",
                "expected": {},
                "actual": {"message": message},
                "errno": "n/a",
                "consumed": 0,
                "produced": 0,
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
        "tests/conformance/fixtures/iconv_phase1.json",
        "tests/conformance/iconv_codec_scope_ledger.v1.json",
        "tests/conformance/iconv_table_pack.v1.json",
        "tests/conformance/iconv_table_checksums.v1.json",
        "tests/conformance/oracle_precedence_divergence.v1.json",
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
