#!/usr/bin/env bash
# check_tsm_logging_completion_contract.sh - bd-32e.7.1 completion-debt evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_TSM_LOGGING_CONTRACT:-${ROOT}/tests/conformance/tsm_logging_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_TSM_LOGGING_REPORT:-${ROOT}/target/conformance/tsm_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_TSM_LOGGING_LOG:-${ROOT}/target/conformance/tsm_logging_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import stat
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

EXPECTED_SCHEMA = "tsm_logging_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "tsm_logging_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-32e.7"
COMPLETION_BEAD = "bd-32e.7.1"
PASS_EVENT = "tsm_logging_completion_contract_validated"
FAIL_EVENT = "tsm_logging_completion_contract_failed"
REQUIRED_SECTIONS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
REQUIRED_CONTROLS = {
    "set_validation_logging_enabled",
    "clear_validation_logs",
    "export_validation_log_jsonl",
}
REQUIRED_STRUCTS = {
    "ValidationLogRow",
    "ValidationLogInputs",
    "ValidationTraceContext",
}
REQUIRED_RUNTIME_EVENTS = {
    "validation_stage",
    "validation_transition",
    "validation_order_rewrite",
    "validation_budget_overrun",
}
REQUIRED_CHECKER_EVENTS = {PASS_EVENT, FAIL_EVENT}
REQUIRED_LEVELS = {"trace", "debug", "info", "warn", "error"}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "span_id",
    "parent_span_id",
    "decision_id",
    "schema_version",
    "level",
    "event",
    "controller_id",
    "decision_path",
    "decision_action",
    "outcome",
    "mode",
    "api_family",
    "symbol",
    "stage",
    "security_context",
    "capability_scope",
    "security_verdict",
    "latency_ns",
    "policy_id",
    "risk_upper_bound_ppm",
    "evidence_seqno",
    "stage_inputs",
    "artifact_refs",
}
REQUIRED_STAGE_INPUT_FIELDS = {
    "aligned",
    "recent_page",
    "bloom_negative",
    "cache_hit",
}
REQUIRED_SECURITY_VERDICTS = {"allow", "deny"}
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_items_bound",
    "test_refs",
    "required_runtime_events",
    "required_checker_events",
    "required_levels",
    "required_log_fields",
    "required_stage_input_fields",
    "required_security_verdicts",
    "artifact_refs",
    "failure_signature",
}


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path, errors):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append("contract root must be an object")
        return {}
    return value


def string_set(value, label, errors, allow_empty=False):
    if not isinstance(value, list) or (not value and not allow_empty):
        errors.append(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return set()
    result = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            errors.append(f"{label}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_source(path_text, source_name, errors):
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"source_artifacts.{source_name} missing")
        return ""
    path = root / path_text
    if not path.is_file():
        errors.append(f"source_artifacts.{source_name} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"source_artifacts.{source_name} unreadable: {path_text}: {exc}")
        return ""


def file_line_ref_exists(ref, errors):
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"invalid file-line ref: {ref!r}")
        return
    path_text, line_text = ref.rsplit(":", 1)
    try:
        line_no = int(line_text)
    except ValueError:
        errors.append(f"invalid file-line ref line: {ref}")
        return
    path = root / path_text
    if line_no <= 0 or not path.is_file():
        errors.append(f"file-line ref missing path or positive line: {ref}")
        return
    line_count = len(path.read_text(encoding="utf-8").splitlines())
    if line_no > line_count:
        errors.append(f"file-line ref outside file: {ref}")


def function_exists(source_text, name):
    return f"fn {name}" in source_text


def has_executable_bit(path):
    try:
        return bool(path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
    except OSError:
        return False


errors = []
contract = load_json(contract_path, errors)

if contract.get("schema_version") != EXPECTED_SCHEMA:
    errors.append("schema_version drifted")
if contract.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD}")

audit = contract.get("audit_reference")
if not isinstance(audit, dict):
    errors.append("audit_reference must be an object")
    audit = {}
if audit.get("score_threshold", 0) < 800:
    errors.append("audit_reference.score_threshold must be >= 800")

source_artifacts = contract.get("source_artifacts")
if not isinstance(source_artifacts, dict):
    errors.append("source_artifacts must be an object")
    source_artifacts = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in source_artifacts.items()
}
ptr_text = source_texts.get("ptr_validator", "")
stage_contract_text = source_texts.get("validation_stage_contract", "")

for ref in contract.get("implementation_refs", []):
    file_line_ref_exists(ref, errors)

gate_path = root / "scripts/check_tsm_logging_completion_contract.sh"
if not gate_path.is_file():
    errors.append("gate script missing")
elif not has_executable_bit(gate_path):
    errors.append("gate script must be executable")

logging = contract.get("logging_contract")
if not isinstance(logging, dict):
    errors.append("logging_contract must be an object")
    logging = {}

controls = string_set(logging.get("required_public_controls"), "logging_contract.required_public_controls", errors)
missing_controls = sorted(REQUIRED_CONTROLS - controls)
if missing_controls:
    errors.append(f"logging_contract.required_public_controls missing {','.join(missing_controls)}")
for control in sorted(REQUIRED_CONTROLS):
    if f"fn {control}" not in ptr_text and f"pub fn {control}" not in ptr_text:
        errors.append(f"ptr_validator source missing logging control {control}")

structs = string_set(logging.get("required_structs"), "logging_contract.required_structs", errors)
missing_structs = sorted(REQUIRED_STRUCTS - structs)
if missing_structs:
    errors.append(f"logging_contract.required_structs missing {','.join(missing_structs)}")
for struct_name in sorted(REQUIRED_STRUCTS):
    if f"struct {struct_name}" not in ptr_text:
        errors.append(f"ptr_validator source missing struct {struct_name}")

runtime_events = string_set(logging.get("required_runtime_events"), "logging_contract.required_runtime_events", errors)
missing_runtime_events = sorted(REQUIRED_RUNTIME_EVENTS - runtime_events)
if missing_runtime_events:
    errors.append(f"logging_contract.required_runtime_events missing {','.join(missing_runtime_events)}")
for event in sorted(REQUIRED_RUNTIME_EVENTS):
    if f'"{event}"' not in ptr_text:
        errors.append(f"ptr_validator source missing runtime event {event}")

checker_events = string_set(logging.get("required_checker_events"), "logging_contract.required_checker_events", errors)
missing_checker_events = sorted(REQUIRED_CHECKER_EVENTS - checker_events)
if missing_checker_events:
    errors.append(f"logging_contract.required_checker_events missing {','.join(missing_checker_events)}")

levels = string_set(logging.get("required_levels"), "logging_contract.required_levels", errors)
missing_levels = sorted(REQUIRED_LEVELS - levels)
if missing_levels:
    errors.append(f"logging_contract.required_levels missing {','.join(missing_levels)}")
for level in sorted(REQUIRED_LEVELS):
    if f'"{level}"' not in ptr_text:
        errors.append(f"ptr_validator source missing log level {level}")

log_fields = string_set(logging.get("required_log_fields"), "logging_contract.required_log_fields", errors)
missing_log_fields = sorted(REQUIRED_LOG_FIELDS - log_fields)
if missing_log_fields:
    errors.append(f"logging_contract.required_log_fields missing {','.join(missing_log_fields)}")
for field in sorted(REQUIRED_LOG_FIELDS):
    if f"{field}:" not in ptr_text:
        errors.append(f"ValidationLogRow source missing field {field}")

stage_input_fields = string_set(
    logging.get("required_stage_input_fields"),
    "logging_contract.required_stage_input_fields",
    errors,
)
missing_stage_input_fields = sorted(REQUIRED_STAGE_INPUT_FIELDS - stage_input_fields)
if missing_stage_input_fields:
    errors.append(
        f"logging_contract.required_stage_input_fields missing {','.join(missing_stage_input_fields)}"
    )
for field in sorted(REQUIRED_STAGE_INPUT_FIELDS):
    if f"{field}:" not in ptr_text:
        errors.append(f"ValidationLogInputs source missing field {field}")

security_verdicts = string_set(
    logging.get("required_security_verdicts"),
    "logging_contract.required_security_verdicts",
    errors,
)
missing_security_verdicts = sorted(REQUIRED_SECURITY_VERDICTS - security_verdicts)
if missing_security_verdicts:
    errors.append(
        f"logging_contract.required_security_verdicts missing {','.join(missing_security_verdicts)}"
    )
for verdict in sorted(REQUIRED_SECURITY_VERDICTS):
    if f'"{verdict}"' not in ptr_text:
        errors.append(f"ptr_validator source missing security verdict {verdict}")

bounded = logging.get("bounded_cardinality")
if not isinstance(bounded, dict):
    errors.append("logging_contract.bounded_cardinality must be an object")
    bounded = {}
if bounded.get("log_capacity") != 2048:
    errors.append("bounded_cardinality.log_capacity must be 2048")
if bounded.get("max_level_label_cardinality") != 5:
    errors.append("bounded_cardinality.max_level_label_cardinality must be 5")
if bounded.get("max_stage_label_cardinality") != 16:
    errors.append("bounded_cardinality.max_stage_label_cardinality must be 16")
for needle in [
    "VALIDATION_LOG_CAPACITY: usize = 2048",
    "MAX_LEVEL_LABEL_CARDINALITY: usize = 5",
    "MAX_STAGE_LABEL_CARDINALITY: usize = 16",
]:
    if needle not in ptr_text:
        errors.append(f"ptr_validator source missing bounded-cardinality needle {needle}")

if "validation_pipeline_stage_coverage_contract.v1" not in stage_contract_text:
    errors.append("validation_stage_contract source is not the stage-coverage contract")
if "validation_pipeline_stage_coverage_contract_validated" not in stage_contract_text:
    errors.append("validation_stage_contract missing pass telemetry event")

test_refs = []
missing_items_bound = []
for section, missing_item_id in REQUIRED_SECTIONS.items():
    block = contract.get(section)
    if not isinstance(block, dict):
        errors.append(f"{section} missing")
        continue
    if block.get("missing_item_id") != missing_item_id:
        errors.append(f"{section}.missing_item_id must be {missing_item_id}")
    missing_items_bound.append(missing_item_id)
    refs = block.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section}.required_test_refs missing")
        continue
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{section}.required_test_refs entry must be object")
            continue
        source_key = ref.get("source")
        name = ref.get("name")
        if not isinstance(source_key, str) or source_key not in source_texts:
            errors.append(f"{section} references undeclared source {source_key!r}")
            continue
        if not isinstance(name, str) or not function_exists(source_texts[source_key], name):
            errors.append(f"{section} references missing test {source_key}::{name}")
            continue
        test_refs.append(f"{source_key}::{name}")
    commands = block.get("required_commands", [])
    if section != "telemetry_primary" and (not isinstance(commands, list) or not commands):
        errors.append(f"{section}.required_commands missing")

telemetry = contract.get("telemetry_primary")
if not isinstance(telemetry, dict):
    errors.append("telemetry_primary missing")
    telemetry = {}
telemetry_events = string_set(telemetry.get("required_events"), "telemetry_primary.required_events", errors)
missing_telemetry_events = sorted((REQUIRED_RUNTIME_EVENTS | REQUIRED_CHECKER_EVENTS) - telemetry_events)
if missing_telemetry_events:
    errors.append(f"telemetry_primary.required_events missing {','.join(missing_telemetry_events)}")
telemetry_fields = string_set(telemetry.get("required_fields"), "telemetry_primary.required_fields", errors)
missing_telemetry_fields = sorted(REQUIRED_TELEMETRY_FIELDS - telemetry_fields)
if missing_telemetry_fields:
    errors.append(f"telemetry_primary.required_fields missing {','.join(missing_telemetry_fields)}")
if telemetry.get("default_report_path") != "target/conformance/tsm_logging_completion_contract.report.json":
    errors.append("telemetry_primary.default_report_path drifted")
if telemetry.get("default_log_path") != "target/conformance/tsm_logging_completion_contract.log.jsonl":
    errors.append("telemetry_primary.default_log_path drifted")

timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else ";".join(errors[:8])
artifact_refs = [rel(contract_path), rel(report_path), rel(log_path)]
event = PASS_EVENT if not errors else FAIL_EVENT
row = {
    "timestamp": timestamp,
    "trace_id": f"{COMPLETION_BEAD}:tsm_logging_completion",
    "event": event,
    "level": "info" if not errors else "error",
    "completion_debt_bead": COMPLETION_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": sorted(set(test_refs)),
    "required_runtime_events": sorted(runtime_events),
    "required_checker_events": sorted(checker_events),
    "required_levels": sorted(levels),
    "required_log_fields": sorted(log_fields),
    "required_stage_input_fields": sorted(stage_input_fields),
    "required_security_verdicts": sorted(security_verdicts),
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
}
report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "source_commit": source_commit,
    "status": status,
    "contract": rel(contract_path),
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "missing_items_bound": sorted(set(missing_items_bound)),
    "test_refs": sorted(set(test_refs)),
    "required_runtime_events": sorted(runtime_events),
    "required_checker_events": sorted(checker_events),
    "required_levels": sorted(levels),
    "required_log_fields": sorted(log_fields),
    "required_stage_input_fields": sorted(stage_input_fields),
    "required_security_verdicts": sorted(security_verdicts),
    "errors": errors,
}

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    sys.exit(1)
PY
