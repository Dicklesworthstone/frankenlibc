#!/usr/bin/env bash
# check_pointer_validation_adversarial_completion_contract.sh - bd-66wz.3.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_POINTER_VALIDATION_ADVERSARIAL_CONTRACT:-${ROOT}/tests/conformance/pointer_validation_adversarial_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_POINTER_VALIDATION_ADVERSARIAL_REPORT:-${ROOT}/target/conformance/pointer_validation_adversarial_completion_contract.report.json}"
LOG="${FRANKENLIBC_POINTER_VALIDATION_ADVERSARIAL_LOG:-${ROOT}/target/conformance/pointer_validation_adversarial_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

COMPLETION_DEBT_BEAD = "bd-66wz.3.1"
ORIGINAL_BEAD = "bd-66wz.3"
MISSING_ITEM_ID = "tests.unit.primary"
PASS_EVENT = "pointer_validation_adversarial_completion_contract_validated"
FAIL_EVENT = "pointer_validation_adversarial_completion_contract_failed"
EXPECTED_CASE_TOKENS = {
    "foreign_validate_unknown_unbounded": {
        "ValidationOutcome::Foreign",
        "SafetyState::Unknown",
        "alloc_base.is_none()",
        "remaining.is_none()",
        "generation.is_none()",
    },
    "foreign_free_reported": {
        "FreeResult::ForeignPointer",
    },
    "double_free_reported": {
        "FreeResult::Freed",
        "FreeResult::DoubleFree",
    },
    "uaf_cache_invalidated_after_free": {
        "lock_tls_cache_epoch_for_tests",
        "ValidationOutcome::CachedValid",
        "FreeResult::Freed",
        "!outcome.can_read()",
        "!outcome.can_write()",
    },
    "canary_corruption_free_quarantines": {
        "inject_trailing_canary_corruption",
        "FreeResult::FreedWithCanaryCorruption",
        "!outcome.can_read()",
        "!outcome.can_write()",
        "ValidationOutcome::CachedValid",
    },
    "foreign_early_exit_skips_deep_integrity": {
        "ValidationOutcome::Foreign",
        "!stages.contains(\"fingerprint\")",
        "!stages.contains(\"canary\")",
        "!stages.contains(\"bounds\")",
    },
}
REQUIRED_COMMAND_MARKERS = {
    "frankenlibc-membrane": "ptr_validator",
    "frankenlibc-harness": "pointer_validation_adversarial_completion_contract_test",
}
FORBIDDEN_COMMAND_SUBSTRINGS = (
    "git reset",
    "git clean",
    "rm -rf",
    "rm -r",
    "rm -f",
)
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_item_id",
    "adversarial_case_ids",
    "test_refs",
    "validation_commands",
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
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract unreadable: {rel(path)}: {exc}")
        return {}


def read_source(path_text, source_name, errors):
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"test_sources.{source_name} missing")
        return ""
    path = root / path_text
    if not path.is_file():
        errors.append(f"test_sources.{source_name} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"test_sources.{source_name} unreadable: {path_text}: {exc}")
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


def function_body(source_text, name):
    needle = f"fn {name}"
    start = source_text.find(needle)
    if start < 0:
        return None
    brace = source_text.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(source_text)):
        char = source_text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source_text[brace : index + 1]
    return None


def as_string_set(values, label, errors):
    if not isinstance(values, list):
        errors.append(f"{label} must be an array")
        return set()
    actual = {value for value in values if isinstance(value, str)}
    if len(actual) != len(values):
        errors.append(f"{label} must contain only strings")
    return actual


def append_event(status, errors, case_ids, test_refs, validation_commands):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    failure_signature = "none" if not errors else ";".join(errors[:8])
    row = {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD}:pointer_validation_adversarial_completion",
        "event": PASS_EVENT if status == "pass" else FAIL_EVENT,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "missing_item_id": MISSING_ITEM_ID,
        "adversarial_case_ids": sorted(case_ids),
        "test_refs": sorted(set(test_refs)),
        "validation_commands": validation_commands,
        "artifact_refs": [rel(contract_path), rel(report_path), rel(log_path)],
        "failure_signature": failure_signature,
    }
    log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")


def write_json(status, errors, case_ids, test_refs, validation_commands):
    report = {
        "schema_version": "pointer_validation_adversarial_completion_contract.report.v1",
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "contract": rel(contract_path),
        "report_path": rel(report_path),
        "log_path": rel(log_path),
        "missing_item_id": MISSING_ITEM_ID,
        "adversarial_case_ids": sorted(case_ids),
        "test_refs": sorted(set(test_refs)),
        "validation_commands": validation_commands,
        "errors": errors,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_cases(evidence, source_texts, errors):
    cases = evidence.get("adversarial_cases")
    if not isinstance(cases, list):
        errors.append("adversarial_cases must be an array")
        return set(), []
    seen = set()
    test_refs = []
    for case in cases:
        if not isinstance(case, dict):
            errors.append("adversarial_cases entries must be objects")
            continue
        case_id = case.get("id")
        if not isinstance(case_id, str):
            errors.append("adversarial_cases entry missing id")
            continue
        seen.add(case_id)
        expected_tokens = EXPECTED_CASE_TOKENS.get(case_id)
        if expected_tokens is None:
            errors.append(f"adversarial_cases contains unexpected {case_id}")
            continue
        source_key = case.get("source")
        test_name = case.get("test")
        if not isinstance(source_key, str) or source_key not in source_texts:
            errors.append(f"adversarial_cases.{case_id}.source undeclared")
            continue
        if not isinstance(test_name, str):
            errors.append(f"adversarial_cases.{case_id}.test missing")
            continue
        body = function_body(source_texts[source_key], test_name)
        if body is None:
            errors.append(f"adversarial_cases.{case_id} references missing test {source_key}::{test_name}")
            continue
        declared_tokens = as_string_set(
            case.get("required_tokens"),
            f"adversarial_cases.{case_id}.required_tokens",
            errors,
        )
        missing_declared = sorted(expected_tokens - declared_tokens)
        if missing_declared:
            errors.append(
                f"adversarial_cases.{case_id}.required_tokens missing {','.join(missing_declared)}"
            )
        for token in sorted(expected_tokens):
            if token not in body:
                errors.append(f"adversarial_cases.{case_id} body missing token {token}")
        file_line_ref_exists(case.get("implementation_ref"), errors)
        test_refs.append(f"{source_key}::{test_name}")
    missing_cases = sorted(set(EXPECTED_CASE_TOKENS) - seen)
    if missing_cases:
        errors.append(f"adversarial_cases missing {','.join(missing_cases)}")
    return seen, test_refs


def validate_unit_primary(evidence, case_ids, errors):
    block = evidence.get("unit_primary")
    if not isinstance(block, dict):
        errors.append("unit_primary missing")
        return [], []
    if block.get("missing_item_id") != MISSING_ITEM_ID:
        errors.append(f"unit_primary.missing_item_id must be {MISSING_ITEM_ID}")
    refs = block.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        errors.append("unit_primary.required_test_refs missing")
    else:
        ref_cases = set()
        for ref in refs:
            if not isinstance(ref, dict):
                errors.append("unit_primary.required_test_refs entries must be objects")
                continue
            case_id = ref.get("case_id")
            name = ref.get("name")
            source = ref.get("source")
            if case_id in ref_cases:
                errors.append(f"unit_primary.required_test_refs duplicate case_id {case_id}")
            if case_id not in EXPECTED_CASE_TOKENS:
                errors.append(f"unit_primary.required_test_refs unknown case_id {case_id!r}")
            if case_id not in case_ids:
                errors.append(f"unit_primary.required_test_refs case_id not bound by adversarial_cases {case_id!r}")
            if not isinstance(name, str) or not isinstance(source, str):
                errors.append("unit_primary.required_test_refs source/name missing")
            ref_cases.add(case_id)
        missing_refs = sorted(set(EXPECTED_CASE_TOKENS) - ref_cases)
        if missing_refs:
            errors.append(f"unit_primary.required_test_refs missing {','.join(missing_refs)}")
    commands = block.get("validation_commands")
    if not isinstance(commands, list) or not commands:
        errors.append("unit_primary.validation_commands missing")
        return refs or [], []
    validation_commands = []
    marker_hits = {key: False for key in REQUIRED_COMMAND_MARKERS}
    for command in commands:
        if not isinstance(command, str):
            errors.append("unit_primary.validation_commands entries must be strings")
            continue
        validation_commands.append(command)
        if not command.startswith("rch exec -- "):
            errors.append("unit_primary.validation_commands must use rch exec")
        for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS:
            if forbidden in command:
                errors.append(f"unit_primary.validation_commands contains forbidden command {forbidden}")
        for crate, marker in REQUIRED_COMMAND_MARKERS.items():
            if crate in command and marker in command:
                marker_hits[crate] = True
    for crate, hit in marker_hits.items():
        if not hit:
            errors.append(f"unit_primary.validation_commands missing {crate} {REQUIRED_COMMAND_MARKERS[crate]}")
    return refs or [], validation_commands


errors = []
contract = load_json(contract_path, errors)
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "pointer_validation_adversarial_completion_contract.v1":
    errors.append("schema_version drifted")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
audit = contract.get("audit", {})
if not isinstance(audit, dict) or MISSING_ITEM_ID not in audit.get("missing_item_ids", []):
    errors.append(f"audit.missing_item_ids must include {MISSING_ITEM_ID}")
if evidence.get("bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if evidence.get("next_audit_score_threshold", 0) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

for ref in evidence.get("implementation_refs", []):
    file_line_ref_exists(ref, errors)

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

case_ids, test_refs = validate_cases(evidence, source_texts, errors)
_, validation_commands = validate_unit_primary(evidence, case_ids, errors)

telemetry = evidence.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    errors.append("telemetry_contract missing")
    telemetry = {}
events = as_string_set(telemetry.get("required_events"), "telemetry_contract.required_events", errors)
if {PASS_EVENT, FAIL_EVENT} - events:
    errors.append("telemetry_contract.required_events missing required events")
fields = as_string_set(telemetry.get("required_fields"), "telemetry_contract.required_fields", errors)
missing_fields = sorted(REQUIRED_TELEMETRY_FIELDS - fields)
if missing_fields:
    errors.append(f"telemetry_contract.required_fields missing {','.join(missing_fields)}")

status = "pass" if not errors else "fail"
write_json(status, errors, case_ids, test_refs, validation_commands)
append_event(status, errors, case_ids, test_refs, validation_commands)

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
for error in errors:
    print(f"ERROR: {error}")

if errors:
    sys.exit(1)
print(f"pointer_validation_adversarial_completion_contract: PASS validated {len(case_ids)} cases")
PY
