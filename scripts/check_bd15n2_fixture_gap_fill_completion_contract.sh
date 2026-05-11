#!/usr/bin/env bash
# check_bd15n2_fixture_gap_fill_completion_contract.sh - bd-15n.2.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_BD15N2_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/bd15n2_fixture_gap_fill_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_BD15N2_COMPLETION_REPORT:-${ROOT}/target/conformance/bd15n2_fixture_gap_fill_completion_contract.report.json}"
LOG="${FRANKENLIBC_BD15N2_COMPLETION_LOG:-${ROOT}/target/conformance/bd15n2_fixture_gap_fill_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
import hashlib
import json
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

COMPLETION_DEBT_BEAD = "bd-15n.2.1"
ORIGINAL_BEAD = "bd-15n.2"
MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
PASS_EVENT = "bd15n2_fixture_gap_fill_completion_contract_validated"
FAIL_EVENT = "bd15n2_fixture_gap_fill_completion_contract_failed"
REQUIRED_FIXTURES = {"fixture_ctype", "fixture_math", "fixture_socket"}
REQUIRED_MODES = {"strict", "hardened"}
REQUIRED_TRACE_FIELDS = {
    "timestamp",
    "trace_id",
    "level",
    "event",
    "bead_id",
    "stream",
    "gate",
    "mode",
    "fixture_id",
    "api_family",
    "symbol",
    "spec_ref",
    "outcome",
    "errno",
    "latency_ns",
    "details",
    "artifact_refs",
}
REQUIRED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_item_ids",
    "fixture_ids",
    "modes",
    "unit_refs",
    "e2e_refs",
    "artifact_refs",
    "failure_signature",
}
FORBIDDEN_COMMAND_SUBSTRINGS = ("git reset", "git clean", "rm -rf", "rm -r", "rm -f")


def rel(path):
    try:
        return Path(path).resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path, errors, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def path_from_root(path_text, errors, label):
    if not isinstance(path_text, str) or not path_text:
        errors.append(f"{label} path missing")
        return root / "__missing__"
    path = Path(path_text)
    if path.is_absolute():
        errors.append(f"{label} path must be repo-relative: {path_text}")
        return path
    full = root / path
    if not full.exists():
        errors.append(f"{label} path missing: {path_text}")
    return full


def read_source(path_text, source_name, errors):
    path = path_from_root(path_text, errors, f"test_sources.{source_name}")
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"test_sources.{source_name} unreadable: {rel(path)}: {exc}")
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


def as_string_set(values, label, errors):
    if not isinstance(values, list):
        errors.append(f"{label} must be an array")
        return set()
    actual = {value for value in values if isinstance(value, str)}
    if len(actual) != len(values):
        errors.append(f"{label} must contain only strings")
    return actual


def validate_fixture_spec(spec, errors):
    fixtures = spec.get("fixtures")
    if not isinstance(fixtures, list):
        errors.append("fixture_spec.fixtures must be an array")
        return
    by_id = {fixture.get("id"): fixture for fixture in fixtures if isinstance(fixture, dict)}
    for fixture_id in sorted(REQUIRED_FIXTURES):
        fixture = by_id.get(fixture_id)
        if not isinstance(fixture, dict):
            errors.append(f"fixture_spec missing {fixture_id}")
            continue
        traceability = fixture.get("spec_traceability")
        if not isinstance(traceability, dict):
            errors.append(f"fixture_spec.{fixture_id}.spec_traceability missing")
        else:
            for key in ("posix", "c11", "internal"):
                refs = traceability.get(key)
                if not isinstance(refs, list) or not any(isinstance(ref, str) and ref.strip() for ref in refs):
                    errors.append(f"fixture_spec.{fixture_id}.spec_traceability.{key} missing")
        expectations = fixture.get("mode_expectations")
        if not isinstance(expectations, dict):
            errors.append(f"fixture_spec.{fixture_id}.mode_expectations missing")
        else:
            for mode in sorted(REQUIRED_MODES):
                expectation = expectations.get(mode)
                if not isinstance(expectation, dict):
                    errors.append(f"fixture_spec.{fixture_id}.mode_expectations.{mode} missing")
                    continue
                if expectation.get("expected_exit") != 0:
                    errors.append(f"fixture_spec.{fixture_id}.mode_expectations.{mode}.expected_exit must be 0")
                marker = expectation.get("expected_stdout_contains")
                if not isinstance(marker, str) or not marker.strip():
                    errors.append(f"fixture_spec.{fixture_id}.mode_expectations.{mode}.expected_stdout_contains missing")


def validate_trace(trace_path, errors):
    seen_modes = set()
    seen_fixtures = set()
    result_events = 0
    try:
        lines = trace_path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        errors.append(f"gap_fill_trace unreadable: {rel(trace_path)}: {exc}")
        return seen_fixtures, seen_modes, result_events
    for number, raw in enumerate(lines, 1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"gap_fill_trace line {number} invalid JSON: {exc}")
            continue
        missing = REQUIRED_TRACE_FIELDS - set(row)
        if missing:
            errors.append(f"gap_fill_trace line {number} missing {','.join(sorted(missing))}")
        if row.get("event") != "test_result":
            continue
        result_events += 1
        if row.get("bead_id") != ORIGINAL_BEAD:
            errors.append(f"gap_fill_trace line {number} bead_id must be {ORIGINAL_BEAD}")
        mode = row.get("mode")
        fixture_id = row.get("fixture_id")
        if mode in REQUIRED_MODES:
            seen_modes.add(mode)
        else:
            errors.append(f"gap_fill_trace line {number} invalid mode {mode!r}")
        if fixture_id in REQUIRED_FIXTURES:
            seen_fixtures.add(fixture_id)
        if row.get("outcome") != "pass":
            errors.append(f"gap_fill_trace line {number} outcome must be pass")
        if not isinstance(row.get("spec_ref"), str) or not row.get("spec_ref", "").strip():
            errors.append(f"gap_fill_trace line {number} spec_ref missing")
        details = row.get("details")
        if not isinstance(details, dict) or not isinstance(details.get("expected_vs_actual"), dict):
            errors.append(f"gap_fill_trace line {number} details.expected_vs_actual missing")
    if seen_modes != REQUIRED_MODES:
        errors.append(f"gap_fill_trace modes must be strict,hardened saw {sorted(seen_modes)}")
    if seen_fixtures != REQUIRED_FIXTURES:
        errors.append(f"gap_fill_trace fixtures must be {','.join(sorted(REQUIRED_FIXTURES))} saw {sorted(seen_fixtures)}")
    if result_events < 6:
        errors.append(f"gap_fill_trace needs at least 6 test_result rows saw {result_events}")
    return seen_fixtures, seen_modes, result_events


def validate_report(report, errors):
    if report.get("schema_version") != "v1":
        errors.append("gap_fill_report.schema_version must be v1")
    if report.get("bead") != ORIGINAL_BEAD:
        errors.append(f"gap_fill_report.bead must be {ORIGINAL_BEAD}")
    summary = report.get("summary")
    if not isinstance(summary, dict):
        errors.append("gap_fill_report.summary missing")
    else:
        if int(summary.get("total_cases", 0)) < 6:
            errors.append("gap_fill_report.summary.total_cases must be >= 6")
        if int(summary.get("pass_count", 0)) < 6:
            errors.append("gap_fill_report.summary.pass_count must be >= 6")
        if int(summary.get("fail_count", 1)) != 0:
            errors.append("gap_fill_report.summary.fail_count must be 0")
    profiles = report.get("mode_profiles")
    if not isinstance(profiles, dict):
        errors.append("gap_fill_report.mode_profiles missing")
    else:
        for mode in sorted(REQUIRED_MODES):
            profile = profiles.get(mode)
            if not isinstance(profile, dict):
                errors.append(f"gap_fill_report.mode_profiles.{mode} missing")
                continue
            if int(profile.get("observed_pass", 0)) < 3:
                errors.append(f"gap_fill_report.mode_profiles.{mode}.observed_pass must be >= 3")
            if int(profile.get("observed_fail", 1)) != 0:
                errors.append(f"gap_fill_report.mode_profiles.{mode}.observed_fail must be 0")
    fixtures = report.get("fixtures")
    if not isinstance(fixtures, list):
        errors.append("gap_fill_report.fixtures missing")
    else:
        by_id = {fixture.get("id"): fixture for fixture in fixtures if isinstance(fixture, dict)}
        for fixture_id in sorted(REQUIRED_FIXTURES):
            if fixture_id not in by_id:
                errors.append(f"gap_fill_report.fixtures missing {fixture_id}")
    scenarios = report.get("scenarios")
    if not isinstance(scenarios, list):
        errors.append("gap_fill_report.scenarios missing")
    else:
        pairs = set()
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            fixture_id = scenario.get("fixture_id")
            mode = scenario.get("mode")
            if fixture_id in REQUIRED_FIXTURES and mode in REQUIRED_MODES:
                pairs.add((fixture_id, mode))
                if scenario.get("outcome") != "pass":
                    errors.append(f"gap_fill_report.scenarios {fixture_id}/{mode} outcome must be pass")
                if scenario.get("expected_exit") != 0 or scenario.get("actual_exit") != 0:
                    errors.append(f"gap_fill_report.scenarios {fixture_id}/{mode} exit mismatch")
                if scenario.get("stdout_contains_expected") != 1:
                    errors.append(f"gap_fill_report.scenarios {fixture_id}/{mode} stdout marker missing")
                refs = scenario.get("artifact_refs")
                if not isinstance(refs, list) or not refs:
                    errors.append(f"gap_fill_report.scenarios {fixture_id}/{mode} artifact_refs missing")
        expected_pairs = {(fixture, mode) for fixture in REQUIRED_FIXTURES for mode in REQUIRED_MODES}
        missing = sorted(expected_pairs - pairs)
        if missing:
            errors.append(f"gap_fill_report.scenarios missing pairs {missing}")


def validate_artifact_index(index, errors):
    if index.get("index_version") != 1:
        errors.append("gap_fill_artifact_index.index_version must be 1")
    if index.get("bead_id") != ORIGINAL_BEAD:
        errors.append(f"gap_fill_artifact_index.bead_id must be {ORIGINAL_BEAD}")
    artifacts = index.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        errors.append("gap_fill_artifact_index.artifacts missing")
        return []
    refs = []
    for item in artifacts:
        if not isinstance(item, dict):
            errors.append("gap_fill_artifact_index artifact entries must be objects")
            continue
        path_text = item.get("path")
        refs.append(path_text)
        path = path_from_root(path_text, errors, "gap_fill_artifact_index.artifacts.path")
        if not path.is_file():
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != item.get("sha256"):
            errors.append(f"gap_fill_artifact_index sha256 mismatch for {path_text}")
    for required in (
        "tests/cve_arena/results/bd-15n.2/report.json",
        "tests/cve_arena/results/bd-15n.2/trace.jsonl",
    ):
        if required not in refs:
            errors.append(f"gap_fill_artifact_index missing {required}")
    return [ref for ref in refs if isinstance(ref, str)]


def validate_refs(section_name, evidence, source_texts, errors):
    block = evidence.get(section_name)
    if not isinstance(block, dict):
        errors.append(f"{section_name} missing")
        return []
    expected_missing = "tests.unit.primary" if section_name == "unit_primary" else "tests.e2e.primary"
    if block.get("missing_item_id") != expected_missing:
        errors.append(f"{section_name}.missing_item_id must be {expected_missing}")
    refs = block.get("required_refs")
    if not isinstance(refs, list) or not refs:
        errors.append(f"{section_name}.required_refs missing")
        return []
    seen = []
    for ref in refs:
        if not isinstance(ref, dict):
            errors.append(f"{section_name}.required_refs entries must be objects")
            continue
        source_key = ref.get("source")
        if source_key not in source_texts:
            errors.append(f"{section_name}.required_refs undeclared source {source_key!r}")
            continue
        kind = ref.get("kind")
        source = source_texts[source_key]
        if kind == "rust_test":
            name = ref.get("name")
            if not isinstance(name, str) or not function_exists(source, name):
                errors.append(f"{section_name} references missing rust test {source_key}::{name}")
                continue
            seen.append(f"{source_key}::{name}")
        elif kind == "script_tokens":
            tokens = as_string_set(ref.get("required_tokens"), f"{section_name}.{source_key}.required_tokens", errors)
            for token in sorted(tokens):
                if token not in source:
                    errors.append(f"{section_name}.{source_key} missing token {token}")
            seen.append(f"{source_key}::script_tokens")
        else:
            errors.append(f"{section_name}.required_refs unknown kind {kind!r}")
    return seen


def validate_commands(commands, errors):
    if not isinstance(commands, list) or not commands:
        errors.append("validation_commands missing")
        return []
    cleaned = []
    for command in commands:
        if not isinstance(command, str):
            errors.append("validation_commands entries must be strings")
            continue
        cleaned.append(command)
        if not command.startswith("rch exec -- "):
            errors.append("validation_commands must use rch exec")
        for forbidden in FORBIDDEN_COMMAND_SUBSTRINGS:
            if forbidden in command:
                errors.append(f"validation_commands contains forbidden command {forbidden}")
    if not any("bd15n2_fixture_gap_fill_completion_contract_test" in command for command in cleaned):
        errors.append("validation_commands missing completion contract harness test")
    if not any("c_fixture_suite_test" in command for command in cleaned):
        errors.append("validation_commands missing c_fixture_suite_test unit lane")
    return cleaned


def write_outputs(status, errors, fixtures, modes, unit_refs, e2e_refs, artifact_refs):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    failure_signature = "none" if not errors else ";".join(errors[:8])
    row = {
        "timestamp": timestamp,
        "trace_id": f"{COMPLETION_DEBT_BEAD}:fixture_gap_fill_completion",
        "event": PASS_EVENT if status == "pass" else FAIL_EVENT,
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "missing_item_ids": sorted(MISSING_ITEMS),
        "fixture_ids": sorted(fixtures),
        "modes": sorted(modes),
        "unit_refs": sorted(unit_refs),
        "e2e_refs": sorted(e2e_refs),
        "artifact_refs": artifact_refs,
        "failure_signature": failure_signature,
    }
    report = {
        "schema_version": "bd15n2_fixture_gap_fill_completion_contract.report.v1",
        "completion_debt_bead": COMPLETION_DEBT_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": source_commit,
        "status": status,
        "contract": rel(contract_path),
        "report_path": rel(report_path),
        "log_path": rel(log_path),
        "missing_item_ids": sorted(MISSING_ITEMS),
        "fixture_ids": sorted(fixtures),
        "modes": sorted(modes),
        "unit_refs": sorted(unit_refs),
        "e2e_refs": sorted(e2e_refs),
        "artifact_refs": artifact_refs,
        "errors": errors,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")


errors = []
contract = load_json(contract_path, errors, "contract")
evidence = contract.get("completion_debt_evidence")
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}

if contract.get("schema_version") != "bd15n2_fixture_gap_fill_completion_contract.v1":
    errors.append("schema_version drifted")
if contract.get("bead") != ORIGINAL_BEAD:
    errors.append(f"bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")
audit = contract.get("audit", {})
if not isinstance(audit, dict) or not MISSING_ITEMS <= set(audit.get("missing_item_ids", [])):
    errors.append("audit.missing_item_ids must include tests.unit.primary and tests.e2e.primary")
if evidence.get("bead") != COMPLETION_DEBT_BEAD:
    errors.append(f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if evidence.get("next_audit_score_threshold", 0) < 800:
    errors.append("next_audit_score_threshold must be >= 800")

fixtures_from_contract = as_string_set(evidence.get("required_fixtures"), "required_fixtures", errors)
if fixtures_from_contract != REQUIRED_FIXTURES:
    errors.append("required_fixtures must be fixture_ctype,fixture_math,fixture_socket")
modes_from_contract = as_string_set(evidence.get("required_modes"), "required_modes", errors)
if modes_from_contract != REQUIRED_MODES:
    errors.append("required_modes must be strict,hardened")
trace_fields = as_string_set(evidence.get("required_trace_fields"), "required_trace_fields", errors)
if not REQUIRED_TRACE_FIELDS <= trace_fields:
    errors.append("required_trace_fields missing required fields")

for ref in evidence.get("implementation_refs", []):
    file_line_ref_exists(ref, errors)

gate = evidence.get("gate")
if not isinstance(gate, str) or not (root / gate).is_file():
    errors.append("completion_debt_evidence.gate missing")
elif not (root / gate).stat().st_mode & 0o111:
    errors.append(f"completion_debt_evidence.gate must be executable: {gate}")

test_sources = evidence.get("test_sources", {})
if not isinstance(test_sources, dict):
    errors.append("test_sources must be an object")
    test_sources = {}
source_texts = {
    key: read_source(path, key, errors)
    for key, path in test_sources.items()
}
unit_refs = validate_refs("unit_primary", evidence, source_texts, errors)
e2e_refs = validate_refs("e2e_primary", evidence, source_texts, errors)
validation_commands = validate_commands(evidence.get("validation_commands"), errors)

artifacts = evidence.get("source_artifacts", {})
if not isinstance(artifacts, dict):
    errors.append("source_artifacts must be an object")
    artifacts = {}
fixture_spec_path = path_from_root(artifacts.get("fixture_spec"), errors, "source_artifacts.fixture_spec")
report_artifact_path = path_from_root(artifacts.get("gap_fill_report"), errors, "source_artifacts.gap_fill_report")
trace_artifact_path = path_from_root(artifacts.get("gap_fill_trace"), errors, "source_artifacts.gap_fill_trace")
index_artifact_path = path_from_root(artifacts.get("gap_fill_artifact_index"), errors, "source_artifacts.gap_fill_artifact_index")

fixture_spec = load_json(fixture_spec_path, errors, "fixture_spec")
report_artifact = load_json(report_artifact_path, errors, "gap_fill_report")
artifact_index = load_json(index_artifact_path, errors, "gap_fill_artifact_index")
validate_fixture_spec(fixture_spec, errors)
trace_fixtures, trace_modes, _ = validate_trace(trace_artifact_path, errors)
validate_report(report_artifact, errors)
indexed_refs = validate_artifact_index(artifact_index, errors)

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

artifact_refs = [
    rel(contract_path),
    rel(report_artifact_path),
    rel(trace_artifact_path),
    rel(index_artifact_path),
    rel(report_path),
    rel(log_path),
] + indexed_refs[:6]
status = "pass" if not errors else "fail"
write_outputs(status, errors, trace_fixtures or fixtures_from_contract, trace_modes or modes_from_contract, unit_refs, e2e_refs, artifact_refs)

print(f"STATUS={status}")
print(f"ERROR_COUNT={len(errors)}")
print(f"REPORT={rel(report_path)}")
print(f"LOG={rel(log_path)}")
print(f"VALIDATION_COMMANDS={len(validation_commands)}")
for error in errors:
    print(f"ERROR: {error}")
if errors:
    sys.exit(1)
print(f"bd15n2_fixture_gap_fill_completion_contract: PASS fixtures={len(trace_fixtures)} modes={len(trace_modes)}")
PY
