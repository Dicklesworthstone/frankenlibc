#!/usr/bin/env bash
# check_verification_matrix_completion_contract.sh - bd-id3.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_CONTRACT:-$ROOT/tests/conformance/verification_matrix_completion_contract.v1.json}"
MATRIX="${FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_MATRIX:-$ROOT/tests/conformance/verification_matrix.json}"
BEADS="${FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_BEADS:-$ROOT/.beads/issues.jsonl}"
REPORT="${FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_REPORT:-$ROOT/target/conformance/verification_matrix_completion_contract.report.json}"
LOG="${FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_LOG:-$ROOT/target/conformance/verification_matrix_completion_contract.log.jsonl}"
GATE_TRANSCRIPT="${FRANKENLIBC_VERIFICATION_MATRIX_COMPLETION_GATE_TRANSCRIPT:-$ROOT/target/conformance/verification_matrix_completion_contract.gate.txt}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$GATE_TRANSCRIPT")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
MATRIX="$MATRIX" \
BEADS="$BEADS" \
REPORT="$REPORT" \
LOG="$LOG" \
GATE_TRANSCRIPT="$GATE_TRANSCRIPT" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from collections import Counter, defaultdict
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
MATRIX = pathlib.Path(os.environ["MATRIX"])
BEADS = pathlib.Path(os.environ["BEADS"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])
GATE_TRANSCRIPT = pathlib.Path(os.environ["GATE_TRANSCRIPT"])

COMPLETION_BEAD = "bd-id3.1"
ORIGINAL_BEAD = "bd-id3"
EXPECTED_SCHEMA = "verification_matrix_completion_contract.v1"
EXPECTED_MANIFEST = "bd-id3.1-verification-matrix-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_PASS_EVENTS = {
    "verification_matrix_completion_contract_validated",
    "verification_matrix_summary",
    "verification_matrix_gate_replayed",
    "verification_matrix_dashboard_validated",
    "verification_matrix_rows_validated",
}
EXPECTED_EVENTS = EXPECTED_PASS_EVENTS | {
    "verification_matrix_completion_contract_failed",
}
EXPECTED_TELEMETRY_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "level",
    "bead_id",
    "completion_debt_bead",
    "original_bead",
    "status",
    "source_commit",
    "missing_items_bound",
    "test_refs",
    "matrix_summary",
    "verification_gate_transcript",
    "artifact_refs",
    "failure_signature",
}
EXPECTED_FUZZ_TARGETS = {
    "completion_debt_evidence.required_top_level_keys",
    "completion_debt_evidence.required_row_template_fields",
    "completion_debt_evidence.required_stream_examples",
    "completion_debt_evidence.telemetry_primary.required_fields",
    "verification_matrix.dashboard.by_stream",
    "verification_matrix.entries.row.artifact_paths",
}

errors: list[str] = []


def err(message: str) -> None:
    errors.append(message)


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        err(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        err(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        return "unknown"


def as_string_list(value: Any, context: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.append(item)
    return result


def validate_file_line_ref(value: Any, context: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        err(f"{context} must be a file:line string")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        err(f"{context} must be a file:line string")
        return
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        err(f"{context} references line past EOF: {value}")
    elif not lines[line_number - 1].strip():
        err(f"{context} references a blank line: {value}")


def source_texts(test_sources: Any) -> dict[str, str]:
    texts: dict[str, str] = {}
    if not isinstance(test_sources, dict) or not test_sources:
        err("completion_debt_evidence.test_sources must be a non-empty object")
        return texts
    for key, path_text in test_sources.items():
        if not isinstance(key, str) or not key:
            err("test_sources keys must be non-empty strings")
            continue
        if not isinstance(path_text, str) or not path_text:
            err(f"test_sources.{key} must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            err(f"test_sources.{key} references missing file: {path_text}")
            continue
        texts[key] = path.read_text(encoding="utf-8")
    return texts


def function_exists(source_text: str, name: str) -> bool:
    return f"fn {name}" in source_text or f"def {name}" in source_text


def validate_test_refs(section: dict[str, Any], section_name: str, texts: dict[str, str]) -> list[dict[str, str]]:
    refs = section.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"completion_debt_evidence.{section_name}.required_test_refs must be non-empty")
        return []
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not source:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].source must be non-empty")
            continue
        if not isinstance(name, str) or not name:
            err(f"completion_debt_evidence.{section_name}.required_test_refs[{index}].name must be non-empty")
            continue
        key = (source, name)
        if key in seen:
            err(f"completion_debt_evidence.{section_name} duplicates test ref {source}::{name}")
        seen.add(key)
        text = texts.get(source, "")
        if not text:
            err(f"completion_debt_evidence.{section_name} references unknown source {source}")
        elif not function_exists(text, name):
            err(f"completion_debt_evidence.{section_name} references missing test {source}::{name}")
        normalized.append({"source": source, "name": name})
    return normalized


def validate_required_commands(section: dict[str, Any], section_name: str) -> None:
    commands = as_string_list(section.get("required_commands"), f"completion_debt_evidence.{section_name}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec --" not in command:
            err(f"completion_debt_evidence.{section_name}.required_commands must route cargo through rch: {command}")


def run_verification_gate() -> None:
    result = subprocess.run(
        ["bash", "scripts/check_verification_matrix.sh"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    transcript = result.stdout
    if result.stderr:
        transcript += "\n[stderr]\n" + result.stderr
    GATE_TRANSCRIPT.write_text(transcript, encoding="utf-8")
    if result.returncode != 0:
        err(f"verification matrix gate failed: exit={result.returncode}")
    if "check_verification_matrix: PASS" not in transcript:
        err("verification matrix gate transcript missing PASS sentinel")


source_commit = git_head()
contract = load_json(CONTRACT, "completion contract")
matrix = load_json(MATRIX, "verification matrix")

if contract.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if contract.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

source_artifacts = contract.get("source_artifacts", {})
if not isinstance(source_artifacts, dict):
    err("source_artifacts must be an object")
else:
    for key in [
        "verification_matrix",
        "verification_matrix_gate",
        "verification_matrix_harness",
        "completion_gate",
        "completion_harness",
    ]:
        value = source_artifacts.get(key)
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{key} must be a non-empty string")
        elif not (ROOT / value).is_file():
            err(f"source_artifacts.{key} references missing file: {value}")

evidence = contract.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    err("completion_debt_evidence must be an object")
    evidence = {}
if evidence.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if evidence.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
if int(evidence.get("next_audit_score_threshold", 0) or 0) < 800:
    err("completion_debt_evidence.next_audit_score_threshold must be at least 800")

for index, ref in enumerate(evidence.get("implementation_refs", [])):
    validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

texts = source_texts(evidence.get("test_sources"))
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
missing_items_bound: list[str] = []
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = evidence.get(section_name, {})
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    if int(section.get("next_audit_score_threshold", 0) or 0) < 800:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be at least 800")
    validate_required_commands(section, section_name)
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    missing_items_bound.append(missing_item)

fuzz_targets = set(as_string_list(evidence.get("required_fuzz_mutation_targets"), "completion_debt_evidence.required_fuzz_mutation_targets"))
missing_fuzz_targets = sorted(EXPECTED_FUZZ_TARGETS - fuzz_targets)
if missing_fuzz_targets:
    err(f"completion_debt_evidence.required_fuzz_mutation_targets missing {missing_fuzz_targets}")

expected_top_keys = set(as_string_list(evidence.get("required_top_level_keys"), "completion_debt_evidence.required_top_level_keys"))
expected_schema_keys = set(as_string_list(evidence.get("required_schema_keys"), "completion_debt_evidence.required_schema_keys"))
expected_row_fields = set(as_string_list(evidence.get("required_row_template_fields"), "completion_debt_evidence.required_row_template_fields"))
expected_statuses = set(as_string_list(evidence.get("required_coverage_statuses"), "completion_debt_evidence.required_coverage_statuses"))
expected_obligations = set(as_string_list(evidence.get("required_obligation_types"), "completion_debt_evidence.required_obligation_types"))
expected_streams = set(as_string_list(evidence.get("required_stream_examples"), "completion_debt_evidence.required_stream_examples"))

missing_top = sorted(expected_top_keys - set(matrix))
if missing_top:
    err(f"verification matrix missing top-level keys {missing_top}")
schema = matrix.get("schema", {}) if isinstance(matrix.get("schema"), dict) else {}
missing_schema = sorted(expected_schema_keys - set(schema))
if missing_schema:
    err(f"verification matrix schema missing keys {missing_schema}")
if set(schema.get("coverage_statuses", {})) != expected_statuses:
    err("verification matrix coverage_statuses must match completion contract")
if set(schema.get("obligation_types", {})) != expected_obligations:
    err("verification matrix obligation_types must match completion contract")
row_template = schema.get("row_template", {}) if isinstance(schema.get("row_template"), dict) else {}
if set(row_template) != expected_row_fields:
    err("verification matrix row_template fields must match completion contract")

transition_targets = {
    row.get("to")
    for row in schema.get("row_status_transitions", [])
    if isinstance(row, dict) and isinstance(row.get("to"), str)
}
if transition_targets != {"missing", "partial", "complete"}:
    err("row_status_transitions must define missing, partial, complete")
for index, transition in enumerate(schema.get("row_status_transitions", [])):
    if not isinstance(transition, dict) or not transition.get("when"):
        err(f"row_status_transitions[{index}] must have a non-empty when clause")

stream_examples = schema.get("stream_examples", [])
seen_streams = {
    row.get("stream")
    for row in stream_examples
    if isinstance(row, dict) and isinstance(row.get("stream"), str)
}
missing_streams = sorted(expected_streams - seen_streams)
if missing_streams:
    err(f"stream_examples missing streams {missing_streams}")
for index, row in enumerate(stream_examples):
    if not isinstance(row, dict):
        err(f"stream_examples[{index}] must be an object")
        continue
    if set(row) != expected_row_fields:
        err(f"stream_examples[{index}] fields must match row_template")
    if row.get("status") not in {"missing", "partial", "complete"}:
        err(f"stream_examples[{index}] has invalid status")

entries = [row for row in matrix.get("entries", []) if isinstance(row, dict)]
dashboard = matrix.get("dashboard", {}) if isinstance(matrix.get("dashboard"), dict) else {}
expectations = evidence.get("minimum_expectations", {})
if not isinstance(expectations, dict):
    err("completion_debt_evidence.minimum_expectations must be an object")
    expectations = {}

if matrix.get("matrix_version") != expectations.get("matrix_version"):
    err("verification matrix_version does not match completion expectation")
if schema.get("row_schema_version") != expectations.get("row_schema_version"):
    err("verification matrix row_schema_version does not match completion expectation")
if len(entries) != int(expectations.get("entry_count", 0) or 0):
    err("verification matrix entry count does not match completion expectation")
if int(dashboard.get("total_critique_beads", 0) or 0) != len(entries):
    err("dashboard total_critique_beads must match entries length")

by_status = Counter()
by_priority = Counter()
by_stream: dict[str, Counter[str]] = defaultdict(Counter)
row_contract_errors = 0
for entry in entries:
    bead_id = entry.get("bead_id", "<missing>")
    coverage = entry.get("coverage", {})
    coverage_summary = entry.get("coverage_summary", {})
    row = entry.get("row", {})
    if not isinstance(coverage, dict) or not isinstance(coverage_summary, dict):
        err(f"{bead_id}: coverage and coverage_summary must be objects")
        continue
    required = int(coverage_summary.get("required", 0) or 0)
    complete = int(coverage_summary.get("complete", 0) or 0)
    partial = int(coverage_summary.get("partial", 0) or 0)
    missing = int(coverage_summary.get("missing", 0) or 0)
    if complete + partial + missing != required:
        err(f"{bead_id}: coverage_summary count mismatch")
    actual_required = sum(
        1
        for value in coverage.values()
        if isinstance(value, dict) and value.get("status") != "not_required"
    )
    if actual_required != required:
        err(f"{bead_id}: coverage required count mismatch")
    overall = coverage_summary.get("overall")
    if overall not in {"missing", "partial", "complete"}:
        err(f"{bead_id}: invalid coverage_summary.overall")
    else:
        by_status[str(overall)] += 1
    priority = entry.get("priority")
    if isinstance(priority, int):
        by_priority[f"P{priority}"] += 1
    if not isinstance(row, dict) or set(row) != expected_row_fields:
        row_contract_errors += 1
        err(f"{bead_id}: row fields must match row_template")
        continue
    stream = str(row.get("stream", "syscall"))
    by_stream[stream]["total"] += 1
    by_stream[stream][str(overall)] += 1
    for list_key in ["unit_cmds", "expected_assertions", "log_schema_refs", "artifact_paths"]:
        if not isinstance(row.get(list_key), list) or not row.get(list_key):
            row_contract_errors += 1
            err(f"{bead_id}: row.{list_key} must be non-empty")
    for key, value in coverage.items():
        if isinstance(value, dict) and value.get("status") not in expected_statuses:
            err(f"{bead_id}.{key}: invalid coverage status")

for status_key, expected_key in [
    ("complete", "complete_entries"),
    ("partial", "partial_entries"),
    ("missing", "missing_entries"),
]:
    if by_status.get(status_key, 0) != int(expectations.get(expected_key, 0) or 0):
        err(f"dashboard status count {status_key} does not match completion expectation")
dashboard_status = dashboard.get("by_coverage_status", {}) if isinstance(dashboard.get("by_coverage_status"), dict) else {}
for status_key, count in by_status.items():
    if int(dashboard_status.get(status_key, 0) or 0) != count:
        err(f"dashboard.by_coverage_status.{status_key} mismatch")
dashboard_priority = dashboard.get("by_priority", {}) if isinstance(dashboard.get("by_priority"), dict) else {}
if int(dashboard_priority.get("P0", {}).get("total", 0) or 0) != int(expectations.get("p0_total", 0) or 0):
    err("dashboard.by_priority.P0.total does not match completion expectation")
dashboard_stream = dashboard.get("by_stream", {}) if isinstance(dashboard.get("by_stream"), dict) else {}
for stream, counts in by_stream.items():
    dash = dashboard_stream.get(stream, {}) if isinstance(dashboard_stream.get(stream), dict) else {}
    if int(dash.get("total", 0) or 0) != counts["total"]:
        err(f"dashboard.by_stream.{stream}.total mismatch")

dashboard_obligations = dashboard.get("by_obligation_type", {}) if isinstance(dashboard.get("by_obligation_type"), dict) else {}
for obligation, expectation_key in [
    ("unit_tests", "unit_required"),
    ("e2e_scripts", "e2e_required"),
    ("structured_logs", "structured_logs_required"),
]:
    actual = int(dashboard_obligations.get(obligation, {}).get("required", 0) or 0)
    if actual != int(expectations.get(expectation_key, 0) or 0):
        err(f"dashboard.by_obligation_type.{obligation}.required does not match completion expectation")

matrix_ids = {str(row.get("bead_id")) for row in entries if isinstance(row.get("bead_id"), str)}
try:
    for line_number, line in enumerate(BEADS.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        bead = json.loads(line)
        labels = bead.get("labels", [])
        status = bead.get("status", "")
        if "critique" in labels and status in ("open", "in_progress") and bead.get("id") not in matrix_ids:
            err(f"critique bead missing from verification matrix: {bead.get('id')} (line {line_number})")
except Exception as exc:
    err(f"could not read beads JSONL: {exc}")

telemetry = evidence.get("telemetry_primary", {})
if isinstance(telemetry, dict):
    required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
    missing_events = sorted(EXPECTED_EVENTS - required_events)
    if missing_events:
        err(f"telemetry_primary.required_events missing {missing_events}")
    required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
    missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_fields)
    if missing_fields:
        err(f"telemetry_primary.required_fields missing {missing_fields}")
else:
    err("completion_debt_evidence.telemetry_primary must be an object")
    required_events = set()
    required_fields = set()

run_verification_gate()

matrix_summary = {
    "matrix_version": matrix.get("matrix_version"),
    "row_schema_version": schema.get("row_schema_version"),
    "entry_count": len(entries),
    "total_critique_beads": dashboard.get("total_critique_beads"),
    "by_coverage_status": dict(by_status),
    "by_priority": dict(by_priority),
    "by_stream_total": {key: value["total"] for key, value in by_stream.items()},
    "unit_required": dashboard_obligations.get("unit_tests", {}).get("required"),
    "e2e_required": dashboard_obligations.get("e2e_scripts", {}).get("required"),
    "structured_logs_required": dashboard_obligations.get("structured_logs", {}).get("required"),
    "row_contract_errors": row_contract_errors,
    "verification_gate_status": "pass" if "check_verification_matrix: PASS" in GATE_TRANSCRIPT.read_text(encoding="utf-8") else "fail",
}

status = "fail" if errors else "pass"


def event_payload(event: str, level: str, failure_signature: str = "none") -> dict[str, Any]:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trace_id": f"{COMPLETION_BEAD}::{event}",
        "event": event,
        "level": level,
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "status": status,
        "source_commit": source_commit,
        "missing_items_bound": missing_items_bound,
        "test_refs": test_refs_by_section,
        "matrix_summary": matrix_summary,
        "verification_gate_transcript": rel(GATE_TRANSCRIPT),
        "artifact_refs": [rel(CONTRACT), rel(MATRIX), rel(REPORT), rel(LOG), rel(GATE_TRANSCRIPT)],
        "failure_signature": failure_signature,
    }


events = [
    event_payload("verification_matrix_summary", "info"),
    event_payload("verification_matrix_gate_replayed", "info"),
    event_payload("verification_matrix_dashboard_validated", "info"),
    event_payload("verification_matrix_rows_validated", "info"),
]
if errors:
    events.append(event_payload("verification_matrix_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("verification_matrix_completion_contract_validated", "info"))

for index, event in enumerate(events):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - set(event))
    if missing:
        err(f"generated telemetry event {index} missing fields {missing}")
if not errors:
    emitted = {event["event"] for event in events}
    missing = sorted(EXPECTED_PASS_EVENTS - emitted)
    if missing:
        err(f"pass telemetry missing events {missing}")
        status = "fail"
        for event in events:
            event["status"] = status

LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

report = {
    "schema_version": "verification_matrix_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": matrix_summary,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "verification_gate_transcript": rel(GATE_TRANSCRIPT),
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "errors": errors,
    "log": rel(LOG),
    "artifact_refs": [rel(CONTRACT), rel(MATRIX), rel(REPORT), rel(LOG), rel(GATE_TRANSCRIPT)],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: verification matrix completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: verification matrix completion contract "
    f"(entries={len(entries)}, row_contract_errors={row_contract_errors}, report={rel(REPORT)})"
)
PY
