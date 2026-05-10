#!/usr/bin/env bash
# check_feature_parity_done_audit_completion_contract.sh - bd-bp8fl.3.2.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FEATURE_PARITY_DONE_AUDIT_CONTRACT:-$ROOT/tests/conformance/feature_parity_done_audit_completion_contract.v1.json}"
LEDGER="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER:-$ROOT/tests/conformance/feature_parity_gap_ledger.v1.json}"
REPORT="${FRANKENLIBC_FEATURE_PARITY_DONE_AUDIT_REPORT:-$ROOT/target/conformance/feature_parity_done_audit_completion_contract.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_DONE_AUDIT_LOG:-$ROOT/target/conformance/feature_parity_done_audit_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" CONTRACT="$CONTRACT" LEDGER="$LEDGER" REPORT="$REPORT" LOG="$LOG" python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
LEDGER = pathlib.Path(os.environ["LEDGER"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

COMPLETION_BEAD = "bd-bp8fl.3.2.1"
ORIGINAL_BEAD = "bd-bp8fl.3.2"
EXPECTED_SCHEMA = "feature_parity_done_audit_completion_contract.v1"
EXPECTED_MANIFEST = "bd-bp8fl.3.2.1-feature-parity-done-audit-completion-contract"
EXPECTED_MISSING_ITEMS = {
    "unit_primary": "tests.unit.primary",
    "e2e_primary": "tests.e2e.primary",
    "conformance_primary": "tests.conformance.primary",
    "telemetry_primary": "telemetry.primary",
}
EXPECTED_AUDIT_FIELDS = {
    "ledger_row_id",
    "audit_status",
    "freshness_state",
    "expected",
    "actual",
    "source_commit",
    "artifact_refs",
    "failure_signature",
}
EXPECTED_TELEMETRY_EVENTS = {
    "feature_parity_done_audit_completion_contract_validated",
    "feature_parity_done_audit_completion_contract_failed",
    "feature_parity_done_evidence_summary",
    "feature_parity_invalid_done_evidence_preserved",
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
    "ledger_summary",
    "freshness_counts",
    "artifact_refs",
    "failure_signature",
}

errors: list[str] = []


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


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
            ["git", "rev-parse", "--short", "HEAD"],
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


manifest = load_json(CONTRACT, "contract")
ledger = load_json(LEDGER, "ledger")
source_commit = git_head()

if manifest.get("schema_version") != EXPECTED_SCHEMA:
    err(f"schema_version must be {EXPECTED_SCHEMA}")
if manifest.get("manifest_id") != EXPECTED_MANIFEST:
    err(f"manifest_id must be {EXPECTED_MANIFEST}")
if manifest.get("bead") != ORIGINAL_BEAD:
    err(f"bead must be {ORIGINAL_BEAD}")

source_artifacts = manifest.get("source_artifacts")
if not isinstance(source_artifacts, dict):
    err("source_artifacts must be an object")
    source_artifacts = {}
for key in [
    "ledger",
    "ledger_gate",
    "ledger_generator",
    "ledger_harness",
    "completion_gate",
    "completion_harness",
]:
    path_text = source_artifacts.get(key)
    if not isinstance(path_text, str) or not path_text:
        err(f"source_artifacts.{key} must be a non-empty string")
    elif not (ROOT / path_text).is_file():
        err(f"source_artifacts.{key} references missing file: {path_text}")

completion = manifest.get("completion_debt_evidence")
if not isinstance(completion, dict):
    err("completion_debt_evidence must be an object")
    completion = {}
if completion.get("bead") != COMPLETION_BEAD:
    err(f"completion_debt_evidence.bead must be {COMPLETION_BEAD}")
if completion.get("original_bead") != ORIGINAL_BEAD:
    err(f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
threshold = completion.get("next_audit_score_threshold")
if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
    err("completion_debt_evidence.next_audit_score_threshold must be 800..1000")

implementation_refs = completion.get("implementation_refs")
if not isinstance(implementation_refs, list) or len(implementation_refs) < 12:
    err("completion_debt_evidence.implementation_refs must contain at least 12 file:line refs")
else:
    for index, ref in enumerate(implementation_refs):
        validate_file_line_ref(ref, f"completion_debt_evidence.implementation_refs[{index}]")

required_audit_fields = set(as_string_list(completion.get("required_audit_fields"), "required_audit_fields"))
missing_audit_fields = sorted(EXPECTED_AUDIT_FIELDS - required_audit_fields)
if missing_audit_fields:
    err(f"required_audit_fields missing {missing_audit_fields}")

policy = completion.get("freshness_state_policy")
if not isinstance(policy, dict):
    err("freshness_state_policy must be an object")
    policy = {}
pass_states = set(as_string_list(policy.get("pass_states"), "freshness_state_policy.pass_states"))
fail_states = set(as_string_list(policy.get("fail_states"), "freshness_state_policy.fail_states"))
if pass_states != {"fresh", "archived"}:
    err("freshness_state_policy.pass_states must be fresh,archived")
if fail_states != {"missing_artifact", "stale_commit", "contradictory", "source_only", "prose_only"}:
    err("freshness_state_policy.fail_states drifted")
all_states = pass_states | fail_states

texts = source_texts(completion.get("test_sources"))
missing_items_bound: list[str] = []
test_refs_by_section: dict[str, list[dict[str, str]]] = {}
for section_name, missing_item in EXPECTED_MISSING_ITEMS.items():
    section = completion.get(section_name)
    if not isinstance(section, dict):
        err(f"completion_debt_evidence.{section_name} must be an object")
        continue
    if section.get("missing_item_id") != missing_item:
        err(f"completion_debt_evidence.{section_name}.missing_item_id must be {missing_item}")
    section_threshold = section.get("next_audit_score_threshold", threshold)
    if not isinstance(section_threshold, int) or section_threshold < 800:
        err(f"completion_debt_evidence.{section_name}.next_audit_score_threshold must be >= 800")
    missing_items_bound.append(str(section.get("missing_item_id", "")))
    test_refs_by_section[section_name] = validate_test_refs(section, section_name, texts)
    if section_name != "telemetry_primary":
        validate_required_commands(section, section_name)

telemetry = completion.get("telemetry_primary") if isinstance(completion.get("telemetry_primary"), dict) else {}
required_events = set(as_string_list(telemetry.get("required_events"), "telemetry_primary.required_events"))
missing_events = sorted(EXPECTED_TELEMETRY_EVENTS - required_events)
if missing_events:
    err(f"telemetry_primary.required_events missing {missing_events}")
required_fields = set(as_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields"))
missing_fields = sorted(EXPECTED_TELEMETRY_FIELDS - required_fields)
if missing_fields:
    err(f"telemetry_primary.required_fields missing {missing_fields}")

rows = ledger.get("rows")
done_audit = ledger.get("done_evidence_audit")
summary = ledger.get("summary") if isinstance(ledger.get("summary"), dict) else {}
if not isinstance(rows, list) or not rows:
    err("ledger.rows must be non-empty")
    rows = []
if not isinstance(done_audit, list):
    err("ledger.done_evidence_audit must be an array")
    done_audit = []
parse_errors = ledger.get("parse_errors", [])
if parse_errors:
    err("ledger.parse_errors must be empty")

done_rows = [row for row in rows if isinstance(row, dict) and row.get("status") == "DONE"]
done_row_ids = {str(row.get("row_id", "")) for row in done_rows}
audit_row_ids = [str(row.get("ledger_row_id", "")) for row in done_audit if isinstance(row, dict)]
duplicate_audit_ids = sorted({row_id for row_id in audit_row_ids if audit_row_ids.count(row_id) > 1})
if duplicate_audit_ids:
    err(f"duplicate done_evidence_audit ledger_row_id values: {duplicate_audit_ids}")
if len(done_audit) != len(done_rows):
    err(f"done_evidence_audit count must match DONE rows: audit={len(done_audit)} done={len(done_rows)}")
if set(audit_row_ids) != done_row_ids:
    err("done_evidence_audit row IDs must exactly match DONE row IDs")

invalid_done_rows: list[dict[str, Any]] = []
freshness_counts: dict[str, int] = {}
audit_status_counts: dict[str, int] = {}
for index, row in enumerate(done_audit):
    if not isinstance(row, dict):
        err(f"done_evidence_audit[{index}] must be an object")
        continue
    for field in sorted(required_audit_fields):
        if field not in row:
            err(f"done_evidence_audit[{index}] missing required field {field}")
    state = row.get("freshness_state")
    if state not in all_states:
        err(f"done_evidence_audit[{index}] has unexpected freshness_state {state!r}")
    else:
        freshness_counts[str(state)] = freshness_counts.get(str(state), 0) + 1
    audit_status = str(row.get("audit_status", ""))
    audit_status_counts[audit_status] = audit_status_counts.get(audit_status, 0) + 1
    expected_status = "pass" if state in pass_states else "fail"
    if audit_status != expected_status:
        err(f"done_evidence_audit[{index}] audit_status should be {expected_status} for {state}")
    failure_signature = row.get("failure_signature")
    if audit_status == "pass" and failure_signature != "none":
        err(f"done_evidence_audit[{index}] passing row must use failure_signature=none")
    if audit_status != "pass":
        invalid_done_rows.append(row)

expected_summary = completion.get("expected_ledger_summary")
if not isinstance(expected_summary, dict):
    err("expected_ledger_summary must be an object")
    expected_summary = {}
actual_summary = {
    "row_count": len(rows),
    "done_row_count": len(done_rows),
    "done_evidence_audit_count": len(done_audit),
    "done_evidence_audit_counts": audit_status_counts,
    "done_evidence_freshness_counts": freshness_counts,
    "invalid_done_evidence_count": len(invalid_done_rows),
    "parse_error_count": len(parse_errors) if isinstance(parse_errors, list) else -1,
}
for key, expected in expected_summary.items():
    actual = actual_summary.get(key)
    if actual != expected:
        err(f"expected_ledger_summary.{key} mismatch: expected {expected!r} actual {actual!r}")
for key in [
    "row_count",
    "done_evidence_audit_count",
    "invalid_done_evidence_count",
    "parse_error_count",
]:
    if summary.get(key) != actual_summary.get(key):
        err(f"ledger.summary.{key} mismatch: expected actual {actual_summary.get(key)!r} got {summary.get(key)!r}")

status = "pass" if not errors else "fail"
events: list[dict[str, Any]] = []


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
        "ledger_summary": actual_summary,
        "freshness_counts": freshness_counts,
        "artifact_refs": [
            rel(CONTRACT),
            rel(LEDGER),
            rel(REPORT),
            rel(LOG),
        ],
        "failure_signature": failure_signature,
    }


events.append(event_payload("feature_parity_done_evidence_summary", "info"))
if invalid_done_rows:
    events.append(event_payload("feature_parity_invalid_done_evidence_preserved", "warning"))
if errors:
    events.append(event_payload("feature_parity_done_audit_completion_contract_failed", "error", ",".join(errors[:8])))
else:
    events.append(event_payload("feature_parity_done_audit_completion_contract_validated", "info"))

LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)

for index, event in enumerate(events):
    missing = sorted(EXPECTED_TELEMETRY_FIELDS - set(event))
    if missing:
        err(f"generated telemetry event {index} missing fields {missing}")
if not errors:
    emitted = {event["event"] for event in events}
    required_for_pass = EXPECTED_TELEMETRY_EVENTS - {"feature_parity_done_audit_completion_contract_failed"}
    missing = sorted(required_for_pass - emitted)
    if missing:
        err(f"pass telemetry missing events {missing}")
        status = "fail"

report = {
    "schema_version": "feature_parity_done_audit_completion_contract.report.v1",
    "bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "source_commit": source_commit,
    "summary": actual_summary,
    "missing_items_bound": missing_items_bound,
    "test_refs": test_refs_by_section,
    "required_telemetry_events": sorted(required_events),
    "required_telemetry_fields": sorted(required_fields),
    "invalid_done_rows_sample": invalid_done_rows[:10],
    "errors": errors,
    "log": rel(LOG),
    "artifact_refs": [
        rel(CONTRACT),
        rel(LEDGER),
        rel(REPORT),
        rel(LOG),
    ],
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    print(f"FAIL: feature parity DONE audit completion contract ({len(errors)} errors)")
    for message in errors[:20]:
        print(f"  - {message}")
    raise SystemExit(1)

print(
    "PASS: feature parity DONE audit completion contract "
    f"(done={actual_summary['done_row_count']}, audited={actual_summary['done_evidence_audit_count']}, "
    f"invalid={actual_summary['invalid_done_evidence_count']}, report={rel(REPORT)})"
)
PY
