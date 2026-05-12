#!/usr/bin/env bash
# check_pthread_mutex_state_invariants_completion_contract.sh - bd-19j.1 completion evidence gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_CONTRACT:-${ROOT}/tests/conformance/pthread_mutex_state_invariants_completion_contract.v1.json}"
REPORT="${FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_REPORT:-${ROOT}/target/conformance/pthread_mutex_state_invariants_completion_contract.report.json}"
LOG="${FRANKENLIBC_PTHREAD_MUTEX_STATE_INVARIANTS_LOG:-${ROOT}/target/conformance/pthread_mutex_state_invariants_completion_contract.log.jsonl}"
SOURCE_COMMIT="$(git -C "${ROOT}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SOURCE_COMMIT}" <<'PY'
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])
log_path = Path(sys.argv[4])
source_commit = sys.argv[5]

ORIGINAL_BEAD = "bd-19j"
COMPLETION_DEBT_BEAD = "bd-19j.1"
REQUIRED_MISSING_ITEMS = {
    "tests.unit.primary",
    "tests.golden.primary",
    "telemetry.primary",
}
REQUIRED_GOLDEN_TRANSITIONS = {
    "init-default-to-unlocked",
    "lock-unlocked-fast-path",
    "lock-contended-slow-path",
    "trylock-locked-is-ebusy",
    "unlock-owned-releases",
    "destroy-unlocked-is-terminal",
}
REQUIRED_EVENTS = {
    "pthread_mutex_state_invariants.source_ref",
    "pthread_mutex_state_invariants.golden_transition",
    "pthread_mutex_state_invariants.telemetry_contract",
    "pthread_mutex_state_invariants.completion_contract_validated",
}
REQUIRED_REPORT_FIELDS = {
    "timestamp",
    "trace_id",
    "event",
    "completion_debt_bead",
    "original_bead",
    "source_commit",
    "status",
    "missing_items",
    "golden_transition_count",
    "unit_test_ref_count",
    "fixture_case_count",
    "artifact_refs",
    "failure_signature",
}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def workspace_path(path_text: str) -> Path:
    path = Path(path_text)
    return path if path.is_absolute() else root / path


def append_error(errors: list[str], message: str) -> None:
    errors.append(message)


def load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        append_error(errors, f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        append_error(errors, f"{label} must be a JSON object")
        return {}
    return value


def require_dict(value: Any, label: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        append_error(errors, f"{label} must be an object")
        return {}
    return value


def require_string_list(value: Any, label: str, errors: list[str]) -> list[str]:
    if not isinstance(value, list) or not value:
        append_error(errors, f"{label} must be a non-empty array")
        return []
    strings: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            append_error(errors, f"{label}[{index}] must be a non-empty string")
        else:
            strings.append(item)
    return strings


def validate_line_ref(ref: Any, label: str, errors: list[str]) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        append_error(errors, f"{label} must be file:line")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not line_text.isdigit() or int(line_text) <= 0:
        append_error(errors, f"{label} has invalid line number: {ref}")
        return
    path = workspace_path(path_text)
    if not path.is_file():
        append_error(errors, f"{label} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_number = int(line_text)
    if line_number > len(lines):
        append_error(errors, f"{label} references line past EOF: {ref}")
    elif not lines[line_number - 1].strip():
        append_error(errors, f"{label} references blank line: {ref}")


def validate_artifacts(evidence: dict[str, Any], errors: list[str], rows: list[dict[str, Any]]) -> dict[str, str]:
    artifacts = require_dict(evidence.get("artifacts"), "completion_debt_evidence.artifacts", errors)
    required = {
        "core_contract",
        "abi_mutex",
        "fixture",
        "fixture_harness",
        "completion_contract",
        "completion_gate",
        "completion_harness",
    }
    if set(artifacts) != required:
        append_error(errors, f"artifacts must be exactly {sorted(required)}, got {sorted(artifacts)}")
    texts: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        if not isinstance(path_text, str) or not path_text:
            append_error(errors, f"artifact {artifact_id} path must be a non-empty string")
            continue
        path = workspace_path(path_text)
        if not path.is_file():
            append_error(errors, f"artifact {artifact_id} missing file: {path_text}")
            continue
        try:
            texts[artifact_id] = path.read_text(encoding="utf-8")
        except Exception as exc:
            append_error(errors, f"artifact {artifact_id} unreadable: {path_text}: {exc}")
            continue
        rows.append(
            {
                "timestamp": utc_now(),
                "trace_id": f"{COMPLETION_DEBT_BEAD}:pthread-mutex-state-invariants",
                "event": "pthread_mutex_state_invariants.source_ref",
                "completion_debt_bead": COMPLETION_DEBT_BEAD,
                "original_bead": ORIGINAL_BEAD,
                "source_commit": source_commit,
                "artifact_id": artifact_id,
                "path": path_text,
                "status": "pass",
            }
        )
    for ref in evidence.get("implementation_refs", []):
        validate_line_ref(ref, "implementation_refs", errors)
    needles = require_dict(evidence.get("source_needles"), "source_needles", errors)
    for artifact_id, required_needles in needles.items():
        text = texts.get(artifact_id, "")
        for needle in require_string_list(required_needles, f"source_needles.{artifact_id}", errors):
            if needle not in text:
                append_error(errors, f"{artifact_id} missing required needle {needle!r}")
    return texts


def validate_missing_bindings(evidence: dict[str, Any], errors: list[str]) -> None:
    bindings = evidence.get("missing_item_bindings")
    if not isinstance(bindings, list):
        append_error(errors, "missing_item_bindings must be an array")
        return
    actual = set()
    sections = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            append_error(errors, f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("missing_item_id")
        section = binding.get("evidence_section")
        if isinstance(item_id, str):
            actual.add(item_id)
        else:
            append_error(errors, f"missing_item_bindings[{index}].missing_item_id missing")
        if isinstance(section, str):
            sections.add(section)
        else:
            append_error(errors, f"missing_item_bindings[{index}].evidence_section missing")
    if actual != REQUIRED_MISSING_ITEMS:
        append_error(errors, f"missing items must be {sorted(REQUIRED_MISSING_ITEMS)}, got {sorted(actual)}")
    for required_section in ["unit_primary", "golden_primary", "telemetry_primary"]:
        if required_section not in sections or not isinstance(evidence.get(required_section), dict):
            append_error(errors, f"{required_section} must be bound and present")


def validate_unit_primary(evidence: dict[str, Any], texts: dict[str, str], errors: list[str]) -> int:
    unit = require_dict(evidence.get("unit_primary"), "unit_primary", errors)
    commands = require_string_list(unit.get("commands"), "unit_primary.commands", errors)
    if not any("frankenlibc-core" in command and "pthread::mutex" in command for command in commands):
        append_error(errors, "unit_primary.commands must include focused frankenlibc-core pthread::mutex test")
    refs = unit.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        append_error(errors, "unit_primary.required_test_refs must be a non-empty array")
        return 0
    count = 0
    for index, ref in enumerate(refs):
        if not isinstance(ref, dict):
            append_error(errors, f"unit_primary.required_test_refs[{index}] must be an object")
            continue
        source = ref.get("source")
        name = ref.get("name")
        if not isinstance(source, str) or not isinstance(name, str):
            append_error(errors, f"unit_primary.required_test_refs[{index}] source/name missing")
            continue
        if name not in texts.get(source, ""):
            append_error(errors, f"unit test ref {name!r} missing from source {source}")
        count += 1
    if count < 6:
        append_error(errors, f"unit_primary must bind at least 6 unit/property refs, got {count}")
    return count


def fixture_cases(evidence: dict[str, Any], errors: list[str]) -> dict[str, dict[str, Any]]:
    artifacts = require_dict(evidence.get("artifacts"), "artifacts", errors)
    fixture_path = workspace_path(str(artifacts.get("fixture", "")))
    fixture = load_json(fixture_path, "pthread mutex fixture", errors)
    cases = fixture.get("cases")
    if not isinstance(cases, list):
        append_error(errors, "pthread mutex fixture cases must be an array")
        return {}
    result: dict[str, dict[str, Any]] = {}
    for case in cases:
        if not isinstance(case, dict):
            continue
        name = case.get("name")
        if isinstance(name, str):
            result[name] = case
    return result


def validate_golden_primary(
    evidence: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> tuple[int, int]:
    golden = require_dict(evidence.get("golden_primary"), "golden_primary", errors)
    cases = fixture_cases(evidence, errors)
    required_cases = set(require_string_list(golden.get("required_fixture_cases"), "golden_primary.required_fixture_cases", errors))
    missing_cases = sorted(required_cases - set(cases))
    if missing_cases:
        append_error(errors, f"fixture missing required cases: {missing_cases}")
    transitions = golden.get("state_transitions")
    if not isinstance(transitions, list) or not transitions:
        append_error(errors, "golden_primary.state_transitions must be a non-empty array")
        return (len(cases), 0)
    transition_ids = set()
    for index, transition in enumerate(transitions):
        if not isinstance(transition, dict):
            append_error(errors, f"golden transition {index} must be an object")
            continue
        tid = transition.get("id")
        if isinstance(tid, str):
            transition_ids.add(tid)
        else:
            append_error(errors, f"golden transition {index} missing id")
        for field in ["kind", "state_before", "operation", "state_after", "expected_errno", "blocks", "fixture_case"]:
            if field not in transition:
                append_error(errors, f"golden transition {tid or index} missing {field}")
        fixture_case = transition.get("fixture_case")
        if isinstance(fixture_case, str) and fixture_case not in cases:
            append_error(errors, f"golden transition {tid} references missing fixture case {fixture_case}")
        if not isinstance(transition.get("expected_errno"), int):
            append_error(errors, f"golden transition {tid} expected_errno must be integer")
        if not isinstance(transition.get("blocks"), bool):
            append_error(errors, f"golden transition {tid} blocks must be boolean")
        rows.append(
            {
                "timestamp": utc_now(),
                "trace_id": f"{COMPLETION_DEBT_BEAD}:pthread-mutex-state-invariants",
                "event": "pthread_mutex_state_invariants.golden_transition",
                "completion_debt_bead": COMPLETION_DEBT_BEAD,
                "original_bead": ORIGINAL_BEAD,
                "source_commit": source_commit,
                "transition_id": tid,
                "fixture_case": fixture_case,
                "status": "pass",
            }
        )
    if transition_ids != REQUIRED_GOLDEN_TRANSITIONS:
        append_error(errors, f"golden transition IDs must be {sorted(REQUIRED_GOLDEN_TRANSITIONS)}, got {sorted(transition_ids)}")
    return (len(cases), len(transition_ids))


def validate_telemetry_primary(
    evidence: dict[str, Any],
    errors: list[str],
    rows: list[dict[str, Any]],
) -> None:
    telemetry = require_dict(evidence.get("telemetry_primary"), "telemetry_primary", errors)
    events = set(require_string_list(telemetry.get("required_events"), "telemetry_primary.required_events", errors))
    fields = set(require_string_list(telemetry.get("required_fields"), "telemetry_primary.required_fields", errors))
    if not REQUIRED_EVENTS.issubset(events):
        append_error(errors, f"telemetry events missing {sorted(REQUIRED_EVENTS - events)}")
    if not REQUIRED_REPORT_FIELDS.issubset(fields):
        append_error(errors, f"telemetry fields missing {sorted(REQUIRED_REPORT_FIELDS - fields)}")
    for path_field in ["report_path", "log_path"]:
        if not isinstance(telemetry.get(path_field), str) or not telemetry[path_field]:
            append_error(errors, f"telemetry_primary.{path_field} must be a non-empty string")
    rows.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"{COMPLETION_DEBT_BEAD}:pthread-mutex-state-invariants",
            "event": "pthread_mutex_state_invariants.telemetry_contract",
            "completion_debt_bead": COMPLETION_DEBT_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": source_commit,
            "required_events": sorted(events),
            "required_fields": sorted(fields),
            "status": "pass",
        }
    )


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


errors: list[str] = []
rows: list[dict[str, Any]] = []
contract = load_json(contract_path, "completion contract", errors)

if contract:
    if contract.get("schema_version") != "pthread_mutex_state_invariants_completion_contract.v1":
        append_error(errors, "schema_version drifted")
    if contract.get("bead") != ORIGINAL_BEAD:
        append_error(errors, f"bead must be {ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != COMPLETION_DEBT_BEAD:
        append_error(errors, f"completion_debt_bead must be {COMPLETION_DEBT_BEAD}")

evidence = require_dict(contract.get("completion_debt_evidence"), "completion_debt_evidence", errors)
if evidence:
    if evidence.get("bead") != COMPLETION_DEBT_BEAD:
        append_error(errors, f"completion_debt_evidence.bead must be {COMPLETION_DEBT_BEAD}")
    if evidence.get("original_bead") != ORIGINAL_BEAD:
        append_error(errors, f"completion_debt_evidence.original_bead must be {ORIGINAL_BEAD}")
    if int(evidence.get("next_audit_score_threshold", 0)) < 800:
        append_error(errors, "next_audit_score_threshold must be at least 800")
    validate_missing_bindings(evidence, errors)
    texts = validate_artifacts(evidence, errors, rows)
    unit_count = validate_unit_primary(evidence, texts, errors)
    fixture_count, transition_count = validate_golden_primary(evidence, errors, rows)
    validate_telemetry_primary(evidence, errors, rows)
else:
    unit_count = 0
    fixture_count = 0
    transition_count = 0

status = "fail" if errors else "pass"
failure_signature = "pthread_mutex_state_invariants_completion_contract_failed" if errors else "none"
artifact_refs = sorted(require_dict(evidence.get("artifacts"), "artifacts", []).values()) if isinstance(evidence, dict) else []

summary_row = {
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_DEBT_BEAD}:pthread-mutex-state-invariants",
    "event": "pthread_mutex_state_invariants.completion_contract_validated" if not errors else "pthread_mutex_state_invariants.completion_contract_failed",
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "missing_items": sorted(REQUIRED_MISSING_ITEMS),
    "golden_transition_count": transition_count,
    "unit_test_ref_count": unit_count,
    "fixture_case_count": fixture_count,
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
    "errors": errors,
}
rows.append(summary_row)

report = {
    "schema_version": "pthread_mutex_state_invariants_completion_contract.report.v1",
    "timestamp": utc_now(),
    "trace_id": f"{COMPLETION_DEBT_BEAD}:pthread-mutex-state-invariants",
    "event": summary_row["event"],
    "completion_debt_bead": COMPLETION_DEBT_BEAD,
    "original_bead": ORIGINAL_BEAD,
    "source_commit": source_commit,
    "status": status,
    "missing_items": sorted(REQUIRED_MISSING_ITEMS),
    "golden_transition_count": transition_count,
    "unit_test_ref_count": unit_count,
    "fixture_case_count": fixture_count,
    "artifact_refs": artifact_refs,
    "failure_signature": failure_signature,
    "errors": errors,
    "log_path": rel(log_path),
}

write_json(report_path, report)
write_jsonl(log_path, rows)

if errors:
    print("FAIL: pthread mutex state invariant completion contract", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS: pthread mutex state invariant completion contract "
    f"transitions={transition_count} unit_refs={unit_count} fixture_cases={fixture_count}"
)
PY
