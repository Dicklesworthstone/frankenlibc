#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_CONTRACT:-$ROOT/tests/conformance/decision_card_evidence_ledger_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_OUT_DIR:-$ROOT/target/conformance/decision_card_evidence_ledger_completion_contract}"
REPORT="${FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_REPORT:-$OUT_DIR/report.json}"
LOG="${FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_LOG:-$OUT_DIR/events.jsonl}"
EVIDENCE_REPORT="${FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_REPLAY_REPORT:-$OUT_DIR/evidence_ledger_contract.report.json}"
EVIDENCE_LOG="${FRANKENLIBC_DECISION_CARD_EVIDENCE_LEDGER_REPLAY_LOG:-$OUT_DIR/evidence_ledger_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")" "$(dirname "$EVIDENCE_REPORT")" "$(dirname "$EVIDENCE_LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$EVIDENCE_REPORT" "$EVIDENCE_LOG" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
evidence_report_path = pathlib.Path(sys.argv[5])
evidence_log_path = pathlib.Path(sys.argv[6])
start_ns = time.time_ns()

EXPECTED_SCHEMA = "decision_card_evidence_ledger_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "decision_card_evidence_ledger_completion_contract.report.v1"
EXPECTED_ORIGINAL_BEAD = "bd-3h1u.2"
EXPECTED_COMPLETION_BEAD = "bd-3h1u.2.1"
EXPECTED_SOURCE_IDS = {
    "runtime_math_evidence",
    "runtime_math_mod",
    "unified_evidence_ledger",
    "evidence_ledger_contract",
    "evidence_ledger_checker",
    "completion_checker",
    "completion_harness",
}
EXPECTED_MISSING_ITEMS = {
    "tests.golden.primary",
    "telemetry.primary",
}
REQUIRED_COMPLETION_EVENTS = {
    "decision_card_evidence.source_artifacts_validated",
    "decision_card_evidence.golden_validated",
    "decision_card_evidence.telemetry_validated",
    "decision_card_evidence.evidence_ledger_gate_replayed",
    "decision_card_evidence.completion_contract_validated",
    "decision_card_evidence.completion_contract_failed",
}
REQUIRED_LEDGER_EVENTS = {
    "evidence_ledger_contract_validated",
    "evidence_ledger_contract_failed",
}
REQUIRED_REPORT_FIELDS = {
    "schema_version",
    "original_bead",
    "completion_debt_bead",
    "source_commit",
    "status",
    "failure_signature",
    "source_count",
    "implementation_ref_count",
    "runtime_math_test_count",
    "telemetry_smoke_test_count",
    "completion_event_count",
    "evidence_ledger_report",
    "evidence_ledger_log",
    "artifact_refs",
}
REQUIRED_LOG_FIELDS = {
    "timestamp",
    "trace_id",
    "original_bead",
    "completion_debt_bead",
    "event",
    "status",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "failure_signature",
}
REQUIRED_EXPORT_FIELDS = {
    "schema",
    "count",
    "cards",
    "decision_id",
    "trace_id",
    "decision_type",
    "mode",
    "symbol",
    "context_hash",
    "reason_hash",
    "outcome_hash",
    "counterfactual_hash",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except Exception:
        return "unknown"


def load_json(path: pathlib.Path, context: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{context} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(data, dict):
        errors.append(f"{context} must be a JSON object")
        return {}
    return data


def string_set(value: Any, context: str) -> set[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        errors.append(f"{context} must be a non-empty string array")
        return set()
    return set(value)


def append_event(event: str, status: str, details: dict[str, Any] | None = None) -> None:
    details = details or {}
    failure_signature = "none" if status == "pass" else "decision_card_evidence_ledger_completion_contract_invalid"
    events.append(
        {
            "timestamp": now_utc(),
            "trace_id": f"{EXPECTED_COMPLETION_BEAD}::decision-card-evidence::{event}::{status}",
            "original_bead": EXPECTED_ORIGINAL_BEAD,
            "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
            "event": event,
            "status": status,
            "mode": "strict",
            "api_family": "membrane",
            "symbol": "decision_card_evidence_ledger",
            "decision_path": "decision_card_evidence_ledger::completion_contract::validate",
            "healing_action": None,
            "errno": 0 if status == "pass" else 22,
            "latency_ns": time.time_ns() - start_ns,
            "artifact_refs": [
                rel(contract_path),
                rel(report_path),
                rel(log_path),
                rel(evidence_report_path),
                rel(evidence_log_path),
            ],
            "failure_signature": failure_signature,
            "details": details,
        }
    )


def validate_file_line_ref(ref: Any, context: str) -> None:
    if not isinstance(ref, str) or ":" not in ref:
        errors.append(f"{context} must be a file:line string")
        return
    path_text, line_text = ref.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        errors.append(f"{context} must be a file:line string")
        return
    path = root / path_text
    if not path.is_file():
        errors.append(f"{context} references missing file: {path_text}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        errors.append(f"{context} references line past EOF: {ref}")
    elif not lines[line_no - 1].strip():
        errors.append(f"{context} references blank line: {ref}")


def source_artifact_map(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    sources = contract.get("source_artifacts")
    if not isinstance(sources, list):
        errors.append("source_artifacts must be an array")
        return {}
    by_id: dict[str, dict[str, Any]] = {}
    for source in sources:
        if not isinstance(source, dict):
            errors.append("source_artifacts entries must be objects")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            errors.append("source_artifacts entry missing id")
            continue
        if source_id in by_id:
            errors.append(f"duplicate source_artifacts id: {source_id}")
        by_id[source_id] = source
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"source_artifacts.{source_id}.path must be non-empty")
            continue
        path = root / path_text
        if not path.is_file():
            errors.append(f"source artifact missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8")
        for needle in source.get("required_needles", []):
            if not isinstance(needle, str) or not needle:
                errors.append(f"source_artifacts.{source_id}.required_needles contains invalid needle")
            elif needle not in text:
                errors.append(f"{path_text} missing required needle: {needle}")
    declared = set(by_id)
    if declared != EXPECTED_SOURCE_IDS:
        errors.append(f"source artifact ids drifted: declared={sorted(declared)} expected={sorted(EXPECTED_SOURCE_IDS)}")
    if not errors:
        append_event("decision_card_evidence.source_artifacts_validated", "pass", {"source_count": len(by_id)})
    return by_id


def source_text(sources: dict[str, dict[str, Any]], source_id: str) -> str:
    source = sources.get(source_id, {})
    path_text = source.get("path")
    if not isinstance(path_text, str):
        return ""
    path = root / path_text
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def validate_golden(contract: dict[str, Any], sources: dict[str, dict[str, Any]]) -> tuple[int, int]:
    golden = contract.get("golden_primary")
    if not isinstance(golden, dict):
        errors.append("golden_primary must be an object")
        return 0, 0
    if golden.get("missing_item_id") != "tests.golden.primary":
        errors.append("golden_primary.missing_item_id must be tests.golden.primary")
    if golden.get("required_export_schema") != "decision_cards.v1":
        errors.append("golden_primary.required_export_schema must be decision_cards.v1")
    declared_fields = string_set(golden.get("required_export_fields"), "golden_primary.required_export_fields")
    missing_fields = sorted(REQUIRED_EXPORT_FIELDS - declared_fields)
    if missing_fields:
        errors.append(f"golden export fields missing {missing_fields}")

    runtime_math_evidence = source_text(sources, "runtime_math_evidence")
    runtime_math_mod = source_text(sources, "runtime_math_mod")
    runtime_tests = string_set(golden.get("required_runtime_math_tests"), "golden_primary.required_runtime_math_tests")
    telemetry_tests = string_set(golden.get("required_telemetry_smoke_tests"), "golden_primary.required_telemetry_smoke_tests")

    expected_runtime_tests = {
        "decision_card_export_is_valid_json",
        "decision_card_export_json_roundtrip_preserves_payload",
        "deterministic_replay_produces_identical_decisions_and_evidence",
        "decision_card_journal_replays_after_restart",
    }
    expected_telemetry_tests = {
        "decision_card_query_latency_smoke_budget",
        "decision_card_journal_append_overhead_smoke_budget",
    }
    if runtime_tests != expected_runtime_tests:
        errors.append(f"runtime math golden test set drifted: {sorted(runtime_tests)}")
    if telemetry_tests != expected_telemetry_tests:
        errors.append(f"telemetry smoke test set drifted: {sorted(telemetry_tests)}")

    for test_name in runtime_tests | telemetry_tests:
        needle = f"fn {test_name}("
        if needle not in runtime_math_evidence and needle not in runtime_math_mod:
            errors.append(f"required runtime math test missing: {test_name}")

    for prefix in golden.get("required_stdout_prefixes", []):
        if not isinstance(prefix, str) or not prefix:
            errors.append("golden_primary.required_stdout_prefixes contains invalid prefix")
        elif prefix not in runtime_math_evidence:
            errors.append(f"runtime_math_evidence missing stdout prefix {prefix}")

    if not errors:
        append_event(
            "decision_card_evidence.golden_validated",
            "pass",
            {
                "runtime_math_test_count": len(runtime_tests),
                "telemetry_smoke_test_count": len(telemetry_tests),
            },
        )
    return len(runtime_tests), len(telemetry_tests)


def read_jsonl_events(path: pathlib.Path) -> set[str]:
    events_seen: set[str] = set()
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except Exception as exc:
        errors.append(f"cannot read JSONL log {rel(path)}: {exc}")
        return events_seen
    for line in lines:
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            errors.append(f"invalid JSONL row in {rel(path)}: {exc}")
            continue
        event = row.get("event")
        if isinstance(event, str):
            events_seen.add(event)
    return events_seen


def validate_telemetry(contract: dict[str, Any]) -> int:
    telemetry = contract.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        errors.append("telemetry_primary must be an object")
        return 0
    if telemetry.get("missing_item_id") != "telemetry.primary":
        errors.append("telemetry_primary.missing_item_id must be telemetry.primary")
    completion_events = string_set(telemetry.get("required_completion_events"), "telemetry_primary.required_completion_events")
    missing_events = sorted(REQUIRED_COMPLETION_EVENTS - completion_events)
    if missing_events:
        errors.append(f"completion events missing {missing_events}")
    ledger_events = string_set(telemetry.get("required_evidence_ledger_events"), "telemetry_primary.required_evidence_ledger_events")
    missing_ledger = sorted(REQUIRED_LEDGER_EVENTS - ledger_events)
    if missing_ledger:
        errors.append(f"evidence ledger events missing {missing_ledger}")
    report_fields = string_set(telemetry.get("required_report_fields"), "telemetry_primary.required_report_fields")
    missing_report = sorted(REQUIRED_REPORT_FIELDS - report_fields)
    if missing_report:
        errors.append(f"report fields missing {missing_report}")
    log_fields = string_set(telemetry.get("required_log_fields"), "telemetry_primary.required_log_fields")
    missing_log = sorted(REQUIRED_LOG_FIELDS - log_fields)
    if missing_log:
        errors.append(f"log fields missing {missing_log}")
    if not errors:
        append_event("decision_card_evidence.telemetry_validated", "pass", {"completion_event_count": len(completion_events)})
    return len(completion_events)


def replay_evidence_ledger_gate() -> None:
    env = os.environ.copy()
    env["FRANKENLIBC_EVIDENCE_LEDGER_REPORT"] = str(evidence_report_path)
    env["FRANKENLIBC_EVIDENCE_LEDGER_LOG"] = str(evidence_log_path)
    env.setdefault("FRANKENLIBC_EVIDENCE_LEDGER_CONTRACT", str(root / "tests/conformance/evidence_ledger_contract.v1.json"))
    result = subprocess.run(
        ["bash", "scripts/check_evidence_ledger_contract.sh"],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        errors.append(
            "scripts/check_evidence_ledger_contract.sh failed: "
            f"status={result.returncode} stdout={result.stdout[-2000:]} stderr={result.stderr[-2000:]}"
        )
        return
    report = load_json(evidence_report_path, "evidence ledger replay report")
    if report.get("status") != "pass":
        errors.append(f"evidence ledger replay report status drifted: {report.get('status')}")
    events_seen = read_jsonl_events(evidence_log_path)
    if "evidence_ledger_contract_validated" not in events_seen:
        errors.append("evidence ledger replay log missing evidence_ledger_contract_validated")
    if not errors:
        append_event(
            "decision_card_evidence.evidence_ledger_gate_replayed",
            "pass",
            {
                "evidence_ledger_report": rel(evidence_report_path),
                "evidence_ledger_log": rel(evidence_log_path),
            },
        )


contract = load_json(contract_path, "completion contract")
if contract:
    if contract.get("schema_version") != EXPECTED_SCHEMA:
        errors.append(f"schema_version must be {EXPECTED_SCHEMA}")
    if contract.get("original_bead") != EXPECTED_ORIGINAL_BEAD:
        errors.append(f"original_bead must be {EXPECTED_ORIGINAL_BEAD}")
    if contract.get("completion_debt_bead") != EXPECTED_COMPLETION_BEAD:
        errors.append(f"completion_debt_bead must be {EXPECTED_COMPLETION_BEAD}")
    missing_items = string_set(
        contract.get("completion_debt_evidence", {}).get("missing_items_closed")
        if isinstance(contract.get("completion_debt_evidence"), dict)
        else None,
        "completion_debt_evidence.missing_items_closed",
    )
    if missing_items != EXPECTED_MISSING_ITEMS:
        errors.append(f"completion debt missing items drifted: {sorted(missing_items)}")
    threshold = contract.get("completion_debt_evidence", {}).get("next_audit_score_threshold") if isinstance(contract.get("completion_debt_evidence"), dict) else None
    if not isinstance(threshold, int) or threshold < 800 or threshold > 1000:
        errors.append("completion_debt_evidence.next_audit_score_threshold must be 800..1000")
    refs = contract.get("implementation_refs")
    if not isinstance(refs, list) or not refs:
        errors.append("implementation_refs must be a non-empty array")
    else:
        for index, ref in enumerate(refs):
            validate_file_line_ref(ref, f"implementation_refs[{index}]")

sources = source_artifact_map(contract) if contract else {}
runtime_math_test_count, telemetry_smoke_test_count = validate_golden(contract, sources) if contract else (0, 0)
completion_event_count = validate_telemetry(contract) if contract else 0
if not errors:
    replay_evidence_ledger_gate()

status = "pass" if not errors else "fail"
failure_signature = "none" if not errors else "decision_card_evidence_ledger_completion_contract_invalid"
if status == "pass":
    append_event(
        "decision_card_evidence.completion_contract_validated",
        "pass",
        {"contract": rel(contract_path)},
    )
else:
    append_event(
        "decision_card_evidence.completion_contract_failed",
        "fail",
        {"errors": errors[:20]},
    )

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": EXPECTED_ORIGINAL_BEAD,
    "completion_debt_bead": EXPECTED_COMPLETION_BEAD,
    "source_commit": git_head(),
    "status": status,
    "failure_signature": failure_signature,
    "generated_at_utc": now_utc(),
    "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
    "contract": rel(contract_path),
    "source_count": len(sources),
    "implementation_ref_count": len(contract.get("implementation_refs", [])) if isinstance(contract.get("implementation_refs"), list) else 0,
    "runtime_math_test_count": runtime_math_test_count,
    "telemetry_smoke_test_count": telemetry_smoke_test_count,
    "completion_event_count": completion_event_count,
    "evidence_ledger_report": rel(evidence_report_path),
    "evidence_ledger_log": rel(evidence_log_path),
    "errors": errors,
    "artifact_refs": [
        rel(contract_path),
        rel(report_path),
        rel(log_path),
        rel(evidence_report_path),
        rel(evidence_log_path),
    ],
}

missing_report_keys = sorted(REQUIRED_REPORT_FIELDS - set(report))
if missing_report_keys:
    errors.append(f"internal report missing keys {missing_report_keys}")
    report["status"] = "fail"
    report["failure_signature"] = "decision_card_evidence_ledger_completion_contract_invalid"
    report["errors"] = errors

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text(
    "".join(json.dumps(row, sort_keys=True) + "\n" for row in events),
    encoding="utf-8",
)

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "decision_card_evidence_ledger_completion_contract: PASS "
    f"sources={len(sources)} runtime_tests={runtime_math_test_count} "
    f"telemetry_smoke_tests={telemetry_smoke_test_count} events={len(events)}"
)
PY
