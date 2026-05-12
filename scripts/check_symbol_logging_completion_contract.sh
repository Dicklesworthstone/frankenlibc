#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYMBOL_LOGGING_CONTRACT:-$ROOT/tests/conformance/symbol_logging_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SYMBOL_LOGGING_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_SYMBOL_LOGGING_REPORT:-$OUT_DIR/symbol_logging_completion_contract.report.json}"
LOG="${FRANKENLIBC_SYMBOL_LOGGING_LOG:-$OUT_DIR/symbol_logging_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "symbol_logging_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "symbol_logging_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-ldj.8"
COMPLETION_BEAD = "bd-ldj.8.1"
TRACE_ID = "bd-ldj-8-1-symbol-logging-completion-v1"
PASS_EVENT = "symbol_logging_completion_contract_validated"
FAIL_EVENT = "symbol_logging_completion_contract_failed"
EXPECTED_MISSING_ITEMS = {"tests.conformance.primary", "telemetry.primary"}
EXPECTED_EVENTS = {
    "symbol_logging_source_gate",
    "symbol_logging_sample_gate",
    "symbol_logging_report_gate",
    "symbol_logging_telemetry_gate",
    PASS_EVENT,
}
BASE_REQUIRED_FIELDS = {"timestamp", "trace_id", "event", "status", "artifact_refs"}

errors: list[str] = []
log_rows: list[dict[str, Any]] = []


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def err(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        err(message)


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


COMMIT = source_commit()


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


def string_set(value: Any, context: str, allow_empty: bool = False) -> set[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return set()
    result: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


def read_text(path_text: str, context: str) -> str:
    path = ROOT / path_text
    if not path.is_file():
        err(f"{context} path missing: {path_text}")
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} unreadable: {path_text}: {exc}")
        return ""


def event(event_name: str, status: str, artifact_refs: list[str], **extra: Any) -> None:
    row = {
        "timestamp": utc_now(),
        "trace_id": TRACE_ID,
        "event": event_name,
        "status": status,
        "artifact_refs": artifact_refs,
        "bead_id": COMPLETION_BEAD,
        "source_commit": COMMIT,
    }
    row.update(extra)
    log_rows.append(row)


def validate_sources(contract: dict[str, Any]) -> dict[str, str]:
    artifacts = contract.get("source_artifacts")
    anchors = contract.get("source_anchors")
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    if not isinstance(anchors, dict) or not anchors:
        err("source_anchors must be a non-empty object")
        return {}

    paths: dict[str, str] = {}
    for key, value in artifacts.items():
        if not isinstance(value, str) or not value:
            err(f"source_artifacts.{key} must be a non-empty string")
            continue
        paths[key] = value
        text = read_text(value, f"source_artifacts.{key}")
        required = string_set(anchors.get(key), f"source_anchors.{key}")
        missing = sorted(anchor for anchor in required if anchor not in text)
        if missing:
            err(f"source_artifacts.{key} missing anchors: {missing}")
        event(
            "symbol_logging_source_gate",
            "pass" if text and not missing else "fail",
            [value],
            source_key=key,
            anchor_count=len(required),
            missing_anchors=missing,
        )
    return paths


def validate_missing_items(contract: dict[str, Any]) -> None:
    bindings = contract.get("missing_item_bindings")
    if not isinstance(bindings, list) or not bindings:
        err("missing_item_bindings must be a non-empty array")
        return
    observed: set[str] = set()
    for index, binding in enumerate(bindings):
        if not isinstance(binding, dict):
            err(f"missing_item_bindings[{index}] must be an object")
            continue
        item_id = binding.get("id")
        if not isinstance(item_id, str) or not item_id:
            err(f"missing_item_bindings[{index}].id missing")
            continue
        observed.add(item_id)
        evidence = binding.get("evidence")
        if not isinstance(evidence, list) or not evidence:
            err(f"missing_item_bindings[{item_id}].evidence must be non-empty")
    require(
        observed == EXPECTED_MISSING_ITEMS,
        f"missing_item_bindings must be {sorted(EXPECTED_MISSING_ITEMS)}, got {sorted(observed)}",
    )


def validate_symbol_rows(contract: dict[str, Any]) -> dict[str, Any]:
    spec = contract.get("symbol_logging_contract")
    if not isinstance(spec, dict):
        err("symbol_logging_contract must be an object")
        return {"sample_count": 0, "unique_symbols": []}

    runtime_event = spec.get("runtime_event")
    require(runtime_event == "runtime_decision", "symbol_logging_contract.runtime_event must be runtime_decision")
    required_fields = string_set(
        spec.get("required_runtime_decision_fields"),
        "symbol_logging_contract.required_runtime_decision_fields",
    )
    required_risk_inputs = string_set(
        spec.get("required_risk_input_fields"),
        "symbol_logging_contract.required_risk_input_fields",
    )
    required_symbols = string_set(
        spec.get("required_symbols"),
        "symbol_logging_contract.required_symbols",
    )
    actions = string_set(
        spec.get("decision_action_vocabulary"),
        "symbol_logging_contract.decision_action_vocabulary",
    )
    controller = spec.get("expected_controller_id")
    min_rows = spec.get("minimum_sample_rows")
    if not isinstance(min_rows, int) or min_rows < 1:
        err("symbol_logging_contract.minimum_sample_rows must be a positive integer")
        min_rows = 1

    rows = contract.get("sample_runtime_decision_rows")
    if not isinstance(rows, list) or len(rows) < min_rows:
        err(f"sample_runtime_decision_rows must contain at least {min_rows} rows")
        return {"sample_count": 0, "unique_symbols": []}

    unique_symbols: set[str] = set()
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            err(f"sample_runtime_decision_rows[{index}] must be an object")
            continue
        missing = sorted(field for field in required_fields if field not in row)
        if missing:
            err(f"sample_runtime_decision_rows[{index}] missing fields: {missing}")
        symbol = row.get("symbol")
        if isinstance(symbol, str):
            unique_symbols.add(symbol)
        else:
            err(f"sample_runtime_decision_rows[{index}].symbol must be a string")
            symbol = "<missing>"
        require(row.get("event") == runtime_event, f"sample_runtime_decision_rows[{index}].event must be runtime_decision")
        require(row.get("controller_id") == controller, f"sample_runtime_decision_rows[{index}].controller_id drifted")
        require(row.get("decision_action") in actions, f"sample_runtime_decision_rows[{index}].decision_action unknown")
        require(row.get("decision") in actions, f"sample_runtime_decision_rows[{index}].decision unknown")
        require(isinstance(row.get("decision_id"), int) and row.get("decision_id", 0) > 0, f"sample_runtime_decision_rows[{index}].decision_id must be positive")
        for id_field, prefix in (
            ("trace_id", f"abi::{symbol}::"),
            ("span_id", f"abi::{symbol}::decision::"),
            ("parent_span_id", f"abi::{symbol}::entry::"),
        ):
            value = row.get(id_field)
            require(
                isinstance(value, str) and value.startswith(prefix),
                f"sample_runtime_decision_rows[{index}].{id_field} must start with {prefix}",
            )
        risk_inputs = row.get("risk_inputs")
        if not isinstance(risk_inputs, dict):
            err(f"sample_runtime_decision_rows[{index}].risk_inputs must be an object")
        else:
            for field in sorted(required_risk_inputs):
                if field not in risk_inputs:
                    err(f"sample_runtime_decision_rows[{index}].risk_inputs missing {field}")
        event(
            "symbol_logging_sample_gate",
            "pass" if not missing else "fail",
            [rel(CONTRACT)],
            sample_index=index,
            symbol=symbol,
            decision_action=row.get("decision_action"),
        )

    require(
        required_symbols.issubset(unique_symbols),
        f"sample rows missing required symbols: {sorted(required_symbols - unique_symbols)}",
    )
    event(
        "symbol_logging_report_gate",
        "pass",
        [rel(CONTRACT), "crates/frankenlibc-harness/src/report.rs"],
        sample_count=len(rows),
        unique_symbols=sorted(unique_symbols),
    )
    return {"sample_count": len(rows), "unique_symbols": sorted(unique_symbols)}


def validate_telemetry_contract(contract: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_contract")
    if not isinstance(telemetry, dict):
        err("telemetry_contract must be an object")
        return
    events = string_set(telemetry.get("required_events"), "telemetry_contract.required_events")
    fields = string_set(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields")
    require(events == EXPECTED_EVENTS, f"telemetry_contract.required_events mismatch: {sorted(events)}")
    require(BASE_REQUIRED_FIELDS.issubset(fields), f"telemetry_contract.required_log_fields missing {sorted(BASE_REQUIRED_FIELDS - fields)}")
    event(
        "symbol_logging_telemetry_gate",
        "pass",
        [rel(CONTRACT)],
        required_events=sorted(events),
        required_log_fields=sorted(fields),
    )


def write_outputs(report: dict[str, Any]) -> None:
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with LOG.open("w", encoding="utf-8") as handle:
        for row in log_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> int:
    contract = load_json(CONTRACT, "contract")

    require(contract.get("schema_version") == EXPECTED_SCHEMA, f"schema_version must be {EXPECTED_SCHEMA}")
    require(contract.get("original_bead") == ORIGINAL_BEAD, f"original_bead must be {ORIGINAL_BEAD}")
    require(contract.get("completion_debt_bead") == COMPLETION_BEAD, f"completion_debt_bead must be {COMPLETION_BEAD}")
    require(contract.get("trace_id") == TRACE_ID, f"trace_id must be {TRACE_ID}")

    validate_sources(contract)
    validate_missing_items(contract)
    summary = validate_symbol_rows(contract)
    validate_telemetry_contract(contract)

    status = "pass" if not errors else "fail"
    event(
        PASS_EVENT if status == "pass" else FAIL_EVENT,
        status,
        [rel(CONTRACT), rel(REPORT), rel(LOG)],
        error_count=len(errors),
    )

    required_events = EXPECTED_EVENTS if status == "pass" else EXPECTED_EVENTS - {PASS_EVENT}
    observed_events = {row.get("event") for row in log_rows}
    if status == "pass" and not required_events.issubset(observed_events):
        errors.append(f"log missing required events: {sorted(required_events - observed_events)}")
        status = "fail"

    report = {
        "schema_version": EXPECTED_REPORT_SCHEMA,
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": COMMIT,
        "status": status,
        "failure_signature": "none" if status == "pass" else "symbol_logging_contract_invalid",
        "summary": {
            "missing_item_count": len(EXPECTED_MISSING_ITEMS),
            "sample_count": summary.get("sample_count", 0),
            "unique_symbols": summary.get("unique_symbols", []),
            "event_count": len(log_rows),
        },
        "artifact_refs": [
            rel(CONTRACT),
            "crates/frankenlibc-abi/src/runtime_policy.rs",
            "crates/frankenlibc-harness/src/report.rs",
            "tests/conformance/log_schema.json",
            rel(LOG),
        ],
        "errors": errors,
    }
    write_outputs(report)

    if errors:
        print("symbol_logging_completion_contract: FAILED")
        for message in errors:
            print(f"  - {message}")
        return 1

    print(
        "symbol_logging_completion_contract: PASS "
        f"samples={report['summary']['sample_count']} events={report['summary']['event_count']}"
    )
    return 0


raise SystemExit(main())
PY
