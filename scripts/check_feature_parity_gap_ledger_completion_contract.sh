#!/usr/bin/env bash
# check_feature_parity_gap_ledger_completion_contract.sh - bd-w2c3.1.1.1 completion gate
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_CONTRACT:-$ROOT/tests/conformance/feature_parity_gap_ledger_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_REPORT:-$OUT_DIR/feature_parity_gap_ledger_completion_contract.report.json}"
LOG="${FRANKENLIBC_FEATURE_PARITY_GAP_LEDGER_COMPLETION_LOG:-$OUT_DIR/feature_parity_gap_ledger_completion_contract.log.jsonl}"

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

ROOT="$ROOT" \
CONTRACT="$CONTRACT" \
OUT_DIR="$OUT_DIR" \
REPORT="$REPORT" \
LOG="$LOG" \
python3 - <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time
from collections import Counter
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "feature_parity_gap_ledger_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "feature_parity_gap_ledger_completion_contract.report.v1"
EXPECTED_MANIFEST = "bd-w2c3.1.1.1-feature-parity-gap-ledger-completion-contract"
ORIGINAL_BEAD = "bd-w2c3.1.1"
COMPLETION_BEAD = "bd-w2c3.1.1.1"
REQUIRED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary"}
REQUIRED_TEST_REFS_BY_ITEM = {
    "tests.unit.primary": {
        "artifact_exists_and_valid",
        "row_ids_are_unique_and_parser_errors_empty",
        "done_rows_have_evidence_audit_records",
        "generator_self_tests_pass",
        "manifest_binds_gap_ledger_completion_items",
    },
    "tests.e2e.primary": {
        "gate_script_exists_and_succeeds",
        "gate_script_emits_done_evidence_log_and_report",
        "checker_validates_gap_ledger_contract_and_emits_report_log",
        "checker_rejects_missing_required_test_binding",
        "checker_rejects_non_rch_cargo_command",
    },
}
REQUIRED_EVENTS = {
    "gap_ledger_completion_manifest_verified",
    "gap_ledger_completion_source_gate_verified",
    "gap_ledger_completion_artifact_verified",
    "gap_ledger_completion_contract_pass",
}
FAIL_EVENT = "gap_ledger_completion_contract_fail"

errors: list[str] = []
events: list[dict[str, Any]] = []


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


def json_lines(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{label} is unreadable: {rel(path)}: {exc}")
        return []
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        if not raw.strip():
            continue
        try:
            row = json.loads(raw)
        except Exception as exc:
            err(f"{label}:{index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            err(f"{label}:{index} must be a JSON object")
            continue
        rows.append(row)
    return rows


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


def artifact_path(path_text: Any, context: str) -> pathlib.Path | None:
    if not isinstance(path_text, str) or not path_text:
        err(f"{context} must be a non-empty repo-relative path")
        return None
    path = pathlib.Path(path_text)
    if path.is_absolute() or ".." in path.parts:
        err(f"{context} must be repo-relative without parent traversal: {path_text}")
        return None
    full = ROOT / path
    if not full.is_file():
        err(f"{context} references missing file: {path_text}")
        return None
    return full


def source_text(path_text: Any, context: str) -> str:
    path = artifact_path(path_text, context)
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8")
    except Exception as exc:
        err(f"{context} is unreadable: {rel(path)}: {exc}")
        return ""


def function_exists(text: str, name: str) -> bool:
    return f"fn {name}(" in text or f"fn {name}<" in text


def append_event(event: str, status: str, artifact_refs: list[str], details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": f"{COMPLETION_BEAD}:{event}:{len(events) + 1:03d}",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "source_bead": ORIGINAL_BEAD,
            "completion_debt_bead": COMPLETION_BEAD,
            "status": status,
            "outcome": "pass" if status == "pass" else "fail",
            "artifact_refs": artifact_refs,
            "failure_signature": "none" if status == "pass" else "gap_ledger_completion_contract_failed",
            "details": details,
        }
    )


def validate_source_artifacts(manifest: dict[str, Any]) -> dict[str, str]:
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return {}
    out: dict[str, str] = {}
    for artifact_id, path_text in artifacts.items():
        artifact_path(path_text, f"source_artifacts.{artifact_id}")
        if isinstance(path_text, str):
            out[str(artifact_id)] = path_text
    return out


def validate_test_refs(
    item: dict[str, Any],
    item_id: str,
    artifacts: dict[str, str],
    source_cache: dict[str, str],
) -> list[str]:
    found: list[str] = []
    refs = item.get("required_test_refs")
    if not isinstance(refs, list) or not refs:
        err(f"missing_item_bindings.{item_id}.required_test_refs must be a non-empty array")
        return found
    for index, ref_obj in enumerate(refs):
        if not isinstance(ref_obj, dict):
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] must be an object")
            continue
        source_id = ref_obj.get("source")
        name = ref_obj.get("name")
        if not isinstance(source_id, str) or source_id not in artifacts:
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] references unknown source {source_id!r}")
            continue
        if source_id not in source_cache:
            source_cache[source_id] = source_text(artifacts[source_id], f"test_source.{source_id}")
        if not isinstance(name, str) or not function_exists(source_cache[source_id], name):
            err(f"missing_item_bindings.{item_id}.required_test_refs[{index}] missing test {source_id}::{name}")
            continue
        found.append(f"{source_id}::{name}")
    found_names = {item.rsplit("::", 1)[1] for item in found}
    missing_names = sorted(REQUIRED_TEST_REFS_BY_ITEM.get(item_id, set()) - found_names)
    if missing_names:
        err(f"missing_item_bindings.{item_id}.required_test_refs missing required bindings {missing_names}")
    commands = as_string_list(item.get("required_commands"), f"missing_item_bindings.{item_id}.required_commands")
    for command in commands:
        if "cargo " in command and "rch exec" not in command and not command.startswith("rch cargo "):
            err(f"missing_item_bindings.{item_id} cargo command must be rch-backed: {command}")
    return found


def run_source_checker(checker_path: str) -> dict[str, Any]:
    done_log = OUT_DIR / "feature_parity_gap_ledger_completion_done_evidence.log.jsonl"
    done_report = OUT_DIR / "feature_parity_gap_ledger_completion_done_evidence.report.json"
    proc = subprocess.run(
        ["bash", checker_path],
        cwd=ROOT,
        env={
            **os.environ,
            "FLC_FP_DONE_EVIDENCE_LOG": str(done_log),
            "FLC_FP_DONE_EVIDENCE_REPORT": str(done_report),
        },
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    result = {
        "command": f"bash {checker_path}",
        "status": "pass" if proc.returncode == 0 else "fail",
        "exit_code": proc.returncode,
        "stdout_tail": proc.stdout[-1200:],
        "stderr_tail": proc.stderr[-1200:],
        "done_log": rel(done_log),
        "done_report": rel(done_report),
    }
    if proc.returncode != 0:
        err(f"source gap ledger checker failed exit={proc.returncode} stdout={proc.stdout[-600:]!r} stderr={proc.stderr[-600:]!r}")
    return result


def expect_exact(actual: Any, expected: Any, context: str) -> None:
    require(actual == expected, f"{context} expected {expected!r}, got {actual!r}")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("manifest_id") == EXPECTED_MANIFEST, "manifest_id mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

artifacts = validate_source_artifacts(manifest)
required = manifest.get("required_gap_ledger_contract", {})
if not isinstance(required, dict):
    err("required_gap_ledger_contract must be an object")
    required = {}

missing_items_seen: set[str] = set()
source_cache: dict[str, str] = {}
test_refs: dict[str, list[str]] = {}
for item in manifest.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        err("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    if not isinstance(item_id, str):
        err("missing_item_bindings entry missing id")
        continue
    missing_items_seen.add(item_id)
    test_refs[item_id] = validate_test_refs(item, item_id, artifacts, source_cache)
require(missing_items_seen == REQUIRED_MISSING_ITEMS, "missing_item_bindings must close exactly unit and e2e primary items")

generator_text = source_text(artifacts.get("gap_ledger_generator"), "gap ledger generator")
for token in as_string_list(required.get("required_generator_tokens"), "required_gap_ledger_contract.required_generator_tokens"):
    require(token in generator_text, f"gap ledger generator missing token {token!r}")

append_event(
    "gap_ledger_completion_manifest_verified",
    "pass" if not errors else "fail",
    [rel(CONTRACT), artifacts.get("gap_ledger_generator", "")],
    {"missing_items_closed": sorted(missing_items_seen), "test_ref_count": sum(len(refs) for refs in test_refs.values())},
)

source_gate = run_source_checker(artifacts.get("gap_ledger_checker", ""))
done_report = load_json(ROOT / source_gate.get("done_report", ""), "source DONE evidence report")
done_log_rows = json_lines(ROOT / source_gate.get("done_log", ""), "source DONE evidence log")

expect_exact(done_report.get("schema_version"), "v1", "source DONE report schema_version")
expect_exact(done_report.get("bead"), "bd-bp8fl.3.2", "source DONE report bead")
done_summary = done_report.get("summary", {}) if isinstance(done_report.get("summary"), dict) else {}
expect_exact(done_summary.get("done_row_count"), required.get("done_evidence_audit_count"), "source DONE report done_row_count")
expect_exact(done_summary.get("audited_done_row_count"), required.get("done_evidence_audit_count"), "source DONE report audited_done_row_count")
expect_exact(done_summary.get("invalid_done_evidence_count"), required.get("done_evidence_audit_status_counts", {}).get("fail"), "source DONE report invalid_done_evidence_count")
expect_exact(len(done_log_rows), required.get("done_evidence_audit_count"), "source DONE evidence log row count")
for row in done_log_rows[: min(len(done_log_rows), 10)]:
    for field in as_string_list(required.get("required_done_log_fields"), "required_gap_ledger_contract.required_done_log_fields"):
        require(field in row, f"source DONE evidence log row missing field {field}")

append_event(
    "gap_ledger_completion_source_gate_verified",
    "pass" if not errors else "fail",
    [artifacts.get("gap_ledger_checker", ""), source_gate.get("done_report", ""), source_gate.get("done_log", "")],
    {
        "source_gate_status": source_gate.get("status"),
        "done_report_rows": done_summary.get("audited_done_row_count"),
        "done_log_rows": len(done_log_rows),
    },
)

ledger = load_json(ROOT / artifacts.get("gap_ledger", ""), "gap ledger")
expect_exact(ledger.get("schema_version"), required.get("schema_version"), "ledger.schema_version")
expect_exact(ledger.get("bead"), required.get("bead"), "ledger.bead")
for array_name in as_string_list(required.get("required_ledger_arrays"), "required_gap_ledger_contract.required_ledger_arrays"):
    require(isinstance(ledger.get(array_name), list), f"ledger.{array_name} must be an array")
expect_exact(len(ledger.get("rows", [])), required.get("row_count"), "ledger row count")
expect_exact(len(ledger.get("gaps", [])), required.get("gap_count"), "ledger gap count")
expect_exact(len(ledger.get("deltas", [])), required.get("delta_count"), "ledger delta count")
expect_exact(len(ledger.get("parse_errors", [])), required.get("parse_error_count"), "ledger parse_error count")
expect_exact(len(ledger.get("done_evidence_audit", [])), required.get("done_evidence_audit_count"), "ledger DONE evidence audit count")
summary = ledger.get("summary", {}) if isinstance(ledger.get("summary"), dict) else {}
expect_exact(summary.get("row_count"), required.get("row_count"), "ledger summary.row_count")
expect_exact(summary.get("gap_count"), required.get("gap_count"), "ledger summary.gap_count")
expect_exact(summary.get("delta_count"), required.get("delta_count"), "ledger summary.delta_count")
expect_exact(summary.get("parse_error_count"), required.get("parse_error_count"), "ledger summary.parse_error_count")
expect_exact(summary.get("done_evidence_audit_count"), required.get("done_evidence_audit_count"), "ledger summary.done_evidence_audit_count")
expect_exact(summary.get("done_evidence_audit_counts"), required.get("done_evidence_audit_status_counts"), "ledger summary.done_evidence_audit_counts")
expect_exact(summary.get("done_evidence_freshness_counts"), required.get("done_evidence_freshness_counts"), "ledger summary.done_evidence_freshness_counts")
row_ids = [row.get("row_id") for row in ledger.get("rows", []) if isinstance(row, dict)]
require(len(row_ids) == len(set(row_ids)), "ledger row_id values must be unique")
for row_id in row_ids:
    require(isinstance(row_id, str) and row_id.startswith("fp-"), "ledger row_id values must use fp-* prefix")
for audit in ledger.get("done_evidence_audit", []):
    if isinstance(audit, dict):
        for field in ["ledger_row_id", "freshness_state", "expected", "actual", "artifact_refs", "failure_signature"]:
            require(field in audit, f"DONE evidence audit row missing {field}")
audit_counts = Counter(str(row.get("audit_status")) for row in ledger.get("done_evidence_audit", []) if isinstance(row, dict))
expect_exact(dict(sorted(audit_counts.items())), required.get("done_evidence_audit_status_counts"), "ledger computed DONE evidence audit counts")

append_event(
    "gap_ledger_completion_artifact_verified",
    "pass" if not errors else "fail",
    [artifacts.get("gap_ledger", "")],
    {
        "row_count": len(ledger.get("rows", [])),
        "gap_count": len(ledger.get("gaps", [])),
        "done_evidence_audit_count": len(ledger.get("done_evidence_audit", [])),
    },
)

telemetry = manifest.get("telemetry_contract", {})
if not isinstance(telemetry, dict):
    err("telemetry_contract must be an object")
    telemetry = {}

status = "pass" if not errors else "fail"
if status == "pass":
    append_event(
        "gap_ledger_completion_contract_pass",
        "pass",
        [rel(CONTRACT), artifacts.get("completion_checker", "")],
        {"missing_items_closed": sorted(missing_items_seen)},
    )
else:
    append_event(FAIL_EVENT, "fail", [rel(CONTRACT)], {"errors": errors.copy()})

event_names = {event["event"] for event in events}
for event_name in as_string_list(telemetry.get("required_events"), "telemetry_contract.required_events"):
    require(event_name in event_names, f"required telemetry event missing: {event_name}")
if status == "pass":
    forbidden = set(as_string_list(telemetry.get("forbidden_pass_events"), "telemetry_contract.forbidden_pass_events", allow_empty=True))
    observed_forbidden = sorted(forbidden & event_names)
    if observed_forbidden:
        err(f"forbidden pass events observed {observed_forbidden}")
for event in events:
    for field in as_string_list(telemetry.get("required_log_fields"), "telemetry_contract.required_log_fields"):
        require(field in event, f"telemetry event {event.get('event')} missing field {field}")

status = "pass" if not errors else "fail"
for event in events:
    event["status"] = status if event["event"] != FAIL_EVENT else "fail"
    if event["event"] == "gap_ledger_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "manifest_id": manifest.get("manifest_id"),
    "source_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "status": status,
    "gap_ledger_summary": {
        "row_count": len(ledger.get("rows", [])),
        "gap_count": len(ledger.get("gaps", [])),
        "delta_count": len(ledger.get("deltas", [])),
        "parse_error_count": len(ledger.get("parse_errors", [])),
        "done_evidence_audit_count": len(ledger.get("done_evidence_audit", [])),
        "done_log_row_count": len(done_log_rows),
    },
    "test_refs": test_refs,
    "source_gate": source_gate,
    "events": [event["event"] for event in events],
    "errors": errors,
}
for field in as_string_list(telemetry.get("required_report_fields"), "telemetry_contract.required_report_fields"):
    if field not in report:
        err(f"completion report missing required field {field}")

status = "pass" if not errors else "fail"
report["status"] = status
report["errors"] = errors
for event in events:
    event["status"] = status if event["event"] != FAIL_EVENT else "fail"
    if event["event"] == "gap_ledger_completion_contract_pass":
        event["outcome"] = "pass" if status == "pass" else "fail"

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")

if errors:
    for message in errors:
        print(f"ERROR: {message}", file=os.sys.stderr)
    raise SystemExit(1)

print(
    "PASS: feature parity gap ledger completion contract validated "
    f"rows={report['gap_ledger_summary']['row_count']} "
    f"gaps={report['gap_ledger_summary']['gap_count']} "
    f"done_audit={report['gap_ledger_summary']['done_evidence_audit_count']}"
)
PY
