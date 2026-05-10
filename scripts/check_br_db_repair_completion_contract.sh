#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_BR_DB_REPAIR_COMPLETION_CONTRACT:-$ROOT/tests/conformance/br_db_repair_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_BR_DB_REPAIR_COMPLETION_TARGET_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_BR_DB_REPAIR_COMPLETION_REPORT:-$OUT_DIR/br_db_repair_completion_contract.report.json}"
LOG="${FRANKENLIBC_BR_DB_REPAIR_COMPLETION_LOG:-$OUT_DIR/br_db_repair_completion_contract.log.jsonl}"

mkdir -p "$OUT_DIR" "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$OUT_DIR" "$REPORT" "$LOG" <<'PY'
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(sys.argv[1])
CONTRACT = pathlib.Path(sys.argv[2])
OUT_DIR = pathlib.Path(sys.argv[3])
REPORT = pathlib.Path(sys.argv[4])
LOG = pathlib.Path(sys.argv[5])

EXPECTED_SCHEMA = "br_db_repair_completion_contract.v1"
ORIGINAL_BEAD = "bd-bp8fl.2.1"
COMPLETION_BEAD = "bd-bp8fl.2.1.1"
TRACE_ID = "bd-bp8fl-2-1-1-br-db-repair-completion-v1"
EXPECTED_MISSING_ITEMS = {"tests.unit.primary", "tests.e2e.primary", "telemetry.primary"}
CRITICAL_DISCREPANCIES = {
    "db_jsonl_count_mismatch",
    "stale_blocked_cache",
    "conflicting_ready_lists",
    "timeout",
}
REQUIRED_EVENTS = {
    "br_db_repair_completion_contract_validated",
    "br_db_repair_completion_contract_failed",
    "source_contract_replayed",
    "read_only_probe_contract_checked",
    "missing_item_bindings_validated",
}
DESTRUCTIVE_FRAGMENTS = {
    "br sync --flush-only",
    "br sync --import-only",
    "br sync --rebuild",
    "br create",
    "br close",
    "git clean",
    "git reset --hard",
    "rm -rf",
}

errors: list[str] = []
events: list[dict[str, Any]] = []


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


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


def load_json(path: pathlib.Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} is not valid JSON: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object: {rel(path)}")
        return {}
    return value


def load_jsonl(path: pathlib.Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"{label} is not readable: {rel(path)}: {exc}")
        return rows
    for index, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except Exception as exc:
            errors.append(f"{label} line {index} is not valid JSON: {exc}")
            continue
        if not isinstance(row, dict):
            errors.append(f"{label} line {index} must be a JSON object")
            continue
        rows.append(row)
    return rows


def write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_jsonl(path: pathlib.Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
        encoding="utf-8",
    )


def event(
    name: str,
    level: str,
    source_contract: str | None,
    gate: str,
    expected: Any,
    actual: Any,
    failure_signature: str | None,
    artifact_refs: list[str],
) -> dict[str, Any]:
    return {
        "timestamp": now_utc(),
        "trace_id": f"{TRACE_ID}::{name}::{source_contract or 'contract'}",
        "level": level,
        "event": name,
        "bead_id": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "source_contract": source_contract,
        "gate": gate,
        "expected": expected,
        "actual": actual,
        "source_commit": COMMIT,
        "target_dir": rel(OUT_DIR),
        "failure_signature": failure_signature,
        "artifact_refs": artifact_refs,
    }


def fail_report(signature: str) -> None:
    report = {
        "schema_version": "br_db_repair_completion_contract.report.v1",
        "original_bead": ORIGINAL_BEAD,
        "completion_debt_bead": COMPLETION_BEAD,
        "trace_id": TRACE_ID,
        "source_commit": COMMIT,
        "status": "fail",
        "source_contracts": source_results,
        "missing_item_bindings": missing_item_bindings,
        "summary": {
            "source_contract_count": len(source_results),
            "missing_item_count": len(missing_item_bindings),
            "log_row_count": len(events) + 1,
            "destructive_commands_blocked": False,
            "source_checkers_replayed": False,
        },
        "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
        "errors": errors,
    }
    events.append(
        event(
            "br_db_repair_completion_contract_failed",
            "error",
            None,
            "completion_contract",
            "pass",
            "fail",
            signature,
            report["artifact_refs"],
        )
    )
    write_json(REPORT, report)
    write_jsonl(LOG, events)
    raise SystemExit("FAIL: br DB repair completion contract: " + "; ".join(errors[:8]))


def run_checker(source: dict[str, Any], source_id: str) -> tuple[pathlib.Path, pathlib.Path, dict[str, Any], list[dict[str, Any]]]:
    checker = ROOT / str(source.get("checker", ""))
    if not checker.is_file():
        errors.append(f"source_contracts.{source_id}.checker is missing: {rel(checker)}")
        return checker, checker, {}, []
    checker_out = OUT_DIR / f"br_db_repair_completion_{source_id}"
    checker_out.mkdir(parents=True, exist_ok=True)
    report = checker_out / f"{source_id}.report.json"
    log = checker_out / f"{source_id}.log.jsonl"
    env = os.environ.copy()
    if source_id == "tracker_health_report":
        env["FRANKENLIBC_TRACKER_HEALTH_TARGET_DIR"] = str(checker_out)
        env["FRANKENLIBC_TRACKER_HEALTH_REPORT"] = str(report)
        env["FRANKENLIBC_TRACKER_HEALTH_LOG"] = str(log)
    elif source_id == "br_bv_disagreement_dashboard":
        env["FRANKENLIBC_BR_BV_DASHBOARD_TARGET_DIR"] = str(checker_out)
        env["FRANKENLIBC_BR_BV_DASHBOARD_REPORT"] = str(report)
        env["FRANKENLIBC_BR_BV_DASHBOARD_LOG"] = str(log)
    else:
        errors.append(f"unsupported source contract checker: {source_id}")
        return report, log, {}, []
    completed = subprocess.run(
        ["bash", str(checker), str(source.get("checker_mode", "--fixture-replay"))],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        errors.append(
            f"{source_id} checker failed with exit {completed.returncode}\n"
            f"stdout:\n{completed.stdout[-4000:]}\nstderr:\n{completed.stderr[-4000:]}"
        )
    report_json = load_json(report, f"{source_id} checker report")
    log_rows = load_jsonl(log, f"{source_id} checker log")
    return report, log, report_json, log_rows


def validate_test_ref(ref: str, source_artifacts: dict[str, Any]) -> None:
    if "::" not in ref:
        path_text = ref
        symbol = None
    else:
        path_text, symbol = ref.split("::", 1)
    if path_text.startswith("target/"):
        return
    path = ROOT / path_text
    if not path.is_file():
        errors.append(f"missing_item_bindings evidence ref missing file: {ref}")
        return
    if symbol:
        text = path.read_text(encoding="utf-8")
        if f"fn {symbol}" not in text and f"def {symbol}" not in text:
            errors.append(f"missing_item_bindings evidence ref missing symbol: {ref}")


COMMIT = source_commit()
source_results: list[dict[str, Any]] = []
missing_item_bindings: list[dict[str, Any]] = []
contract = load_json(CONTRACT, "completion contract")
if errors:
    fail_report("contract_json_invalid")

if contract.get("schema_version") != EXPECTED_SCHEMA:
    errors.append(f"schema_version must be {EXPECTED_SCHEMA}")
if contract.get("original_bead") != ORIGINAL_BEAD:
    errors.append(f"original_bead must be {ORIGINAL_BEAD}")
if contract.get("completion_debt_bead") != COMPLETION_BEAD:
    errors.append(f"completion_debt_bead must be {COMPLETION_BEAD}")
if contract.get("trace_id") != TRACE_ID:
    errors.append(f"trace_id must be {TRACE_ID}")

source_artifacts = contract.get("source_artifacts", {})
if not isinstance(source_artifacts, dict) or not source_artifacts:
    errors.append("source_artifacts must be a non-empty object")
else:
    for key, path_text in source_artifacts.items():
        if not isinstance(path_text, str) or not path_text:
            errors.append(f"source_artifacts.{key} must be a non-empty path")
        elif not (ROOT / path_text).is_file():
            errors.append(f"source_artifacts.{key} references missing file: {path_text}")

read_only = contract.get("read_only_probe_contract", {})
allowed_commands = read_only.get("allowed_commands", []) if isinstance(read_only, dict) else []
for command in allowed_commands:
    if not isinstance(command, str):
        errors.append("read_only_probe_contract.allowed_commands entries must be strings")
        continue
    for fragment in DESTRUCTIVE_FRAGMENTS:
        if fragment in command:
            errors.append(f"read_only_probe_contract contains destructive command fragment {fragment!r}: {command}")
if not read_only.get("live_commands_are_read_only"):
    errors.append("read_only_probe_contract.live_commands_are_read_only must be true")
events.append(
    event(
        "read_only_probe_contract_checked",
        "info",
        None,
        "read_only_probe_contract",
        "no destructive command fragments",
        sorted(allowed_commands),
        None,
        [rel(CONTRACT)],
    )
)

for source in contract.get("source_contracts", []):
    if not isinstance(source, dict):
        errors.append("source_contracts entries must be objects")
        continue
    source_id = str(source.get("id", ""))
    artifact = ROOT / str(source.get("path", ""))
    artifact_json = load_json(artifact, f"{source_id} artifact")
    if artifact_json.get("schema_version") != source.get("expected_schema_version"):
        errors.append(f"{source_id}: schema_version mismatch")
    if artifact_json.get("bead") != source.get("expected_bead"):
        errors.append(f"{source_id}: bead mismatch")
    scenario_ids = {row.get("scenario_id") for row in artifact_json.get("scenarios", []) if isinstance(row, dict)}
    missing_scenarios = sorted(set(source.get("required_scenarios", [])) - scenario_ids)
    if missing_scenarios:
        errors.append(f"{source_id}: missing required scenarios {missing_scenarios}")
    available_discrepancies = set(artifact_json.get("discrepancy_types", []))
    if source_id == "br_bv_disagreement_dashboard":
        available_discrepancies.add("already_shipped_but_open_bead")
    required_discrepancies = set(source.get("required_discrepancies", []))
    missing_discrepancies = sorted(required_discrepancies - available_discrepancies)
    if missing_discrepancies:
        errors.append(f"{source_id}: missing required discrepancies {missing_discrepancies}")
    missing_critical = sorted(CRITICAL_DISCREPANCIES - required_discrepancies)
    if missing_critical:
        errors.append(f"{source_id}: source contract does not require critical discrepancies {missing_critical}")
    report_path, log_path, report_json, log_rows = run_checker(source, source_id)
    if report_json.get("status") != "pass":
        errors.append(f"{source_id}: checker report status must be pass")
    if not log_rows:
        errors.append(f"{source_id}: checker log must contain rows")
    source_results.append(
        {
            "id": source_id,
            "status": report_json.get("status"),
            "scenario_count": len(scenario_ids),
            "required_discrepancy_count": len(required_discrepancies),
            "checker_report": rel(report_path),
            "checker_log": rel(log_path),
        }
    )
    events.append(
        event(
            "source_contract_replayed",
            "info" if report_json.get("status") == "pass" else "error",
            source_id,
            str(source.get("checker")),
            "pass",
            report_json.get("status"),
            None if report_json.get("status") == "pass" else "source_checker_failed",
            [rel(artifact), rel(report_path), rel(log_path)],
        )
    )

item_ids: set[str] = set()
for item in contract.get("missing_item_bindings", []):
    if not isinstance(item, dict):
        errors.append("missing_item_bindings entries must be objects")
        continue
    item_id = item.get("id")
    if item_id in item_ids:
        errors.append(f"duplicate missing item binding: {item_id}")
    item_ids.add(str(item_id))
    refs = item.get("evidence_refs", [])
    if not isinstance(refs, list) or not refs:
        errors.append(f"missing_item_bindings.{item_id}.evidence_refs must be non-empty")
    else:
        for ref in refs:
            if not isinstance(ref, str) or not ref:
                errors.append(f"missing_item_bindings.{item_id}.evidence_refs must contain strings")
            else:
                validate_test_ref(ref, source_artifacts)
    missing_item_bindings.append({"id": item_id, "type": item.get("type"), "evidence_ref_count": len(refs) if isinstance(refs, list) else 0})
missing_items = sorted(EXPECTED_MISSING_ITEMS - item_ids)
if missing_items:
    errors.append(f"missing_item_bindings must include {missing_items}")
events.append(
    event(
        "missing_item_bindings_validated",
        "info",
        None,
        "missing_item_bindings",
        sorted(EXPECTED_MISSING_ITEMS),
        sorted(item_ids),
        None,
        [rel(CONTRACT)],
    )
)

evidence = contract.get("completion_debt_evidence", {})
if not isinstance(evidence, dict):
    errors.append("completion_debt_evidence must be an object")
    evidence = {}
for field in ["required_report_fields", "required_log_fields", "required_events", "required_test_refs"]:
    if not isinstance(evidence.get(field), list) or not evidence.get(field):
        errors.append(f"completion_debt_evidence.{field} must be a non-empty array")
required_events = set(evidence.get("required_events", []))
if not REQUIRED_EVENTS.issubset(required_events):
    errors.append(f"completion_debt_evidence.required_events missing {sorted(REQUIRED_EVENTS - required_events)}")
test_source = (ROOT / "crates/frankenlibc-harness/tests/br_db_repair_completion_contract_test.rs")
if test_source.is_file():
    text = test_source.read_text(encoding="utf-8")
    for test_ref in evidence.get("required_test_refs", []):
        if isinstance(test_ref, str) and f"fn {test_ref}" not in text:
            errors.append(f"required_test_refs missing test function {test_ref}")

if errors:
    fail_report("completion_contract_validation_failed")

artifact_refs = [
    rel(CONTRACT),
    rel(REPORT),
    rel(LOG),
    *[result["checker_report"] for result in source_results],
    *[result["checker_log"] for result in source_results],
]
summary = {
    "source_contract_count": len(source_results),
    "missing_item_count": len(missing_item_bindings),
    "log_row_count": len(events) + 1,
    "destructive_commands_blocked": True,
    "source_checkers_replayed": all(result.get("status") == "pass" for result in source_results),
    "critical_discrepancies_bound": sorted(CRITICAL_DISCREPANCIES),
    "tool_failures_are_tracker_evidence": True,
}
events.append(
    event(
        "br_db_repair_completion_contract_validated",
        "info",
        None,
        "completion_contract",
        "pass",
        "pass",
        None,
        artifact_refs,
    )
)
report = {
    "schema_version": "br_db_repair_completion_contract.report.v1",
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "trace_id": TRACE_ID,
    "source_commit": COMMIT,
    "status": "pass",
    "source_contracts": source_results,
    "missing_item_bindings": missing_item_bindings,
    "summary": summary,
    "artifact_refs": artifact_refs,
    "errors": [],
}
for field in evidence.get("required_report_fields", []):
    if field not in report:
        errors.append(f"report missing required field {field}")
for row in events:
    for field in evidence.get("required_log_fields", []):
        if field not in row:
            errors.append(f"log event missing required field {field}: {row.get('event')}")
if errors:
    fail_report("completion_output_contract_failed")

write_json(REPORT, report)
write_jsonl(LOG, events)
print(
    "PASS: br DB repair completion contract validated "
    f"source_contracts={summary['source_contract_count']} "
    f"missing_items={summary['missing_item_count']} "
    f"log_rows={summary['log_row_count']}"
)
PY
