#!/usr/bin/env bash
# Validate the current residual replacement call-through blocker truth.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${RESIDUAL_REPLACEMENT_CONTRACT:-${ROOT}/tests/conformance/residual_replacement_callthrough_blockers.v1.json}"
OUT_DIR="${RESIDUAL_REPLACEMENT_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${RESIDUAL_REPLACEMENT_REPORT:-${OUT_DIR}/residual_replacement_callthrough_blockers.report.json}"
LOG="${RESIDUAL_REPLACEMENT_LOG:-${OUT_DIR}/residual_replacement_callthrough_blockers.log.jsonl}"
REPLACEMENT_REPORT="${RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_REPORT:-${OUT_DIR}/replacement_guard.replacement.report.json}"
REPLACEMENT_LOG="${RESIDUAL_REPLACEMENT_GUARD_REPLACEMENT_LOG:-${OUT_DIR}/replacement_guard.replacement.log.jsonl}"
INTERPOSE_REPORT="${RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_REPORT:-${OUT_DIR}/replacement_guard.interpose.report.json}"
INTERPOSE_LOG="${RESIDUAL_REPLACEMENT_GUARD_INTERPOSE_LOG:-${OUT_DIR}/replacement_guard.interpose.log.jsonl}"
RUN_GUARD="${RESIDUAL_REPLACEMENT_RUN_GUARD:-1}"
TRACE_ID="bd-0agsk.9::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

MODE="validate-only"
if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:${1}"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:${1}"
fi

mkdir -p "${OUT_DIR}" "$(dirname "${REPLACEMENT_REPORT}")" "$(dirname "${INTERPOSE_REPORT}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${REPLACEMENT_REPORT}" "${REPLACEMENT_LOG}" "${INTERPOSE_REPORT}" "${INTERPOSE_LOG}" "${RUN_GUARD}" "${TRACE_ID}" "${MODE}" <<'PY'
import json
import os
import pathlib
import subprocess
import sys
import time

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
replacement_report_path = pathlib.Path(sys.argv[5])
replacement_log_path = pathlib.Path(sys.argv[6])
interpose_report_path = pathlib.Path(sys.argv[7])
interpose_log_path = pathlib.Path(sys.argv[8])
run_guard = sys.argv[9] != "0"
trace_id = sys.argv[10]
mode = sys.argv[11]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "residual_replacement_callthrough_blockers.v1"
EXPECTED_BEAD = "bd-0agsk.9"


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def git_head() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def write_event(report, event_name: str) -> None:
    event = {
        "timestamp": now_utc(),
        "trace_id": trace_id,
        "level": "error" if report.get("outcome") == "fail" else "info",
        "event": event_name,
        "bead_id": EXPECTED_BEAD,
        "source_commit": report.get("source_commit"),
        "artifact_refs": [
            str(contract_path),
            str(report_path),
            str(replacement_report_path),
            str(interpose_report_path),
        ],
        "outcome": report.get("outcome"),
        "failure_signature": report.get("failure_signature"),
        "duration_ms": report.get("duration_ms"),
        "details": report.get("summary", {}),
    }
    log_path.write_text(json.dumps(event, sort_keys=True) + "\n", encoding="utf-8")


def finish(report, event_name: str) -> None:
    report["duration_ms"] = (time.time_ns() - start_ns) // 1_000_000
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_event(report, event_name)


def fail(signature: str, message: str, **extra) -> None:
    report = {
        "schema_version": "residual_replacement_callthrough_blockers.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": trace_id,
        "source_commit": extra.pop("source_commit", None),
        "mode": mode,
        "outcome": "fail",
        "failure_signature": signature,
        "failure_message": message,
        "contract": str(contract_path),
        "summary": extra,
    }
    finish(report, "residual_replacement_callthrough_blockers_failed")
    raise SystemExit(f"FAIL[{signature}]: {message}")


def run_replacement_guard(guard_mode: str, report: pathlib.Path, log: pathlib.Path, source_commit: str) -> None:
    env = os.environ.copy()
    env["FRANKENLIBC_REPLACEMENT_GUARD_REPORT"] = str(report)
    env["FRANKENLIBC_REPLACEMENT_GUARD_LOG"] = str(log)
    command = [str(root / "scripts/check_replacement_guard.sh"), guard_mode]
    completed = subprocess.run(command, cwd=root, text=True, capture_output=True, env=env, check=False)
    if completed.returncode != 0:
        fail(
            "replacement_guard_failed",
            f"replacement guard failed in {guard_mode} mode",
            source_commit=source_commit,
            guard_mode=guard_mode,
            stdout=completed.stdout[-4000:],
            stderr=completed.stderr[-4000:],
        )


def validate_guard_report(path: pathlib.Path, expected_mode: str, source_commit: str) -> dict:
    if not path.is_file():
        fail("guard_report_missing", f"guard report missing: {path}", source_commit=source_commit, guard_mode=expected_mode)
    report = load_json(path)
    if report.get("schema_version") != "v1":
        fail("guard_report_schema_invalid", f"{expected_mode}: schema_version must be v1", source_commit=source_commit, guard_mode=expected_mode)
    if report.get("mode") != expected_mode:
        fail("guard_report_schema_invalid", f"{expected_mode}: report mode mismatch", source_commit=source_commit, guard_mode=expected_mode, actual_mode=report.get("mode"))
    required_numeric = [
        "total_call_throughs",
        "modules_with_call_throughs",
        "violations",
        "mutex_forbidden_count",
    ]
    for field in required_numeric:
        if not isinstance(report.get(field), int):
            fail("guard_report_schema_invalid", f"{expected_mode}: {field} must be an integer", source_commit=source_commit, guard_mode=expected_mode, field=field)
    if report.get("ok") is not True:
        fail("residual_callthrough_reintroduced", f"{expected_mode}: guard report is not ok", source_commit=source_commit, guard_mode=expected_mode, guard_report=rel(path))
    forbidden_count = int(report.get("violations", 0)) + int(report.get("mutex_forbidden_count", 0))
    total_call_throughs = int(report.get("total_call_throughs", 0))
    modules = sorted(str(module) for module in report.get("module_counts", {}).keys())
    symbols = [
        {
            "module": row.get("module"),
            "symbol": row.get("symbol"),
            "source_pattern": row.get("source_pattern"),
            "callthrough_count": row.get("callthrough_count"),
        }
        for row in report.get("symbol_rankings", [])
        if isinstance(row, dict)
    ]
    if forbidden_count != 0 or total_call_throughs != 0 or modules or symbols:
        fail(
            "residual_callthrough_reintroduced",
            f"{expected_mode}: residual call-through blocker count is nonzero",
            source_commit=source_commit,
            guard_mode=expected_mode,
            guard_report=rel(path),
            total_call_throughs=total_call_throughs,
            forbidden_count=forbidden_count,
            modules=modules,
            symbols=symbols,
        )
    return {
        "mode": expected_mode,
        "ok": True,
        "total_call_throughs": total_call_throughs,
        "modules_with_call_throughs": int(report.get("modules_with_call_throughs", 0)),
        "violations": int(report.get("violations", 0)),
        "mutex_forbidden_count": int(report.get("mutex_forbidden_count", 0)),
        "forbidden_modules": modules,
        "forbidden_symbols": symbols,
        "guard_report": rel(path),
        "guard_log": rel(pathlib.Path(report.get("log_jsonl", ""))) if report.get("log_jsonl") else rel(path.with_suffix(".log.jsonl")),
    }


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")
if not contract_path.is_file():
    fail("contract_missing", f"contract missing: {contract_path}")

source_commit = git_head()
contract = load_json(contract_path)
if contract.get("schema_version") != EXPECTED_SCHEMA:
    fail("contract_schema_version", f"contract schema_version must be {EXPECTED_SCHEMA}", source_commit=source_commit)
if contract.get("generated_by_bead") != EXPECTED_BEAD:
    fail("contract_schema_version", f"contract generated_by_bead must be {EXPECTED_BEAD}", source_commit=source_commit)

stale_reconciliation = contract.get("stale_ledger_reconciliation", {})
todo_ids = stale_reconciliation.get("todo_ids")
if not isinstance(todo_ids, list) or sorted(todo_ids) != ["TODO-0203f", "TODO-0204", "TODO-0205", "TODO-0206"]:
    fail("stale_reconciliation_invalid", "stale ledger reconciliation must list TODO-0203f/TODO-0204/TODO-0205/TODO-0206", source_commit=source_commit)

if run_guard:
    run_replacement_guard("replacement", replacement_report_path, replacement_log_path, source_commit)
    run_replacement_guard("interpose", interpose_report_path, interpose_log_path, source_commit)

replacement = validate_guard_report(replacement_report_path, "replacement", source_commit)
interpose = validate_guard_report(interpose_report_path, "interpose", source_commit)

current_truth = contract.get("current_truth", {})
if current_truth.get("residual_forbidden_count") != 0:
    fail("contract_schema_version", "current_truth.residual_forbidden_count must be zero for this bead", source_commit=source_commit)
if current_truth.get("followup_child_beads_created") is not False:
    fail("stale_reconciliation_invalid", "zero residual blockers must not create child beads", source_commit=source_commit)

summary = {
    "source_commit": source_commit,
    "residual_forbidden_count": 0,
    "claim_status": current_truth.get("claim_status", "replacement_callthrough_blockers_cleared"),
    "replacement_total_call_throughs": replacement["total_call_throughs"],
    "interpose_total_call_throughs": interpose["total_call_throughs"],
    "replacement_modules": replacement["forbidden_modules"],
    "interpose_modules": interpose["forbidden_modules"],
    "replacement_symbols": replacement["forbidden_symbols"],
    "interpose_symbols": interpose["forbidden_symbols"],
    "followup_child_beads_created": False,
}

report = {
    "schema_version": "residual_replacement_callthrough_blockers.report.v1",
    "bead": EXPECTED_BEAD,
    "trace_id": trace_id,
    "source_commit": source_commit,
    "mode": mode,
    "outcome": "pass",
    "failure_signature": None,
    "contract": str(contract_path),
    "summary": summary,
    "replacement": replacement,
    "interpose": interpose,
    "stale_ledger_reconciliation": stale_reconciliation,
    "checks": {
        "replacement_guard_reports_current": "pass" if run_guard else "pass_supplied_reports",
        "zero_residual_forbidden_count": "pass",
        "stale_ledger_reconciled": "pass",
        "followup_child_beads_not_created": "pass",
    },
}
finish(report, "residual_replacement_callthrough_blockers_validated")
print(
    "PASS: residual replacement call-through blockers validated "
    "replacement=0 interpose=0 residual=0"
)
PY
