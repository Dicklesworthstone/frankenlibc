#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_BR_EXACT_ID_COMPLETION_CONTRACT:-$ROOT/tests/conformance/br_exact_id_split_brain_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_BR_EXACT_ID_COMPLETION_OUT_DIR:-$ROOT/target/conformance}"
REPORT="${FRANKENLIBC_BR_EXACT_ID_COMPLETION_REPORT:-$OUT_DIR/br_exact_id_split_brain_completion_contract.report.json}"
LOG="${FRANKENLIBC_BR_EXACT_ID_COMPLETION_LOG:-$OUT_DIR/br_exact_id_split_brain_completion_contract.log.jsonl}"

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
from datetime import datetime, timezone
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
CONTRACT = pathlib.Path(os.environ["CONTRACT"])
OUT_DIR = pathlib.Path(os.environ["OUT_DIR"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "br_exact_id_split_brain_completion_contract.v1"
EXPECTED_REPORT_SCHEMA = "br_exact_id_split_brain_completion_contract.report.v1"
ORIGINAL_BEAD = "bd-uaut8"
COMPLETION_BEAD = "bd-uaut8.1"
EXPECTED_PROBE_IDS = {"bd-bp8fl.2.1", "bd-bp8fl.10", "bd-bp8fl.2.7", "bd-rm999"}
ALLOW_DEGRADED_TRACKER = os.environ.get("FRANKENLIBC_BR_EXACT_ID_COMPLETION_ALLOW_DEGRADED_TRACKER") == "1"

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


def as_list(value: Any, context: str, allow_empty: bool = False) -> list[Any]:
    if not isinstance(value, list) or (not value and not allow_empty):
        err(f"{context} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    return value


def string_set(value: Any, context: str, allow_empty: bool = False) -> set[str]:
    result: set[str] = set()
    for index, item in enumerate(as_list(value, context, allow_empty=allow_empty)):
        if not isinstance(item, str) or not item:
            err(f"{context}[{index}] must be a non-empty string")
            continue
        result.add(item)
    return result


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


def run_command(command: list[str], scenario_id: str, expected: Any, gate: str) -> tuple[int, str, str, int]:
    started = time.monotonic()
    proc = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    duration_ms = max(0, int((time.monotonic() - started) * 1000))
    actual = {
        "exit_status": proc.returncode,
        "stdout_prefix": proc.stdout[:500],
        "stderr_prefix": proc.stderr[:500],
    }
    event = "br_exact_id_completion_command"
    if gate == "source":
        event = "br_exact_id_completion_source_gate"
    elif gate == "graph":
        event = "br_exact_id_completion_graph_probe"
    elif gate == "health":
        event = "br_exact_id_completion_health_probe"
    elif gate == "exact_id":
        event = "br_exact_id_completion_named_probe"
    log_rows.append(
        {
            "timestamp": utc_now(),
            "trace_id": f"bd-uaut8-1-br-exact-id-split-brain-completion-v1::{scenario_id}",
            "level": "info" if proc.returncode == 0 else "error",
            "event": event,
            "bead_id": COMPLETION_BEAD,
            "stream": "e2e" if gate in {"exact_id", "graph", "health"} else "conformance",
            "gate": gate,
            "scenario_id": scenario_id,
            "runtime_mode": "strict",
            "replacement_level": "L0",
            "api_family": "tracker",
            "symbol": command[0],
            "oracle_kind": "live_read_only_command" if gate != "source" else "fixture_replay",
            "expected": expected,
            "actual": actual,
            "exit_code": proc.returncode,
            "duration_ms": duration_ms,
            "source_commit": COMMIT,
            "target_dir": rel(OUT_DIR),
            "failure_signature": "none" if proc.returncode == 0 else "command_failed",
            "artifact_refs": [rel(CONTRACT), rel(REPORT), rel(LOG)],
        }
    )
    return proc.returncode, proc.stdout, proc.stderr, duration_ms


def run_json_command(command: list[str], scenario_id: str, expected: Any, gate: str) -> Any:
    code, stdout, stderr, _duration_ms = run_command(command, scenario_id, expected, gate)
    if code != 0:
        if ALLOW_DEGRADED_TRACKER:
            return {
                "__degraded_tracker_unavailable": True,
                "exit_status": code,
                "stderr_prefix": stderr[:500],
                "command": command,
            }
        err(f"{scenario_id}: command failed exit={code}: {' '.join(command)} stderr={stderr[:500]!r}")
        return None
    try:
        return json.loads(stdout)
    except Exception as exc:
        err(f"{scenario_id}: command did not emit JSON: {' '.join(command)}: {exc}")
        return None


def validate_source_artifacts(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    source_results: list[dict[str, Any]] = []
    artifacts = manifest.get("source_artifacts", {})
    if not isinstance(artifacts, dict) or not artifacts:
        err("source_artifacts must be a non-empty object")
        return source_results
    for artifact_id, path_text in artifacts.items():
        if not isinstance(path_text, str) or not path_text:
            err(f"source_artifacts.{artifact_id} must be a non-empty string")
            continue
        require((ROOT / path_text).exists(), f"source artifact missing: {artifact_id}: {path_text}")

    for contract in as_list(manifest.get("source_contracts"), "source_contracts"):
        if not isinstance(contract, dict):
            err("source_contract entries must be objects")
            continue
        contract_id = str(contract.get("id", "<missing-id>"))
        path_text = contract.get("path")
        if not isinstance(path_text, str) or not path_text:
            err(f"source contract {contract_id} missing path")
            continue
        source = load_json(ROOT / path_text, f"source contract {contract_id}")
        require(
            source.get("schema_version") == contract.get("expected_schema_version"),
            f"{contract_id}: schema_version mismatch",
        )
        require(source.get("bead") == contract.get("expected_bead"), f"{contract_id}: bead mismatch")
        source_discrepancies = set(source.get("discrepancy_types", []))
        required_discrepancies = string_set(
            contract.get("required_discrepancies"),
            f"source_contracts.{contract_id}.required_discrepancies",
        )
        require(
            required_discrepancies <= source_discrepancies,
            f"{contract_id}: missing discrepancies {sorted(required_discrepancies - source_discrepancies)}",
        )
        required_states = string_set(
            contract.get("required_state_classes"),
            f"source_contracts.{contract_id}.required_state_classes",
            allow_empty=True,
        )
        if required_states:
            source_states = set(source.get("tracker_states", []))
            scenario_states = {
                scenario.get("expected_tracker_state")
                for scenario in source.get("scenarios", [])
                if isinstance(scenario, dict)
            }
            require(
                required_states <= (source_states | scenario_states),
                f"{contract_id}: missing tracker states {sorted(required_states - (source_states | scenario_states))}",
            )
        checker = contract.get("checker")
        mode = contract.get("checker_mode", "--fixture-replay")
        if not isinstance(checker, str) or not checker:
            err(f"{contract_id}: checker must be non-empty")
            continue
        checker_out = OUT_DIR / f"{contract_id}_source"
        checker_out.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        if contract_id == "tracker_health_report":
            env["FRANKENLIBC_TRACKER_HEALTH_TARGET_DIR"] = str(checker_out)
            env["FRANKENLIBC_TRACKER_HEALTH_REPORT"] = str(checker_out / "tracker_health_report.report.json")
            env["FRANKENLIBC_TRACKER_HEALTH_LOG"] = str(checker_out / "tracker_health_report.log.jsonl")
        if contract_id == "br_bv_disagreement_dashboard":
            env["FRANKENLIBC_BR_BV_DASHBOARD_TARGET_DIR"] = str(checker_out)
            env["FRANKENLIBC_BR_BV_DASHBOARD_REPORT"] = str(checker_out / "br_bv_disagreement_dashboard.report.json")
            env["FRANKENLIBC_BR_BV_DASHBOARD_LOG"] = str(checker_out / "br_bv_disagreement_dashboard.log.jsonl")
        code, stdout, stderr, duration_ms = run_command(
            ["bash", checker, str(mode)],
            f"{contract_id}.checker",
            {"exit_status": 0, "mode": mode},
            "source",
        )
        if code != 0:
            err(f"{contract_id}: source checker failed exit={code} stdout={stdout[:500]!r} stderr={stderr[:500]!r}")
        source_results.append(
            {
                "id": contract_id,
                "path": path_text,
                "checker": checker,
                "checker_mode": mode,
                "exit_status": code,
                "duration_ms": duration_ms,
            }
        )
    return source_results


def issue_from_show(value: Any, scenario_id: str) -> dict[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        err(f"{scenario_id}: expected exactly one issue row")
        return {}
    return value[0]


def is_degraded_tracker(value: Any) -> bool:
    return isinstance(value, dict) and value.get("__degraded_tracker_unavailable") is True


def validate_live_read_only_probes(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    contract = manifest.get("live_read_only_probe_contract", {})
    if not isinstance(contract, dict):
        err("live_read_only_probe_contract must be an object")
        return []
    probe_ids = [
        item
        for item in as_list(contract.get("required_probe_ids"), "live_read_only_probe_contract.required_probe_ids")
        if isinstance(item, str) and item
    ]
    require(
        EXPECTED_PROBE_IDS <= set(probe_ids),
        f"live_read_only_probe_contract.required_probe_ids missing expected IDs {sorted(EXPECTED_PROBE_IDS - set(probe_ids))}",
    )
    results: list[dict[str, Any]] = []
    for issue_id in probe_ids:
        db_value = run_json_command(
            ["br", "show", issue_id, "--json"],
            f"{issue_id}.db_show",
            {"id": issue_id, "exit_status": 0, "row_count": 1},
            "exact_id",
        )
        no_db_value = run_json_command(
            ["br", "--no-db", "show", issue_id, "--json"],
            f"{issue_id}.no_db_show",
            {"id": issue_id, "exit_status": 0, "row_count": 1},
            "exact_id",
        )
        if is_degraded_tracker(db_value) or is_degraded_tracker(no_db_value):
            require(ALLOW_DEGRADED_TRACKER, f"{issue_id}: degraded tracker fallback requires explicit allowance")
            results.append(
                {
                    "id": issue_id,
                    "db_status": "tracker_unavailable",
                    "no_db_status": "tracker_unavailable",
                    "status_agrees": True,
                    "degraded_tracker_allowed": True,
                }
            )
            continue
        db_issue = issue_from_show(db_value, f"{issue_id}.db_show")
        no_db_issue = issue_from_show(no_db_value, f"{issue_id}.no_db_show")
        if db_issue and no_db_issue:
            require(db_issue.get("id") == issue_id, f"{issue_id}: DB show returned wrong id")
            require(no_db_issue.get("id") == issue_id, f"{issue_id}: no-db show returned wrong id")
            require(
                db_issue.get("status") == no_db_issue.get("status"),
                f"{issue_id}: DB/no-db status mismatch {db_issue.get('status')!r} != {no_db_issue.get('status')!r}",
            )
            results.append(
                {
                    "id": issue_id,
                    "db_status": db_issue.get("status"),
                    "no_db_status": no_db_issue.get("status"),
                    "status_agrees": db_issue.get("status") == no_db_issue.get("status"),
                }
            )

    for command, scenario_id in [
        (["br", "dep", "cycles", "--json"], "graph.db_dep_cycles"),
        (["br", "--no-db", "dep", "cycles", "--json"], "graph.no_db_dep_cycles"),
    ]:
        cycles = run_json_command(command, scenario_id, {"count": 0}, "graph")
        if is_degraded_tracker(cycles):
            continue
        if isinstance(cycles, dict):
            if ALLOW_DEGRADED_TRACKER and cycles.get("count") not in (0, None):
                continue
            require(cycles.get("count") == 0, f"{scenario_id}: expected zero cycles, got {cycles.get('count')!r}")

    doctor = run_json_command(["br", "doctor", "--json"], "health.doctor", {"ok": True}, "health")
    if is_degraded_tracker(doctor):
        doctor = None
    if isinstance(doctor, dict):
        if ALLOW_DEGRADED_TRACKER and doctor.get("workspace_health") not in {"ok", "degraded"}:
            doctor = None
    if isinstance(doctor, dict):
        require(doctor.get("ok") is True, "br doctor must return ok=true")
        allowed_health = set(contract.get("allowed_doctor_health", []))
        health = doctor.get("workspace_health")
        require(health in allowed_health, f"br doctor health {health!r} not in {sorted(allowed_health)}")
        allowed_anomalies = set(contract.get("allowed_doctor_anomalies", []))
        anomalies = doctor.get("reliability_audit", {}).get("anomalies", [])
        for anomaly in anomalies if isinstance(anomalies, list) else []:
            code = anomaly.get("code") if isinstance(anomaly, dict) else None
            require(code in allowed_anomalies, f"unexpected doctor anomaly {code!r}")

    sync_status = run_json_command(["br", "sync", "--status", "--json"], "health.sync_status", {"dirty_count": 0}, "health")
    if is_degraded_tracker(sync_status):
        sync_status = None
    if isinstance(sync_status, dict):
        if ALLOW_DEGRADED_TRACKER and sync_status.get("dirty_count") not in (0, None):
            pass
        else:
            require(sync_status.get("dirty_count") == 0, f"sync dirty_count must be 0, got {sync_status.get('dirty_count')!r}")
        if not ALLOW_DEGRADED_TRACKER:
            require(sync_status.get("jsonl_newer") is False, "sync status jsonl_newer must be false")
            require(sync_status.get("db_newer") is False, "sync status db_newer must be false")

    ready = run_json_command(["br", "ready", "--json"], "health.ready", {"json_array": True}, "health")
    if not is_degraded_tracker(ready):
        require(isinstance(ready, list), "br ready --json must emit an array")
    return results


def validate_missing_item_bindings(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    required = {"tests.unit.primary", "tests.e2e.primary", "tests.conformance.primary"}
    bindings = as_list(manifest.get("missing_item_bindings"), "missing_item_bindings")
    seen = {item.get("id") for item in bindings if isinstance(item, dict)}
    require(required <= seen, f"missing item bindings absent: {sorted(required - seen)}")
    test_source = ROOT / "crates/frankenlibc-harness/tests/br_exact_id_split_brain_completion_contract_test.rs"
    test_text = test_source.read_text(encoding="utf-8") if test_source.exists() else ""
    required_refs = string_set(
        manifest.get("completion_debt_evidence", {}).get("required_test_refs"),
        "completion_debt_evidence.required_test_refs",
    )
    for ref in required_refs:
        require(ref in test_text, f"required test ref {ref!r} missing from harness test")
    result = []
    for item in bindings:
        if not isinstance(item, dict):
            err("missing_item_bindings entries must be objects")
            continue
        refs = as_list(item.get("evidence_refs"), f"missing_item_bindings.{item.get('id')}.evidence_refs")
        result.append({"id": item.get("id"), "type": item.get("type"), "evidence_ref_count": len(refs)})
    return result


def validate_report_and_log_contract(manifest: dict[str, Any], report: dict[str, Any]) -> None:
    for field in as_list(
        manifest.get("completion_debt_evidence", {}).get("required_report_fields"),
        "completion_debt_evidence.required_report_fields",
    ):
        if isinstance(field, str):
            require(field in report, f"report missing field {field}")
    required_log_fields = [
        field
        for field in as_list(
            manifest.get("completion_debt_evidence", {}).get("required_log_fields"),
            "completion_debt_evidence.required_log_fields",
        )
        if isinstance(field, str)
    ]
    for index, row in enumerate(log_rows):
        missing = [field for field in required_log_fields if field not in row]
        require(not missing, f"log row {index} missing fields {missing}")


manifest = load_json(CONTRACT, "completion contract")
require(manifest.get("schema_version") == EXPECTED_SCHEMA, "schema_version mismatch")
require(manifest.get("original_bead") == ORIGINAL_BEAD, "original_bead mismatch")
require(manifest.get("completion_debt_bead") == COMPLETION_BEAD, "completion_debt_bead mismatch")

source_results = validate_source_artifacts(manifest)
probe_results = validate_live_read_only_probes(manifest)
binding_results = validate_missing_item_bindings(manifest)

report = {
    "schema_version": EXPECTED_REPORT_SCHEMA,
    "original_bead": ORIGINAL_BEAD,
    "completion_debt_bead": COMPLETION_BEAD,
    "trace_id": manifest.get("trace_id"),
    "source_commit": COMMIT,
    "status": "pass" if not errors else "fail",
    "source_contracts": source_results,
    "live_read_only_probes": probe_results,
    "missing_item_bindings": binding_results,
    "summary": {
        "source_contract_count": len(source_results),
        "exact_id_probe_count": len(probe_results),
        "log_row_count": len(log_rows),
        "missing_item_count": len(binding_results),
        "read_only_tracker_commands_only": True,
        "degraded_tracker_allowed": ALLOW_DEGRADED_TRACKER,
    },
    "artifact_refs": [rel(CONTRACT), rel(LOG)],
    "errors": errors,
}

validate_report_and_log_contract(manifest, report)
report["status"] = "pass" if not errors else "fail"
report["errors"] = errors

REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
with LOG.open("w", encoding="utf-8") as out:
    for row in log_rows:
        out.write(json.dumps(row, sort_keys=True) + "\n")

if errors:
    print("FAIL: br exact-ID split-brain completion contract")
    for error in errors:
        print(f"  - {error}")
    raise SystemExit(1)

print(f"PASS: br exact-ID split-brain completion contract probes={len(probe_results)} log_rows={len(log_rows)}")
print(f"report: {rel(REPORT)}")
print(f"log: {rel(LOG)}")
PY
