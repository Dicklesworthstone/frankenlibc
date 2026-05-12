#!/usr/bin/env bash
# Validate bd-l93x.5.1 symbol-latency budget completion evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_CONTRACT:-${ROOT}/tests/conformance/symbol_latency_budget_completion_contract.v1.json}"
OUT_DIR="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_OUT_DIR:-${ROOT}/target/conformance/symbol_latency_budget_completion}"
REPORT="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_REPORT:-${OUT_DIR}/symbol_latency_budget_completion_contract.report.json}"
LOG="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_COMPLETION_LOG:-${OUT_DIR}/symbol_latency_budget_completion_contract.events.jsonl}"
SYMBOL_REPORT="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_SYMBOL_REPORT:-${OUT_DIR}/symbol_latency_perf_gate.current.v1.json}"
SYMBOL_LOG="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_SYMBOL_LOG:-${OUT_DIR}/symbol_latency_perf_gate.events.jsonl}"
SYMBOL_GENERATED="${FRANKENLIBC_SYMBOL_LATENCY_BUDGET_SYMBOL_GENERATED:-${OUT_DIR}/symbol_latency_baseline.generated.v1.json}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${REPORT}" "${LOG}" "${SYMBOL_REPORT}" "${SYMBOL_LOG}" "${SYMBOL_GENERATED}" <<'PY'
from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys
import time
from collections import Counter
from typing import Any

ROOT = pathlib.Path(sys.argv[1]).resolve()
CONTRACT = pathlib.Path(sys.argv[2]).resolve()
REPORT = pathlib.Path(sys.argv[3]).resolve()
LOG = pathlib.Path(sys.argv[4]).resolve()
SYMBOL_REPORT = pathlib.Path(sys.argv[5]).resolve()
SYMBOL_LOG = pathlib.Path(sys.argv[6]).resolve()
SYMBOL_GENERATED = pathlib.Path(sys.argv[7]).resolve()

SCHEMA = "symbol_latency_budget_completion_contract.v1"
REPORT_SCHEMA = "symbol_latency_budget_completion_contract.report.v1"
LOG_SCHEMA = "symbol_latency_budget_completion_contract.log.v1"
ORIGINAL_BEAD = "bd-l93x.5"
COMPLETION_BEAD = "bd-l93x.5.1"
TRACE_ID = "bd-l93x-5-1-symbol-latency-budget-completion-v1"
EXPECTED_MISSING = {"tests.conformance.primary", "telemetry.primary"}
REQUIRED_SOURCE_IDS = {
    "canonical_baseline",
    "perf_budget_policy",
    "baseline_checker",
    "benchmark_gate",
    "ci_wiring",
    "baseline_harness",
    "completion_contract",
    "completion_checker",
    "completion_harness",
}
REQUIRED_COMPLETION_EVENTS = {
    "symbol_latency_budget.source_artifacts_validated",
    "symbol_latency_budget.conformance_binding_validated",
    "symbol_latency_budget.telemetry_validated",
    "symbol_latency_budget.budget_gate_replayed",
    "symbol_latency_budget.completion_contract_validated",
    "symbol_latency_budget.completion_contract_failed",
}
REQUIRED_SYMBOL_EVENTS = {
    "ci.symbol_latency_budget.pass",
    "ci.symbol_latency_budget.waived_target_violation",
}

errors: list[str] = []
events: list[dict[str, Any]] = []
symbol_event_counts: Counter[str] = Counter()
symbol_summary: dict[str, Any] = {}
source_count = 0
implementation_ref_count = 0


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path | str) -> str:
    path = pathlib.Path(path)
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "--short", "HEAD"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def error(message: str) -> None:
    errors.append(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        error(message)


def load_json(path: pathlib.Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        error(f"{label} unreadable: {rel(path)}: {exc}")
        return {}


def string_array(value: Any, label: str, allow_empty: bool = False) -> list[str]:
    if not isinstance(value, list) or (not value and not allow_empty):
        error(f"{label} must be a {'possibly empty ' if allow_empty else 'non-empty '}array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            error(f"{label}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def append_event(event: str, status: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "schema_version": LOG_SCHEMA,
            "timestamp": utc_now(),
            "trace_id": f"{TRACE_ID}:{event}",
            "event": event,
            "level": "info" if status == "pass" else "error",
            "status": status,
            "completion_debt_bead": COMPLETION_BEAD,
            "original_bead": ORIGINAL_BEAD,
            "source_commit": SOURCE_COMMIT,
            "artifact_refs": [rel(CONTRACT), rel(REPORT)],
            "details": details,
        }
    )


def validate_file_line_ref(value: Any, label: str) -> None:
    if not isinstance(value, str) or ":" not in value:
        error(f"{label} must be file:line")
        return
    path_text, line_text = value.rsplit(":", 1)
    if not path_text or not line_text.isdigit() or int(line_text) <= 0:
        error(f"{label} must be file:line")
        return
    path = ROOT / path_text
    if not path.is_file():
        error(f"{label} references missing file: {value}")
        return
    lines = path.read_text(encoding="utf-8").splitlines()
    line_no = int(line_text)
    if line_no > len(lines):
        error(f"{label} references line past EOF: {value}")
    elif not lines[line_no - 1].strip():
        error(f"{label} references blank line: {value}")


def validate_executable(path: pathlib.Path, label: str) -> None:
    if not path.is_file():
        error(f"{label} missing: {rel(path)}")
        return
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        error(f"{label} stat failed: {rel(path)}: {exc}")
        return
    if not (mode & stat.S_IXUSR):
        error(f"{label} must be executable: {rel(path)}")


def validate_sources(contract: dict[str, Any]) -> None:
    global source_count
    sources = contract.get("source_artifacts")
    if not isinstance(sources, list):
        error("source_artifacts must be an array")
        return
    ids: set[str] = set()
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            error(f"source_artifacts[{index}] must be an object")
            continue
        source_id = source.get("id")
        path_text = source.get("path")
        if not isinstance(source_id, str) or not source_id:
            error(f"source_artifacts[{index}].id must be a non-empty string")
            continue
        ids.add(source_id)
        if not isinstance(path_text, str) or not path_text:
            error(f"source artifact {source_id} path must be a non-empty string")
            continue
        path = ROOT / path_text
        if not path.is_file():
            error(f"source artifact {source_id} missing: {path_text}")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for needle in string_array(
            source.get("required_needles"),
            f"source artifact {source_id} required_needles",
        ):
            if needle not in text:
                error(f"source artifact {source_id} missing required needle: {needle}")
    missing = REQUIRED_SOURCE_IDS - ids
    extra = ids - REQUIRED_SOURCE_IDS
    if missing:
        error(f"source_artifacts missing required ids: {sorted(missing)}")
    if extra:
        error(f"source_artifacts contains unexpected ids: {sorted(extra)}")
    source_count = len(ids)
    append_event(
        "symbol_latency_budget.source_artifacts_validated",
        "pass" if not errors else "fail",
        {"source_count": source_count},
    )


def validate_contract_shape(contract: dict[str, Any]) -> None:
    global implementation_ref_count
    require(contract.get("schema_version") == SCHEMA, "schema_version drifted")
    require(contract.get("original_bead") == ORIGINAL_BEAD, "original_bead drifted")
    require(
        contract.get("completion_debt_bead") == COMPLETION_BEAD,
        "completion_debt_bead drifted",
    )
    require(contract.get("trace_id") == TRACE_ID, "trace_id drifted")
    audit = contract.get("audit_reference", {})
    require(isinstance(audit, dict), "audit_reference must be an object")
    require(audit.get("score_before") == 470, "audit_reference.score_before drifted")
    require(
        isinstance(audit.get("score_threshold"), int)
        and audit.get("score_threshold") >= 800,
        "audit_reference.score_threshold must be at least 800",
    )
    evidence = contract.get("completion_debt_evidence", {})
    require(isinstance(evidence, dict), "completion_debt_evidence must be an object")
    missing_items = set(
        string_array(
            evidence.get("missing_items_closed"),
            "completion_debt_evidence.missing_items_closed",
        )
    )
    if "tests.conformance.primary" not in missing_items:
        error("missing_items_closed must bind tests.conformance.primary")
    if "telemetry.primary" not in missing_items:
        error("missing_items_closed must bind telemetry.primary")
    if missing_items != EXPECTED_MISSING:
        error(f"missing_items_closed drifted: {sorted(missing_items)}")
    require(
        evidence.get("next_audit_score_threshold") == 800,
        "next_audit_score_threshold must be 800",
    )
    implementation_refs = string_array(
        contract.get("implementation_refs"),
        "implementation_refs",
    )
    implementation_ref_count = len(implementation_refs)
    for index, reference in enumerate(implementation_refs):
        validate_file_line_ref(reference, f"implementation_refs[{index}]")


def validate_conformance_binding(contract: dict[str, Any], baseline: dict[str, Any]) -> None:
    conformance = contract.get("conformance_primary")
    if not isinstance(conformance, dict):
        error("conformance_primary must be an object")
        return
    require(
        conformance.get("missing_item_id") == "tests.conformance.primary",
        "conformance_primary.missing_item_id drifted",
    )
    test_names = {
        row.get("name")
        for row in conformance.get("required_test_refs", [])
        if isinstance(row, dict)
    }
    required_tests = {
        "artifact_exists_and_valid",
        "summary_counts_consistent",
        "perf_budget_report_is_emitted_with_policy_aware_summary",
        "drift_gate_script_passes",
        "checker_accepts_contract_and_replays_budget_gate",
    }
    if not required_tests.issubset(test_names):
        error(f"conformance_primary.required_test_refs missing {sorted(required_tests - test_names)}")
    commands = set(string_array(conformance.get("required_commands"), "conformance_primary.required_commands"))
    required_commands = {
        "bash scripts/check_symbol_latency_budget_completion_contract.sh",
        "bash scripts/check_symbol_latency_baseline.sh",
        "rch exec -- cargo test -p frankenlibc-harness --test symbol_latency_budget_completion_contract_test -- --nocapture",
        "rch exec -- cargo test -p frankenlibc-harness --test symbol_latency_baseline_test -- --nocapture",
    }
    if not required_commands.issubset(commands):
        error(f"conformance_primary.required_commands missing {sorted(required_commands - commands)}")
    required_summary = conformance.get("required_baseline_summary", {})
    if not isinstance(required_summary, dict):
        error("conformance_primary.required_baseline_summary must be object")
        required_summary = {}
    summary = baseline.get("summary", {})
    ingestion = baseline.get("ingestion", {})
    measured = summary.get("mode_percentile_measured_counts", {})
    total_symbols = summary.get("total_symbols", 0)
    strict_hotpaths = summary.get("strict_hotpath_symbols", 0)
    require(
        isinstance(total_symbols, int)
        and total_symbols >= required_summary.get("minimum_total_symbols", 0),
        "baseline total_symbols below completion threshold",
    )
    require(
        isinstance(strict_hotpaths, int)
        and strict_hotpaths >= required_summary.get("minimum_strict_hotpath_symbols", 0),
        "baseline strict_hotpath_symbols below completion threshold",
    )
    for mode in ("raw", "strict", "hardened"):
        p50 = measured.get(mode, {}).get("p50")
        require(
            isinstance(p50, int)
            and p50 >= required_summary.get("minimum_measured_symbols_per_mode", 0),
            f"baseline measured {mode}.p50 below completion threshold",
        )
    require(
        ingestion.get("updated_symbols", 0) >= required_summary.get("minimum_updated_symbols", 0),
        "ingestion.updated_symbols below completion threshold",
    )
    require(
        ingestion.get("updated_modes", 0) >= required_summary.get("minimum_updated_modes", 0),
        "ingestion.updated_modes below completion threshold",
    )
    append_event(
        "symbol_latency_budget.conformance_binding_validated",
        "pass" if not errors else "fail",
        {
            "total_symbols": total_symbols,
            "strict_hotpath_symbols": strict_hotpaths,
            "updated_symbols": ingestion.get("updated_symbols"),
            "updated_modes": ingestion.get("updated_modes"),
        },
    )


def validate_policy_and_telemetry_binding(contract: dict[str, Any], policy: dict[str, Any]) -> None:
    telemetry = contract.get("telemetry_primary")
    if not isinstance(telemetry, dict):
        error("telemetry_primary must be an object")
        return
    require(
        telemetry.get("missing_item_id") == "telemetry.primary",
        "telemetry_primary.missing_item_id drifted",
    )
    symbol_events = set(
        string_array(
            telemetry.get("required_symbol_latency_events"),
            "telemetry_primary.required_symbol_latency_events",
        )
    )
    missing_symbol_events = REQUIRED_SYMBOL_EVENTS - symbol_events
    if missing_symbol_events:
        error(
            "telemetry_primary.required_symbol_latency_events missing "
            f"{sorted(missing_symbol_events)}"
        )
    completion_events = set(
        string_array(
            telemetry.get("required_completion_events"),
            "telemetry_primary.required_completion_events",
        )
    )
    missing_completion_events = REQUIRED_COMPLETION_EVENTS - completion_events
    if missing_completion_events:
        error(
            "telemetry_primary.required_completion_events missing "
            f"{sorted(missing_completion_events)}"
        )
    required_fields = set(
        string_array(
            telemetry.get("required_report_fields"),
            "telemetry_primary.required_report_fields",
        )
    )
    for field in [
        "schema_version",
        "status",
        "completion_debt_bead",
        "original_bead",
        "measured_symbol_count",
        "symbol_latency_report",
        "symbol_latency_log",
        "failure_signature",
    ]:
        if field not in required_fields:
            error(f"telemetry_primary.required_report_fields missing {field}")
    budgets = telemetry.get("required_policy_budgets", {})
    if not isinstance(budgets, dict):
        error("telemetry_primary.required_policy_budgets must be object")
        budgets = {}
    strict_req = budgets.get("strict_hotpath", {})
    strict_policy = policy.get("budgets", {}).get("strict_hotpath", {})
    if strict_req.get("strict_mode_ns") != strict_policy.get("strict_mode_ns"):
        error("telemetry_primary.required_policy_budgets strict_hotpath.strict_mode_ns drifted")
    if strict_req.get("hardened_mode_ns") != strict_policy.get("hardened_mode_ns"):
        error("telemetry_primary.required_policy_budgets strict_hotpath.hardened_mode_ns drifted")
    if strict_policy.get("strict_mode_ns") != 20:
        error("perf policy strict_hotpath.strict_mode_ns must remain 20")
    if strict_policy.get("hardened_mode_ns") != 200:
        error("perf policy strict_hotpath.hardened_mode_ns must remain 200")


def replay_symbol_latency_gate(contract: dict[str, Any]) -> None:
    env = os.environ.copy()
    env["FRANKENLIBC_SYMBOL_LATENCY_REPORT"] = str(SYMBOL_REPORT)
    env["FRANKENLIBC_SYMBOL_LATENCY_EVENT_LOG"] = str(SYMBOL_LOG)
    env["FRANKENLIBC_SYMBOL_LATENCY_GENERATED"] = str(SYMBOL_GENERATED)
    env.setdefault("FRANKENLIBC_SYMBOL_LATENCY_ALLOW_WAIVED_TARGET_VIOLATIONS", "1")
    proc = subprocess.run(
        ["bash", "scripts/check_symbol_latency_baseline.sh"],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        error(
            "check_symbol_latency_baseline.sh failed: "
            f"status={proc.returncode} stdout={proc.stdout!r} stderr={proc.stderr!r}"
        )
        append_event(
            "symbol_latency_budget.budget_gate_replayed",
            "fail",
            {"status": proc.returncode},
        )
        return
    if "symbol_latency_perf_budget_gate:" not in proc.stdout:
        error("symbol latency gate stdout missing perf budget summary")
    if "check_symbol_latency_baseline: PASS" not in proc.stdout:
        error("symbol latency gate stdout missing PASS summary")
    symbol_report = load_json(SYMBOL_REPORT, "symbol latency report")
    if not isinstance(symbol_report, dict):
        error("symbol latency report must be object")
        return
    summary = symbol_report.get("summary", {})
    if not isinstance(summary, dict):
        error("symbol latency report summary must be object")
        summary = {}
    global symbol_summary, symbol_event_counts
    symbol_summary = summary
    telemetry = contract.get("telemetry_primary", {})
    required_summary = telemetry.get("required_summary", {}) if isinstance(telemetry, dict) else {}
    if not isinstance(required_summary, dict):
        required_summary = {}
    require(symbol_report.get("schema_version") == 1, "symbol latency report schema drifted")
    require(symbol_report.get("bead") == ORIGINAL_BEAD, "symbol latency report bead drifted")
    require(symbol_report.get("trace_id") == "bd-l93x.5::symbol-latency-budget-gate", "symbol latency report trace drifted")
    require(summary.get("gate_passed") is True, "symbol latency gate_passed must be true")
    require(
        summary.get("allow_waived_target_violations") is True,
        "symbol latency report must allow current waived target violations",
    )
    require(
        summary.get("measured_symbol_count", 0)
        >= required_summary.get("minimum_measured_symbol_count", 0),
        "symbol latency measured_symbol_count below telemetry threshold",
    )
    require(
        summary.get("evaluated_mode_count", 0)
        >= required_summary.get("minimum_evaluated_mode_count", 0),
        "symbol latency evaluated_mode_count below telemetry threshold",
    )
    required_waivers = set(required_summary.get("required_active_waiver_beads", []))
    active_waivers = set(summary.get("active_waiver_beads", []))
    if not required_waivers.issubset(active_waivers):
        error(f"symbol latency report missing active waiver beads: {sorted(required_waivers - active_waivers)}")
    if not SYMBOL_LOG.is_file():
        error(f"symbol latency log missing: {rel(SYMBOL_LOG)}")
        return
    for line_no, line in enumerate(SYMBOL_LOG.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            error(f"symbol latency log line {line_no} is invalid JSON: {exc}")
            continue
        event = row.get("event")
        if isinstance(event, str):
            symbol_event_counts[event] += 1
        if row.get("bead_id") != ORIGINAL_BEAD:
            error(f"symbol latency log line {line_no} bead_id drifted")
    missing_events = REQUIRED_SYMBOL_EVENTS - set(symbol_event_counts)
    if missing_events:
        error(f"symbol latency log missing required events: {sorted(missing_events)}")
    append_event(
        "symbol_latency_budget.budget_gate_replayed",
        "pass" if not errors else "fail",
        {
            "measured_symbol_count": summary.get("measured_symbol_count"),
            "evaluated_mode_count": summary.get("evaluated_mode_count"),
            "symbol_event_counts": dict(symbol_event_counts),
            "symbol_latency_report": rel(SYMBOL_REPORT),
            "symbol_latency_log": rel(SYMBOL_LOG),
        },
    )
    append_event(
        "symbol_latency_budget.telemetry_validated",
        "pass" if not errors else "fail",
        {
            "gate_passed": summary.get("gate_passed"),
            "active_waiver_beads": summary.get("active_waiver_beads", []),
        },
    )


def write_outputs(contract: dict[str, Any]) -> None:
    status = "fail" if errors else "pass"
    event = (
        "symbol_latency_budget.completion_contract_failed"
        if errors
        else "symbol_latency_budget.completion_contract_validated"
    )
    append_event(event, status, {"error_count": len(errors)})
    missing_items = []
    evidence = contract.get("completion_debt_evidence", {}) if isinstance(contract, dict) else {}
    if isinstance(evidence, dict):
        missing_items = string_array(
            evidence.get("missing_items_closed", []),
            "completion_debt_evidence.missing_items_closed",
            allow_empty=True,
        )
    report = {
        "schema_version": REPORT_SCHEMA,
        "timestamp": utc_now(),
        "event": event,
        "status": status,
        "completion_debt_bead": COMPLETION_BEAD,
        "original_bead": ORIGINAL_BEAD,
        "source_commit": SOURCE_COMMIT,
        "missing_items_bound": sorted(missing_items),
        "source_count": source_count,
        "implementation_ref_count": implementation_ref_count,
        "measured_symbol_count": symbol_summary.get("measured_symbol_count", 0),
        "evaluated_mode_count": symbol_summary.get("evaluated_mode_count", 0),
        "active_waiver_beads": symbol_summary.get("active_waiver_beads", []),
        "symbol_event_counts": dict(symbol_event_counts),
        "symbol_latency_report": rel(SYMBOL_REPORT),
        "symbol_latency_log": rel(SYMBOL_LOG),
        "artifact_refs": [
            rel(CONTRACT),
            "tests/conformance/symbol_latency_baseline.v1.json",
            "tests/conformance/perf_budget_policy.json",
            "scripts/check_symbol_latency_baseline.sh",
            "crates/frankenlibc-harness/tests/symbol_latency_baseline_test.rs",
        ],
        "failure_signature": "none" if not errors else "symbol_latency_budget_completion_contract_failed",
        "errors": errors,
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with LOG.open("w", encoding="utf-8") as handle:
        for row in events:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


contract_value = load_json(CONTRACT, "completion contract")
if not isinstance(contract_value, dict):
    error("completion contract root must be object")
    contract_value = {}

validate_contract_shape(contract_value)
validate_sources(contract_value)

baseline = load_json(ROOT / "tests/conformance/symbol_latency_baseline.v1.json", "canonical baseline")
policy = load_json(ROOT / "tests/conformance/perf_budget_policy.json", "perf budget policy")

if isinstance(baseline, dict):
    require(baseline.get("schema_version") == 1, "canonical baseline schema_version drifted")
    require(baseline.get("bead") == "bd-3h1u.1", "canonical baseline source bead drifted")
    require(
        baseline.get("trace_id") == "bd-3h1u.1-symbol-latency-baseline-v1",
        "canonical baseline trace_id drifted",
    )
    ingestion = baseline.get("ingestion", {})
    if isinstance(ingestion, dict):
        require(
            ingestion.get("trace_id") == "bd-3h1u.1-symbol-latency-ingest-v1",
            "canonical baseline ingestion trace_id drifted",
        )
    validate_conformance_binding(contract_value, baseline)
else:
    error("canonical baseline root must be object")

if isinstance(policy, dict):
    require(policy.get("schema_version") == 1, "perf budget policy schema_version drifted")
    validate_policy_and_telemetry_binding(contract_value, policy)
else:
    error("perf budget policy root must be object")

validate_executable(ROOT / "scripts/check_symbol_latency_baseline.sh", "symbol latency baseline checker")
validate_executable(
    ROOT / "scripts/check_symbol_latency_budget_completion_contract.sh",
    "completion checker",
)

if not errors:
    replay_symbol_latency_gate(contract_value)

write_outputs(contract_value)

if errors:
    print("FAIL symbol latency budget completion contract", file=sys.stderr)
    for item in errors:
        print(f"ERROR: {item}", file=sys.stderr)
    raise SystemExit(1)

print(
    "PASS symbol latency budget completion contract "
    f"sources={source_count} "
    f"events={len(events)} "
    f"measured_symbols={symbol_summary.get('measured_symbol_count', 0)}"
)
PY
