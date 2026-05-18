#!/usr/bin/env bash
# check_workload_latency_budget_join.sh -- workload latency budget join for bd-fp4tm.4
#
# Consumes caller-provided workload replay/smoke latency JSONL rows and joins
# them to tests/conformance/perf_budget_policy.json. The checker does not run
# benchmarks; it fails closed on stale, missing, or over-budget latency rows.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT="${FRANKENLIBC_WORKLOAD_LATENCY_CONTRACT:-${ROOT}/tests/conformance/workload_latency_budget_join.v1.json}"
POLICY="${FRANKENLIBC_WORKLOAD_LATENCY_POLICY:-${ROOT}/tests/conformance/perf_budget_policy.json}"
INPUTS="${FRANKENLIBC_WORKLOAD_LATENCY_INPUTS:-${ROOT}/target/conformance/user_workload_replay_traces.log.jsonl}"
OUT_DIR="${FRANKENLIBC_WORKLOAD_LATENCY_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_WORKLOAD_LATENCY_REPORT:-${OUT_DIR}/workload_latency_budget_join.report.json}"
LOG="${FRANKENLIBC_WORKLOAD_LATENCY_LOG:-${OUT_DIR}/workload_latency_budget_join.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

python3 - "${ROOT}" "${CONTRACT}" "${POLICY}" "${INPUTS}" "${REPORT}" "${LOG}" <<'PY'
from __future__ import annotations

import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

root = Path(sys.argv[1])
contract_path = Path(sys.argv[2])
policy_path = Path(sys.argv[3])
input_spec = sys.argv[4]
report_path = Path(sys.argv[5])
log_path = Path(sys.argv[6])

BEAD_ID = "bd-fp4tm.4"
PASS_SIGNATURES = {"", "none", "ok"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def source_commit() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return proc.stdout.strip() or "unknown"


SOURCE_COMMIT = source_commit()


def rel(path: Path | str) -> str:
    path = Path(path)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return str(path)


def normalize_rel(path: Any) -> str:
    if not isinstance(path, str) or not path:
        return ""
    candidate = Path(path)
    if candidate.is_absolute():
        return rel(candidate)
    return candidate.as_posix()


def configured_report_fields(contract: dict[str, Any]) -> list[str]:
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        return []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list):
        return []
    return [field for field in fields if isinstance(field, str) and field]


def validate_report_contract(contract: dict[str, Any], report: dict[str, Any]) -> list[str]:
    report_contract = contract.get("report_contract")
    if not isinstance(report_contract, dict):
        return ["missing_report_contract"]
    errors: list[str] = []
    fields = report_contract.get("must_materialize")
    if not isinstance(fields, list) or not all(isinstance(field, str) and field for field in fields):
        errors.append("report_contract.must_materialize must be a non-empty string list")
        fields = []
    expected_report = normalize_rel(report_contract.get("output_path"))
    expected_log = normalize_rel(report_contract.get("log_path"))
    outputs = contract.get("outputs", {})
    canonical_report = rel(root / str(outputs.get("report", ""))) if isinstance(outputs, dict) else ""
    canonical_log = rel(root / str(outputs.get("jsonl_log", ""))) if isinstance(outputs, dict) else ""
    actual_report = rel(report_path)
    actual_log = rel(log_path)
    if actual_report == canonical_report and expected_report != actual_report:
        errors.append(f"report_contract.output_path expected {actual_report} got {expected_report or '<missing>'}")
    if actual_log == canonical_log and expected_log != actual_log:
        errors.append(f"report_contract.log_path expected {actual_log} got {expected_log or '<missing>'}")
    missing = [field for field in fields if field not in report]
    if missing:
        errors.append("report_contract missing materialized fields: " + ", ".join(missing))
    return errors


def load_json(path: Path, label: str, errors: list[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{label} unreadable: {rel(path)}: {exc}")
        return {}
    if not isinstance(value, dict):
        errors.append(f"{label} must be a JSON object")
        return {}
    return value


def split_inputs(raw: str) -> list[Path]:
    paths: list[Path] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        path = Path(item)
        paths.append(path if path.is_absolute() else root / path)
    return paths


def load_jsonl(path: Path, errors: list[str]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as exc:
        errors.append(f"input unreadable: {rel(path)}: {exc}")
        return rows
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"{rel(path)}:{line_number}: malformed JSONL row: {exc}")
            continue
        if not isinstance(value, dict):
            errors.append(f"{rel(path)}:{line_number}: JSONL row must be object")
            continue
        value["_source_input"] = rel(path)
        rows.append(value)
    return rows


def validate_contract(contract: dict[str, Any], errors: list[str]) -> None:
    if contract.get("schema_version") != "v1":
        errors.append("contract.schema_version must be v1")
    if contract.get("bead") != BEAD_ID:
        errors.append(f"contract.bead must be {BEAD_ID}")
    for key in [
        "required_runtime_modes",
        "required_input_fields",
        "required_output_fields",
        "failure_signature_schema",
        "budget_resolution_policy",
        "overload_policy",
    ]:
        if key not in contract:
            errors.append(f"contract.{key} missing")
    schema = contract.get("failure_signature_schema", {})
    if not isinstance(schema, dict):
        errors.append("contract.failure_signature_schema must be object")
        return
    for signature, entry in schema.items():
        if not isinstance(entry, dict):
            errors.append(f"contract.failure_signature_schema.{signature} must be object")
            continue
        for field in ["perf_state", "decision", "next_safe_action"]:
            if not isinstance(entry.get(field), str) or not entry.get(field):
                errors.append(f"contract.failure_signature_schema.{signature}.{field} missing")


def numeric(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return None


def string_field(row: dict[str, Any], key: str) -> str:
    value = row.get(key)
    return value if isinstance(value, str) else ""


def list_field(row: dict[str, Any], key: str) -> list[str]:
    value = row.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item]


def exact_budget_map(policy: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    budgets = policy.get("workload_performance_budgets", [])
    if not isinstance(budgets, list):
        return result
    for budget in budgets:
        if not isinstance(budget, dict):
            continue
        workload_id = string_field(budget, "workload_id")
        mode = string_field(budget, "runtime_mode")
        if workload_id and mode:
            result[(workload_id, mode)] = budget
    return result


def mode_threshold_field(mode: str, contract: dict[str, Any]) -> str:
    policy = contract.get("budget_resolution_policy", {})
    if not isinstance(policy, dict):
        policy = {}
    if mode == "strict":
        return str(policy.get("strict_threshold_field", "strict_mode_ns"))
    return str(policy.get("hardened_threshold_field", "hardened_mode_ns"))


def resolve_budget(
    row: dict[str, Any],
    mode: str,
    policy: dict[str, Any],
    contract: dict[str, Any],
    exact: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any] | None:
    workload_id = string_field(row, "workload_id")
    exact_budget = exact.get((workload_id, mode))
    if exact_budget is not None:
        threshold = numeric(exact_budget.get("latency_threshold_ns"))
        if threshold is not None:
            return {
                "budget_id": exact_budget.get("budget_id"),
                "budget_source": "workload_performance_budgets",
                "latency_threshold_ns": threshold,
                "api_family": exact_budget.get("api_family"),
                "symbol": exact_budget.get("symbol"),
                "budget_class": None,
            }

    resolution = contract.get("budget_resolution_policy", {})
    if not isinstance(resolution, dict):
        resolution = {}
    budget_class = string_field(row, "budget_class") or str(
        resolution.get("fallback_default_budget_class", "strict_hotpath")
    )
    class_budget = policy.get("budgets", {}).get(budget_class)
    if not isinstance(class_budget, dict):
        return None
    threshold = numeric(class_budget.get(mode_threshold_field(mode, contract)))
    if threshold is None:
        return None
    return {
        "budget_id": f"{budget_class}:{mode}",
        "budget_source": "budgets",
        "latency_threshold_ns": threshold,
        "api_family": row.get("api_family"),
        "symbol": row.get("symbol") or row.get("symbol_family"),
        "budget_class": budget_class,
    }


def is_overloaded_skip(row: dict[str, Any], contract: dict[str, Any]) -> bool:
    overload = contract.get("overload_policy", {})
    if not isinstance(overload, dict):
        overload = {}
    skip_signatures = {
        str(item)
        for item in overload.get("skip_signatures", [])
        if isinstance(item, str)
    }
    load_values = {
        str(item)
        for item in overload.get("load_state_values", [])
        if isinstance(item, str)
    }
    signature = string_field(row, "failure_signature")
    load_state = string_field(row, "load_state")
    skip_reason = string_field(row, "skip_reason")
    return (
        signature in skip_signatures
        or load_state in load_values
        or "overload" in skip_reason
        or "overloaded" in skip_reason
    )


def freshness_state(row: dict[str, Any]) -> str:
    value = string_field(row, "freshness_state")
    if value:
        return value
    if string_field(row, "source_commit") in {"", "unknown", "stale"}:
        return "stale"
    return "current"


def error_signature(errors: list[str], row: dict[str, Any], signature: str, message: str) -> None:
    trace_id = string_field(row, "trace_id") or "<missing>"
    errors.append(f"{trace_id}: {signature}: {message}")


def schema_entry(contract: dict[str, Any], signature: str) -> dict[str, Any]:
    schema = contract.get("failure_signature_schema", {})
    if isinstance(schema, dict) and isinstance(schema.get(signature), dict):
        return schema[signature]
    return {"perf_state": "unknown", "decision": "fail", "next_safe_action": "Inspect latency row."}


def observed_regression_pct(row: dict[str, Any], latency_ns: float | None) -> float | None:
    baseline = numeric(row.get("baseline_latency_ns")) or numeric(row.get("baseline_value"))
    if baseline is None or baseline == 0 or latency_ns is None:
        return None
    return round(((latency_ns - baseline) / baseline) * 100.0, 6)


def build_joined_row(
    row: dict[str, Any],
    contract: dict[str, Any],
    policy: dict[str, Any],
    exact: dict[tuple[str, str], dict[str, Any]],
    errors: list[str],
) -> dict[str, Any] | None:
    mode = string_field(row, "mode")
    if not mode:
        error_signature(errors, row, "workload_latency_missing_mode", "latency row must carry runtime mode")
        return None
    if mode not in {"strict", "hardened"}:
        return None

    workload_id = string_field(row, "workload_id") or string_field(row, "case")
    if not workload_id:
        workload_id = "<missing>"

    source_refs = list_field(row, "artifact_refs")
    if row.get("_source_input"):
        source_refs = sorted(set(source_refs + [str(row["_source_input"])]))

    fresh_state = freshness_state(row)
    if fresh_state in {"stale", "expired"}:
        signature = "workload_latency_stale_evidence"
        entry = schema_entry(contract, signature)
        error_signature(errors, row, signature, "latency evidence is stale")
        return {
            "trace_id": string_field(row, "trace_id"),
            "bead_id": BEAD_ID,
            "workload_id": workload_id,
            "mode": mode,
            "api_family": string_field(row, "api_family") or "unknown",
            "symbol_family": string_field(row, "symbol_family") or string_field(row, "symbol") or "unknown",
            "latency_ns": None,
            "budget_policy": None,
            "latency_threshold_ns": None,
            "observed_regression_pct": None,
            "overload_policy": "not_overloaded",
            "perf_state": entry["perf_state"],
            "decision": entry["decision"],
            "user_recommendation": "Do not advance workload performance claims from stale evidence.",
            "artifact_refs": source_refs,
            "source_commit": string_field(row, "source_commit") or SOURCE_COMMIT,
            "freshness_state": fresh_state,
            "failure_signature": signature,
            "next_safe_action": entry["next_safe_action"],
        }

    if is_overloaded_skip(row, contract):
        signature = "workload_latency_overloaded_skip"
        entry = schema_entry(contract, signature)
        return {
            "trace_id": string_field(row, "trace_id"),
            "bead_id": BEAD_ID,
            "workload_id": workload_id,
            "mode": mode,
            "api_family": string_field(row, "api_family") or "unknown",
            "symbol_family": string_field(row, "symbol_family") or string_field(row, "symbol") or "unknown",
            "latency_ns": numeric(row.get("latency_ns")),
            "budget_policy": None,
            "latency_threshold_ns": None,
            "observed_regression_pct": None,
            "overload_policy": "overloaded_host_skip",
            "perf_state": entry["perf_state"],
            "decision": entry["decision"],
            "user_recommendation": "Rerun under load guard before pass/fail classification.",
            "artifact_refs": source_refs,
            "source_commit": string_field(row, "source_commit") or SOURCE_COMMIT,
            "freshness_state": fresh_state,
            "failure_signature": signature,
            "next_safe_action": entry["next_safe_action"],
        }

    latency = numeric(row.get("latency_ns"))
    if latency is None:
        signature = "workload_latency_missing_latency"
        entry = schema_entry(contract, signature)
        error_signature(errors, row, signature, "latency_ns missing or invalid")
        threshold = None
        budget_policy = None
        decision = entry["decision"]
        perf_state = entry["perf_state"]
        recommendation = "Capture a fresh latency sample before making workload performance claims."
    else:
        budget = resolve_budget(row, mode, policy, contract, exact)
        if budget is None:
            signature = "workload_latency_missing_budget"
            entry = schema_entry(contract, signature)
            error_signature(errors, row, signature, "no budget threshold resolved")
            threshold = None
            budget_policy = None
            decision = entry["decision"]
            perf_state = entry["perf_state"]
            recommendation = "Bind this workload to perf_budget_policy before claims advance."
        else:
            threshold = float(budget["latency_threshold_ns"])
            budget_policy = {
                "budget_id": budget["budget_id"],
                "budget_source": budget["budget_source"],
                "budget_class": budget["budget_class"],
            }
            if latency > threshold:
                signature = "workload_latency_over_budget"
                entry = schema_entry(contract, signature)
                error_signature(errors, row, signature, f"latency_ns {latency} exceeds threshold {threshold}")
                decision = entry["decision"]
                perf_state = entry["perf_state"]
                recommendation = "Treat workload as performance-blocked pending repeat samples or optimization."
            else:
                signature = "none"
                decision = "pass"
                perf_state = "within_budget"
                recommendation = "Latency is within the resolved budget for this mode."

    return {
        "trace_id": string_field(row, "trace_id"),
        "bead_id": BEAD_ID,
        "workload_id": workload_id,
        "mode": mode,
        "api_family": string_field(row, "api_family") or "unknown",
        "symbol_family": string_field(row, "symbol_family") or string_field(row, "symbol") or "unknown",
        "latency_ns": latency,
        "budget_policy": budget_policy,
        "latency_threshold_ns": threshold,
        "observed_regression_pct": observed_regression_pct(row, latency),
        "overload_policy": "not_overloaded",
        "perf_state": perf_state,
        "decision": decision,
        "user_recommendation": recommendation,
        "artifact_refs": source_refs,
        "source_commit": string_field(row, "source_commit") or SOURCE_COMMIT,
        "freshness_state": fresh_state,
        "failure_signature": signature,
        "next_safe_action": schema_entry(contract, signature).get("next_safe_action", "No action required.")
        if signature != "none"
        else "No action required.",
    }


errors: list[str] = []
contract = load_json(contract_path, "contract", errors)
policy = load_json(policy_path, "policy", errors)
validate_contract(contract, errors)

input_paths = split_inputs(input_spec)
if not input_paths:
    errors.append("no workload latency inputs configured")

rows: list[dict[str, Any]] = []
for path in input_paths:
    rows.extend(load_jsonl(path, errors))

exact = exact_budget_map(policy)
joined_rows: list[dict[str, Any]] = []
for row in rows:
    joined = build_joined_row(row, contract, policy, exact, errors)
    if joined is not None:
        joined_rows.append(joined)

required_modes = {
    str(item)
    for item in contract.get("required_runtime_modes", [])
    if isinstance(item, str)
}
seen_modes = {row["mode"] for row in joined_rows if row.get("mode") in required_modes}
for mode in sorted(required_modes - seen_modes):
    errors.append(f"<summary>: workload_latency_missing_mode: no {mode} latency row represented")

required_output_fields = contract.get("required_output_fields", [])
if isinstance(required_output_fields, list):
    for row in joined_rows:
        for field in required_output_fields:
            if field not in row:
                errors.append(f"{row.get('trace_id', '<missing>')}: output missing {field}")

decision_counts = Counter(str(row.get("decision", "<missing>")) for row in joined_rows)
perf_state_counts = Counter(str(row.get("perf_state", "<missing>")) for row in joined_rows)
failure_counts = Counter(str(row.get("failure_signature", "<missing>")) for row in joined_rows)

report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "status": "pending",
    "generated_at_utc": utc_now(),
    "source_commit": SOURCE_COMMIT,
    "contract": rel(contract_path),
    "policy": rel(policy_path),
    "input_logs": [rel(path) for path in input_paths],
    "summary": {
        "input_row_count": len(rows),
        "joined_row_count": len(joined_rows),
        "represented_modes": sorted(seen_modes),
        "decision_counts": dict(sorted(decision_counts.items())),
        "perf_state_counts": dict(sorted(perf_state_counts.items())),
        "failure_signature_counts": dict(sorted(failure_counts.items())),
    },
    "workload_latency_rows": joined_rows,
    "failure_signatures": sorted(
        {
            part.split(": ", 2)[1]
            for part in errors
            if part.count(": ") >= 2 and part.split(": ", 2)[1].startswith("workload_latency_")
        }
    ),
    "errors": errors,
    "artifact_refs": [
        rel(contract_path),
        rel(policy_path),
        rel(log_path),
    ],
    "report_path": rel(report_path),
    "log_path": rel(log_path),
    "report_contract_fields": configured_report_fields(contract),
    "contract_status": "pending",
    "contract_errors": [],
}
contract_errors = validate_report_contract(contract, report)
report["contract_errors"] = contract_errors
report["contract_status"] = "pass" if not contract_errors else "fail"
if contract_errors:
    errors.extend(f"report_contract: {error}" for error in contract_errors)
report["status"] = "pass" if not errors else "fail"
report["errors"] = errors

report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
log_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in joined_rows), encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))
sys.exit(0 if report["status"] == "pass" else 1)
PY
