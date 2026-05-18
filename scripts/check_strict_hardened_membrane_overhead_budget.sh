#!/usr/bin/env bash
# Fail-closed checker for bd-wpr1n strict/hardened membrane overhead evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
EVIDENCE="${FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_EVIDENCE:-${ROOT}/tests/conformance/strict_hardened_membrane_overhead_budget_golden.v1.json}"
OUT_DIR="${FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_OUT_DIR:-${ROOT}/target/conformance}"
REPORT="${FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_REPORT:-${OUT_DIR}/strict_hardened_membrane_overhead_budget.report.json}"
LOG="${FRANKENLIBC_STRICT_HARDENED_OVERHEAD_BUDGET_LOG:-${OUT_DIR}/strict_hardened_membrane_overhead_budget.log.jsonl}"

mkdir -p "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

ROOT="${ROOT}" \
EVIDENCE="${EVIDENCE}" \
REPORT="${REPORT}" \
LOG="${LOG}" \
python3 - <<'PY'
from __future__ import annotations

import json
import math
import os
import pathlib
import subprocess
import time
from typing import Any

ROOT = pathlib.Path(os.environ["ROOT"])
EVIDENCE = pathlib.Path(os.environ["EVIDENCE"])
REPORT = pathlib.Path(os.environ["REPORT"])
LOG = pathlib.Path(os.environ["LOG"])

EXPECTED_SCHEMA = "v1"
EXPECTED_BEAD = "bd-wpr1n"
CHECKER_SCHEMA = "strict_hardened_membrane_overhead_budget_checker.v1"
CHECKER_BEAD = "bd-e1eko"
REQUIRED_MODES = ["strict", "hardened"]
REQUIRED_FAMILIES = [
    "string_memory",
    "allocator",
    "stdio_buffer",
    "pthread_sync",
    "ctype",
    "math_fenv",
    "runtime_math",
]
DEFAULT_BUDGETS = {
    "strict": 20.0,
    "hardened": 200.0,
}
LOCAL_FALLBACK_MARKERS = [
    "[RCH] local",
    "remote execution failed",
    "local fallback",
]

failures: list[dict[str, Any]] = []
events: list[dict[str, Any]] = []


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def rel(path: pathlib.Path) -> str:
    try:
        return path.resolve().relative_to(ROOT.resolve()).as_posix()
    except Exception:
        return str(path)


def current_head() -> str:
    proc = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


def add_failure(signature: str, path: str, message: str) -> None:
    failures.append(
        {
            "failure_signature": signature,
            "path": path,
            "message": message,
        }
    )


def add_event(event: str, details: dict[str, Any]) -> None:
    events.append(
        {
            "timestamp": utc_now(),
            "event": event,
            "checker_bead": CHECKER_BEAD,
            "source_bead": EXPECTED_BEAD,
            "details": details,
        }
    )


def load_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        add_failure("invalid_json", rel(path), f"evidence is not valid JSON: {exc}")
        return {}
    if not isinstance(value, dict):
        add_failure("invalid_json", rel(path), "evidence root must be an object")
        return {}
    return value


def is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value))


def as_string_list(value: Any, default: list[str], path: str) -> list[str]:
    if value is None:
        return default
    if not isinstance(value, list) or not value:
        add_failure("malformed_policy", path, "expected a non-empty string array")
        return default
    out: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, str) or not item:
            add_failure("malformed_policy", f"{path}[{index}]", "expected a non-empty string")
            continue
        out.append(item)
    return out or default


def budgets(packet: dict[str, Any]) -> dict[str, float]:
    policy = packet.get("budget_policy", {})
    if not isinstance(policy, dict):
        policy = {}
    out = dict(DEFAULT_BUDGETS)
    strict = os.environ.get("FRANKENLIBC_STRICT_HARDENED_OVERHEAD_STRICT_P99_NS") or policy.get("strict_p99_ns")
    hardened = os.environ.get("FRANKENLIBC_STRICT_HARDENED_OVERHEAD_HARDENED_P99_NS") or policy.get("hardened_p99_ns")
    if strict is not None:
        if is_number(strict) and float(strict) > 0:
            out["strict"] = float(strict)
        else:
            add_failure("malformed_policy", "budget_policy.strict_p99_ns", "strict budget must be a positive number")
    if hardened is not None:
        if is_number(hardened) and float(hardened) > 0:
            out["hardened"] = float(hardened)
        else:
            add_failure("malformed_policy", "budget_policy.hardened_p99_ns", "hardened budget must be a positive number")
    return out


def expected_source_commit(packet: dict[str, Any]) -> str:
    env_expected = os.environ.get("FRANKENLIBC_STRICT_HARDENED_OVERHEAD_EXPECTED_SOURCE_COMMIT")
    if env_expected:
        return env_expected
    policy = packet.get("source_commit_policy", {})
    if isinstance(policy, dict):
        expected = policy.get("expected_source_commit")
        if isinstance(expected, str) and expected:
            return expected
    expected = packet.get("expected_source_commit")
    if isinstance(expected, str) and expected:
        return expected
    return current_head()


def text_contains_local_fallback(value: Any) -> bool:
    if isinstance(value, str):
        return any(marker in value for marker in LOCAL_FALLBACK_MARKERS)
    if isinstance(value, list):
        return any(text_contains_local_fallback(item) for item in value)
    return False


def validate_record(
    record: dict[str, Any],
    index: int,
    expected_commit: str,
    budget_by_mode: dict[str, float],
    seen: set[tuple[str, str]],
) -> None:
    path = f"records[{index}]"
    trace_id = record.get("trace_id")
    if not isinstance(trace_id, str) or not trace_id:
        trace_id = path

    if record.get("schema_version") != EXPECTED_SCHEMA:
        add_failure("schema_version", f"{path}.schema_version", "record schema_version must be v1")
    if record.get("bead_id") != EXPECTED_BEAD:
        add_failure("schema_version", f"{path}.bead_id", "record bead_id must be bd-wpr1n")

    source_commit = record.get("source_commit")
    if source_commit != expected_commit:
        add_failure(
            "stale_source_commit",
            f"{path}.source_commit",
            f"{trace_id} source_commit {source_commit!r} does not match expected {expected_commit!r}",
        )

    command = record.get("command")
    if not isinstance(command, str) or "RCH_REQUIRE_REMOTE=1" not in command or "rch exec" not in command:
        add_failure(
            "missing_rch_remote",
            f"{path}.command",
            f"{trace_id} must carry an RCH_REQUIRE_REMOTE=1 rch exec command transcript",
        )
    if text_contains_local_fallback(command) or text_contains_local_fallback(record.get("worker_id")) or text_contains_local_fallback(record.get("cpu_model")) or text_contains_local_fallback(record.get("artifact_refs")):
        add_failure("local_fallback_seen", path, f"{trace_id} contains an RCH local-fallback marker")

    mode = record.get("runtime_mode")
    family = record.get("api_family")
    if isinstance(mode, str) and isinstance(family, str):
        seen.add((mode, family))

    if mode not in REQUIRED_MODES:
        add_failure("missing_mode", f"{path}.runtime_mode", f"{trace_id} has unknown or missing runtime_mode")
    if not isinstance(family, str) or not family:
        add_failure("missing_family", f"{path}.api_family", f"{trace_id} has missing api_family")

    raw = record.get("raw_timings_ns")
    sample_count = record.get("sample_count")
    if not isinstance(raw, list) or not raw:
        add_failure("invalid_quantile", f"{path}.raw_timings_ns", f"{trace_id} must include raw timing samples")
    elif any(not isinstance(item, int) or isinstance(item, bool) or item <= 0 for item in raw):
        add_failure("invalid_quantile", f"{path}.raw_timings_ns", f"{trace_id} raw timings must be positive integers")
    if not isinstance(sample_count, int) or isinstance(sample_count, bool) or sample_count <= 0:
        add_failure("invalid_quantile", f"{path}.sample_count", f"{trace_id} sample_count must be positive")
    elif isinstance(raw, list) and sample_count != len(raw):
        add_failure("invalid_quantile", f"{path}.sample_count", f"{trace_id} sample_count must match raw timing length")

    p50 = record.get("p50_ns_op")
    p95 = record.get("p95_ns_op")
    p99 = record.get("p99_ns_op")
    if not all(is_number(value) and float(value) >= 0 for value in [p50, p95, p99]):
        add_failure("invalid_quantile", path, f"{trace_id} p50/p95/p99 must be finite non-negative numbers")
    elif not (float(p50) <= float(p95) <= float(p99)):
        add_failure("invalid_quantile", path, f"{trace_id} quantiles must be ordered p50 <= p95 <= p99")
    elif mode in budget_by_mode and float(p99) > budget_by_mode[mode]:
        add_failure(
            "budget_regression",
            f"{path}.p99_ns_op",
            f"{trace_id} p99_ns_op {float(p99):.3f} exceeds {mode} budget {budget_by_mode[mode]:.3f}",
        )

    for field in ["mean_ns_op", "cv_pct", "throughput_ops_s"]:
        value = record.get(field)
        if not is_number(value) or (field != "cv_pct" and float(value) <= 0):
            add_failure("invalid_quantile", f"{path}.{field}", f"{trace_id} {field} must be finite and positive")

    decision_count = record.get("decision_count")
    if (
        record.get("missing_decision_telemetry") is not False
        or not isinstance(decision_count, int)
        or isinstance(decision_count, bool)
        or not isinstance(sample_count, int)
        or decision_count < sample_count
    ):
        add_failure(
            "missing_runtime_math_telemetry",
            path,
            f"{trace_id} must include runtime-math decision telemetry for every sample",
        )

    artifact_refs = record.get("artifact_refs")
    if not isinstance(artifact_refs, list) or not artifact_refs or any(not isinstance(item, str) or not item for item in artifact_refs):
        add_failure("missing_artifact_refs", f"{path}.artifact_refs", f"{trace_id} artifact_refs must be a non-empty string array")

    add_event(
        "strict_hardened_overhead_record_checked",
        {
            "trace_id": trace_id,
            "mode": mode,
            "family": family,
            "p99_ns_op": p99,
        },
    )


packet = load_json(EVIDENCE)
budget_by_mode = budgets(packet)
expected_commit = expected_source_commit(packet)
required_modes = as_string_list(packet.get("required_modes"), REQUIRED_MODES, "required_modes")
required_families = as_string_list(packet.get("required_families"), REQUIRED_FAMILIES, "required_families")

if packet.get("schema_version") != EXPECTED_SCHEMA:
    add_failure("schema_version", "schema_version", "strict/hardened overhead evidence schema_version must be v1")
if packet.get("bead_id") != EXPECTED_BEAD:
    add_failure("schema_version", "bead_id", "strict/hardened overhead evidence bead_id must be bd-wpr1n")

records_value = packet.get("records")
records: list[Any]
if not isinstance(records_value, list) or not records_value:
    add_failure("missing_records", "records", "records must be a non-empty array")
    records = []
else:
    records = records_value

record_count = packet.get("record_count")
if isinstance(record_count, int) and not isinstance(record_count, bool) and record_count != len(records):
    add_failure("record_count_mismatch", "record_count", "record_count must match records length")

seen_pairs: set[tuple[str, str]] = set()
for index, value in enumerate(records):
    if not isinstance(value, dict):
        add_failure("malformed_record", f"records[{index}]", "record must be an object")
        continue
    validate_record(value, index, expected_commit, budget_by_mode, seen_pairs)

seen_modes = {mode for mode, _family in seen_pairs}
seen_families = {family for _mode, family in seen_pairs}
for mode in required_modes:
    if mode not in seen_modes:
        add_failure("missing_mode", "records", f"missing required runtime mode {mode}")
for family in required_families:
    if family not in seen_families:
        add_failure("missing_family", "records", f"missing required API family {family}")
for mode in required_modes:
    for family in required_families:
        if (mode, family) not in seen_pairs:
            add_failure("missing_family", "records", f"missing required {mode}/{family} matrix row")

status = "pass" if not failures else "fail"
report = {
    "schema_version": CHECKER_SCHEMA,
    "checker_bead": CHECKER_BEAD,
    "source_bead": EXPECTED_BEAD,
    "generated_at_utc": utc_now(),
    "evidence": rel(EVIDENCE),
    "expected_source_commit": expected_commit,
    "budget_policy": budget_by_mode,
    "required_modes": required_modes,
    "required_families": required_families,
    "record_count": len(records),
    "events": events,
    "failures": failures,
    "status": status,
}
REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
LOG.write_text(
    "".join(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n" for event in events),
    encoding="utf-8",
)
if failures:
    print(json.dumps(report, indent=2, sort_keys=True), file=os.sys.stderr)
    raise SystemExit(1)
print(json.dumps({"status": "pass", "record_count": len(records)}, sort_keys=True))
PY
