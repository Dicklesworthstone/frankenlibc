#!/usr/bin/env bash
# check_htm_fast_path.sh — closure gate for bd-1sp.6
#
# Validates that the live HTM fast paths remain:
# - wired into the intended hot libc sites,
# - correctness-preserving under commit/abort/unsupported modes, and
# - visible through deterministic JSONL + JSON evidence artifacts.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
LOG_PATH="${OUT_DIR}/htm_fast_path.log.jsonl"
REPORT_PATH="${OUT_DIR}/htm_fast_path.report.json"

mkdir -p "${OUT_DIR}"

python3 - "${ROOT}" "${LOG_PATH}" "${REPORT_PATH}" <<'PY'
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
log_path = Path(sys.argv[2])
report_path = Path(sys.argv[3])

BEAD_ID = "bd-1sp.6"
RUN_PREFIX = "bd-1sp.6::htm-fast-path"

SOURCE_FILES = {
    "htm_fast_path_rs": "crates/frankenlibc-abi/src/htm_fast_path.rs",
    "string_abi_rs": "crates/frankenlibc-abi/src/string_abi.rs",
    "malloc_abi_rs": "crates/frankenlibc-abi/src/malloc_abi.rs",
    "pthread_abi_rs": "crates/frankenlibc-abi/src/pthread_abi.rs",
}


def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rel(path: Path) -> str:
    return path.relative_to(root).as_posix()


def tail_lines(text: str, limit: int = 20):
    lines = [line for line in text.splitlines() if line.strip()]
    return lines[-limit:]


checks = []
log_entries = []


def append_log(
    *,
    trace_id: str,
    level: str,
    event: str,
    mode: str,
    symbol: str,
    outcome: str,
    latency_ns: int,
    artifact_refs,
    details,
):
    log_entries.append(
        {
            "timestamp": now_utc(),
            "trace_id": trace_id,
            "level": level,
            "event": event,
            "bead_id": BEAD_ID,
            "gate": "htm_fast_path",
            "mode": mode,
            "api_family": "abi_hot_path",
            "symbol": symbol,
            "decision_path": "htm_fast_path::gate",
            "healing_action": "none",
            "errno": 0,
            "latency_ns": latency_ns,
            "artifact_refs": artifact_refs,
            "outcome": outcome,
            "details": details,
        }
    )


def run_check(*, check_id, gate_name, mode, symbol, artifact_refs, command):
    env = os.environ.copy()
    env["FRANKENLIBC_MODE"] = mode
    start = time.perf_counter_ns()
    result = subprocess.run(
        command,
        cwd=root,
        env=env,
        capture_output=True,
        text=True,
    )
    latency_ns = time.perf_counter_ns() - start
    ok = result.returncode == 0
    outcome = "pass" if ok else "fail"
    checks.append(
        {
            "id": check_id,
            "gate": gate_name,
            "mode": mode,
            "symbol": symbol,
            "status": outcome,
            "command": command,
            "latency_ns": latency_ns,
            "artifact_refs": artifact_refs,
            "stdout_tail": tail_lines(result.stdout),
            "stderr_tail": tail_lines(result.stderr),
        }
    )
    append_log(
        trace_id=f"{RUN_PREFIX}::{check_id}",
        level="info" if ok else "error",
        event="htm.fast_path.test_command",
        mode=mode,
        symbol=symbol,
        outcome=outcome,
        latency_ns=latency_ns,
        artifact_refs=artifact_refs,
        details={
            "check_id": check_id,
            "gate_name": gate_name,
            "command": command,
            "returncode": result.returncode,
            "stdout_tail": tail_lines(result.stdout),
            "stderr_tail": tail_lines(result.stderr),
        },
    )


run_check(
    check_id="controller_unit_tests",
    gate_name="HTM controller invariants",
    mode="strict",
    symbol="htm_fast_path::tests",
    artifact_refs=[SOURCE_FILES["htm_fast_path_rs"]],
    command=[
        "cargo",
        "test",
        "-p",
        "frankenlibc-abi",
        "--lib",
        "htm_fast_path::tests::",
        "--",
        "--nocapture",
    ],
)

site_commands = [
    (
        "memcpy",
        "string_abi HTM path",
        SOURCE_FILES["string_abi_rs"],
        ["cargo", "test", "-p", "frankenlibc-abi", "--test", "string_abi_test", "memcpy_htm_", "--", "--nocapture"],
    ),
    (
        "malloc_stats_combiner",
        "malloc stats HTM path",
        SOURCE_FILES["malloc_abi_rs"],
        ["cargo", "test", "-p", "frankenlibc-abi", "--test", "malloc_abi_test", "test_malloc_stats_htm_", "--", "--nocapture"],
    ),
    (
        "pthread_mutex_lock",
        "pthread mutex HTM path",
        SOURCE_FILES["pthread_abi_rs"],
        ["cargo", "test", "-p", "frankenlibc-abi", "--test", "pthread_mutex_core_test", "futex_mutex_htm_", "--", "--nocapture"],
    ),
]

for mode in ("strict", "hardened"):
    for symbol, gate_name, source_ref, command in site_commands:
        run_check(
            check_id=f"{symbol}_{mode}",
            gate_name=gate_name,
            mode=mode,
            symbol=symbol,
            artifact_refs=[source_ref],
            command=command,
        )


def source_contains(path_key: str, needle: str):
    path = root / SOURCE_FILES[path_key]
    text = path.read_text(encoding="utf-8")
    return path, needle in text


integration_checks = [
    (
        "runtime_rtm_detection",
        "strict",
        "htm_fast_path::runtime_detection",
        SOURCE_FILES["htm_fast_path_rs"],
        'std::is_x86_feature_detected!("rtm")',
    ),
    (
        "adaptive_cooldown",
        "strict",
        "htm_fast_path::cooldown_policy",
        SOURCE_FILES["htm_fast_path_rs"],
        "fn evaluate_window(&self, aborted: bool)",
    ),
    (
        "memcpy_site_wired",
        "strict",
        "memcpy",
        SOURCE_FILES["string_abi_rs"],
        "MEMCPY_HTM_SITE.run(||",
    ),
    (
        "malloc_site_wired",
        "strict",
        "malloc_stats_combiner",
        SOURCE_FILES["malloc_abi_rs"],
        "MALLOC_STATS_HTM_SITE.run(||",
    ),
    (
        "pthread_site_wired",
        "strict",
        "pthread_mutex_lock",
        SOURCE_FILES["pthread_abi_rs"],
        "PTHREAD_MUTEX_HTM_SITE.run(||",
    ),
]

integration_results = []
for check_id, mode, symbol, artifact_ref, needle in integration_checks:
    path = root / artifact_ref
    text = path.read_text(encoding="utf-8")
    ok = needle in text
    integration_results.append(
        {
            "id": check_id,
            "symbol": symbol,
            "artifact_ref": artifact_ref,
            "needle": needle,
            "present": ok,
        }
    )
    checks.append(
        {
            "id": check_id,
            "gate": "integration_marker",
            "mode": mode,
            "symbol": symbol,
            "status": "pass" if ok else "fail",
            "command": None,
            "latency_ns": 0,
            "artifact_refs": [artifact_ref],
            "stdout_tail": [],
            "stderr_tail": [],
        }
    )
    append_log(
        trace_id=f"{RUN_PREFIX}::{check_id}",
        level="info" if ok else "error",
        event="htm.fast_path.integration_marker",
        mode=mode,
        symbol=symbol,
        outcome="pass" if ok else "fail",
        latency_ns=0,
        artifact_refs=[artifact_ref],
        details={
            "check_id": check_id,
            "needle": needle,
            "present": ok,
        },
    )

failed = sum(1 for check in checks if check["status"] != "pass")
passed = len(checks) - failed
pure_optimization_contract = all(
    check["status"] == "pass"
    for check in checks
    if check["id"] == "controller_unit_tests"
    or check["id"].endswith("_strict")
    or check["id"].endswith("_hardened")
)

append_log(
    trace_id=f"{RUN_PREFIX}::summary",
    level="info" if failed == 0 else "error",
    event="htm.fast_path.summary",
    mode="strict",
    symbol="htm_fast_path",
    outcome="pass" if failed == 0 else "fail",
    latency_ns=0,
    artifact_refs=[rel(log_path), rel(report_path)],
    details={
        "checks": len(checks),
        "passed": passed,
        "failed": failed,
        "pure_optimization_contract": pure_optimization_contract,
        "guarded_sites": ["memcpy", "malloc_stats_combiner", "pthread_mutex_lock"],
    },
)

report = {
    "schema_version": "v1",
    "bead": BEAD_ID,
    "generated_at": now_utc(),
    "sources": {
        **SOURCE_FILES,
        "log_path": rel(log_path),
        "report_path": rel(report_path),
    },
    "summary": {
        "checks": len(checks),
        "passed": passed,
        "failed": failed,
    },
    "pure_optimization_contract": {
        "correctness_independent_of_htm": pure_optimization_contract,
        "modes_exercised": ["strict", "hardened"],
        "guarded_sites": ["memcpy", "malloc_stats_combiner", "pthread_mutex_lock"],
        "fallback_policy": "software fallback remains correct after aborts or unsupported CPUs",
    },
    "integration": {
        "runtime_rtm_detection_present": any(
            item["id"] == "runtime_rtm_detection" and item["present"]
            for item in integration_results
        ),
        "adaptive_cooldown_present": any(
            item["id"] == "adaptive_cooldown" and item["present"]
            for item in integration_results
        ),
        "site_markers": integration_results,
    },
    "tests": checks,
}

log_path.write_text(
    "".join(json.dumps(entry, sort_keys=True) + "\n" for entry in log_entries),
    encoding="utf-8",
)
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

print("OK: HTM fast-path gate emitted:")
print(f"- {rel(log_path)}")
print(f"- {rel(report_path)}")

if failed:
    sys.exit(1)
PY
