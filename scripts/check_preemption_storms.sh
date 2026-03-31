#!/usr/bin/env bash
# check_preemption_storms.sh — deterministic preemption-storm gate (bd-18qq.3)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/preemption_storms_gate"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

TEST_FILE="preemption_storms_test"
TEST_FILTER="preemption_storms_suite_emits_metrics"
TARGET_BASE="${CARGO_TARGET_DIR_BASE:-/tmp/cargo-target-preemption-storms-${RUN_ID}}"

run_preemption_test() {
  local mode="$1"
  local attempt="$2"
  local log_path="$3"
  local mode_target_dir="${TARGET_BASE}-${mode}-${attempt}"
  mkdir -p "${mode_target_dir}"

  if command -v rch >/dev/null 2>&1; then
    rch exec -- \
      env \
      FRANKENLIBC_MODE="${mode}" \
      CARGO_TARGET_DIR="${mode_target_dir}" \
      cargo test -p frankenlibc-membrane --release --test "${TEST_FILE}" "${TEST_FILTER}" -- --nocapture \
      >"${log_path}" 2>&1
  else
    FRANKENLIBC_MODE="${mode}" \
      CARGO_TARGET_DIR="${mode_target_dir}" \
      cargo test -p frankenlibc-membrane --release --test "${TEST_FILE}" "${TEST_FILTER}" -- --nocapture \
      >"${log_path}" 2>&1
  fi
}

for mode in strict hardened; do
  for attempt in 1 2; do
    LOG_PATH="${RUN_DIR}/${mode}.${attempt}.log"
    echo "=== mode=${mode} attempt=${attempt} ==="
    set +e
    run_preemption_test "${mode}" "${attempt}" "${LOG_PATH}"
    rc=$?
    set -e
    if [[ ${rc} -ne 0 ]]; then
      echo "mode=${mode} attempt=${attempt} run failed rc=${rc}; see ${LOG_PATH}" >&2
      exit ${rc}
    fi
    echo "mode=${mode} attempt=${attempt} log=${LOG_PATH}"
  done
done

REPORT_PATH="${RUN_DIR}/preemption_storm_report.json"
RUN_DIR_ARG="${RUN_DIR}" \
REPORT_PATH_ARG="${REPORT_PATH}" \
python3 - <<'PY'
import json
import os
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR_ARG"])
report_path = Path(os.environ["REPORT_PATH_ARG"])

summary = {
    "schema_version": "v1",
    "bead": "bd-18qq.3",
    "run_dir": str(run_dir),
    "modes": {},
    "overall_ok": True,
}

expected = {
    "quantum_yield",
    "signal_jitter",
    "affinity_collapse",
    "priority_inversion",
    "thundering_herd",
}

for mode in ("strict", "hardened"):
    attempts = []
    mode_ok = True
    reasons = []
    duration_map = {}
    for attempt in (1, 2):
        log_path = run_dir / f"{mode}.{attempt}.log"
        payloads = []
        for line in log_path.read_text(errors="replace").splitlines():
            if line.startswith("PREEMPTION_STORM_REPORT "):
                payloads.append(json.loads(line[len("PREEMPTION_STORM_REPORT "):]))
        if not payloads:
            mode_ok = False
            reasons.append(f"attempt_{attempt}:missing_preemption_storm_report")
            continue
        payload = payloads[-1]
        storms = payload.get("storm_results", [])
        attempts.append({
            "attempt": attempt,
            "log": str(log_path),
            "payload": payload,
        })
        if len(storms) != 5:
            mode_ok = False
            reasons.append(f"attempt_{attempt}:expected_5_storms_got_{len(storms)}")
        seen = {storm.get("storm_type") for storm in storms}
        if seen != expected:
            mode_ok = False
            reasons.append(f"attempt_{attempt}:unexpected_storm_set={sorted(seen)}")
        for storm in storms:
            storm_type = storm.get("storm_type", "unknown")
            duration_map.setdefault(storm_type, []).append(int(storm.get("completion_time_ms", 0)))
            if storm.get("deadlock_detected"):
                mode_ok = False
                reasons.append(f"{storm_type}:deadlock")
            if storm.get("corruption_detected"):
                mode_ok = False
                reasons.append(f"{storm_type}:corruption")
            if int(storm.get("allocations", 0)) != int(storm.get("frees", -1)):
                mode_ok = False
                reasons.append(f"{storm_type}:allocations!=frees")
            if int(storm.get("max_progress_gap_ms", 10**9)) > 1000:
                mode_ok = False
                reasons.append(f"{storm_type}:progress_gap_ms={storm.get('max_progress_gap_ms')}>1000")
            if int(storm.get("p99_ratio_x1000", 10**9)) >= 10_000:
                mode_ok = False
                reasons.append(f"{storm_type}:p99_ratio_x1000={storm.get('p99_ratio_x1000')}>=10000")
            if int(storm.get("ops_completed", 0)) <= 0:
                mode_ok = False
                reasons.append(f"{storm_type}:ops_completed<=0")
    for storm_type, durations in duration_map.items():
        if len(durations) == 2:
            lo = min(durations)
            hi = max(durations)
            if lo == 0 or hi > lo * 2:
                mode_ok = False
                reasons.append(f"{storm_type}:replay_variance={durations}>2x")
    summary["modes"][mode] = {
        "ok": mode_ok,
        "reasons": reasons,
        "attempts": attempts,
    }
    if not mode_ok:
        summary["overall_ok"] = False

report_path.write_text(json.dumps(summary, indent=2) + "\n")

for mode in ("strict", "hardened"):
    mode_summary = summary["modes"].get(mode, {})
    status = "PASS" if mode_summary.get("ok") else "FAIL"
    print(f"[{status}] mode={mode} reasons={','.join(mode_summary.get('reasons', [])) or 'none'}")

if not summary["overall_ok"]:
    raise SystemExit(1)
PY

echo "report=${REPORT_PATH}"
echo "check_preemption_storms: PASS"
