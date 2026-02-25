#!/usr/bin/env bash
# check_fragmentation_storms.sh — fragmentation storm gate (bd-18qq.2)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/fragmentation_storms"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

TEST_FILE="fragmentation_storms_test"
TEST_FILTER="fragmentation_storms_suite_emits_metrics"
TARGET_BASE="${CARGO_TARGET_DIR_BASE:-/data/tmp/cargo-target-fragmentation-storms-${RUN_ID}}"

run_fragmentation_test() {
  local mode="$1"
  local log_path="$2"
  local mode_target_dir="${TARGET_BASE}-${mode}"
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
  LOG_PATH="${RUN_DIR}/${mode}.log"
  echo "=== mode=${mode} ==="
  set +e
  run_fragmentation_test "${mode}" "${LOG_PATH}"
  rc=$?
  set -e
  if [[ ${rc} -ne 0 ]]; then
    echo "mode=${mode} run failed rc=${rc}; see ${LOG_PATH}" >&2
    exit ${rc}
  fi
  echo "mode=${mode} log=${LOG_PATH}"
done

REPORT_PATH="${RUN_DIR}/fragmentation_storm_report.json"
SOS_PATH="${RUN_DIR}/sos_vs_actual_fragmentation.json"
RUN_DIR_ARG="${RUN_DIR}" \
REPORT_PATH_ARG="${REPORT_PATH}" \
SOS_PATH_ARG="${SOS_PATH}" \
python3 - <<'PY'
import json
import os
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR_ARG"])
report_path = Path(os.environ["REPORT_PATH_ARG"])
sos_path = Path(os.environ["SOS_PATH_ARG"])

summary = {
    "schema_version": "v1",
    "bead": "bd-18qq.2",
    "run_dir": str(run_dir),
    "modes": {},
    "overall_ok": True,
}

sos_pairs = []

for mode in ("strict", "hardened"):
    log_path = run_dir / f"{mode}.log"
    payloads = []
    for line in log_path.read_text(errors="replace").splitlines():
        if line.startswith("FRAGMENTATION_STORM_REPORT "):
            payload = line[len("FRAGMENTATION_STORM_REPORT "):]
            payloads.append(json.loads(payload))

    mode_ok = True
    reasons = []
    storms = []
    if not payloads:
        mode_ok = False
        reasons.append("missing_fragmentation_storm_report")
    else:
        storms = payloads[-1].get("storm_results", [])
        if len(storms) != 6:
            mode_ok = False
            reasons.append(f"expected_6_storms_got_{len(storms)}")

    for storm in storms:
        storm_type = storm.get("storm_type", "unknown")
        ops_count = int(storm.get("ops_count", 0))
        frag_ratio = float(storm.get("fragmentation_ratio", 1.0))
        peak_rss_ratio = float(storm.get("peak_rss_ratio", 999.0))
        alloc_p99_ns = int(storm.get("alloc_p99_ns", 10**9))
        integrity = bool(storm.get("integrity_check_passed", False))

        if ops_count < 1_000_000:
            mode_ok = False
            reasons.append(f"{storm_type}:ops_count={ops_count}<1000000")
        if frag_ratio > 0.50:
            mode_ok = False
            reasons.append(f"{storm_type}:fragmentation_ratio={frag_ratio:.4f}>0.50")
        if peak_rss_ratio > 2.0:
            mode_ok = False
            reasons.append(f"{storm_type}:peak_rss_ratio={peak_rss_ratio:.4f}>2.0")
        if alloc_p99_ns > 1000:
            mode_ok = False
            reasons.append(f"{storm_type}:alloc_p99_ns={alloc_p99_ns}>1000")
        if not integrity:
            mode_ok = False
            reasons.append(f"{storm_type}:integrity_check_failed")

        # SOS correlation is optional; if present in future, gather pairs.
        if "sos_certificate_value" in storm and "fragmentation_ratio" in storm:
            sos_pairs.append(
                {
                    "mode": mode,
                    "storm_type": storm_type,
                    "certificate_value": storm["sos_certificate_value"],
                    "actual_ratio": storm["fragmentation_ratio"],
                }
            )

    summary["modes"][mode] = {
        "ok": mode_ok,
        "reasons": reasons,
        "log": str(log_path),
        "storm_results": storms,
    }
    if not mode_ok:
        summary["overall_ok"] = False

report_path.write_text(json.dumps(summary, indent=2) + "\n")
sos_path.write_text(json.dumps({"schema_version": "v1", "pairs": sos_pairs}, indent=2) + "\n")

for mode in ("strict", "hardened"):
    status = "PASS" if summary["modes"][mode]["ok"] else "FAIL"
    reasons = summary["modes"][mode]["reasons"]
    print(f"[{status}] mode={mode} reasons={','.join(reasons) if reasons else 'none'}")

if not summary["overall_ok"]:
    raise SystemExit(1)
PY

echo "report=${REPORT_PATH}"
echo "sos_pairs=${SOS_PATH}"
echo "check_fragmentation_storms: PASS"
