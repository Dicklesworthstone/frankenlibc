#!/usr/bin/env bash
# check_killer_demo.sh — deterministic killer-demo gate (bd-13zp)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/killer_demo_gate"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
mkdir -p "${RUN_DIR}"

LOG_PATH="${RUN_DIR}/killer_demo.log"
EXAMPLE_OUT="${RUN_DIR}/artifacts"
TARGET_BASE="${CARGO_TARGET_DIR_BASE:-/tmp/cargo-target-killer-demo-${RUN_ID}}"

run_example() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- \
      env \
      CARGO_TARGET_DIR="${TARGET_BASE}-example" \
      cargo run -p frankenlibc-membrane --example killer_demo -- --output-dir "${EXAMPLE_OUT}" --no-color \
      >"${LOG_PATH}" 2>&1
  else
    CARGO_TARGET_DIR="${TARGET_BASE}-example" \
      cargo run -p frankenlibc-membrane --example killer_demo -- --output-dir "${EXAMPLE_OUT}" --no-color \
      >"${LOG_PATH}" 2>&1
  fi
}

run_tests() {
  if command -v rch >/dev/null 2>&1; then
    rch exec -- \
      env \
      CARGO_TARGET_DIR="${TARGET_BASE}-tests" \
      cargo test -p frankenlibc-membrane --test killer_demo_test -- --nocapture \
      >>"${LOG_PATH}" 2>&1
  else
    CARGO_TARGET_DIR="${TARGET_BASE}-tests" \
      cargo test -p frankenlibc-membrane --test killer_demo_test -- --nocapture \
      >>"${LOG_PATH}" 2>&1
  fi
}

run_example
run_tests

REPORT_PATH="${EXAMPLE_OUT}/killer_demo_report.json"
TRACE_PATH="${EXAMPLE_OUT}/trace.jsonl"
INDEX_PATH="${EXAMPLE_OUT}/artifact_index.json"
SUITE_PATH="${EXAMPLE_OUT}/killer_demo.suite.json"
FTUI_PATH="${EXAMPLE_OUT}/summary.ftui.txt"

RUN_DIR_ARG="${RUN_DIR}" \
REPORT_PATH_ARG="${REPORT_PATH}" \
TRACE_PATH_ARG="${TRACE_PATH}" \
INDEX_PATH_ARG="${INDEX_PATH}" \
SUITE_PATH_ARG="${SUITE_PATH}" \
FTUI_PATH_ARG="${FTUI_PATH}" \
python3 - <<'PY'
import json
import os
from pathlib import Path

run_dir = Path(os.environ["RUN_DIR_ARG"])
report_path = Path(os.environ["REPORT_PATH_ARG"])
trace_path = Path(os.environ["TRACE_PATH_ARG"])
index_path = Path(os.environ["INDEX_PATH_ARG"])
suite_path = Path(os.environ["SUITE_PATH_ARG"])
ftui_path = Path(os.environ["FTUI_PATH_ARG"])

for path in (report_path, trace_path, index_path, suite_path, ftui_path):
    if not path.exists():
        raise SystemExit(f"FAIL: missing artifact {path}")

report = json.loads(report_path.read_text())
scenarios = {row["mode"]: row for row in report.get("scenarios", [])}

required = {"glibc", "strict", "hardened"}
if set(scenarios) != required:
    raise SystemExit(f"FAIL: expected modes {sorted(required)}, got {sorted(scenarios)}")

strict = scenarios["strict"]
hardened = scenarios["hardened"]
glibc = scenarios["glibc"]

if not strict.get("detected"):
    raise SystemExit("FAIL: strict mode did not detect the stale pointer")
if strict.get("repaired"):
    raise SystemExit("FAIL: strict mode should not report repair")
if not hardened.get("detected") or not hardened.get("repaired"):
    raise SystemExit("FAIL: hardened mode must detect and repair")
if hardened.get("healing_action") != "ReturnSafeDefault":
    raise SystemExit("FAIL: hardened mode must use ReturnSafeDefault")
if not hardened.get("continued"):
    raise SystemExit("FAIL: hardened mode must continue safely")
if not glibc.get("reused_same_addr"):
    raise SystemExit("FAIL: glibc baseline did not immediately reuse the freed chunk")
if not glibc.get("corruption_observed"):
    raise SystemExit("FAIL: glibc baseline did not show visible corruption")

trace_lines = [
    json.loads(line)
    for line in trace_path.read_text().splitlines()
    if line.strip()
]
result_rows = [row for row in trace_lines if row.get("event") == "killer_demo.scenario_result"]
if len(result_rows) < 3:
    raise SystemExit("FAIL: expected at least three scenario result rows in trace.jsonl")

summary = {
    "schema_version": "v1",
    "bead_id": "bd-13zp",
    "run_dir": str(run_dir),
    "report": str(report_path),
    "trace": str(trace_path),
    "artifact_index": str(index_path),
    "suite": str(suite_path),
    "ftui_summary": str(ftui_path),
    "strict_overhead_ns": strict.get("overhead_ns"),
    "hardened_overhead_ns": hardened.get("overhead_ns"),
    "glibc_corruption": glibc.get("corruption_observed"),
}
summary_path = run_dir / "killer_demo_gate_report.json"
summary_path.write_text(json.dumps(summary, indent=2) + "\n")
print(f"report={summary_path}")
PY

echo "check_killer_demo: PASS"
