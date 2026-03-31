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

materialize_local_artifacts_from_log() {
  mkdir -p "${EXAMPLE_OUT}"
  LOG_PATH_ARG="${LOG_PATH}" EXAMPLE_OUT_ARG="${EXAMPLE_OUT}" python3 - <<'PY'
import json
import os
from pathlib import Path

log_path = Path(os.environ["LOG_PATH_ARG"])
out_dir = Path(os.environ["EXAMPLE_OUT_ARG"])
report_payload = None

for line in log_path.read_text(errors="replace").splitlines():
    if line.startswith("KILLER_DEMO_REPORT "):
        report_payload = json.loads(line[len("KILLER_DEMO_REPORT "):])

if report_payload is None:
    raise SystemExit("FAIL: missing KILLER_DEMO_REPORT line in killer_demo.log")

report_path = out_dir / "killer_demo_report.json"
trace_path = out_dir / "trace.jsonl"
index_path = out_dir / "artifact_index.json"
suite_path = out_dir / "killer_demo.suite.json"
ftui_path = out_dir / "summary.ftui.txt"

report_path.write_text(json.dumps(report_payload, indent=2) + "\n")

trace_lines = []
for scenario in report_payload.get("scenarios", []):
    trace_lines.append(json.dumps({
        "timestamp": "replayed-from-gate-log",
        "trace_id": f"bd-13zp::{scenario['mode']}::replayed",
        "bead_id": "bd-13zp",
        "mode": scenario["mode"],
        "api_family": "allocator",
        "symbol": "free/use-after-free" if scenario["mode"] != "glibc" else "malloc/free",
        "decision_path": scenario["decision_path"],
        "healing_action": scenario.get("healing_action"),
        "errno": scenario["errno"],
        "latency_ns": scenario["latency_ns"],
        "artifact_refs": ["scripts/check_killer_demo.sh"],
        "event": "killer_demo.scenario_result",
        "outcome": "pass" if scenario["detected"] else "fail",
        "details": {
            "summary": scenario["summary"],
            "repaired": scenario["repaired"],
            "continued": scenario["continued"],
            "overhead_ns": scenario["overhead_ns"],
            "baseline_ns": scenario["baseline_ns"],
            "reused_same_addr": scenario["reused_same_addr"],
            "corruption_observed": scenario["corruption_observed"],
        },
    }))
trace_path.write_text("\n".join(trace_lines) + "\n")

suite_path.write_text(json.dumps({
    "suite_id": "frankenlibc-membrane:killer_demo",
    "replayed": True,
    "scenario_count": len(report_payload.get("scenarios", [])),
}, indent=2) + "\n")

rows = ["mode | detected | repaired | errno | summary"]
for scenario in report_payload.get("scenarios", []):
    rows.append(
        f"{scenario['mode']} | {scenario['detected']} | {scenario['repaired']} | {scenario['errno']} | {scenario['summary']}"
    )
ftui_path.write_text("\n".join(rows) + "\n")

artifacts = []
for path, kind in (
    (trace_path, "structured_log"),
    (suite_path, "asupersync_suite"),
    (ftui_path, "frankentui_summary"),
    (report_path, "report"),
):
    artifacts.append({
        "path": path.name,
        "kind": kind,
        "sha256": "",
        "size_bytes": path.stat().st_size,
        "description": "materialized locally from remote gate log fallback",
    })

index_path.write_text(json.dumps({
    "index_version": 1,
    "run_id": report_payload.get("run_id", "artifacts"),
    "bead_id": "bd-13zp",
    "generated_utc": "replayed-from-gate-log",
    "artifacts": artifacts,
}, indent=2) + "\n")
PY
}

run_example
run_tests

if [[ ! -f "${REPORT_PATH:-${EXAMPLE_OUT}/killer_demo_report.json}" ]]; then
  materialize_local_artifacts_from_log
fi

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
