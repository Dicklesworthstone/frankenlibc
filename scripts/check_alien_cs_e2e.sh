#!/usr/bin/env bash
# check_alien_cs_e2e.sh — deterministic Alien CS E2E gate for bd-1sp.10
#
# Runs the artifact-emitting Alien CS E2E matrix test and validates the report
# and structured trace emitted under tests/conformance/.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${ROOT}/tests/conformance/alien_cs_e2e_report.v1.json"
TRACE="${ROOT}/tests/conformance/alien_cs_e2e_trace.v1.jsonl"

cd "${ROOT}"

echo "=== Alien CS E2E Gate (bd-1sp.10) ==="
cargo test -p frankenlibc-membrane --test alien_cs_e2e_test alien_cs_e2e_matrix_emits_structured_artifacts -- --nocapture

python3 - <<'PY'
import json
from pathlib import Path

root = Path.cwd()
report_path = root / "tests/conformance/alien_cs_e2e_report.v1.json"
trace_path = root / "tests/conformance/alien_cs_e2e_trace.v1.jsonl"

if not report_path.exists():
    raise SystemExit(f"FAIL: missing report {report_path}")
if not trace_path.exists():
    raise SystemExit(f"FAIL: missing trace {trace_path}")

report = json.loads(report_path.read_text(encoding="utf-8"))
trace_rows = [
    json.loads(line)
    for line in trace_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]

if report.get("schema_version") != "v1":
    raise SystemExit("FAIL: report schema_version must be v1")
if report.get("bead_id") != "bd-1sp.10":
    raise SystemExit("FAIL: report bead_id must be bd-1sp.10")

scenario_reports = report.get("scenario_reports")
if not isinstance(scenario_reports, list) or len(scenario_reports) != 5:
    raise SystemExit("FAIL: scenario_reports must contain 5 scenarios")

expected_scenarios = {
    "serial_read_heavy": 1,
    "quad_read_heavy": 4,
    "octa_balanced": 8,
    "hexa_balanced": 16,
    "thirtytwo_write_heavy": 32,
}

for row in scenario_reports:
    scenario_id = row.get("scenario_id")
    if scenario_id not in expected_scenarios:
        raise SystemExit(f"FAIL: unexpected scenario_id {scenario_id!r}")
    if int(row.get("thread_count", 0)) != expected_scenarios[scenario_id]:
        raise SystemExit(f"FAIL: wrong thread_count for {scenario_id}")
    if int(row.get("duration_ns", 0)) <= 0:
        raise SystemExit(f"FAIL: duration_ns must be positive for {scenario_id}")
    if int(row.get("seqlock_reads", 0)) < int(row.get("total_ops", 0)):
        raise SystemExit(f"FAIL: seqlock_reads must cover total_ops for {scenario_id}")
    if int(row.get("ebr_total_reclaimed", 0)) > int(row.get("ebr_total_retired", 0)):
        raise SystemExit(f"FAIL: reclaimed exceeds retired for {scenario_id}")
    if int(row.get("rcu_epoch", 0)) <= 0:
        raise SystemExit(f"FAIL: rcu_epoch must advance for {scenario_id}")

benchmark = report.get("benchmark_summary", {})
if int(benchmark.get("composite_ns_per_op_x1000", 0)) <= 0:
    raise SystemExit("FAIL: composite benchmark latency must be positive")
individual = benchmark.get("individual_ns_per_op_x1000", {})
for key in ("rcu", "seqlock", "flat_combining", "ebr"):
    if int(individual.get(key, 0)) <= 0:
        raise SystemExit(f"FAIL: individual benchmark latency missing for {key}")

required_keys = {
    "trace_id",
    "mode",
    "api_family",
    "symbol",
    "decision_path",
    "healing_action",
    "errno",
    "latency_ns",
    "artifact_refs",
    "bead_id",
}

if len(trace_rows) != 25:
    raise SystemExit("FAIL: trace must contain 25 rows (5 scenarios × 5 concepts)")

for row in trace_rows:
    missing = sorted(required_keys - set(row))
    if missing:
        raise SystemExit(f"FAIL: trace row missing keys {missing}")
    if row.get("bead_id") != "bd-1sp.10":
        raise SystemExit("FAIL: trace row bead_id mismatch")
    if row.get("api_family") != "alien_cs":
        raise SystemExit("FAIL: trace row api_family must be alien_cs")

print("PASS: Alien CS E2E report + trace validated")
print(f"REPORT={report_path.relative_to(root)}")
print(f"TRACE={trace_path.relative_to(root)}")
PY
