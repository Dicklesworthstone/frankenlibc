#!/usr/bin/env bash
# check_conformance_matrix.sh — deterministic conformance-matrix drift/regression gate (bd-l93x.2)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BASELINE="${ROOT}/tests/conformance/conformance_matrix.v1.json"
CURRENT="${OUT_DIR}/conformance_matrix.current.v1.json"
REPORT="${OUT_DIR}/conformance_matrix.report.json"
LOG="${OUT_DIR}/conformance_matrix.log.jsonl"

mkdir -p "${OUT_DIR}"

if [[ ! -f "${BASELINE}" ]]; then
  echo "FAIL: baseline matrix missing at ${BASELINE}" >&2
  exit 1
fi

echo "--- generating conformance matrix ---"
TZ=UTC0 cargo run -p frankenlibc-harness --bin harness -- conformance-matrix \
  --fixture "${ROOT}/tests/conformance/fixtures" \
  --isolate \
  --case-timeout-ms 5000 \
  --output "${CURRENT}" >/dev/null

python3 - "${BASELINE}" "${CURRENT}" "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from datetime import datetime, timezone

baseline_path, current_path, report_path, log_path = sys.argv[1:]

with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = json.load(f)
with open(current_path, "r", encoding="utf-8") as f:
    current = json.load(f)

required_top = ["schema_version", "bead", "summary", "symbol_matrix", "cases"]

def check_shape(doc, name):
    issues = []
    for key in required_top:
        if key not in doc:
            issues.append(f"{name}: missing top-level key '{key}'")
    if doc.get("schema_version") != "v1":
        issues.append(f"{name}: schema_version must be v1")
    if doc.get("bead") != "bd-l93x.2":
        issues.append(f"{name}: bead must be bd-l93x.2")
    if not isinstance(doc.get("cases"), list):
        issues.append(f"{name}: cases must be an array")
    if not isinstance(doc.get("symbol_matrix"), list):
        issues.append(f"{name}: symbol_matrix must be an array")
    summary = doc.get("summary", {})
    if not isinstance(summary, dict):
        issues.append(f"{name}: summary must be an object")
    else:
        for key in ["total_cases", "passed", "failed", "errors", "pass_rate_percent"]:
            if key not in summary:
                issues.append(f"{name}: summary missing '{key}'")
    return issues

shape_issues = check_shape(baseline, "baseline") + check_shape(current, "current")

baseline_cases = {row["trace_id"]: row for row in baseline.get("cases", []) if "trace_id" in row}
current_cases = {row["trace_id"]: row for row in current.get("cases", []) if "trace_id" in row}

regressions = []
new_case_count = 0
for trace_id, row in current_cases.items():
    if trace_id not in baseline_cases:
        new_case_count += 1
        continue
    old_status = baseline_cases[trace_id].get("status")
    new_status = row.get("status")
    if old_status == "pass" and new_status != "pass":
        regressions.append(
            {
                "trace_id": trace_id,
                "symbol": row.get("symbol"),
                "mode": row.get("mode"),
                "old_status": old_status,
                "new_status": new_status,
            }
        )

missing_from_current = []
for trace_id in baseline_cases:
    if trace_id not in current_cases:
        missing_from_current.append(trace_id)

current_summary = current.get("summary", {})
report = {
    "schema_version": "v1",
    "bead": "bd-l93x.2",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "artifacts": {
        "baseline": baseline_path,
        "current": current_path,
    },
    "checks": {
        "matrix_shape_valid": "pass" if not shape_issues else "fail",
        "no_pass_to_nonpass_regressions": "pass" if not regressions else "fail",
        "no_missing_baseline_cases": "pass" if not missing_from_current else "fail",
    },
    "counts": {
        "baseline_case_count": len(baseline_cases),
        "current_case_count": len(current_cases),
        "new_case_count": new_case_count,
        "missing_from_current_count": len(missing_from_current),
        "regression_count": len(regressions),
        "current_passed": current_summary.get("passed", 0),
        "current_failed": current_summary.get("failed", 0),
        "current_errors": current_summary.get("errors", 0),
    },
    "shape_issues": shape_issues,
    "regressions": regressions,
    "missing_from_current": missing_from_current[:100],
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)

log_row = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "trace_id": "bd-l93x.2::conformance-matrix-gate",
    "level": "INFO",
    "event": "conformance_matrix_gate",
    "mode": "strict+hardened",
    "api_family": "conformance",
    "symbol": "matrix",
    "decision_path": "generate->compare->report",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [current_path, baseline_path, report_path],
    "case_count": len(current_cases),
    "pass_count": current_summary.get("passed", 0),
    "fail_count": current_summary.get("failed", 0),
    "error_count": current_summary.get("errors", 0),
}
with open(log_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(log_row, sort_keys=True) + "\n")

if shape_issues:
    print("FAIL: matrix shape issues detected", file=sys.stderr)
    for issue in shape_issues:
        print(f"  - {issue}", file=sys.stderr)
    sys.exit(1)
if regressions:
    print(f"FAIL: found {len(regressions)} pass->nonpass regressions", file=sys.stderr)
    sys.exit(1)
if missing_from_current:
    print(f"FAIL: current matrix missing {len(missing_from_current)} baseline cases", file=sys.stderr)
    sys.exit(1)

print(
    f"PASS: conformance matrix gate (cases={len(current_cases)}, pass={current_summary.get('passed', 0)}, "
    f"fail={current_summary.get('failed', 0)}, errors={current_summary.get('errors', 0)})"
)
PY

echo "PASS: wrote conformance matrix report ${REPORT}"
echo "PASS: wrote conformance matrix log ${LOG}"
