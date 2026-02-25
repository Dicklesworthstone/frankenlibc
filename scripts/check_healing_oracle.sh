#!/usr/bin/env bash
# check_healing_oracle.sh — deterministic healing-oracle gate (bd-l93x.4)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT}/target/conformance"
BASELINE="${ROOT}/tests/conformance/healing_oracle_report.v1.json"
CURRENT="${OUT_DIR}/healing_oracle.current.v1.json"
REPORT="${OUT_DIR}/healing_oracle_gate.report.json"
LOG="${OUT_DIR}/healing_oracle.log.jsonl"
GATE_LOG="${OUT_DIR}/healing_oracle_gate.log.jsonl"

mkdir -p "${OUT_DIR}"

if [[ ! -f "${BASELINE}" ]]; then
  echo "FAIL: baseline report missing at ${BASELINE}" >&2
  exit 1
fi

echo "--- generating healing oracle report ---"
RUN_CMD=(cargo run -p frankenlibc-harness --bin harness -- verify-membrane
  --mode both
  --campaign healing_oracle
  --fail-on-mismatch
)

if command -v rch >/dev/null 2>&1; then
  rch exec -- "${RUN_CMD[@]}" --output "${CURRENT}" --log "${LOG}" >/dev/null
else
  echo "WARN: rch not found; running local cargo fallback" >&2
  "${RUN_CMD[@]}" --output "${CURRENT}" --log "${LOG}" >/dev/null
fi

if [[ ! -s "${CURRENT}" ]]; then
  echo "FAIL: generated current report missing or empty at ${CURRENT}" >&2
  exit 1
fi
if ! jq empty "${CURRENT}" >/dev/null 2>&1; then
  echo "FAIL: generated current report is not valid JSON at ${CURRENT}" >&2
  exit 1
fi

python3 - "${BASELINE}" "${CURRENT}" "${REPORT}" "${GATE_LOG}" <<'PY'
import json
import sys
from datetime import datetime, timezone

baseline_path, current_path, report_path, gate_log_path = sys.argv[1:]

with open(baseline_path, "r", encoding="utf-8") as f:
    baseline = json.load(f)
with open(current_path, "r", encoding="utf-8") as f:
    current = json.load(f)

required_top = ["schema_version", "bead", "campaign", "mode", "summary", "cases"]
required_summary = [
    "total_cases",
    "passed",
    "failed",
    "detected",
    "repaired",
    "posix_valid",
    "evidence_logged",
    "pass_rate_percent",
]

def check_shape(doc, name):
    issues = []
    for key in required_top:
        if key not in doc:
            issues.append(f"{name}: missing top-level key '{key}'")
    if doc.get("schema_version") != "v1":
        issues.append(f"{name}: schema_version must be v1")
    if doc.get("bead") != "bd-l93x.4":
        issues.append(f"{name}: bead must be bd-l93x.4")
    if not isinstance(doc.get("cases"), list):
        issues.append(f"{name}: cases must be an array")
    if not isinstance(doc.get("summary"), dict):
        issues.append(f"{name}: summary must be object")
    else:
        for key in required_summary:
            if key not in doc["summary"]:
                issues.append(f"{name}: summary missing '{key}'")
    return issues

shape_issues = check_shape(baseline, "baseline") + check_shape(current, "current")

baseline_cases = {row["trace_id"]: row for row in baseline.get("cases", []) if "trace_id" in row}
current_cases = {row["trace_id"]: row for row in current.get("cases", []) if "trace_id" in row}

regressions = []
for trace_id, row in current_cases.items():
    if trace_id not in baseline_cases:
        continue
    old_status = baseline_cases[trace_id].get("status")
    new_status = row.get("status")
    if old_status == "pass" and new_status != "pass":
        regressions.append({
            "trace_id": trace_id,
            "case_id": row.get("case_id"),
            "symbol": row.get("symbol"),
            "mode": row.get("mode"),
            "old_status": old_status,
            "new_status": new_status,
        })

missing_from_current = [trace_id for trace_id in baseline_cases if trace_id not in current_cases]

rows = current.get("cases", [])
summary = current.get("summary", {})
computed = {
    "total_cases": len(rows),
    "passed": sum(1 for row in rows if row.get("status") == "pass"),
    "failed": sum(1 for row in rows if row.get("status") != "pass"),
    "detected": sum(1 for row in rows if row.get("detected") is True),
    "repaired": sum(1 for row in rows if row.get("repaired") is True),
    "posix_valid": sum(1 for row in rows if row.get("posix_valid") is True),
    "evidence_logged": sum(1 for row in rows if row.get("evidence_logged") is True),
}

summary_mismatches = []
for key, value in computed.items():
    if summary.get(key) != value:
        summary_mismatches.append(f"summary.{key}={summary.get(key)} != computed={value}")

mode_values = {row.get("mode") for row in rows}
mode_coverage_ok = {"strict", "hardened"}.issubset(mode_values)

report = {
    "schema_version": "v1",
    "bead": "bd-l93x.4",
    "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    "artifacts": {
        "baseline": baseline_path,
        "current": current_path,
    },
    "checks": {
        "shape_valid": "pass" if not shape_issues else "fail",
        "no_pass_to_nonpass_regressions": "pass" if not regressions else "fail",
        "no_missing_baseline_cases": "pass" if not missing_from_current else "fail",
        "summary_consistent": "pass" if not summary_mismatches else "fail",
        "strict_and_hardened_covered": "pass" if mode_coverage_ok else "fail",
    },
    "counts": {
        "baseline_case_count": len(baseline_cases),
        "current_case_count": len(current_cases),
        "regression_count": len(regressions),
        "missing_from_current_count": len(missing_from_current),
    },
    "shape_issues": shape_issues,
    "summary_mismatches": summary_mismatches,
    "regressions": regressions,
    "missing_from_current": missing_from_current[:100],
}

with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2, sort_keys=True)

gate_log = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "trace_id": "bd-l93x.4::healing_oracle_gate",
    "level": "INFO",
    "event": "healing_oracle_gate",
    "mode": "strict+hardened",
    "api_family": "membrane",
    "symbol": "healing_oracle",
    "decision_path": "generate->compare->report",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [baseline_path, current_path, report_path],
    "case_count": len(rows),
    "pass_count": computed["passed"],
    "fail_count": computed["failed"],
}
with open(gate_log_path, "w", encoding="utf-8") as f:
    f.write(json.dumps(gate_log, sort_keys=True) + "\n")

if shape_issues:
    print("FAIL: healing oracle shape issues detected", file=sys.stderr)
    for issue in shape_issues:
        print(f"  - {issue}", file=sys.stderr)
    sys.exit(1)
if regressions:
    print(f"FAIL: found {len(regressions)} pass->nonpass regressions", file=sys.stderr)
    sys.exit(1)
if missing_from_current:
    print(
        f"FAIL: current report missing {len(missing_from_current)} baseline cases",
        file=sys.stderr,
    )
    sys.exit(1)
if summary_mismatches:
    print("FAIL: summary consistency issues detected", file=sys.stderr)
    for issue in summary_mismatches:
        print(f"  - {issue}", file=sys.stderr)
    sys.exit(1)
if not mode_coverage_ok:
    print("FAIL: strict+hardened coverage missing in current report", file=sys.stderr)
    sys.exit(1)

print(
    "PASS: healing oracle gate "
    f"(cases={len(rows)}, pass={computed['passed']}, fail={computed['failed']})"
)
PY

echo "PASS: wrote healing oracle report ${REPORT}"
echo "PASS: wrote healing oracle gate log ${GATE_LOG}"
