#!/usr/bin/env bash
# check_uncovered_hotpath_benchmark_manifest.sh - gate for bd-b92jd.2.2.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${FRANKENLIBC_UNCOVERED_HOTPATH_REPORT:-target/conformance/uncovered_hotpath_benchmark_manifest.report.json}"
LOG="${FRANKENLIBC_UNCOVERED_HOTPATH_LOG:-target/conformance/uncovered_hotpath_benchmark_manifest.log.jsonl}"

cd "${ROOT}"

python3 scripts/generate_uncovered_hotpath_benchmark_manifest.py --self-test >/dev/null
python3 scripts/generate_uncovered_hotpath_benchmark_manifest.py \
  --output "${REPORT}" \
  --log "${LOG}" \
  --target-dir "target/conformance" \
  --check-current >/dev/null
python3 scripts/generate_uncovered_hotpath_benchmark_manifest.py \
  --validate-manifest tests/conformance/uncovered_hotpath_benchmark_manifest.v1.json >/dev/null

python3 - "${REPORT}" "${LOG}" <<'PY'
import json
import sys
from pathlib import Path

report_path = Path(sys.argv[1])
log_path = Path(sys.argv[2])

report = json.loads(report_path.read_text(encoding="utf-8"))
rows = report.get("rows", [])
summary = report.get("summary", {})
modules = report.get("modules", [])

required_summary = [
    "total_strict_hotpath_symbols",
    "current_uncovered_symbol_count",
    "current_covered_symbol_count",
    "module_count",
    "modules",
    "coverage_blockers",
    "unsafe_benchmark_blocker_count",
    "duplicate_row_count",
    "missing_expected_row_count",
    "stale_support_matrix_row_count",
]
for field in required_summary:
    if field not in summary:
        raise SystemExit(f"missing summary.{field}")

if report.get("schema_version") != "v1":
    raise SystemExit("schema_version must be v1")
if report.get("bead") != "bd-b92jd.2.2":
    raise SystemExit("bead must be bd-b92jd.2.2")
if summary["current_uncovered_symbol_count"] != len(rows):
    raise SystemExit("current_uncovered_symbol_count does not match rows")
if summary["current_uncovered_symbol_count"] != 62:
    raise SystemExit(f"expected 62 uncovered strict hot-path symbols, got {summary['current_uncovered_symbol_count']}")
if summary["module_count"] != len(modules):
    raise SystemExit("module_count does not match modules")
if summary["duplicate_row_count"] != 0:
    raise SystemExit("duplicate rows present")
if summary["missing_expected_row_count"] != 0:
    raise SystemExit("missing expected rows")
if summary["stale_support_matrix_row_count"] != 0:
    raise SystemExit("stale support_matrix rows present")

required_modules = {
    "c11threads_abi",
    "ctype_abi",
    "errno_abi",
    "resolv_abi",
    "stdio_abi",
    "stdlib_abi",
    "time_abi",
    "wchar_abi",
}
actual_modules = {row["module"] for row in rows}
if actual_modules != required_modules:
    raise SystemExit(f"uncovered module mismatch: {sorted(actual_modules)}")

row_ids = [row["row_id"] for row in rows]
if len(set(row_ids)) != len(row_ids):
    raise SystemExit("row_id values must be unique")

for row in rows:
    assignment = row["benchmark_assignment"]
    if not assignment["api_family"] or not assignment["benchmark_id"]:
        raise SystemExit(f"{row['row_id']}: missing benchmark assignment")
    if not assignment["benchmark_file"].startswith("crates/frankenlibc-bench/benches/"):
        raise SystemExit(f"{row['row_id']}: benchmark_file outside bench dir")
    if row["module"] == "resolv_abi" and not row["safety"].get("unsafe_to_benchmark_reason"):
        raise SystemExit(f"{row['row_id']}: resolver row must record real-network blocker")

events = [
    json.loads(line)
    for line in log_path.read_text(encoding="utf-8").splitlines()
    if line.strip()
]
if len(events) != summary["module_count"]:
    raise SystemExit("log event count must match module_count")
required_log_fields = set(report["required_log_fields"])
for event in events:
    missing = required_log_fields.difference(event)
    if missing:
        raise SystemExit(f"{event.get('trace_id', '<unknown>')}: missing log fields {sorted(missing)}")

print(
    "uncovered_hotpath_benchmark_manifest: PASS "
    f"rows={len(rows)} modules={summary['module_count']} unsafe_blockers={summary['unsafe_benchmark_blocker_count']}"
)
PY
