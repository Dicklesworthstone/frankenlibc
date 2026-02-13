#!/usr/bin/env bash
# check_hard_parts_truth.sh — hard-parts docs/parity/support/reality reconciliation gate (bd-8sho)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${ROOT}/tests/conformance/hard_parts_truth_table.v1.json"
README="${ROOT}/README.md"
PARITY="${ROOT}/FEATURE_PARITY.md"
MATRIX="${ROOT}/support_matrix.json"
REPORT="${ROOT}/tests/conformance/reality_report.v1.json"

TRACE_ID="bd-8sho-$(date -u +%Y%m%dT%H%M%SZ)-$$"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

for path in "$ARTIFACT" "$README" "$PARITY" "$MATRIX" "$REPORT"; do
    if [[ ! -f "$path" ]]; then
        echo "FAIL: required file missing: $path" >&2
        exit 1
    fi
done

python3 - "$ARTIFACT" "$README" "$PARITY" "$MATRIX" "$REPORT" "$TRACE_ID" "$START_NS" <<'PY'
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

artifact_path = Path(sys.argv[1])
readme_path = Path(sys.argv[2])
parity_path = Path(sys.argv[3])
matrix_path = Path(sys.argv[4])
report_path = Path(sys.argv[5])
trace_id = sys.argv[6]
start_ns = int(sys.argv[7])

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
readme = readme_path.read_text(encoding="utf-8")
parity = parity_path.read_text(encoding="utf-8")
matrix = json.loads(matrix_path.read_text(encoding="utf-8"))
report = json.loads(report_path.read_text(encoding="utf-8"))

errors = []

if artifact.get("schema_version") != "v1":
    errors.append("artifact schema_version must be v1")
if artifact.get("bead") != "bd-8sho":
    errors.append("artifact bead must be bd-8sho")

subsystems = artifact.get("subsystems", [])
if not isinstance(subsystems, list) or not subsystems:
    errors.append("artifact subsystems must be a non-empty array")

required_subsystems = {"startup", "threading", "resolver", "nss", "locale", "iconv"}
actual_subsystems = {row.get("id") for row in subsystems if isinstance(row, dict)}
missing = sorted(required_subsystems - actual_subsystems)
if missing:
    errors.append(f"artifact missing required subsystems: {missing}")

summary = artifact.get("summary", {})
if summary.get("subsystem_count") != len(subsystems):
    errors.append("summary.subsystem_count must equal subsystem row count")
contradictions = artifact.get("contradictions", [])
if summary.get("contradiction_count") != len(contradictions):
    errors.append("summary.contradiction_count must equal contradictions length")
if contradictions:
    errors.append("hard_parts_truth_table contradictions must be empty")

snapshot = artifact.get("reality_snapshot", {})
if snapshot.get("generated_at_utc") != report.get("generated_at_utc"):
    errors.append(
        "reality_snapshot.generated_at_utc does not match tests/conformance/reality_report.v1.json"
    )
if snapshot.get("total_exported") != report.get("total_exported"):
    errors.append("reality_snapshot.total_exported does not match reality_report")
if snapshot.get("counts") != report.get("counts"):
    errors.append("reality_snapshot.counts do not match reality_report")

symbols = matrix.get("symbols", [])
by_symbol = {}
module_status_counts = defaultdict(Counter)
for row in symbols:
    if not isinstance(row, dict):
        continue
    sym = str(row.get("symbol", ""))
    if sym:
        by_symbol[sym] = row
    module = str(row.get("module", ""))
    status = str(row.get("status", ""))
    if module and status:
        module_status_counts[module][status] += 1

module_names = set(module_status_counts.keys())
all_symbol_names = list(by_symbol.keys())

allowed_statuses = {"IMPLEMENTED_PARTIAL", "IN_PROGRESS", "DEFERRED"}

for row in subsystems:
    if not isinstance(row, dict):
        errors.append("subsystem row must be object")
        continue

    sid = row.get("id", "<unknown>")
    status = row.get("status")
    if status not in allowed_statuses:
        errors.append(f"{sid}: invalid status {status!r}")

    line = row.get("doc_line")
    if not isinstance(line, str) or not line.strip():
        errors.append(f"{sid}: missing doc_line")
    else:
        if line not in readme:
            errors.append(f"README missing hard-parts line for {sid}")
        if line not in parity:
            errors.append(f"FEATURE_PARITY missing hard-parts line for {sid}")

    support = row.get("support_expectations", {})
    if not isinstance(support, dict):
        errors.append(f"{sid}: support_expectations must be object")
        continue

    for req in support.get("required_symbols", []):
        sym = req.get("symbol")
        exp_status = req.get("status")
        actual = by_symbol.get(sym)
        if actual is None:
            errors.append(f"{sid}: required symbol missing from support_matrix: {sym}")
            continue
        actual_status = actual.get("status")
        if actual_status != exp_status:
            errors.append(
                f"{sid}: symbol {sym} status mismatch (expected={exp_status}, actual={actual_status})"
            )

    for req in support.get("required_module_status", []):
        module = req.get("module")
        exp_status = req.get("status")
        min_count = int(req.get("min_count", 1))
        actual_count = module_status_counts.get(module, Counter()).get(exp_status, 0)
        if actual_count < min_count:
            errors.append(
                f"{sid}: module/status requirement failed ({module}:{exp_status} < {min_count}, actual={actual_count})"
            )

    for module in support.get("absent_modules", []):
        if module in module_names:
            errors.append(f"{sid}: module must be absent but is present: {module}")

    for pattern in support.get("absent_symbol_patterns", []):
        regex = re.compile(str(pattern))
        for sym in all_symbol_names:
            if regex.search(sym):
                errors.append(
                    f"{sid}: forbidden symbol pattern {pattern!r} matched support symbol {sym!r}"
                )

elapsed_ns = time.time_ns() - start_ns
event = {
    "trace_id": trace_id,
    "mode": "strict",
    "api_family": "hard_parts_truth",
    "symbol": "all",
    "decision_path": "deny" if errors else "allow",
    "healing_action": "none",
    "errno": 1 if errors else 0,
    "latency_ns": int(elapsed_ns),
    "artifact_refs": [
        artifact_path.as_posix(),
        readme_path.as_posix(),
        parity_path.as_posix(),
        matrix_path.as_posix(),
        report_path.as_posix(),
    ],
}
print(json.dumps(event, separators=(",", ":")))

if errors:
    print("FAIL: hard-parts truth drift detected")
    for err in errors:
        print(f"  - {err}")
    raise SystemExit(1)

print(
    "PASS: hard-parts truth table is consistent "
    f"(subsystems={len(subsystems)}, contradictions={len(contradictions)})"
)
PY
