#!/usr/bin/env bash
# check_callthrough_census.sh — CI gate for bd-7ef9
#
# Validates:
# 1) callthrough census artifact is reproducible from support_matrix.json.
# 2) symbol/module counts and summary fields are internally consistent.
# 3) decommission waves cover every callthrough symbol exactly once.
# 4) wave dependency references are valid and acyclic.
# 5) emits deterministic report + structured log evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_callthrough_census.py"
SUPPORT="${ROOT}/support_matrix.json"
ARTIFACT="${ROOT}/tests/conformance/callthrough_census.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/callthrough_census.report.json"
LOG="${OUT_DIR}/callthrough_census.log.jsonl"
TRACE_ID="bd-7ef9-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"

if [[ ! -f "${GEN}" ]]; then
  echo "FAIL: missing generator script ${GEN}" >&2
  exit 1
fi
if [[ ! -f "${SUPPORT}" ]]; then
  echo "FAIL: missing support matrix ${SUPPORT}" >&2
  exit 1
fi

(
  cd "${ROOT}"
  python3 "scripts/generate_callthrough_census.py" \
    --support-matrix "support_matrix.json" \
    --output "tests/conformance/callthrough_census.v1.json" \
    --check
)

python3 - "${SUPPORT}" "${ARTIFACT}" "${REPORT}" <<'PY'
import json
import pathlib
import sys
from collections import Counter

support_path = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])

support = json.loads(support_path.read_text(encoding="utf-8"))
artifact = json.loads(artifact_path.read_text(encoding="utf-8"))

if artifact.get("schema_version") != "v1":
    raise SystemExit("FAIL: schema_version must be v1")
if artifact.get("bead") != "bd-7ef9":
    raise SystemExit("FAIL: bead field must be bd-7ef9")

symbols = support.get("symbols", [])
matrix_callthrough = [
    row for row in symbols if row.get("status") == "GlibcCallThrough"
]
matrix_symbols = sorted(str(row.get("symbol")) for row in matrix_callthrough)
matrix_symbol_set = set(matrix_symbols)
module_counts = Counter(str(row.get("module")) for row in matrix_callthrough)

census_rows = artifact.get("symbol_census", [])
if not isinstance(census_rows, list) or not census_rows:
    raise SystemExit("FAIL: symbol_census must be a non-empty array")
census_symbols = [str(row.get("symbol")) for row in census_rows]
census_symbol_set = set(census_symbols)
if len(census_symbols) != len(census_symbol_set):
    raise SystemExit("FAIL: symbol_census contains duplicate symbols")

if matrix_symbol_set != census_symbol_set:
    missing = sorted(matrix_symbol_set - census_symbol_set)
    extra = sorted(census_symbol_set - matrix_symbol_set)
    raise SystemExit(
        f"FAIL: symbol_census mismatch with support_matrix callthrough set; missing={missing} extra={extra}"
    )

for row in census_rows:
    symbol = str(row.get("symbol", ""))
    module = str(row.get("module", ""))
    perf_class = str(row.get("perf_class", ""))
    if not symbol:
        raise SystemExit("FAIL: symbol_census row missing symbol")
    if not module:
        raise SystemExit(f"FAIL: symbol_census {symbol} missing module")
    if perf_class not in {"strict_hotpath", "hardened_hotpath", "coldpath"}:
        raise SystemExit(f"FAIL: symbol_census {symbol} has invalid perf_class {perf_class!r}")
    if row.get("replacement_complexity") not in {"low", "medium", "high"}:
        raise SystemExit(
            f"FAIL: symbol_census {symbol} has invalid replacement_complexity {row.get('replacement_complexity')!r}"
        )
    if not isinstance(row.get("priority_score"), int):
        raise SystemExit(f"FAIL: symbol_census {symbol} priority_score must be int")

module_rows = artifact.get("module_census", [])
if not isinstance(module_rows, list) or not module_rows:
    raise SystemExit("FAIL: module_census must be a non-empty array")
for row in module_rows:
    module = str(row.get("module", ""))
    count = int(row.get("count", -1))
    if module not in module_counts:
        raise SystemExit(f"FAIL: module_census includes non-callthrough module {module!r}")
    if count != module_counts[module]:
        raise SystemExit(
            f"FAIL: module_census count mismatch for {module}: census={count} matrix={module_counts[module]}"
        )

waves = artifact.get("decommission_waves", [])
if not isinstance(waves, list) or not waves:
    raise SystemExit("FAIL: decommission_waves must be non-empty array")
wave_ids = [str(w.get("wave_id")) for w in waves]
if len(wave_ids) != len(set(wave_ids)):
    raise SystemExit("FAIL: decommission_waves has duplicate wave_id values")

wave_by_id = {}
coverage = []
for w in waves:
    wave = int(w.get("wave", -1))
    wave_id = str(w.get("wave_id", ""))
    depends_on = w.get("depends_on", [])
    symbols = w.get("symbols", [])
    if wave <= 0:
        raise SystemExit(f"FAIL: wave number must be >= 1 for {wave_id}")
    if not isinstance(depends_on, list):
        raise SystemExit(f"FAIL: {wave_id} depends_on must be an array")
    if not isinstance(symbols, list) or not symbols:
        raise SystemExit(f"FAIL: {wave_id} symbols must be a non-empty array")
    wave_by_id[wave_id] = {"wave": wave, "depends_on": depends_on}
    coverage.extend(symbols)

coverage_set = set(coverage)
if len(coverage) != len(coverage_set):
    dupes = sorted([s for s, n in Counter(coverage).items() if n > 1])
    raise SystemExit(f"FAIL: decommission_waves assign symbols more than once: {dupes}")
if coverage_set != matrix_symbol_set:
    missing = sorted(matrix_symbol_set - coverage_set)
    extra = sorted(coverage_set - matrix_symbol_set)
    raise SystemExit(
        f"FAIL: wave coverage mismatch; missing={missing} extra={extra}"
    )

for wave_id, row in wave_by_id.items():
    for dep in row["depends_on"]:
        if dep not in wave_by_id:
            raise SystemExit(f"FAIL: {wave_id} depends on unknown wave_id {dep}")
        if wave_by_id[dep]["wave"] >= row["wave"]:
            raise SystemExit(
                f"FAIL: {wave_id} dependency ordering invalid ({dep} is not earlier)"
            )

summary = artifact.get("summary", {})
if int(summary.get("module_count", -1)) != len(module_rows):
    raise SystemExit("FAIL: summary.module_count mismatch")
if int(summary.get("symbol_count", -1)) != len(census_rows):
    raise SystemExit("FAIL: summary.symbol_count mismatch")
if int(summary.get("wave_count", -1)) != len(waves):
    raise SystemExit("FAIL: summary.wave_count mismatch")

source = artifact.get("source", {})
if int(source.get("total_exported", -1)) != int(support.get("total_exported", -2)):
    raise SystemExit("FAIL: source.total_exported mismatch")
if int(source.get("derived_callthrough_symbols", -1)) != len(census_rows):
    raise SystemExit("FAIL: source.derived_callthrough_symbols mismatch")

report = {
    "schema_version": "v1",
    "bead": "bd-7ef9",
    "checks": {
        "artifact_reproducible": "pass",
        "support_matrix_alignment": "pass",
        "module_counts_consistent": "pass",
        "wave_coverage_complete": "pass",
        "wave_dependencies_valid": "pass",
    },
    "summary": {
        "module_count": len(module_rows),
        "symbol_count": len(census_rows),
        "wave_count": len(waves),
        "strict_hotpath_count": int(summary.get("strict_hotpath_count", 0)),
        "coldpath_count": int(summary.get("coldpath_count", 0)),
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(
    "PASS: callthrough census validated "
    f"(symbols={len(census_rows)}, modules={len(module_rows)}, waves={len(waves)})"
)
PY

python3 - "${TRACE_ID}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import pathlib
import sys

trace_id, artifact_path, report_path, log_path = sys.argv[1:5]
artifact = json.loads(pathlib.Path(artifact_path).read_text(encoding="utf-8"))
summary = artifact.get("summary", {})

event = {
    "trace_id": trace_id,
    "mode": "analysis",
    "api_family": "callthrough",
    "symbol": "census",
    "decision_path": "allow",
    "healing_action": "none",
    "errno": 0,
    "latency_ns": 0,
    "artifact_refs": [artifact_path, report_path],
    "symbol_count": int(summary.get("symbol_count", 0)),
    "module_count": int(summary.get("module_count", 0)),
    "wave_count": int(summary.get("wave_count", 0)),
}
pathlib.Path(log_path).write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")
print(f"PASS: wrote callthrough census log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
