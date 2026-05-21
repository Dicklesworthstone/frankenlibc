#!/usr/bin/env bash
# check_host_delegation_census.sh — CI gate for bd-smp21.1
#
# Validates that the canonical host-delegation census is regenerated from ABI
# source and still covers the required startup, dlfcn, and pthread anchors.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_host_delegation_census.py"
ARTIFACT="${ROOT}/tests/conformance/host_delegation_census.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${FRANKENLIBC_HOST_DELEGATION_CENSUS_REPORT:-${OUT_DIR}/host_delegation_census.report.json}"
LOG="${FRANKENLIBC_HOST_DELEGATION_CENSUS_LOG:-${OUT_DIR}/host_delegation_census.log.jsonl}"

mkdir -p "${OUT_DIR}" "$(dirname "${REPORT}")" "$(dirname "${LOG}")"

(
  cd "${ROOT}"
  python3 "${GEN}" --output "${ARTIFACT}" --check
)

python3 - "${ROOT}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
artifact_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
errors = []

if artifact.get("schema_version") != "host_delegation_census.v1":
    errors.append("schema_version_mismatch")
if artifact.get("bead") != "bd-smp21.1":
    errors.append("bead_mismatch")

summary = artifact.get("summary", {})
symbols = artifact.get("symbol_census", [])
callsites = artifact.get("callsite_census", [])
anchors = artifact.get("required_anchor_symbols", [])

if summary.get("host_delegating_symbol_count") != len(symbols):
    errors.append("symbol_count_mismatch")
if summary.get("host_delegation_callsite_count") != len(callsites):
    errors.append("callsite_count_mismatch")
if summary.get("required_anchor_present_count") != len([row for row in anchors if row.get("present")]):
    errors.append("anchor_count_mismatch")

missing_anchors = sorted(row.get("symbol") for row in anchors if not row.get("present"))
if missing_anchors:
    errors.append("missing_required_anchor:" + ",".join(missing_anchors))

symbol_set = {row.get("symbol") for row in symbols}
callsite_ids = set()
for row in symbols:
    symbol = row.get("symbol")
    ids = row.get("callsite_ids", [])
    if not symbol or not ids:
        errors.append(f"symbol_without_callsites:{symbol}")
    if row.get("callsite_count") != len(ids):
        errors.append(f"symbol_callsite_count_mismatch:{symbol}")
    callsite_ids.update(ids)

if len(callsite_ids) != len(callsites):
    errors.append("callsite_id_coverage_mismatch")

for row in callsites:
    if row.get("exported_symbol") not in symbol_set:
        errors.append(f"callsite_unknown_symbol:{row.get('id')}")
    rel_path = row.get("path")
    line = row.get("line")
    if not isinstance(rel_path, str) or not isinstance(line, int) or line <= 0:
        errors.append(f"callsite_bad_location:{row.get('id')}")
        continue
    full_path = root / rel_path
    if not full_path.is_file():
        errors.append(f"callsite_missing_file:{row.get('id')}")
        continue
    text_lines = full_path.read_text(encoding="utf-8").splitlines()
    if line > len(text_lines) or not text_lines[line - 1].strip():
        errors.append(f"callsite_bad_line:{row.get('id')}")

status = "fail" if errors else "pass"
report = {
    "schema_version": "host_delegation_census.report.v1",
    "bead": "bd-smp21.1",
    "status": status,
    "errors": errors,
    "summary": {
        "host_delegating_symbol_count": len(symbols),
        "host_delegation_callsite_count": len(callsites),
        "required_anchor_present_count": len([row for row in anchors if row.get("present")]),
    },
    "artifact_refs": [str(artifact_path.relative_to(root)), str(report_path.relative_to(root)), str(log_path.relative_to(root))],
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
event = {
    "trace_id": "bd-smp21.1:host-delegation-census",
    "event": "host_delegation_census_validated",
    "bead": "bd-smp21.1",
    "status": status,
    "failure_signature": "none" if not errors else errors[0],
    "artifact_refs": report["artifact_refs"],
    "summary": report["summary"],
}
log_path.write_text(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

if errors:
    raise SystemExit("FAIL host delegation census: " + "; ".join(errors))
print(
    "PASS host delegation census "
    f"symbols={len(symbols)} callsites={len(callsites)} anchors={report['summary']['required_anchor_present_count']}"
)
PY
