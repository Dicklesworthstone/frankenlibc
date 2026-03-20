#!/usr/bin/env bash
# check_stub_todo_debt_census.sh — CI gate for bd-1pbw (uplifted by bd-1x3.1)
#
# Validates:
# 1) unified stub/TODO debt census artifact is reproducible from source + support matrix
# 2) exported taxonomy and reconciliation counts are internally consistent
# 3) risk ranking is deterministic, contiguous, and sorted
# 4) emits deterministic report + structured JSONL log with delta/priority reasoning
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_stub_todo_debt_census.py"
SUPPORT="${ROOT}/support_matrix.json"
PROFILE="${ROOT}/tests/conformance/replacement_profile.json"
ARTIFACT="${ROOT}/tests/conformance/stub_todo_debt_census.v1.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/stub_todo_debt_census.report.json"
LOG="${OUT_DIR}/stub_todo_debt_census.log.jsonl"

TRACE_ID="bd-1x3.1::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

mkdir -p "${OUT_DIR}"

for path in "${GEN}" "${SUPPORT}" "${PROFILE}" "${ARTIFACT}"; do
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: required file missing: ${path}" >&2
    exit 1
  fi
done

(
  cd "${ROOT}"
  python3 "scripts/generate_stub_todo_debt_census.py" \
    --support-matrix "support_matrix.json" \
    --replacement-profile "tests/conformance/replacement_profile.json" \
    --output "tests/conformance/stub_todo_debt_census.v1.json" \
    --check
)

python3 - "${SUPPORT}" "${PROFILE}" "${ARTIFACT}" "${REPORT}" <<'PY'
import json
import pathlib
import sys
from collections import Counter

support_path = pathlib.Path(sys.argv[1])
profile_path = pathlib.Path(sys.argv[2])
artifact_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(sys.argv[4])

support = json.loads(support_path.read_text(encoding="utf-8"))
profile = json.loads(profile_path.read_text(encoding="utf-8"))
artifact = json.loads(artifact_path.read_text(encoding="utf-8"))

if artifact.get("schema_version") != "v1":
    raise SystemExit("FAIL: schema_version must be v1")
if artifact.get("bead") != "bd-1pbw":
    raise SystemExit("FAIL: bead must be bd-1pbw")

exported = artifact.get("exported_taxonomy_view", {})
replacement_view = artifact.get("replacement_claim_view", {})
source_debt = artifact.get("critical_source_debt", {})
risk_rows = artifact.get("risk_ranked_debt", [])
recon = artifact.get("reconciliation", {})
summary = artifact.get("summary", {})

if not isinstance(exported, dict):
    raise SystemExit("FAIL: exported_taxonomy_view must be object")
if not isinstance(source_debt, dict):
    raise SystemExit("FAIL: critical_source_debt must be object")
if not isinstance(replacement_view, dict):
    raise SystemExit("FAIL: replacement_claim_view must be object")
if not isinstance(risk_rows, list):
    raise SystemExit("FAIL: risk_ranked_debt must be array")
if not isinstance(recon, dict):
    raise SystemExit("FAIL: reconciliation must be object")
if not isinstance(summary, dict):
    raise SystemExit("FAIL: summary must be object")

symbols = support.get("symbols", [])
derived = Counter(str(row.get("status", "")) for row in symbols)
derived_summary = exported.get("derived_summary", {})
for status in ["Implemented", "RawSyscall", "GlibcCallThrough", "Stub", "DefaultStub"]:
    if int(derived_summary.get(status, 0)) != int(derived.get(status, 0)):
        raise SystemExit(
            f"FAIL: exported_taxonomy_view.derived_summary mismatch for {status} "
            f"(artifact={derived_summary.get(status, 0)} support={derived.get(status, 0)})"
        )

if int(exported.get("total_exported_derived", -1)) != len(symbols):
    raise SystemExit("FAIL: exported_taxonomy_view.total_exported_derived mismatch")
if int(exported.get("total_exported_declared", -1)) != int(support.get("total_exported", -2)):
    raise SystemExit("FAIL: exported_taxonomy_view.total_exported_declared mismatch")

interpose_allowlist = sorted(
    str(m) for m in profile.get("interpose_allowlist", {}).get("modules", [])
)
declared_ct_modules = sorted(
    str(m) for m in profile.get("callthrough_families", {}).get("modules", [])
)
if sorted(replacement_view.get("interpose_allowlist_modules", [])) != interpose_allowlist:
    raise SystemExit("FAIL: replacement_claim_view.interpose_allowlist_modules mismatch")
if sorted(replacement_view.get("declared_callthrough_family_modules", [])) != declared_ct_modules:
    raise SystemExit("FAIL: replacement_claim_view.declared_callthrough_family_modules mismatch")

expected_actual_ct_modules = sorted(
    {
        str(row.get("module", ""))
        for row in symbols
        if row.get("status") == "GlibcCallThrough"
    }
)
if sorted(replacement_view.get("actual_callthrough_modules", [])) != expected_actual_ct_modules:
    raise SystemExit("FAIL: replacement_claim_view.actual_callthrough_modules mismatch")

expected_blockers = []
expected_unapproved_ct = []
for row in symbols:
    status = str(row.get("status", ""))
    if status not in {"Stub", "GlibcCallThrough"}:
        continue
    module = str(row.get("module", ""))
    item = {
        "symbol": str(row.get("symbol", "")),
        "status": status,
        "module": module,
        "perf_class": str(row.get("perf_class", "")),
        "priority": int(row.get("priority", 0)),
        "interpose_allowlisted": module in set(interpose_allowlist),
    }
    expected_blockers.append(item)
    if status == "GlibcCallThrough" and module not in set(interpose_allowlist):
        expected_unapproved_ct.append(item)

expected_blockers.sort(key=lambda row: (row["status"], row["module"], row["symbol"]))
expected_unapproved_ct.sort(key=lambda row: (row["module"], row["symbol"]))

artifact_blockers = replacement_view.get("exported_replacement_blockers", [])
artifact_unapproved_ct = replacement_view.get("exported_interpose_unapproved_callthroughs", [])
if artifact_blockers != expected_blockers:
    raise SystemExit("FAIL: replacement_claim_view.exported_replacement_blockers mismatch")
if artifact_unapproved_ct != expected_unapproved_ct:
    raise SystemExit(
        "FAIL: replacement_claim_view.exported_interpose_unapproved_callthroughs mismatch"
    )

rv_summary = replacement_view.get("summary", {})
if int(rv_summary.get("replacement_blocker_count", -1)) != len(expected_blockers):
    raise SystemExit("FAIL: replacement_claim_view.summary.replacement_blocker_count mismatch")
if int(rv_summary.get("interpose_unapproved_callthrough_count", -1)) != len(expected_unapproved_ct):
    raise SystemExit(
        "FAIL: replacement_claim_view.summary.interpose_unapproved_callthrough_count mismatch"
    )

entries = source_debt.get("entries", [])
if not isinstance(entries, list):
    raise SystemExit("FAIL: critical_source_debt.entries must be array")

unique_symbols = sorted({str(row.get("symbol", "")) for row in entries})
if int(source_debt.get("unique_symbol_count", -1)) != len(unique_symbols):
    raise SystemExit("FAIL: critical_source_debt.unique_symbol_count mismatch")
if int(source_debt.get("occurrence_count", -1)) != len(entries):
    raise SystemExit("FAIL: critical_source_debt.occurrence_count mismatch")

scope_counter = Counter(str(row.get("debt_scope", "")) for row in entries)
if source_debt.get("by_scope", {}) != dict(sorted(scope_counter.items())):
    raise SystemExit("FAIL: critical_source_debt.by_scope mismatch")

for row in entries:
    symbol = str(row.get("symbol", ""))
    if not symbol:
        raise SystemExit("FAIL: debt entry missing symbol")
    if row.get("debt_scope") not in {"critical_non_exported_debt", "exported_shadow_debt"}:
        raise SystemExit(f"FAIL: invalid debt_scope for {symbol}")
    if row.get("family") in {None, "other", ""}:
        raise SystemExit(f"FAIL: non-critical family leaked into debt entries: {symbol}")
    line = int(row.get("line", 0))
    if line <= 0:
        raise SystemExit(f"FAIL: debt entry has invalid line number: {symbol}")

risk_symbols = sorted({str(row.get("symbol", "")) for row in risk_rows})
expected_risk_symbols = sorted(
    set(unique_symbols)
    | {str(row.get("symbol", "")) for row in expected_blockers}
)
if len(risk_rows) != len(expected_risk_symbols):
    raise SystemExit(
        f"FAIL: risk_ranked_debt length mismatch "
        f"(risk={len(risk_rows)} expected={len(expected_risk_symbols)})"
    )
if risk_symbols != expected_risk_symbols:
    raise SystemExit("FAIL: risk_ranked_debt symbol set mismatch")

previous_score = None
for idx, row in enumerate(risk_rows, start=1):
    rank = int(row.get("rank", 0))
    symbol = str(row.get("symbol", ""))
    score = int(row.get("risk_score", -1))
    if rank != idx:
        raise SystemExit(f"FAIL: non-contiguous rank at {symbol}: expected {idx}, got {rank}")
    if previous_score is not None and score > previous_score:
        raise SystemExit("FAIL: risk_ranked_debt is not sorted by descending risk_score")
    previous_score = score
    if row.get("risk_tier") not in {"critical", "high", "medium", "low"}:
        raise SystemExit(f"FAIL: invalid risk_tier for {symbol}")
    if not isinstance(row.get("rationale"), list) or not row["rationale"]:
        raise SystemExit(f"FAIL: missing rationale for {symbol}")

non_exported_symbols = sorted(
    {str(row.get("symbol")) for row in entries if not bool(row.get("in_support_matrix"))}
)
exported_symbols = sorted(
    {str(row.get("symbol")) for row in entries if bool(row.get("in_support_matrix"))}
)

if int(recon.get("critical_non_exported_todo_count", -1)) != len(non_exported_symbols):
    raise SystemExit("FAIL: reconciliation.critical_non_exported_todo_count mismatch")
if int(recon.get("critical_exported_shadow_todo_count", -1)) != len(exported_symbols):
    raise SystemExit("FAIL: reconciliation.critical_exported_shadow_todo_count mismatch")
if sorted(recon.get("critical_non_exported_symbols", [])) != non_exported_symbols:
    raise SystemExit("FAIL: reconciliation.critical_non_exported_symbols mismatch")
if sorted(recon.get("critical_exported_shadow_symbols", [])) != exported_symbols:
    raise SystemExit("FAIL: reconciliation.critical_exported_shadow_symbols mismatch")
if bool(recon.get("ambiguity_resolved")) is not True:
    raise SystemExit("FAIL: reconciliation.ambiguity_resolved must be true")
if int(recon.get("replacement_blocker_count", -1)) != len(expected_blockers):
    raise SystemExit("FAIL: reconciliation.replacement_blocker_count mismatch")
if int(recon.get("interpose_unapproved_callthrough_count", -1)) != len(expected_unapproved_ct):
    raise SystemExit("FAIL: reconciliation.interpose_unapproved_callthrough_count mismatch")
if sorted(recon.get("replacement_blocker_symbols", [])) != sorted(
    [row["symbol"] for row in expected_blockers]
):
    raise SystemExit("FAIL: reconciliation.replacement_blocker_symbols mismatch")
if sorted(recon.get("interpose_unapproved_callthrough_symbols", [])) != sorted(
    [row["symbol"] for row in expected_unapproved_ct]
):
    raise SystemExit("FAIL: reconciliation.interpose_unapproved_callthrough_symbols mismatch")

if int(summary.get("priority_item_count", -1)) != len(risk_rows):
    raise SystemExit("FAIL: summary.priority_item_count mismatch")
if risk_rows:
    if summary.get("top_priority_symbol") != risk_rows[0]["symbol"]:
        raise SystemExit("FAIL: summary.top_priority_symbol mismatch")
    if int(summary.get("top_priority_risk_score", -1)) != int(risk_rows[0]["risk_score"]):
        raise SystemExit("FAIL: summary.top_priority_risk_score mismatch")
if int(summary.get("replacement_blocker_count", -1)) != len(expected_blockers):
    raise SystemExit("FAIL: summary.replacement_blocker_count mismatch")
if int(summary.get("interpose_unapproved_callthrough_count", -1)) != len(expected_unapproved_ct):
    raise SystemExit("FAIL: summary.interpose_unapproved_callthrough_count mismatch")

report = {
    "schema_version": "v1",
    "bead": "bd-1x3.1",
    "checks": {
        "artifact_reproducible": "pass",
        "exported_taxonomy_consistent": "pass",
        "replacement_claim_alignment": "pass",
        "source_debt_consistent": "pass",
        "risk_ranking_consistent": "pass",
        "reconciliation_consistent": "pass",
    },
    "summary": {
        "priority_item_count": len(risk_rows),
        "replacement_blocker_count": len(expected_blockers),
        "interpose_unapproved_callthrough_count": len(expected_unapproved_ct),
        "critical_non_exported_todo_count": len(non_exported_symbols),
        "critical_exported_shadow_todo_count": len(exported_symbols),
        "matrix_delta_count": len(recon.get("matrix_summary_deltas", [])),
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(
    "PASS: unified stub/TODO debt census validated "
    f"(priority_items={len(risk_rows)}, non_exported={len(non_exported_symbols)})"
)
PY

python3 - "${TRACE_ID}" "${START_NS}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

trace_id, start_ns, artifact_path, report_path, log_path = sys.argv[1:6]
start_ns_i = int(start_ns)
now_ns = time.time_ns()

artifact = json.loads(pathlib.Path(artifact_path).read_text(encoding="utf-8"))
ranking = artifact.get("risk_ranked_debt", [])
recon = artifact.get("reconciliation", {})

top = ranking[0] if ranking else {}
delta_rows = recon.get("matrix_summary_deltas", [])
priority_reasoning = [
    {
        "symbol": row.get("symbol"),
        "risk_score": row.get("risk_score"),
        "rationale": row.get("rationale", []),
    }
    for row in ranking[:5]
]

event = {
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    "trace_id": trace_id,
    "level": "info",
    "event": "stub_todo_debt_census_gate",
    "bead_id": "bd-1x3.1",
    "stream": "unit",
    "gate": "check_stub_todo_debt_census",
    "mode": "strict",
    "api_family": "stubs",
    "symbol": "census",
    "outcome": "pass",
    "errno": 0,
    "duration_ms": int((now_ns - start_ns_i) / 1_000_000),
    "artifact_refs": [artifact_path, report_path],
    "details": {
        "top_priority_symbol": top.get("symbol"),
        "top_priority_score": top.get("risk_score"),
        "critical_non_exported_todo_count": recon.get("critical_non_exported_todo_count", 0),
        "critical_exported_shadow_todo_count": recon.get("critical_exported_shadow_todo_count", 0),
        "summary_deltas": delta_rows,
        "priority_reasoning": priority_reasoning,
    },
}

pathlib.Path(log_path).write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")
print(f"PASS: wrote stub/TODO debt log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
