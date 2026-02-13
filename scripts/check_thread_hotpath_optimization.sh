#!/usr/bin/env bash
# check_thread_hotpath_optimization.sh — CI gate for bd-18rq
#
# Validates thread bootstrap optimization dossier:
# 1) strict/hardened baseline captures are present and within configured budgets,
# 2) opportunity selection maps to opp-005 with score >= threshold,
# 3) pthread_create/join/detach rows exist in support_matrix with strict_hotpath perf class,
# 4) single-lever proof checklist is complete and deterministic,
# 5) emits deterministic report + structured JSONL diagnostics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_THREAD_OPT_ARTIFACT_PATH:-${ROOT}/tests/conformance/thread_hotpath_optimization.v1.json}"
OPPORTUNITY="${FRANKENLIBC_THREAD_OPP_MATRIX_PATH:-${ROOT}/tests/conformance/opportunity_matrix.json}"
SUPPORT="${ROOT}/support_matrix.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/thread_hotpath_optimization.report.json"
LOG="${OUT_DIR}/thread_hotpath_optimization.log.jsonl"

TRACE_ID="bd-18rq::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

mkdir -p "${OUT_DIR}"

for path in "${ARTIFACT}" "${OPPORTUNITY}" "${SUPPORT}"; do
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: required file missing: ${path}" >&2
    exit 1
  fi
done

python3 - "${ARTIFACT}" "${OPPORTUNITY}" "${SUPPORT}" "${REPORT}" <<'PY'
import json
import pathlib
import sys

artifact_path = pathlib.Path(sys.argv[1])
opp_path = pathlib.Path(sys.argv[2])
support_path = pathlib.Path(sys.argv[3])
report_path = pathlib.Path(sys.argv[4])

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
opp = json.loads(opp_path.read_text(encoding="utf-8"))
support = json.loads(support_path.read_text(encoding="utf-8"))

violations = []

if artifact.get("schema_version") != "v1":
    violations.append("artifact schema_version must be v1")
if artifact.get("bead") != "bd-18rq":
    violations.append("artifact bead must be bd-18rq")

baseline = artifact.get("baseline_captures", {})
modes = baseline.get("modes", {})
thresholds = baseline.get("thresholds", {})
scenario_budget_key = {
    ("strict", "fanout_fanin_single"): "strict_fanout_budget_ns",
    ("strict", "create_join_churn"): "strict_create_join_budget_ns",
    ("strict", "mixed_detach_join"): "strict_mixed_detach_budget_ns",
    ("hardened", "fanout_fanin_single"): "hardened_fanout_budget_ns",
    ("hardened", "create_join_churn"): "hardened_create_join_budget_ns",
    ("hardened", "mixed_detach_join"): "hardened_mixed_detach_budget_ns",
}
for mode in ("strict", "hardened"):
    mode_row = modes.get(mode)
    if not isinstance(mode_row, dict):
        violations.append(f"missing baseline mode: {mode}")
        continue
    for scenario in ("fanout_fanin_single", "create_join_churn", "mixed_detach_join"):
        row = mode_row.get(scenario)
        if not isinstance(row, dict):
            violations.append(f"{mode}.{scenario} baseline missing")
            continue
        for key in ("p50_ns_case", "p95_ns_case", "p99_ns_case"):
            value = float(row.get(key, -1))
            if value <= 0:
                violations.append(f"{mode}.{scenario}.{key} must be > 0")
        samples = int(row.get("samples", 0))
        if samples <= 0:
            violations.append(f"{mode}.{scenario}.samples must be > 0")
        total_ops = int(row.get("total_ops", 0))
        if total_ops <= 0:
            violations.append(f"{mode}.{scenario}.total_ops must be > 0")
        budget_key = scenario_budget_key[(mode, scenario)]
        budget = float(thresholds.get(budget_key, 0))
        if budget <= 0:
            violations.append(f"baseline thresholds missing positive {budget_key}")
        elif float(row.get("p50_ns_case", 10**18)) > budget:
            violations.append(
                f"{mode}.{scenario} p50 exceeds budget: {row.get('p50_ns_case')} > {budget}"
            )

profile = artifact.get("profile_bundle", {})
mode_summary = profile.get("mode_summary", {})
for mode in ("strict", "hardened"):
    row = mode_summary.get(mode, {})
    if int(row.get("total_cases", 0)) <= 0:
        violations.append(f"profile_bundle.mode_summary.{mode}.total_cases must be > 0")
    for key in ("mean_latency_ns", "median_latency_ns", "max_latency_ns"):
        if float(row.get(key, 0)) <= 0:
            violations.append(f"profile_bundle.mode_summary.{mode}.{key} must be > 0")
    for key in ("total_create_ops", "total_join_ops"):
        if int(row.get(key, 0)) <= 0:
            violations.append(f"profile_bundle.mode_summary.{mode}.{key} must be > 0")

refs = profile.get("trace_references", [])
if not isinstance(refs, list) or len(refs) < 2:
    violations.append("profile_bundle.trace_references must contain at least 2 refs")

selection = artifact.get("opportunity_selection", {})
selected_id = selection.get("selected_entry_id")
threshold = float(selection.get("threshold", 0))
selected_score = float(selection.get("selected_entry_score", 0))
if not selected_id:
    violations.append("opportunity_selection.selected_entry_id missing")
if threshold < 2.0:
    violations.append("opportunity_selection.threshold must be >= 2.0")
if selected_score < threshold:
    violations.append(
        f"selected entry score below threshold: {selected_score} < {threshold}"
    )

opp_entries = {row.get("id"): row for row in opp.get("entries", []) if isinstance(row, dict)}
if selected_id not in opp_entries:
    violations.append(f"selected opportunity id missing from opportunity_matrix: {selected_id}")
else:
    row = opp_entries[selected_id]
    row_score = float(row.get("score", -1))
    if row_score != selected_score:
        violations.append(
            f"selected score mismatch vs opportunity_matrix ({selected_score} != {row.get('score')})"
        )
    if row.get("status") not in {"eligible", "in_progress", "completed"}:
        violations.append(f"selected opportunity status invalid: {row.get('status')}")
    if row.get("module") != "pthread_abi":
        violations.append(f"selected opportunity module must be pthread_abi (got {row.get('module')})")

support_rows = {row.get("symbol"): row for row in support.get("symbols", []) if isinstance(row, dict)}
targets = artifact.get("single_lever_optimization", {}).get("target_symbols", [])
if not isinstance(targets, list) or not targets:
    violations.append("single_lever_optimization.target_symbols must be non-empty")
for sym in targets:
    row = support_rows.get(sym)
    if row is None:
        violations.append(f"target symbol missing from support_matrix: {sym}")
        continue
    if row.get("status") not in {"Implemented", "GlibcCallThrough"}:
        violations.append(f"target symbol status invalid for hotspot dossier: {sym} => {row.get('status')}")
    if row.get("module") != "pthread_abi":
        violations.append(f"target symbol module must be pthread_abi: {sym}")
    if row.get("perf_class") != "strict_hotpath":
        violations.append(f"target symbol perf_class must be strict_hotpath: {sym}")

single = artifact.get("single_lever_optimization", {})
proof = single.get("isomorphism_proof_template", {})
checklist = proof.get("checklist", [])
if not checklist:
    violations.append("isomorphism_proof_template.checklist must be non-empty")
for item in checklist:
    if item.get("status") != "pass":
        violations.append(f"proof checklist item not pass: {item}")

outcome = single.get("outcome", {})
decision = outcome.get("decision")
if decision not in {"improved", "no_change_justified"}:
    violations.append(f"single_lever outcome decision invalid: {decision}")
if decision == "improved":
    if float(outcome.get("measured_improvement_pct", 0)) < 0.5:
        violations.append("improved decision requires measured_improvement_pct >= 0.5")
if decision == "no_change_justified":
    if not str(outcome.get("justification", "")).strip():
        violations.append("no_change_justified requires non-empty justification")

summary = artifact.get("summary", {})
if summary.get("decision") != decision:
    violations.append("summary.decision must match single_lever_optimization.outcome.decision")
if float(summary.get("selected_opportunity_score", -1)) != selected_score:
    violations.append("summary.selected_opportunity_score must match opportunity_selection.selected_entry_score")

report = {
    "schema_version": "v1",
    "bead": "bd-18rq",
    "checks": {
        "artifact_shape_valid": "fail" if violations else "pass",
        "baseline_budget_valid": "fail" if any("budget" in v for v in violations) else "pass",
        "opportunity_selection_valid": "fail" if any("opportunity" in v or "selected" in v for v in violations) else "pass",
        "support_matrix_alignment_valid": "fail" if any("target symbol" in v for v in violations) else "pass",
        "single_lever_proof_valid": "fail" if any("proof" in v or "outcome" in v or "decision" in v for v in violations) else "pass",
    },
    "violations": violations,
    "summary": {
        "selected_entry_id": selected_id,
        "selected_entry_score": selected_score,
        "strict_create_join_churn_p50_ns": modes.get("strict", {}).get("create_join_churn", {}).get("p50_ns_case"),
        "hardened_create_join_churn_p50_ns": modes.get("hardened", {}).get("create_join_churn", {}).get("p50_ns_case"),
        "decision": decision,
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if violations:
    print("FAIL: thread hot-path optimization guard violations")
    for row in violations:
        print(f"  - {row}")
    raise SystemExit(1)

print(
    "PASS: thread hot-path optimization dossier validated "
    f"(selected={selected_id}, score={selected_score}, decision={decision})"
)
PY

python3 - "${TRACE_ID}" "${START_NS}" "${ARTIFACT}" "${REPORT}" "${LOG}" <<'PY'
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

trace_id, start_ns, artifact_path, report_path, log_path = sys.argv[1:6]
report = json.loads(pathlib.Path(report_path).read_text(encoding="utf-8"))
violations = report.get("violations", [])
now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

event = {
    "timestamp": now,
    "trace_id": trace_id,
    "level": "error" if violations else "info",
    "event": "thread_hotpath_optimization_guard",
    "bead_id": "bd-18rq",
    "stream": "perf",
    "gate": "check_thread_hotpath_optimization",
    "mode": "strict+hardened",
    "api_family": "pthread",
    "symbol": "pthread_create|pthread_join|pthread_detach",
    "outcome": "fail" if violations else "pass",
    "errno": 1 if violations else 0,
    "duration_ms": int((time.time_ns() - int(start_ns)) / 1_000_000),
    "artifact_refs": [artifact_path, report_path],
    "details": {
        "selected_entry_id": report.get("summary", {}).get("selected_entry_id"),
        "selected_entry_score": report.get("summary", {}).get("selected_entry_score"),
        "decision": report.get("summary", {}).get("decision"),
        "violation_count": len(violations),
        "violations": violations,
    },
}
pathlib.Path(log_path).write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")
print(f"PASS: wrote thread optimization log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
