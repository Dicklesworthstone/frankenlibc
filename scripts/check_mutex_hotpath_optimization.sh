#!/usr/bin/env bash
# check_mutex_hotpath_optimization.sh — CI gate for bd-300
#
# Validates mutex optimization dossier:
# 1) baseline captures are present and within strict/hardened budgets,
# 2) opportunity selection maps to an opportunity_matrix entry with score >= threshold,
# 3) mutex target symbols are implemented strict_hotpath in support_matrix,
# 4) single-lever proof template is complete with deterministic decision semantics,
# 5) emits deterministic report + structured JSONL diagnostics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="${FRANKENLIBC_MUTEX_OPT_ARTIFACT_PATH:-${ROOT}/tests/conformance/mutex_hotpath_optimization.v1.json}"
OPPORTUNITY="${FRANKENLIBC_MUTEX_OPP_MATRIX_PATH:-${ROOT}/tests/conformance/opportunity_matrix.json}"
SUPPORT="${ROOT}/support_matrix.json"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/mutex_hotpath_optimization.report.json"
LOG="${OUT_DIR}/mutex_hotpath_optimization.log.jsonl"

TRACE_ID="bd-300::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"
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
if artifact.get("bead") != "bd-300":
    violations.append("artifact bead must be bd-300")

baseline = artifact.get("baseline_captures", {})
modes = baseline.get("modes", {})
thresholds = baseline.get("thresholds", {})
for mode in ("strict", "hardened"):
    mode_row = modes.get(mode)
    if not isinstance(mode_row, dict):
        violations.append(f"missing baseline mode: {mode}")
        continue
    for bench in ("lock_unlock", "try_lock"):
        b = mode_row.get(bench)
        if not isinstance(b, dict):
            violations.append(f"{mode}.{bench} baseline missing")
            continue
        p50 = float(b.get("p50_ns_op", -1))
        if p50 <= 0:
            violations.append(f"{mode}.{bench} p50_ns_op must be > 0")
        samples = int(b.get("samples", 0))
        if samples <= 0:
            violations.append(f"{mode}.{bench} samples must be > 0")

strict_budget = float(thresholds.get("strict_p50_budget_ns", 0))
hardened_budget = float(thresholds.get("hardened_p50_budget_ns", 0))
if strict_budget <= 0 or hardened_budget <= 0:
    violations.append("baseline thresholds must be positive")
else:
    strict_lock = float(modes.get("strict", {}).get("lock_unlock", {}).get("p50_ns_op", 10**9))
    hardened_lock = float(modes.get("hardened", {}).get("lock_unlock", {}).get("p50_ns_op", 10**9))
    if strict_lock > strict_budget:
        violations.append(f"strict lock_unlock exceeds budget: {strict_lock} > {strict_budget}")
    if hardened_lock > hardened_budget:
        violations.append(f"hardened lock_unlock exceeds budget: {hardened_lock} > {hardened_budget}")

profile = artifact.get("profile_bundle", {})
for key in ("cpu_profile", "alloc_profile", "syscall_profile"):
    if key not in profile:
        violations.append(f"profile_bundle missing {key}")

for mode in ("strict", "hardened"):
    cpu = profile.get("cpu_profile", {}).get(mode, {})
    if float(cpu.get("elapsed_s", 0)) <= 0:
        violations.append(f"cpu_profile.{mode}.elapsed_s must be > 0")
    alloc = profile.get("alloc_profile", {}).get(mode, {})
    if int(alloc.get("max_rss_kb", 0)) <= 0:
        violations.append(f"alloc_profile.{mode}.max_rss_kb must be > 0")

for key in ("strict_top5", "hardened_top5"):
    top = profile.get("syscall_profile", {}).get(key, [])
    if not isinstance(top, list) or len(top) < 3:
        violations.append(f"syscall_profile.{key} must contain at least 3 rows")

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
    if float(row.get("score", -1)) != selected_score:
        violations.append(
            f"selected score mismatch vs opportunity_matrix ({selected_score} != {row.get('score')})"
        )
    if row.get("status") not in {"eligible", "in_progress", "completed"}:
        violations.append(f"selected opportunity status invalid: {row.get('status')}")

support_rows = {row.get("symbol"): row for row in support.get("symbols", []) if isinstance(row, dict)}
targets = artifact.get("single_lever_optimization", {}).get("target_symbols", [])
if not isinstance(targets, list) or not targets:
    violations.append("single_lever_optimization.target_symbols must be non-empty")
for sym in targets:
    row = support_rows.get(sym)
    if row is None:
        violations.append(f"target symbol missing from support_matrix: {sym}")
        continue
    if row.get("status") != "Implemented":
        violations.append(f"target symbol status must be Implemented: {sym}")
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

report = {
    "schema_version": "v1",
    "bead": "bd-300",
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
        "strict_lock_unlock_p50_ns": modes.get("strict", {}).get("lock_unlock", {}).get("p50_ns_op"),
        "hardened_lock_unlock_p50_ns": modes.get("hardened", {}).get("lock_unlock", {}).get("p50_ns_op"),
        "decision": decision,
    },
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if violations:
    print("FAIL: mutex hot-path optimization guard violations")
    for row in violations:
        print(f"  - {row}")
    raise SystemExit(1)

print(
    "PASS: mutex hot-path optimization dossier validated "
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
    "event": "mutex_hotpath_optimization_guard",
    "bead_id": "bd-300",
    "stream": "perf",
    "gate": "check_mutex_hotpath_optimization",
    "mode": "strict",
    "api_family": "pthread",
    "symbol": "pthread_mutex_lock",
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
print(f"PASS: wrote mutex optimization log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
