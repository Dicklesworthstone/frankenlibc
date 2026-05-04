#!/usr/bin/env bash
# check_first_optimization_gate.sh - deterministic gate for bd-bp8fl.8.4.
#
# Validates that the first optimization selection is backed by profile evidence,
# a verified before/after proof-ledger candidate, budget policy, and behavior
# invariants before follow-up optimization beads can claim speedups.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ARTIFACT="${FRANKENLIBC_FIRST_OPT_GATE:-tests/conformance/first_optimization_gate.v1.json}"
REPORT="${FRANKENLIBC_FIRST_OPT_REPORT:-target/conformance/first_optimization_gate.report.json}"
LOG="${FRANKENLIBC_FIRST_OPT_LOG:-target/conformance/first_optimization_gate.log.jsonl}"

cd "$REPO_ROOT"
mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

echo "=== First Optimization Gate (bd-bp8fl.8.4) ==="
echo "artifact=${ARTIFACT}"
echo "report=${REPORT}"
echo "log=${LOG}"

python3 - "$ARTIFACT" "$REPORT" "$LOG" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

artifact_path = Path(sys.argv[1])
report_path = Path(sys.argv[2])
log_path = Path(sys.argv[3])

errors: list[str] = []


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - gate prints actionable failures
        errors.append(f"{path}: failed to load JSON: {exc}")
        return {}


def require(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def source_commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


artifact = load_json(artifact_path)
source_refs = artifact.get("source_refs", {}) if isinstance(artifact, dict) else {}
hot_path = load_json(Path(source_refs.get("hot_path_profile_report", "")))
ledger = load_json(Path(source_refs.get("optimization_proof_ledger", "")))
perf_budget = load_json(Path(source_refs.get("perf_budget_policy", "")))

require(artifact.get("schema_version") == "v1", "schema_version must be v1")
require(artifact.get("bead") == "bd-bp8fl.8.4", "bead must be bd-bp8fl.8.4")

required_log_fields = set(artifact.get("required_log_fields", []))
expected_log_fields = {
    "trace_id",
    "bead_id",
    "symbol",
    "api_family",
    "benchmark_id",
    "before_value",
    "after_value",
    "threshold",
    "parity_ref",
    "artifact_refs",
    "source_commit",
    "target_dir",
    "failure_signature",
}
require(required_log_fields == expected_log_fields, "required_log_fields mismatch")

selected = artifact.get("selected_optimization", {})
require(isinstance(selected, dict), "selected_optimization must be an object")
candidate_id = selected.get("candidate_id")
require(candidate_id, "selected candidate_id is required")
require(selected.get("optimization_bead_id"), "optimization_bead_id is required")

score = selected.get("opportunity_score", {})
require(float(score.get("minimum_score", 0.0)) >= 2.0, "minimum opportunity score must be >= 2.0")
require(
    float(score.get("score", 0.0)) >= float(score.get("minimum_score", 0.0)),
    "selected opportunity score is below threshold",
)

measurement = selected.get("measurement", {})
before_value = float(measurement.get("before_value", 0.0))
after_value = float(measurement.get("after_value", 0.0))
minimum_improvement = float(measurement.get("minimum_improvement_pct", 0.0))
improvement_pct = float(measurement.get("improvement_pct", 0.0))
threshold = float(selected.get("threshold", {}).get("p50_ns", 0.0))
require(before_value > 0.0 and after_value > 0.0, "before/after values must be positive")
require(after_value < before_value, "after value must improve before value")
require(improvement_pct >= minimum_improvement, "improvement percentage is below minimum")
require(threshold > 0.0 and after_value <= threshold, "after value exceeds selected threshold")

candidates = ledger.get("candidates", []) if isinstance(ledger, dict) else []
candidate = next((row for row in candidates if row.get("candidate_id") == candidate_id), None)
require(candidate is not None, f"candidate {candidate_id} missing from optimization proof ledger")
if candidate:
    require(candidate.get("proof_status") == "verified", "selected candidate must be verified")
    require(candidate.get("symbol") == selected.get("symbol"), "candidate symbol mismatch")
    cand_measurement = candidate.get("measurement", {})
    require(cand_measurement.get("before") == before_value, "candidate before value mismatch")
    require(cand_measurement.get("after") == after_value, "candidate after value mismatch")
    require(
        abs(float(cand_measurement.get("perf_delta_pct", 0.0)) + improvement_pct) < 0.01,
        "candidate perf_delta_pct does not match improvement_pct",
    )
    checks = candidate.get("behavior_checks", [])
    coverage = {
        input_class
        for check in checks
        for input_class in check.get("input_classes", [])
        if check.get("status") == "pass"
    }
    require({"null_ptr", "in_bounds", "boundary", "oversize"}.issubset(coverage), "behavior coverage is incomplete")
    require(all(check.get("status") == "pass" for check in checks), "all candidate behavior checks must pass")

for invariant in selected.get("behavior_invariants", []):
    require(invariant.get("status") == "pass", f"behavior invariant did not pass: {invariant.get('id')}")
require(selected.get("risk_analysis", {}).get("single_lever") is True, "risk analysis must assert single_lever=true")

profile_ref = selected.get("profile_ref", {})
summary_field = profile_ref.get("summary_field")
summary = hot_path.get("summary", {}) if isinstance(hot_path, dict) else {}
require(summary.get("profile_record_count", 0) > 0, "hot path profile report has no profile records")
require(isinstance(summary.get(summary_field), (int, float)), "profile summary field is missing or non-numeric")
require(
    summary.get(summary_field) == profile_ref.get("observed_p50_ns"),
    "profile summary observed value mismatch",
)

extension = perf_budget.get("workload_budget_extension", {}) if isinstance(perf_budget, dict) else {}
require(extension.get("parity_first") is True, "perf budget policy must be parity_first")
require(extension.get("baseline_first") is True, "perf budget policy must be baseline_first")
require(
    extension.get("performance_claims_require_current_behavior_proof") is True,
    "perf budget policy must require current behavior proof",
)

for ref in selected.get("artifact_refs", []):
    path = Path(ref)
    require(path.exists(), f"artifact ref missing: {ref}")
require(Path(selected.get("parity_ref", "")).exists(), "parity_ref path is missing")
require(artifact.get("deferred_hot_paths"), "deferred_hot_paths must be non-empty")
require(artifact.get("claim_guards"), "claim_guards must be non-empty")

status = "fail" if errors else "pass"
failure_signature = "none" if not errors else "first_opt_gate_validation_failed"
report = {
    "schema_version": "v1",
    "bead": "bd-bp8fl.8.4",
    "status": status,
    "errors": errors,
    "selected_optimization": {
        "candidate_id": candidate_id,
        "symbol": selected.get("symbol"),
        "api_family": selected.get("api_family"),
        "benchmark_id": selected.get("benchmark_id"),
        "before_value": before_value,
        "after_value": after_value,
        "threshold": threshold,
        "improvement_pct": improvement_pct,
        "opportunity_score": score.get("score"),
    },
    "deferred_hot_paths": artifact.get("deferred_hot_paths", []),
    "failure_signature": failure_signature,
}
report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

log_row = {
    "trace_id": f"bd-bp8fl.8.4::{candidate_id or 'missing'}::001",
    "bead_id": "bd-bp8fl.8.4",
    "symbol": selected.get("symbol"),
    "api_family": selected.get("api_family"),
    "benchmark_id": selected.get("benchmark_id"),
    "before_value": before_value,
    "after_value": after_value,
    "threshold": threshold,
    "parity_ref": selected.get("parity_ref"),
    "artifact_refs": selected.get("artifact_refs", []),
    "source_commit": source_commit(),
    "target_dir": str(report_path.parent),
    "failure_signature": failure_signature,
    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
}
log_path.write_text(json.dumps(log_row, sort_keys=True) + "\n", encoding="utf-8")

if errors:
    for error in errors:
        print(f"FAIL: {error}")
    raise SystemExit(1)

print(
    "check_first_optimization_gate: PASS "
    f"candidate={candidate_id} before={before_value} after={after_value} "
    f"threshold={threshold} improvement_pct={improvement_pct}"
)
PY
