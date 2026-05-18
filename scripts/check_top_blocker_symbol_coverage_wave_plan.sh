#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CONTRACT="${TOP_BLOCKER_SYMBOL_WAVE_PLAN_CONTRACT:-$ROOT/tests/conformance/top_blocker_symbol_coverage_wave_plan.v1.json}"
REPORT="${TOP_BLOCKER_SYMBOL_WAVE_PLAN_REPORT:-$ROOT/target/conformance/top_blocker_symbol_coverage_wave_plan.report.json}"
LOG="${TOP_BLOCKER_SYMBOL_WAVE_PLAN_LOG:-$ROOT/target/conformance/top_blocker_symbol_coverage_wave_plan.log.jsonl}"
MODE="validate-only"

if [[ $# -gt 0 ]]; then
  case "$1" in
    --validate-only)
      MODE="validate-only"
      shift
      ;;
    *)
      MODE="unknown:$1"
      shift
      ;;
  esac
fi

if [[ $# -gt 0 ]]; then
  MODE="unknown:$1"
fi

mkdir -p "$(dirname "$REPORT")" "$(dirname "$LOG")"

python3 - "$ROOT" "$CONTRACT" "$REPORT" "$LOG" "$MODE" <<'PY'
import json
import pathlib
import subprocess
import sys
import time
from collections import Counter

root = pathlib.Path(sys.argv[1])
contract_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
log_path = pathlib.Path(sys.argv[4])
mode = sys.argv[5]
start_ns = time.time_ns()

EXPECTED_SCHEMA = "top_blocker_symbol_coverage_wave_plan.v1"
EXPECTED_BEAD = "bd-0agsk.18"
EXPECTED_COMMAND = "scripts/check_top_blocker_symbol_coverage_wave_plan.sh --validate-only"
ALLOWED_STATUSES = {"Implemented", "RawSyscall"}


def load_json(path: pathlib.Path):
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def git_head() -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    except subprocess.CalledProcessError:
        return "unknown"


def now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def finish(outcome: str, signature: str, message: str, **summary):
    report = {
        "schema_version": "top_blocker_symbol_coverage_wave_plan.report.v1",
        "bead": EXPECTED_BEAD,
        "trace_id": f"top-blocker-symbol-wave-plan-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{id(summary)}",
        "source_commit": git_head(),
        "mode": mode,
        "outcome": outcome,
        "failure_signature": signature,
        "message": message,
        "contract": str(contract_path),
        "duration_ms": (time.time_ns() - start_ns) // 1_000_000,
        "summary": summary,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    log_path.write_text(
        json.dumps(
            {
                "timestamp": now_utc(),
                "event": "top_blocker_symbol_coverage_wave_plan_validated" if outcome == "pass" else "top_blocker_symbol_coverage_wave_plan_failed",
                "bead": EXPECTED_BEAD,
                "outcome": outcome,
                "failure_signature": signature,
                "contract": str(contract_path),
                "summary": summary,
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if outcome != "pass":
        raise SystemExit(f"FAIL[{signature}]: {message}")


def fail(signature: str, message: str, **summary):
    finish("fail", signature, message, **summary)


def require(condition: bool, signature: str, message: str, **summary):
    if not condition:
        fail(signature, message, **summary)


if mode != "validate-only":
    fail("unknown_mode", f"only --validate-only is supported; got {mode}")

require(contract_path.is_file(), "contract_missing", f"missing contract: {contract_path}")
contract = load_json(contract_path)
require(contract.get("schema_version") == EXPECTED_SCHEMA, "schema_version", "unexpected schema_version", actual=contract.get("schema_version"))
require(contract.get("generated_by_bead") == EXPECTED_BEAD, "generated_by_bead", "unexpected generated_by_bead", actual=contract.get("generated_by_bead"))
require(contract.get("canonical_command") == EXPECTED_COMMAND, "canonical_command", "unexpected canonical_command", actual=contract.get("canonical_command"))

for rel in contract.get("input_artifacts", []):
    require((root / rel).is_file(), "input_artifact_missing", f"input artifact missing: {rel}", artifact=rel)

support = load_json(root / "support_matrix.json")
support_by_symbol = {row["symbol"]: row for row in support.get("symbols", [])}
readiness = load_json(root / "tests/conformance/replacement_readiness_acceptance_thresholds.v1.json")
drift = load_json(root / "tests/conformance/support_reality_drift_triage.v1.json")
thresholds = load_json(root / "tests/conformance/family_coverage_thresholds.v1.json")
prioritizer = load_json(root / "tests/conformance/fixture_coverage_prioritizer.v1.json")
hardened = load_json(root / "tests/conformance/hardened_mode_coverage_inventory.v1.json")

ctx = contract.get("current_gate_context", {})
expected_summary = readiness.get("expected_current_summary", {})
for key in [
    "claim_gate_decision",
    "family_count",
    "family_fail_count",
    "family_coverage_fail_count",
    "missing_export_count",
    "residual_forbidden_callthrough_count",
    "hardened_coverage_gap_group_count",
]:
    require(ctx.get(key) == expected_summary.get(key), "readiness_context_drift", f"current gate context drifted for {key}", key=key, declared=ctx.get(key), actual=expected_summary.get(key))
require(ctx.get("claim_gate_decision") == "blocked", "claim_gate_not_blocked", "wave plan must preserve blocked readiness decision")

missing_export_symbols = []
missing_export_families = set()
for bucket in drift.get("delta_buckets", []):
    if bucket.get("classification") == "missing_export":
        missing_export_symbols.extend(bucket.get("symbols", []))
        missing_export_families.add(bucket.get("owner_family"))
missing_export_symbols = sorted(missing_export_symbols)
export_wave = contract.get("export_parity_wave", {})
require(sorted(export_wave.get("symbols", [])) == missing_export_symbols, "export_wave_symbol_drift", "export parity wave does not match drift missing exports", declared=sorted(export_wave.get("symbols", [])), actual=missing_export_symbols)
require(set(export_wave.get("module_families", [])) == missing_export_families, "export_wave_family_drift", "export parity wave families do not match drift missing exports", declared=export_wave.get("module_families", []), actual=sorted(missing_export_families))

threshold_records = {row["family_id"]: row for row in thresholds.get("threshold_records", [])}
campaigns = prioritizer.get("campaigns", [])
top_campaigns = campaigns[: contract.get("selection_policy", {}).get("coverage_wave_count", 0)]
waves = contract.get("coverage_waves", [])
require(len(waves) == len(top_campaigns) == 8, "coverage_wave_count", "expected exactly the top eight prioritizer campaigns", declared=len(waves), actual=len(top_campaigns))

for wave, campaign in zip(waves, top_campaigns):
    require(wave.get("campaign_id") == campaign.get("campaign_id"), "campaign_order_drift", "coverage wave order no longer matches prioritizer rank", wave=wave.get("campaign_id"), campaign=campaign.get("campaign_id"))
    for key in ["rank", "module", "title", "current_coverage_pct", "expected_coverage_after_first_wave_pct", "target_total", "target_covered", "target_uncovered"]:
        wave_key = "module_family" if key == "module" else key
        require(wave.get(wave_key) == campaign.get(key), "campaign_field_drift", f"coverage wave field drifted for {campaign.get('campaign_id')}:{key}", field=key, wave=wave.get(wave_key), campaign=campaign.get(key))
    require(wave.get("first_wave_symbols") == campaign.get("first_wave_symbols"), "first_wave_symbol_drift", f"first wave symbols drifted for {campaign.get('campaign_id')}", wave=wave.get("first_wave_symbols"), campaign=campaign.get("first_wave_symbols"))
    record = threshold_records.get(wave.get("module_family"))
    require(record is not None, "threshold_record_missing", f"missing family threshold for {wave.get('module_family')}", family=wave.get("module_family"))
    require(record.get("decision") in {"pass", "fail"}, "threshold_record_decision", f"family threshold has invalid decision for {wave.get('module_family')}", family=wave.get("module_family"), decision=record.get("decision"))
    status_counts = Counter()
    missing_status = []
    disallowed = []
    for symbol in wave.get("first_wave_symbols", []):
        row = support_by_symbol.get(symbol)
        if row is None:
            missing_status.append(symbol)
            continue
        status = row.get("status")
        status_counts[status] += 1
        if status not in ALLOWED_STATUSES:
            disallowed.append({"symbol": symbol, "status": status})
    require(not missing_status, "support_symbol_missing", f"wave has symbols absent from support matrix: {missing_status}", symbols=missing_status)
    require(not disallowed, "disallowed_candidate_status", "wave includes symbols outside Implemented/RawSyscall", disallowed=disallowed)
    require(dict(sorted(status_counts.items())) == wave.get("candidate_status_counts"), "status_count_drift", f"candidate status counts drifted for {wave.get('campaign_id')}", declared=wave.get("candidate_status_counts"), actual=dict(sorted(status_counts.items())))
    for rel in wave.get("fixture_files", []):
        require((root / rel).is_file(), "wave_fixture_missing", f"wave fixture path missing: {rel}", wave=wave.get("wave_id"), fixture=rel)

gap_ids = sorted(
    group.get("id")
    for group in hardened.get("risk_groups", [])
    if group.get("coverage_status") == "gap_identified"
)
declared_gap_ids = sorted(row.get("risk_group_id") for row in contract.get("hardened_gap_prerequisites", []))
require(declared_gap_ids == gap_ids, "hardened_gap_prereq_drift", "hardened gap prerequisites do not match inventory", declared=declared_gap_ids, actual=gap_ids)

non_goals = " ".join(contract.get("non_goals", []))
require("Do not promote support_matrix rows" in non_goals, "non_goal_missing", "planning bead must explicitly forbid support promotion")
require("version scripts" in non_goals, "non_goal_missing", "planning bead must explicitly forbid version script changes")

finish(
    "pass",
    "none",
    "top-blocker symbol coverage wave plan validated",
    coverage_wave_count=len(waves),
    export_missing_symbols=len(missing_export_symbols),
    hardened_gap_prerequisites=len(declared_gap_ids),
    family_threshold_fail_count=thresholds.get("summary", {}).get("fail_count"),
)
PY

echo "PASS: top-blocker symbol coverage wave plan validated"
