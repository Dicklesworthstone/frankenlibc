#!/usr/bin/env bash
# check_stub_regression_guard.sh — CI gate for bd-1p5v (uplifted by bd-1x3.3)
#
# Enforces:
# 1) Unified stub/TODO census artifact is current.
# 2) High/critical source debt cannot appear without active waiver.
# 3) Matrix Stub symbols cannot appear without explicit matrix waiver.
# 4) Waivers must be explicit, unexpired, and auditable.
# 5) Burn-down thresholds must stay within policy (no regression).
# 6) Defer/downgrade evidence requirements are explicit and auditable.
# 7) Emits deterministic report + structured JSONL diagnostics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_stub_todo_debt_census.py"
ARTIFACT="${ROOT}/tests/conformance/stub_todo_debt_census.v1.json"
POLICY_DEFAULT="${ROOT}/tests/conformance/stub_regression_waiver_policy.v1.json"
POLICY="${FRANKENLIBC_STUB_WAIVER_POLICY_PATH:-${POLICY_DEFAULT}}"
RANKING_DEFAULT="${ROOT}/tests/conformance/stub_priority_ranking.json"
RANKING="${FRANKENLIBC_STUB_PRIORITY_RANKING_PATH:-${RANKING_DEFAULT}}"
WAVE_PLAN_DEFAULT="${ROOT}/tests/conformance/workload_api_wave_plan.v1.json"
WAVE_PLAN="${FRANKENLIBC_STUB_WAVE_PLAN_PATH:-${WAVE_PLAN_DEFAULT}}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/stub_regression_guard.report.json"
LOG="${OUT_DIR}/stub_regression_guard.log.jsonl"
NOW_OVERRIDE="${FRANKENLIBC_STUB_WAIVER_NOW:-}"
TRACE_ID="bd-1x3.3::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

mkdir -p "${OUT_DIR}"

for path in "${GEN}" "${ARTIFACT}" "${POLICY}" "${RANKING}" "${WAVE_PLAN}"; do
  if [[ ! -f "${path}" ]]; then
    echo "FAIL: required file missing: ${path}" >&2
    exit 1
  fi
done

(
  cd "${ROOT}"
  python3 "scripts/generate_stub_todo_debt_census.py" \
    --support-matrix "support_matrix.json" \
    --output "tests/conformance/stub_todo_debt_census.v1.json" \
    --check
)

python3 - "${ARTIFACT}" "${POLICY}" "${RANKING}" "${WAVE_PLAN}" "${REPORT}" "${NOW_OVERRIDE}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

artifact_path = pathlib.Path(sys.argv[1])
policy_path = pathlib.Path(sys.argv[2])
ranking_path = pathlib.Path(sys.argv[3])
wave_plan_path = pathlib.Path(sys.argv[4])
report_path = pathlib.Path(sys.argv[5])
now_override = sys.argv[6].strip()

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
policy = json.loads(policy_path.read_text(encoding="utf-8"))
stub_ranking = json.loads(ranking_path.read_text(encoding="utf-8"))
wave_plan = json.loads(wave_plan_path.read_text(encoding="utf-8"))

if artifact.get("schema_version") != "v1":
    raise SystemExit("FAIL: census schema_version must be v1")
if policy.get("schema_version") != "v1":
    raise SystemExit("FAIL: waiver policy schema_version must be v1")
if policy.get("bead") not in {"bd-1p5v", "bd-1x3.3"}:
    raise SystemExit("FAIL: waiver policy bead must be bd-1p5v or bd-1x3.3")
if stub_ranking.get("schema_version") is None:
    raise SystemExit("FAIL: stub ranking schema_version missing")
if wave_plan.get("schema_version") != "v1":
    raise SystemExit("FAIL: workload wave plan schema_version must be v1")

if now_override:
    now = datetime.fromisoformat(now_override.replace("Z", "+00:00"))
else:
    now = datetime.now(timezone.utc)

policy_obj = policy.get("policy", {})
required_waiver_fields = set(
    policy.get("policy", {}).get(
        "waiver_requirements",
        ["symbol", "scope", "risk_tier", "reason", "owner_bead", "approved_by", "expires_utc"],
    )
)
downgrade_fields = set(
    policy_obj.get(
        "downgrade_evidence_requirements",
        ["symbol", "scope", "risk_tier", "reason", "owner_bead", "approved_by", "expires_utc"],
    )
)

waivers = policy.get("waivers", [])
matrix_waivers = set(policy.get("matrix_waivers", []))
if not isinstance(waivers, list):
    raise SystemExit("FAIL: waivers must be an array")
if not isinstance(policy.get("matrix_waivers", []), list):
    raise SystemExit("FAIL: matrix_waivers must be an array")

waiver_by_symbol = {}
violations = []
evidence_violations = []
for idx, waiver in enumerate(waivers):
    if not isinstance(waiver, dict):
        violations.append(f"waivers[{idx}] must be an object")
        continue
    missing = sorted(field for field in required_waiver_fields if field not in waiver)
    if missing:
        violations.append(f"waivers[{idx}] missing required fields: {missing}")
        continue

    symbol = str(waiver["symbol"])
    try:
        expiry = datetime.fromisoformat(str(waiver["expires_utc"]).replace("Z", "+00:00"))
    except ValueError:
        violations.append(f"waiver {symbol}: invalid expires_utc")
        continue
    if expiry <= now:
        violations.append(
            f"waiver {symbol}: expired at {waiver['expires_utc']} (now={now.isoformat()})"
        )
    waiver_by_symbol[symbol] = waiver

    for field in sorted(required_waiver_fields):
        value = waiver.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            evidence_violations.append(f"waiver {symbol}: empty {field}")
    owner_bead = str(waiver.get("owner_bead", ""))
    if owner_bead and not owner_bead.startswith("bd-"):
        evidence_violations.append(f"waiver {symbol}: owner_bead must start with bd-")

ranking = artifact.get("risk_ranked_debt", [])
if not isinstance(ranking, list):
    raise SystemExit("FAIL: artifact risk_ranked_debt must be array")

reconciliation = artifact.get("reconciliation", {})
matrix_summary_deltas = reconciliation.get("matrix_summary_deltas", [])
if not isinstance(matrix_summary_deltas, list):
    raise SystemExit("FAIL: artifact reconciliation.matrix_summary_deltas must be array")
reported_delta_count = artifact.get("summary", {}).get("nonzero_matrix_delta_count")
if reported_delta_count != len(matrix_summary_deltas):
    raise SystemExit(
        "FAIL: artifact summary.nonzero_matrix_delta_count must match matrix_summary_deltas length"
    )
if matrix_summary_deltas:
    raise SystemExit(
        "FAIL: support matrix declared summary disagrees with derived symbol counts: "
        + json.dumps(matrix_summary_deltas, sort_keys=True)
    )

forbidden_tiers = set(policy_obj.get("forbidden_without_waiver", {}).get("risk_tiers", []))
if not forbidden_tiers:
    forbidden_tiers = {"critical", "high"}

required_scopes = set(
    policy_obj.get("forbidden_without_waiver", {}).get("source_debt_scopes", [])
)
if not required_scopes:
    required_scopes = {"critical_non_exported_debt", "exported_shadow_debt"}

active_symbols = set()
violating_symbols = []

for row in ranking:
    symbol = str(row.get("symbol", ""))
    tier = str(row.get("risk_tier", ""))
    scope = str(row.get("debt_scope", ""))
    if not symbol:
        continue
    active_symbols.add(symbol)
    if tier not in forbidden_tiers:
        continue
    if scope not in required_scopes:
        continue

    waiver = waiver_by_symbol.get(symbol)
    if waiver is None:
        violating_symbols.append(
            {
                "symbol": symbol,
                "reason": "missing_waiver",
                "risk_tier": tier,
                "scope": scope,
            }
        )
        continue
    if str(waiver["scope"]) != scope:
        violating_symbols.append(
            {
                "symbol": symbol,
                "reason": "scope_mismatch",
                "risk_tier": tier,
                "scope": scope,
                "waiver_scope": waiver["scope"],
            }
        )
        continue
    if str(waiver["risk_tier"]) != tier:
        violating_symbols.append(
            {
                "symbol": symbol,
                "reason": "risk_tier_mismatch",
                "risk_tier": tier,
                "waiver_risk_tier": waiver["risk_tier"],
                "scope": scope,
            }
        )

stale_waivers = sorted(symbol for symbol in waiver_by_symbol if symbol not in active_symbols)
for symbol in stale_waivers:
    violations.append(f"waiver {symbol}: stale (symbol not present in active debt set)")

stub_symbols = artifact.get("exported_taxonomy_view", {}).get("stub_symbols", [])
if not isinstance(stub_symbols, list):
    raise SystemExit("FAIL: artifact exported_taxonomy_view.stub_symbols must be array")
matrix_violations = []
for row in stub_symbols:
    symbol = str(row.get("symbol", ""))
    if symbol and symbol not in matrix_waivers:
        matrix_violations.append(
            {
                "symbol": symbol,
                "reason": "matrix_stub_without_waiver",
            }
        )

# Burn-down threshold policy (no-regression ceiling check).
burn_down = stub_ranking.get("burn_down", {})
if not isinstance(burn_down, dict):
    raise SystemExit("FAIL: stub ranking burn_down must be object")

wave_rows = burn_down.get("wave_plan", [])
if not isinstance(wave_rows, list):
    raise SystemExit("FAIL: stub ranking burn_down.wave_plan must be array")

total_non_implemented = int(burn_down.get("total_non_implemented", 0))
symbols_unscheduled = int(burn_down.get("symbols_unscheduled", 0))
unscheduled_waves = 0
for row in wave_rows:
    if not isinstance(row, dict):
        continue
    if str(row.get("status", "")) == "unscheduled" and int(row.get("symbols", 0)) > 0:
        unscheduled_waves += 1

unscheduled_share_pct = 0.0
if total_non_implemented > 0:
    unscheduled_share_pct = (symbols_unscheduled * 100.0) / float(total_non_implemented)

thresholds = policy_obj.get("burn_down_thresholds", {})
if not isinstance(thresholds, dict):
    raise SystemExit("FAIL: policy.burn_down_thresholds must be object")

burn_down_violations = []

def check_max(threshold_key: str, actual: float):
    limit = thresholds.get(threshold_key)
    if limit is None:
        return
    try:
        limit_f = float(limit)
    except (TypeError, ValueError):
        burn_down_violations.append(f"invalid threshold {threshold_key}: {limit!r}")
        return
    if actual > limit_f:
        burn_down_violations.append(
            f"{threshold_key} exceeded: actual={actual:.2f} limit={limit_f:.2f}"
        )

check_max("max_total_non_implemented", float(total_non_implemented))
check_max("max_symbols_unscheduled", float(symbols_unscheduled))
check_max("max_unscheduled_waves", float(unscheduled_waves))
check_max("max_unscheduled_share_pct", float(unscheduled_share_pct))

# Downgrade/defer evidence requirements.
downgrade_policy = wave_plan.get("downgrade_policy", {})
if not isinstance(downgrade_policy, dict):
    raise SystemExit("FAIL: workload wave plan downgrade_policy must be object")
downgraded_rows = downgrade_policy.get("waived_symbols", [])
if not isinstance(downgraded_rows, list):
    raise SystemExit("FAIL: workload wave plan downgrade_policy.waived_symbols must be array")

downgrade_evidence_violations = []
for idx, row in enumerate(downgraded_rows):
    if not isinstance(row, dict):
        downgrade_evidence_violations.append(f"downgrade row {idx}: must be object")
        continue
    for field in sorted(downgrade_fields):
        value = row.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            downgrade_evidence_violations.append(
                f"downgrade {row.get('symbol', f'row-{idx}')}: missing/empty {field}"
            )
    symbol = str(row.get("symbol", ""))
    if symbol and symbol not in waiver_by_symbol:
        downgrade_evidence_violations.append(
            f"downgrade {symbol}: missing corresponding waiver entry"
        )
    owner_bead = str(row.get("owner_bead", ""))
    if owner_bead and not owner_bead.startswith("bd-"):
        downgrade_evidence_violations.append(
            f"downgrade {symbol or f'row-{idx}'}: owner_bead must start with bd-"
        )
    expires = str(row.get("expires_utc", ""))
    if expires:
        try:
            expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            if expiry <= now:
                downgrade_evidence_violations.append(
                    f"downgrade {symbol or f'row-{idx}'}: expires_utc is not in the future"
                )
        except ValueError:
            downgrade_evidence_violations.append(
                f"downgrade {symbol or f'row-{idx}'}: invalid expires_utc"
            )

violations.extend(evidence_violations)
violations.extend(burn_down_violations)
violations.extend(downgrade_evidence_violations)
violations.extend([f"{row['symbol']}: {row['reason']}" for row in violating_symbols])
violations.extend([f"{row['symbol']}: {row['reason']}" for row in matrix_violations])

summary = {
    "active_forbidden_symbols": len(
        [
            row
            for row in ranking
            if row.get("risk_tier") in forbidden_tiers
            and row.get("debt_scope") in required_scopes
        ]
    ),
    "waiver_count": len(waivers),
    "stale_waiver_count": len(stale_waivers),
    "symbol_violations": len(violating_symbols),
    "matrix_violations": len(matrix_violations),
    "waiver_evidence_violations": len(evidence_violations),
    "burn_down_threshold_violations": len(burn_down_violations),
    "downgrade_evidence_violations": len(downgrade_evidence_violations),
    "downgraded_symbol_count": len(downgraded_rows),
    "burn_down_snapshot": {
        "total_non_implemented": total_non_implemented,
        "symbols_unscheduled": symbols_unscheduled,
        "unscheduled_waves": unscheduled_waves,
        "unscheduled_share_pct": round(unscheduled_share_pct, 2),
    },
    "structural_violations": len(
        [
            v
            for v in violations
            if "missing required fields" in v
            or "invalid expires_utc" in v
            or "expired" in v
            or "stale" in v
        ]
    ),
}

report = {
    "schema_version": "v1",
    "bead": "bd-1x3.3",
    "uplift_bead": "bd-1p5v",
    "policy_path": policy_path.as_posix(),
    "stub_priority_ranking_path": ranking_path.as_posix(),
    "wave_plan_path": wave_plan_path.as_posix(),
    "now_utc": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    "checks": {
        "artifact_current": "pass",
        "waiver_schema_valid": "fail" if summary["structural_violations"] else "pass",
        "symbol_coverage_valid": "fail" if summary["symbol_violations"] else "pass",
        "matrix_stub_policy_valid": "fail" if summary["matrix_violations"] else "pass",
        "stale_waivers_absent": "fail" if summary["stale_waiver_count"] else "pass",
        "waiver_evidence_valid": "fail" if summary["waiver_evidence_violations"] else "pass",
        "burn_down_thresholds_valid": "fail"
        if summary["burn_down_threshold_violations"]
        else "pass",
        "downgrade_evidence_valid": "fail"
        if summary["downgrade_evidence_violations"]
        else "pass",
    },
    "violations": violations,
    "symbol_violations": violating_symbols,
    "matrix_violations": matrix_violations,
    "stale_waivers": stale_waivers,
    "waiver_evidence_violations": evidence_violations,
    "burn_down_threshold_violations": burn_down_violations,
    "downgrade_evidence_violations": downgrade_evidence_violations,
    "summary": summary,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

if violations:
    print("FAIL: stub regression guard violations detected")
    for item in violations:
        print(f"  - {item}")
    raise SystemExit(1)

print(
    "PASS: stub regression guard validated "
    f"(guarded_symbols={summary['active_forbidden_symbols']}, waivers={summary['waiver_count']})"
)
PY

python3 - "${TRACE_ID}" "${START_NS}" "${ARTIFACT}" "${POLICY}" "${RANKING}" "${WAVE_PLAN}" "${REPORT}" "${LOG}" "${NOW_OVERRIDE}" <<'PY'
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

trace_id, start_ns, artifact_path, policy_path, ranking_path, wave_plan_path, report_path, log_path, now_override = sys.argv[1:10]
report = json.loads(pathlib.Path(report_path).read_text(encoding="utf-8"))
violations = report.get("violations", [])
now = (
    datetime.fromisoformat(now_override.replace("Z", "+00:00"))
    if now_override
    else datetime.now(timezone.utc)
)

event = {
    "timestamp": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    "trace_id": trace_id,
    "level": "error" if violations else "info",
    "event": "stub_regression_guard",
    "bead_id": "bd-1x3.3",
    "stream": "unit",
    "gate": "check_stub_regression_guard",
    "mode": "strict",
    "api_family": "stubs",
    "symbol": "guard",
    "outcome": "fail" if violations else "pass",
    "errno": 1 if violations else 0,
    "duration_ms": int((time.time_ns() - int(start_ns)) / 1_000_000),
    "artifact_refs": [artifact_path, policy_path, ranking_path, wave_plan_path, report_path],
    "details": {
        "violation_count": len(violations),
        "violations": violations,
        "symbol_violations": report.get("symbol_violations", []),
        "matrix_violations": report.get("matrix_violations", []),
        "stale_waivers": report.get("stale_waivers", []),
        "waiver_evidence_violations": report.get("waiver_evidence_violations", []),
        "burn_down_threshold_violations": report.get("burn_down_threshold_violations", []),
        "downgrade_evidence_violations": report.get("downgrade_evidence_violations", []),
    },
}

pathlib.Path(log_path).write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")
print(f"PASS: wrote stub regression guard log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
