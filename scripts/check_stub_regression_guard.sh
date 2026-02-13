#!/usr/bin/env bash
# check_stub_regression_guard.sh — CI gate for bd-1p5v
#
# Enforces:
# 1) Unified stub/TODO census artifact is current.
# 2) High/critical source debt cannot appear without active waiver.
# 3) Matrix Stub symbols cannot appear without explicit matrix waiver.
# 4) Waivers must be explicit, unexpired, and auditable.
# 5) Emits deterministic report + structured JSONL diagnostics.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_stub_todo_debt_census.py"
ARTIFACT="${ROOT}/tests/conformance/stub_todo_debt_census.v1.json"
POLICY_DEFAULT="${ROOT}/tests/conformance/stub_regression_waiver_policy.v1.json"
POLICY="${FRANKENLIBC_STUB_WAIVER_POLICY_PATH:-${POLICY_DEFAULT}}"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/stub_regression_guard.report.json"
LOG="${OUT_DIR}/stub_regression_guard.log.jsonl"
NOW_OVERRIDE="${FRANKENLIBC_STUB_WAIVER_NOW:-}"
TRACE_ID="bd-1p5v::run-$(date -u +%Y%m%dT%H%M%SZ)-$$::001"

START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

mkdir -p "${OUT_DIR}"

for path in "${GEN}" "${ARTIFACT}" "${POLICY}"; do
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

python3 - "${ARTIFACT}" "${POLICY}" "${REPORT}" "${NOW_OVERRIDE}" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

artifact_path = pathlib.Path(sys.argv[1])
policy_path = pathlib.Path(sys.argv[2])
report_path = pathlib.Path(sys.argv[3])
now_override = sys.argv[4].strip()

artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
policy = json.loads(policy_path.read_text(encoding="utf-8"))

if artifact.get("schema_version") != "v1":
    raise SystemExit("FAIL: census schema_version must be v1")
if policy.get("schema_version") != "v1":
    raise SystemExit("FAIL: waiver policy schema_version must be v1")
if policy.get("bead") != "bd-1p5v":
    raise SystemExit("FAIL: waiver policy bead must be bd-1p5v")

if now_override:
    now = datetime.fromisoformat(now_override.replace("Z", "+00:00"))
else:
    now = datetime.now(timezone.utc)

required_waiver_fields = set(
    policy.get("policy", {}).get(
        "waiver_requirements",
        ["symbol", "scope", "risk_tier", "reason", "owner_bead", "approved_by", "expires_utc"],
    )
)

waivers = policy.get("waivers", [])
matrix_waivers = set(policy.get("matrix_waivers", []))
if not isinstance(waivers, list):
    raise SystemExit("FAIL: waivers must be an array")

waiver_by_symbol = {}
violations = []
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

ranking = artifact.get("risk_ranked_debt", [])
if not isinstance(ranking, list):
    raise SystemExit("FAIL: artifact risk_ranked_debt must be array")

forbidden_tiers = set(policy.get("policy", {}).get("forbidden_without_waiver", {}).get("risk_tiers", []))
if not forbidden_tiers:
    forbidden_tiers = {"critical", "high"}

required_scopes = set(
    policy.get("policy", {})
    .get("forbidden_without_waiver", {})
    .get("source_debt_scopes", [])
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
    "bead": "bd-1p5v",
    "policy_path": policy_path.as_posix(),
    "now_utc": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    "checks": {
        "artifact_current": "pass",
        "waiver_schema_valid": "fail" if summary["structural_violations"] else "pass",
        "symbol_coverage_valid": "fail" if summary["symbol_violations"] else "pass",
        "matrix_stub_policy_valid": "fail" if summary["matrix_violations"] else "pass",
        "stale_waivers_absent": "fail" if summary["stale_waiver_count"] else "pass",
    },
    "violations": violations,
    "symbol_violations": violating_symbols,
    "matrix_violations": matrix_violations,
    "stale_waivers": stale_waivers,
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

python3 - "${TRACE_ID}" "${START_NS}" "${ARTIFACT}" "${POLICY}" "${REPORT}" "${LOG}" "${NOW_OVERRIDE}" <<'PY'
import json
import pathlib
import sys
import time
from datetime import datetime, timezone

trace_id, start_ns, artifact_path, policy_path, report_path, log_path, now_override = sys.argv[1:8]
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
    "bead_id": "bd-1p5v",
    "stream": "unit",
    "gate": "check_stub_regression_guard",
    "mode": "strict",
    "api_family": "stubs",
    "symbol": "guard",
    "outcome": "fail" if violations else "pass",
    "errno": 1 if violations else 0,
    "duration_ms": int((time.time_ns() - int(start_ns)) / 1_000_000),
    "artifact_refs": [artifact_path, policy_path, report_path],
    "details": {
        "violation_count": len(violations),
        "violations": violations,
        "symbol_violations": report.get("symbol_violations", []),
        "matrix_violations": report.get("matrix_violations", []),
        "stale_waivers": report.get("stale_waivers", []),
    },
}

pathlib.Path(log_path).write_text(json.dumps(event, separators=(",", ":")) + "\n", encoding="utf-8")
print(f"PASS: wrote stub regression guard log {log_path}")
print(json.dumps(event, separators=(",", ":")))
PY
