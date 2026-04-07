#!/usr/bin/env bash
# check_symbol_latency_baseline.sh — drift + integrity gate for bd-3h1u.1
#
# Validates that:
# 1) Canonical symbol latency baseline artifact is valid JSON and internally consistent.
# 2) Canonical artifact matches deterministic generator+ingestion output.
#
# Exit codes:
#   0 -> pass
#   1 -> validation/drift failure
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_symbol_latency_baseline.py"
INGEST="${ROOT}/scripts/ingest_symbol_latency_samples.py"
CANONICAL="${ROOT}/tests/conformance/symbol_latency_baseline.v1.json"
SUPPORT_MATRIX="${ROOT}/support_matrix.json"
CAPTURE_MAP="${ROOT}/tests/conformance/symbol_latency_capture_map.v1.json"
SAMPLE_LOG="${ROOT}/tests/conformance/symbol_latency_samples.v1.log"
PERF_POLICY="${ROOT}/tests/conformance/perf_budget_policy.json"
SYMBOL_LATENCY_REPORT="${FRANKENLIBC_SYMBOL_LATENCY_REPORT:-${ROOT}/target/conformance/symbol_latency_perf_gate.current.v1.json}"
SYMBOL_LATENCY_EVENT_LOG="${FRANKENLIBC_SYMBOL_LATENCY_EVENT_LOG:-${ROOT}/target/conformance/symbol_latency_perf_gate.log.jsonl}"
SYMBOL_LATENCY_TRACE_ID="${FRANKENLIBC_SYMBOL_LATENCY_TRACE_ID:-bd-l93x.5::symbol-latency-budget-gate}"
ALLOW_WAIVED_TARGET_VIOLATIONS="${FRANKENLIBC_SYMBOL_LATENCY_ALLOW_WAIVED_TARGET_VIOLATIONS:-1}"

start_ns="$(date +%s%N)"

fail() {
    echo "FAIL: $1"
    echo "check_symbol_latency_baseline: FAILED"
    exit 1
}

[[ -f "${GEN}" ]] || fail "missing generator: ${GEN}"
[[ -x "${GEN}" ]] || fail "generator not executable: ${GEN}"
[[ -f "${INGEST}" ]] || fail "missing ingestion script: ${INGEST}"
[[ -x "${INGEST}" ]] || fail "ingestion script not executable: ${INGEST}"
[[ -f "${CANONICAL}" ]] || fail "missing canonical artifact: ${CANONICAL}"
[[ -f "${SUPPORT_MATRIX}" ]] || fail "missing support_matrix.json"
[[ -f "${CAPTURE_MAP}" ]] || fail "missing capture map: ${CAPTURE_MAP}"
[[ -f "${SAMPLE_LOG}" ]] || fail "missing sample log: ${SAMPLE_LOG}"
[[ -f "${PERF_POLICY}" ]] || fail "missing perf budget policy: ${PERF_POLICY}"

mkdir -p "$(dirname "${SYMBOL_LATENCY_REPORT}")"
mkdir -p "$(dirname "${SYMBOL_LATENCY_EVENT_LOG}")"

perf_baseline_arg=()
if [[ -f "${ROOT}/scripts/perf_baseline.json" ]]; then
    perf_baseline_arg=(--perf-baseline "scripts/perf_baseline.json")
fi

tmp_out="$(mktemp)"
trap 'rm -f "${tmp_out}"' EXIT

(
    cd "${ROOT}"
    python3 "scripts/generate_symbol_latency_baseline.py" \
        --support-matrix "support_matrix.json" \
        "${perf_baseline_arg[@]}" \
        --symbol-fixture-coverage "tests/conformance/symbol_fixture_coverage.v1.json" \
        --output "${tmp_out}" \
        --quiet
    python3 "scripts/ingest_symbol_latency_samples.py" \
        --artifact "${tmp_out}" \
        --capture-map "tests/conformance/symbol_latency_capture_map.v1.json" \
        --log "tests/conformance/symbol_latency_samples.v1.log" \
        --output "${tmp_out}" \
        --quiet
)

python3 - <<'PY' "${CANONICAL}" "${tmp_out}" "${SUPPORT_MATRIX}" || exit 1
import json
import sys

canonical_path, generated_path, support_path = sys.argv[1:4]

with open(canonical_path, "r", encoding="utf-8") as handle:
    canonical = json.load(handle)
with open(generated_path, "r", encoding="utf-8") as handle:
    generated = json.load(handle)
with open(support_path, "r", encoding="utf-8") as handle:
    support = json.load(handle)

errors = []

if canonical != generated:
    errors.append("canonical artifact drift detected vs generator output")

if canonical.get("schema_version") != 1:
    errors.append("schema_version must be 1")
if canonical.get("bead") != "bd-3h1u.1":
    errors.append("bead id must be bd-3h1u.1")

symbols = canonical.get("symbols")
if not isinstance(symbols, list):
    errors.append("symbols must be an array")
    symbols = []

support_symbols = support.get("symbols", [])
if len(symbols) != len(support_symbols):
    errors.append(
        f"symbol count mismatch: artifact={len(symbols)} support_matrix={len(support_symbols)}"
    )

summary = canonical.get("summary", {})
if summary.get("total_symbols") != len(symbols):
    errors.append("summary.total_symbols mismatch")

modes = ("raw", "strict", "hardened")
pcts = ("p50_ns", "p95_ns", "p99_ns")

for row in symbols:
    base = row.get("baseline")
    if not isinstance(base, dict):
        errors.append(f"{row.get('symbol', '?')}: baseline missing")
        continue
    for mode in modes:
        mode_row = base.get(mode)
        if not isinstance(mode_row, dict):
            errors.append(f"{row.get('symbol', '?')}: missing baseline mode {mode}")
            continue
        for pct in pcts:
            if pct not in mode_row:
                errors.append(f"{row.get('symbol', '?')}: {mode}.{pct} missing")
        if "capture_state" not in mode_row:
            errors.append(f"{row.get('symbol', '?')}: {mode}.capture_state missing")

measured = summary.get("mode_percentile_measured_counts", {})
pending = summary.get("mode_percentile_pending_counts", {})
for mode in modes:
    mode_measured = measured.get(mode, {})
    mode_pending = pending.get(mode, {})
    for pct in ("p50", "p95", "p99"):
        m = mode_measured.get(pct)
        p = mode_pending.get(pct)
        if not isinstance(m, int) or not isinstance(p, int):
            errors.append(f"summary counts missing for {mode}.{pct}")
            continue
        if m + p != len(symbols):
            errors.append(
                f"summary counts inconsistent for {mode}.{pct}: measured+pending != total"
            )

if errors:
    for err in errors:
        print(f"ERROR: {err}")
    raise SystemExit(1)

print("symbol_latency_baseline_gate: validated")
PY

python3 - <<'PY' \
    "${CANONICAL}" \
    "${PERF_POLICY}" \
    "${SYMBOL_LATENCY_REPORT}" \
    "${SYMBOL_LATENCY_EVENT_LOG}" \
    "${SYMBOL_LATENCY_TRACE_ID}" \
    "${ALLOW_WAIVED_TARGET_VIOLATIONS}" || exit 1
import datetime as dt
import json
import sys
from pathlib import Path

canonical_path, policy_path, report_path, log_path, trace_id, allow_waived = sys.argv[1:7]
allow_waived = allow_waived == "1"

with open(canonical_path, "r", encoding="utf-8") as handle:
    artifact = json.load(handle)
with open(policy_path, "r", encoding="utf-8") as handle:
    policy = json.load(handle)

today = dt.date.today()
generated_at = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
artifact_refs = [
    "tests/conformance/symbol_latency_baseline.v1.json",
    "tests/conformance/perf_budget_policy.json",
]

budget_key = {
    "strict": "strict_mode_ns",
    "hardened": "hardened_mode_ns",
}

waivers = []
for row in policy.get("active_waivers", []):
    if not isinstance(row, dict):
        continue
    expiry = row.get("expires_at")
    if not isinstance(expiry, str):
        continue
    try:
        if dt.date.fromisoformat(expiry) < today:
            continue
    except ValueError:
        continue
    waivers.append(row)


def lookup_budget(perf_class: str, mode: str):
    entry = policy.get("budgets", {}).get(perf_class)
    if not isinstance(entry, dict):
        return None
    return entry.get(budget_key[mode])


def matching_waiver(symbol: str):
    matches = []
    for waiver in waivers:
        symbols = waiver.get("symbols", [])
        if not isinstance(symbols, list):
            continue
        if "*" in symbols or symbol in symbols:
            matches.append(waiver)
    return matches


def relpath(value: str) -> str:
    try:
        return Path(value).resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return value


summary = {
    "measured_symbol_count": 0,
    "evaluated_symbol_count": 0,
    "evaluated_mode_count": 0,
    "strict_pass": 0,
    "strict_violations": 0,
    "strict_waived": 0,
    "strict_not_applicable": 0,
    "hardened_pass": 0,
    "hardened_violations": 0,
    "hardened_waived": 0,
    "hardened_not_applicable": 0,
}
results = []
violations = []
waived_rows = []
log_rows = []
unwaived_violation = False

for row in artifact.get("symbols", []):
    baseline = row.get("baseline", {})
    raw = baseline.get("raw", {})
    strict = baseline.get("strict", {})
    hardened = baseline.get("hardened", {})
    states = [
        raw.get("capture_state"),
        strict.get("capture_state"),
        hardened.get("capture_state"),
    ]
    if states != ["measured", "measured", "measured"]:
        continue

    symbol = row.get("symbol", "unknown")
    module = row.get("module", "unknown")
    perf_class = row.get("perf_class", "unknown")
    raw_p99 = raw.get("p99_ns")
    strict_p99 = strict.get("p99_ns")
    hardened_p99 = hardened.get("p99_ns")
    if not all(isinstance(value, (int, float)) for value in [raw_p99, strict_p99, hardened_p99]):
        continue

    summary["measured_symbol_count"] += 1
    strict_overhead = float(strict_p99) - float(raw_p99)
    hardened_overhead = float(hardened_p99) - float(raw_p99)
    row_result = {
        "symbol": symbol,
        "module": module,
        "perf_class": perf_class,
        "raw_p99_ns": raw_p99,
        "strict_p99_ns": strict_p99,
        "hardened_p99_ns": hardened_p99,
        "strict_overhead_ns": strict_overhead,
        "hardened_overhead_ns": hardened_overhead,
        "strict_budget_ns": lookup_budget(perf_class, "strict"),
        "hardened_budget_ns": lookup_budget(perf_class, "hardened"),
        "strict_status": "not_applicable",
        "hardened_status": "not_applicable",
        "waiver_beads": [],
    }
    row_waivers = matching_waiver(symbol)
    row_result["waiver_beads"] = [w.get("bead_id", "") for w in row_waivers if w.get("bead_id")]
    symbol_has_applicable_budget = False

    for mode, overhead in [("strict", strict_overhead), ("hardened", hardened_overhead)]:
        budget = row_result[f"{mode}_budget_ns"]
        if budget is None:
            summary[f"{mode}_not_applicable"] += 1
            status = "not_applicable"
        else:
            symbol_has_applicable_budget = True
            summary["evaluated_mode_count"] += 1
            if overhead <= float(budget):
                summary[f"{mode}_pass"] += 1
                status = "pass"
            else:
                waiver = next(
                    (
                        w
                        for w in row_waivers
                        if w.get("scope") in (None, "target_violation_only")
                    ),
                    None,
                )
                if waiver is not None:
                    summary[f"{mode}_waived"] += 1
                    status = "waived_target_violation"
                    waived_rows.append(
                        {
                            "symbol": symbol,
                            "mode": mode,
                            "budget_ns": budget,
                            "overhead_ns": overhead,
                            "waiver_bead_id": waiver.get("bead_id"),
                            "waiver_scope": waiver.get("scope", "target_violation_only"),
                            "expires_at": waiver.get("expires_at"),
                        }
                    )
                else:
                    summary[f"{mode}_violations"] += 1
                    status = "target_violation"
                    violations.append(
                        {
                            "symbol": symbol,
                            "mode": mode,
                            "budget_ns": budget,
                            "overhead_ns": overhead,
                            "perf_class": perf_class,
                            "module": module,
                        }
                    )
                    unwaived_violation = True
        row_result[f"{mode}_status"] = status
        log_rows.append(
            {
                "timestamp": generated_at,
                "trace_id": trace_id,
                "level": "info" if status in {"pass", "not_applicable"} else "warn",
                "event": f"ci.symbol_latency_budget.{status}",
                "bead_id": "bd-l93x.5",
                "mode": mode,
                "api_family": module,
                "symbol": symbol,
                "decision_path": "ci->symbol_latency_budget_gate",
                "healing_action": "None",
                "outcome": status,
                "errno": None,
                "latency_ns": overhead,
                "budget_ns": budget,
                "perf_class": perf_class,
                "artifact_refs": artifact_refs,
            }
        )

    if symbol_has_applicable_budget:
        summary["evaluated_symbol_count"] += 1

    results.append(row_result)

report = {
    "schema_version": 1,
    "bead": "bd-l93x.5",
    "source_bead": artifact.get("bead"),
    "generated_at_utc": generated_at,
    "trace_id": trace_id,
    "artifact": relpath(canonical_path),
    "policy_ref": relpath(policy_path),
    "summary": {
        **summary,
        "gate_passed": (not unwaived_violation) and (allow_waived or not waived_rows),
        "allow_waived_target_violations": allow_waived,
        "active_waiver_beads": sorted(
            {
                waiver.get("bead_id")
                for waiver in waivers
                if isinstance(waiver.get("bead_id"), str) and waiver.get("bead_id")
            }
        ),
    },
    "results": sorted(results, key=lambda row: row["symbol"]),
    "violations": sorted(
        violations,
        key=lambda row: (row["mode"], -float(row["overhead_ns"]), row["symbol"]),
    ),
    "waived": sorted(
        waived_rows,
        key=lambda row: (row["mode"], -float(row["overhead_ns"]), row["symbol"]),
    ),
}

with open(report_path, "w", encoding="utf-8") as handle:
    json.dump(report, handle, indent=2, sort_keys=True)
    handle.write("\n")

with open(log_path, "w", encoding="utf-8") as handle:
    for row in log_rows:
        handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")))
        handle.write("\n")

status = "PASS"
if unwaived_violation:
    status = "FAIL"
elif report["summary"]["strict_waived"] or report["summary"]["hardened_waived"]:
    status = "WAIVED"
print(
    "symbol_latency_perf_budget_gate: "
    f"{status} measured_symbols={summary['measured_symbol_count']} "
    f"strict_violations={summary['strict_violations']} "
    f"hardened_violations={summary['hardened_violations']} "
    f"strict_waived={summary['strict_waived']} "
    f"hardened_waived={summary['hardened_waived']} "
    f"report={report_path}"
)

if unwaived_violation or (not allow_waived and waived_rows):
    raise SystemExit(1)
PY

elapsed_ms="$(( ( $(date +%s%N) - start_ns ) / 1000000 ))"
echo "check_symbol_latency_baseline: PASS (${elapsed_ms}ms)"
