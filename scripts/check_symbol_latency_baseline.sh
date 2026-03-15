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

elapsed_ms="$(( ( $(date +%s%N) - start_ns ) / 1000000 ))"
echo "check_symbol_latency_baseline: PASS (${elapsed_ms}ms)"
