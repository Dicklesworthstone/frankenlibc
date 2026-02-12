#!/usr/bin/env bash
# check_symbol_fixture_coverage.sh — drift + integrity gate for bd-15n.1
#
# Validates:
# 1. Canonical symbol_fixture_coverage artifact matches freshly-generated output.
# 2. Artifact schema/summary invariants hold.
# 3. Uncovered/weak family lists are internally consistent.
#
# Emits structured JSON logs:
# trace_id, mode, family, covered_count, uncovered_count, severity, artifact_ref.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GEN="${ROOT}/scripts/generate_symbol_fixture_coverage.py"
CANONICAL="${ROOT}/tests/conformance/symbol_fixture_coverage.v1.json"
SUPPORT_MATRIX="${ROOT}/support_matrix.json"
FIXTURES_DIR="${ROOT}/tests/conformance/fixtures"
C_FIXTURE_SPEC="${ROOT}/tests/conformance/c_fixture_spec.json"
WORKLOAD_MATRIX="${ROOT}/tests/conformance/workload_matrix.json"

if [[ ! -f "${GEN}" ]]; then
    echo "ERROR: generator script missing: ${GEN}" >&2
    exit 1
fi

if [[ ! -f "${CANONICAL}" ]]; then
    echo "ERROR: canonical artifact missing: ${CANONICAL}" >&2
    exit 1
fi

TRACE_ID="bd-15n.1-$(date -u +%Y%m%dT%H%M%SZ)-$$"
START_NS="$(python3 - <<'PY'
import time
print(time.time_ns())
PY
)"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

python3 "${GEN}" \
  --support-matrix "${SUPPORT_MATRIX}" \
  --fixtures-dir "${FIXTURES_DIR}" \
  --c-fixture-spec "${C_FIXTURE_SPEC}" \
  --workload-matrix "${WORKLOAD_MATRIX}" \
  --output "${tmp}" \
  --quiet >/dev/null

python3 - "${CANONICAL}" "${tmp}" "${TRACE_ID}" "${START_NS}" <<'PY'
import json
import sys
import time

canonical_path, generated_path, trace_id, start_ns = sys.argv[1:5]
start_ns = int(start_ns)

with open(canonical_path, "r", encoding="utf-8") as f:
    canonical = json.load(f)
with open(generated_path, "r", encoding="utf-8") as f:
    generated = json.load(f)

def emit(mode, family, covered, uncovered, severity, artifact):
    print(
        json.dumps(
            {
                "trace_id": trace_id,
                "mode": mode,
                "family": family,
                "covered_count": covered,
                "uncovered_count": uncovered,
                "severity": severity,
                "artifact_ref": artifact,
            },
            separators=(",", ":"),
        )
    )

if canonical != generated:
    print("ERROR: symbol fixture coverage artifact drift detected")
    can_sum = canonical.get("summary", {})
    gen_sum = generated.get("summary", {})
    for key in [
        "total_exported_symbols",
        "covered_exported_symbols",
        "target_total_symbols",
        "target_covered_symbols",
        "target_uncovered_symbols",
    ]:
        if can_sum.get(key) != gen_sum.get(key):
            print(f"  summary.{key}: canonical={can_sum.get(key)} generated={gen_sum.get(key)}")
    can_uncovered = [r.get("module") for r in canonical.get("uncovered_target_families", [])]
    gen_uncovered = [r.get("module") for r in generated.get("uncovered_target_families", [])]
    if can_uncovered != gen_uncovered:
        print(f"  uncovered_target_families mismatch: canonical={can_uncovered} generated={gen_uncovered}")
    emit(
        "symbol_fixture_coverage_gate",
        "all",
        int(gen_sum.get("target_covered_symbols", 0)),
        int(gen_sum.get("target_uncovered_symbols", 0)),
        "fail",
        canonical_path,
    )
    raise SystemExit(1)

required_top = [
    "schema_version",
    "bead",
    "summary",
    "families",
    "uncovered_target_families",
    "weak_target_families",
    "ownership_map",
    "symbols",
]
for key in required_top:
    if key not in canonical:
        raise SystemExit(f"ERROR: canonical artifact missing key '{key}'")

if canonical.get("schema_version") != 1:
    raise SystemExit("ERROR: schema_version must be 1")

summary = canonical["summary"]
families = canonical["families"]
symbols = canonical["symbols"]

if summary["total_exported_symbols"] != len(symbols):
    raise SystemExit(
        "ERROR: summary.total_exported_symbols does not match symbols length"
    )

covered_symbols = sum(1 for row in symbols if row.get("covered"))
if summary["covered_exported_symbols"] != covered_symbols:
    raise SystemExit(
        "ERROR: summary.covered_exported_symbols does not match symbol coverage count"
    )

target_total = sum(int(row.get("target_total", 0)) for row in families)
target_covered = sum(int(row.get("target_covered", 0)) for row in families)
if summary["target_total_symbols"] != target_total:
    raise SystemExit("ERROR: target_total_symbols inconsistent with families")
if summary["target_covered_symbols"] != target_covered:
    raise SystemExit("ERROR: target_covered_symbols inconsistent with families")
if summary["target_uncovered_symbols"] != (target_total - target_covered):
    raise SystemExit("ERROR: target_uncovered_symbols inconsistent with families")

expected_uncovered = sorted(
    [row["module"] for row in families if row.get("target_total", 0) > 0 and row.get("target_covered", 0) == 0]
)
actual_uncovered = sorted([row["module"] for row in canonical["uncovered_target_families"]])
if expected_uncovered != actual_uncovered:
    raise SystemExit(
        f"ERROR: uncovered_target_families mismatch expected={expected_uncovered} actual={actual_uncovered}"
    )

weak_threshold = float(summary["weak_family_threshold_pct"])
expected_weak = sorted(
    [
        row["module"]
        for row in families
        if row.get("target_total", 0) > 0
        and 0 < float(row.get("target_coverage_pct", 0.0)) < weak_threshold
    ]
)
actual_weak = sorted([row["module"] for row in canonical["weak_target_families"]])
if expected_weak != actual_weak:
    raise SystemExit(
        f"ERROR: weak_target_families mismatch expected={expected_weak} actual={actual_weak}"
    )

elapsed_ms = int((time.time_ns() - start_ns) / 1_000_000)
emit(
    "symbol_fixture_coverage_gate",
    "all",
    int(summary["target_covered_symbols"]),
    int(summary["target_uncovered_symbols"]),
    "pass",
    canonical_path,
)
print(f"check_symbol_fixture_coverage: PASS ({elapsed_ms}ms)")
PY
