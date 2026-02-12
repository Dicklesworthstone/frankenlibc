#!/usr/bin/env bash
# check_support_matrix_drift.sh — Guard docs taxonomy drift against harness reality report.
#
# Validates:
# 1. Canonical `tests/conformance/reality_report.v1.json` exactly matches harness-generated
#    output from `support_matrix.json`.
# 2. README and FEATURE_PARITY reality sections match canonical report counts/timestamp/stubs.
#
# Emits structured JSON logs with:
# trace_id, mode, API/symbol scope, outcome, errno, timing_ms, artifact refs.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/support_matrix.json"
REPORT="${ROOT}/tests/conformance/reality_report.v1.json"
README="${ROOT}/README.md"
PARITY="${ROOT}/FEATURE_PARITY.md"

current_ms() {
    python3 - <<'PY'
import time
print(int(time.time() * 1000))
PY
}

log_event() {
    local mode="$1"
    local api="$2"
    local symbol="$3"
    local outcome="$4"
    local errno_code="$5"
    local timing_ms="$6"
    local artifact="$7"
    python3 - "$TRACE_ID" "$mode" "$api" "$symbol" "$outcome" "$errno_code" "$timing_ms" "$artifact" <<'PY'
import json
import sys

trace_id, mode, api, symbol, outcome, errno_code, timing_ms, artifact = sys.argv[1:9]
record = {
    "trace_id": trace_id,
    "mode": mode,
    "api": api,
    "symbol": symbol,
    "outcome": outcome,
    "errno": int(errno_code),
    "timing_ms": int(timing_ms),
    "artifact_ref": artifact,
}
print(json.dumps(record, separators=(",", ":")))
PY
}

for path in "$MATRIX" "$REPORT" "$README" "$PARITY"; do
    if [[ ! -f "$path" ]]; then
        echo "ERROR: required file missing: $path" >&2
        exit 1
    fi
done

TRACE_ID="bd-3rf-$(date -u +%Y%m%dT%H%M%SZ)-$$"
START_MS="$(current_ms)"

on_err() {
    local exit_code=$?
    local end_ms
    end_ms="$(current_ms)"
    local duration=$((end_ms - START_MS))
    log_event "docs_drift" "reality-report" "all" "fail" "$exit_code" "$duration" "$REPORT"
    exit "$exit_code"
}
trap on_err ERR

echo "=== Support Matrix Drift Check (bd-3rf) ==="
echo ""

echo "--- Step 1: canonical reality report matches harness output ---"
generated_json="$(cargo run --quiet -p frankenlibc-harness --bin harness -- reality-report --support-matrix "$MATRIX")"

python3 - "$REPORT" "$generated_json" <<'PY'
import json
import sys

canonical_path = sys.argv[1]
generated = json.loads(sys.argv[2])
with open(canonical_path, "r", encoding="utf-8") as fh:
    canonical = json.load(fh)

if generated != canonical:
    print("ERROR: reality_report.v1.json drift detected")
    if generated.get("generated_at_utc") != canonical.get("generated_at_utc"):
        print(
            f"  generated_at_utc: harness={generated.get('generated_at_utc')} canonical={canonical.get('generated_at_utc')}"
        )
    if generated.get("total_exported") != canonical.get("total_exported"):
        print(
            f"  total_exported: harness={generated.get('total_exported')} canonical={canonical.get('total_exported')}"
        )
    if generated.get("counts") != canonical.get("counts"):
        print(f"  counts: harness={generated.get('counts')} canonical={canonical.get('counts')}")
    if generated.get("stubs") != canonical.get("stubs"):
        print(f"  stubs: harness={generated.get('stubs')} canonical={canonical.get('stubs')}")
    raise SystemExit(1)
PY
echo "PASS: reality report artifact matches harness output"
echo ""

echo "--- Step 2: README and FEATURE_PARITY match canonical report ---"
python3 - "$REPORT" "$README" "$PARITY" <<'PY'
import json
import sys

report_path, readme_path, parity_path = sys.argv[1:4]

with open(report_path, "r", encoding="utf-8") as fh:
    report = json.load(fh)
with open(readme_path, "r", encoding="utf-8") as fh:
    readme = fh.read()
with open(parity_path, "r", encoding="utf-8") as fh:
    parity = fh.read()

total = int(report["total_exported"])
counts = report["counts"]
generated_at = report["generated_at_utc"]
stubs = report["stubs"]

def pct(count: int, denom: int) -> int:
    if denom <= 0:
        return 0
    return int(round((count * 100.0) / denom))

errors = []

status_map = [
    ("Implemented", "implemented"),
    ("RawSyscall", "raw_syscall"),
    ("GlibcCallThrough", "glibc_call_through"),
    ("Stub", "stub"),
]

readme_source = f"Source of truth: `tests/conformance/reality_report.v1.json` (generated `{generated_at}`)."
if readme_source not in readme:
    errors.append("README missing exact source-of-truth line for canonical reality report")

readme_snapshot = (
    f"Reality snapshot: total_exported={total}, implemented={counts['implemented']}, "
    f"raw_syscall={counts['raw_syscall']}, glibc_call_through={counts['glibc_call_through']}, "
    f"stub={counts['stub']}."
)
if readme_snapshot not in readme:
    errors.append("README missing exact reality snapshot line")

if f"Total currently classified exports: **{total}**." not in readme:
    errors.append("README total classified export count does not match report")

for status, key in status_map:
    count = int(counts[key])
    share = pct(count, total)
    row_fragment = f"| `{status}` | {count} | {share}% |"
    if row_fragment not in readme:
        errors.append(f"README missing or stale taxonomy row fragment: {row_fragment}")

for stub in stubs:
    bullet = f"- `{stub}`"
    if bullet not in readme:
        errors.append(f"README missing stub bullet: {bullet}")

parity_source = (
    f"Source of truth for implementation parity is `tests/conformance/reality_report.v1.json` "
    f"(generated `{generated_at}`)."
)
if parity_source not in parity:
    errors.append("FEATURE_PARITY missing exact source-of-truth line for canonical reality report")

if f"Current exported ABI surface is **{total} symbols**, classified as:" not in parity:
    errors.append("FEATURE_PARITY total exported ABI surface does not match report")

for status, key in status_map:
    count = int(counts[key])
    line = f"- `{status}`: {count}"
    if line not in parity:
        errors.append(f"FEATURE_PARITY missing/stale status line: {line}")

for stub in stubs:
    bullet = f"- `{stub}`"
    if bullet not in parity:
        errors.append(f"FEATURE_PARITY missing stub bullet: {bullet}")

if errors:
    print("ERROR: docs drift detected")
    for err in errors:
        print(f"  - {err}")
    raise SystemExit(1)
PY
echo "PASS: docs reality sections match canonical report"
echo ""

END_MS="$(current_ms)"
DURATION_MS=$((END_MS - START_MS))
log_event "docs_drift" "reality-report" "all" "pass" "0" "$DURATION_MS" "$REPORT"

echo "check_support_matrix_drift: PASS"
