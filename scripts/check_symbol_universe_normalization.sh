#!/usr/bin/env bash
# check_symbol_universe_normalization.sh — CI gate for bd-2vv.9
# Validates symbol universe normalization and support classification.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPORT="$REPO_ROOT/tests/conformance/symbol_universe_normalization.v1.json"
LOG="$REPO_ROOT/target/conformance/symbol_universe_normalization.log.jsonl"
SUPPORT_MATRIX="$REPO_ROOT/support_matrix.json"

echo "=== Symbol Universe Normalization Gate (bd-2vv.9) ==="

echo "--- Generating symbol normalization report ---"
python3 "$SCRIPT_DIR/generate_symbol_universe_normalization.py" -o "$REPORT" --log "$LOG" 2>&1

if [ ! -f "$REPORT" ]; then
    echo "FAIL: symbol normalization report not generated"
    exit 1
fi

if [ ! -f "$LOG" ]; then
    echo "FAIL: symbol normalization telemetry log not generated"
    exit 1
fi

python3 - "$REPORT" "$LOG" "$SUPPORT_MATRIX" <<'PY'
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

report_path = sys.argv[1]
log_path = sys.argv[2]
support_matrix_path = sys.argv[3]
errors = 0

with open(report_path, encoding="utf-8") as f:
    report = json.load(f)
with open(support_matrix_path, encoding="utf-8") as f:
    support_matrix = json.load(f)

summary = report.get("summary", {})
symbols = report.get("normalized_symbols", [])
families = report.get("family_statistics", {})
actions = report.get("unknown_action_list", [])
support_symbols = support_matrix.get("symbols", [])

total = summary.get("total_symbols", 0)
unique = summary.get("unique_symbols", 0)
dupes = summary.get("duplicates", 0)
fam_count = summary.get("families", 0)
native_pct = summary.get("native_implementation_pct", 0)
classifications = summary.get("classifications", {})
confidence = summary.get("confidence_levels", {})

print(f"Symbols:                 {total}")
print(f"  Unique:                {unique}")
print(f"  Duplicates:            {dupes}")
print(f"  Families:              {fam_count}")
print(f"  Native impl:           {native_pct}%")
print(f"  Classifications:       {json.dumps(classifications)}")
print(f"  Confidence levels:     {json.dumps(confidence)}")
print(f"  Action items:          {len(actions)}")
print()

def fail(message):
    global errors
    print(f"FAIL: {message}")
    errors += 1

# Must have symbols
if total < 100:
    fail(f"Only {total} symbols (need >= 100)")
else:
    print(f"PASS: {total} symbols in universe")

if total != len(support_symbols):
    fail(f"report has {total} symbols but support_matrix has {len(support_symbols)}")
else:
    print("PASS: Report symbol count matches support_matrix.symbols[]")

if total != int(support_matrix.get("total_exported", -1)):
    fail("report total differs from support_matrix.total_exported")
else:
    print("PASS: Report total matches support_matrix.total_exported")

# No duplicates
if dupes > 0:
    fail(f"{dupes} duplicate symbols")
else:
    print("PASS: No duplicate symbols")

# Every symbol must have a non-ambiguous classification
unknown_class = classifications.get("unknown", 0)
if unknown_class > 0:
    fail(f"{unknown_class} symbols with unknown classification")
else:
    print("PASS: All symbols have non-ambiguous classification")

# Must have >= 10 families
if fam_count < 10:
    fail(f"Only {fam_count} families (need >= 10)")
else:
    print(f"PASS: {fam_count} families")

unknown_families = sum(1 for row in symbols if row.get("family") == "unknown")
if unknown_families:
    fail(f"{unknown_families} symbols have unknown family")
else:
    print("PASS: All symbols map to canonical families")

issue_rows = [row for row in symbols if row.get("issues")]
if issue_rows:
    sample = ", ".join(row.get("symbol", "?") for row in issue_rows[:5])
    fail(f"{len(issue_rows)} symbols have unresolved normalization issues; sample={sample}")
else:
    print("PASS: No unresolved normalization issues")

# Every symbol must have confidence level != unknown
unknown_conf = confidence.get("unknown", 0)
if unknown_conf > 0:
    fail(f"{unknown_conf} symbols with unknown confidence")
else:
    print("PASS: All symbols have confidence level")

required_rules = {
    "native",
    "syscall-passthrough",
    "host-wrapped",
    "host-delegated",
    "stub",
    "unknown",
}
rules = set(report.get("classification_rules", {}))
missing_rules = sorted(required_rules - rules)
if missing_rules:
    fail(f"missing classification_rules: {missing_rules}")
else:
    print("PASS: Classification rules cover full support taxonomy")

support_by_symbol = {}
for entry in support_symbols:
    symbol = entry.get("symbol")
    if symbol in support_by_symbol:
        fail(f"duplicate support_matrix symbol {symbol}")
    support_by_symbol[symbol] = entry

status_to_class = {
    "Implemented": "native",
    "RawSyscall": "syscall-passthrough",
    "WrapsHostLibc": "host-wrapped",
    "GlibcCallThrough": "host-delegated",
    "Stub": "stub",
}
for row in symbols:
    symbol = row.get("symbol")
    source = support_by_symbol.get(symbol)
    if not source:
        fail(f"{symbol}: missing support_matrix source row")
        continue
    for field in ("module", "status"):
        if row.get(field) != source.get(field):
            fail(f"{symbol}: {field} drift from support_matrix")
    source_perf_class = source.get("perf_class") or "coldpath"
    if row.get("perf_class") != source_perf_class:
        fail(f"{symbol}: perf_class drift from support_matrix defaulting rule")
    expected_class = status_to_class.get(source.get("status"), "unknown")
    if row.get("classification") != expected_class:
        fail(f"{symbol}: classification {row.get('classification')} != {expected_class}")
print("PASS: Normalized rows rebuild support_matrix status/module/perf joins")

with open(log_path, encoding="utf-8") as f:
    log_rows = [json.loads(line) for line in f if line.strip()]

if len(log_rows) != total:
    fail(f"telemetry log has {len(log_rows)} rows, expected {total}")
else:
    print("PASS: Telemetry log has one row per symbol")

required_log_fields = set(report.get("telemetry", {}).get("required_fields", []))
required_log_fields.update({"schema_version", "event", "bead", "module", "support_status", "perf_class"})
log_symbols = Counter()
log_trace_ids = Counter()
report_by_trace = {row.get("trace_id"): row for row in symbols}
for row in log_rows:
    missing = sorted(field for field in required_log_fields if row.get(field) in (None, ""))
    if missing:
        fail(f"log row missing fields {missing}: {row}")
        continue
    log_symbols[row["symbol"]] += 1
    log_trace_ids[row["trace_id"]] += 1
    report_row = report_by_trace.get(row["trace_id"])
    if not report_row:
        fail(f"log trace_id {row['trace_id']} missing from report")
        continue
    for field in ("symbol", "family", "classification", "confidence"):
        if row.get(field) != report_row.get(field):
            fail(f"{row['trace_id']}: log/report {field} mismatch")

duplicate_logged_symbols = [symbol for symbol, count in log_symbols.items() if count != 1]
duplicate_trace_ids = [trace_id for trace_id, count in log_trace_ids.items() if count != 1]
if duplicate_logged_symbols:
    fail(f"telemetry symbol coverage not unique; sample={duplicate_logged_symbols[:5]}")
if duplicate_trace_ids:
    fail(f"telemetry trace_id coverage not unique; sample={duplicate_trace_ids[:5]}")
if not duplicate_logged_symbols and not duplicate_trace_ids:
    print("PASS: Telemetry trace IDs and symbol rows are unique")

# Output must be reproducible (deterministic)
# Re-run generator and compare hash
with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
    tmp_path = tmp.name
with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp_log:
    tmp_log_path = tmp_log.name
result = subprocess.run(
    [
        "python3",
        report_path.replace(
            "tests/conformance/symbol_universe_normalization.v1.json",
            "scripts/generate_symbol_universe_normalization.py",
        ),
        "-o",
        tmp_path,
        "--log",
        tmp_log_path,
    ],
    capture_output=True, text=True
)
if result.returncode == 0:
    with open(tmp_path, encoding="utf-8") as f:
        r2 = json.load(f)
    if r2.get("universe_hash") == report.get("universe_hash"):
        print("PASS: Output is reproducible (same hash)")
    else:
        fail("Output not reproducible (different hash)")
    with open(tmp_log_path, encoding="utf-8") as f:
        log2 = [json.loads(line) for line in f if line.strip()]
    if [row.get("trace_id") for row in log2] == [row.get("trace_id") for row in log_rows]:
        print("PASS: Telemetry trace IDs are reproducible")
    else:
        fail("Telemetry trace IDs are not reproducible")
else:
    fail(f"Could not verify reproducibility: {result.stderr.strip()}")

# Family statistics must be populated
if not families:
    fail("No family statistics")
else:
    print(f"PASS: {len(families)} family statistics populated")

family_symbol_total = sum(int(stats.get("total", 0)) for stats in families.values())
if family_symbol_total != total:
    fail(f"family_statistics totals sum to {family_symbol_total}, expected {total}")
else:
    print("PASS: Family statistics cover the full symbol universe")

if errors > 0:
    print(f"\nFAIL: {errors} errors")
    sys.exit(1)

print(f"\ncheck_symbol_universe_normalization: PASS")
PY
