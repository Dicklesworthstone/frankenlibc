#!/usr/bin/env bash
# profile_python3_preload.sh — bd-35hjg.1
# Capture perf profile of python3 under LD_PRELOAD in strict/hardened modes
# and compare against no-preload baseline.
#
# Outputs deterministic top-N hot-symbol list to target/perf/python3_preload_profile/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$REPO_ROOT/target/perf/python3_preload_profile"
PRELOAD_LIB="${FRANKENLIBC_LIB:-$REPO_ROOT/target/release/libfrankenlibc_abi.so}"
TRACE_ID="bd-35hjg.1-$(date -u +%Y%m%dT%H%M%SZ)-$$"
TOP_N="${PROFILE_TOP_N:-50}"
TIMEOUT_SEC="${PROFILE_TIMEOUT_SEC:-10}"

PYTHON_CMD="${PYTHON_CMD:-python3 -c 'print(1)'}"

mkdir -p "$OUT_DIR"

read_python_argv() {
    python3 - "$PYTHON_CMD" <<'PY'
import shlex
import sys

try:
    argv = shlex.split(sys.argv[1])
except ValueError as exc:
    print(f"invalid PYTHON_CMD: {exc}", file=sys.stderr)
    raise SystemExit(2)

if not argv:
    print("PYTHON_CMD parsed to an empty argv", file=sys.stderr)
    raise SystemExit(2)

for arg in argv:
    print(arg)
PY
}

if ! command -v perf &>/dev/null; then
    echo "FAIL: perf not found"
    exit 1
fi

PYTHON_ARGV_TEXT="$(read_python_argv)"
mapfile -t PYTHON_ARGV <<<"$PYTHON_ARGV_TEXT"

build_preload_lib() {
    if ! command -v rch >/dev/null 2>&1; then
        echo "FAIL: preload library missing and rch is not available" >&2
        echo "Build with: RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR rch exec -- cargo build -p frankenlibc-abi --release" >&2
        exit 1
    fi

    local target_dir="${CARGO_TARGET_DIR:-/data/tmp/rch_target_frankenlibc_profile_python3_preload_${USER:-agent}}"
    local build_log="$OUT_DIR/rch_build.log"
    local allowlist="${RCH_ENV_ALLOWLIST:-}"
    case ",${allowlist}," in
        *,CARGO_TARGET_DIR,*)
            ;;
        *)
            allowlist="${allowlist:+${allowlist},}CARGO_TARGET_DIR"
            ;;
    esac

    echo "Building frankenlibc-abi through rch..."
    CARGO_TARGET_DIR="$target_dir" RCH_ENV_ALLOWLIST="$allowlist" \
        rch exec -- cargo build -p frankenlibc-abi --release >"$build_log" 2>&1

    if grep -q '\[RCH\] local' "$build_log"; then
        echo "FAIL: refusing local rch fallback; see $build_log" >&2
        exit 1
    fi

    PRELOAD_LIB="$target_dir/release/libfrankenlibc_abi.so"
}

# Check prerequisites
if [[ ! -f "$PRELOAD_LIB" ]]; then
    build_preload_lib
fi

if [[ ! -f "$PRELOAD_LIB" ]]; then
    echo "FAIL: preload library not found after build: $PRELOAD_LIB" >&2
    exit 1
fi

echo "=== Python3 Preload Profiling Harness (bd-35hjg.1) ==="
echo "Trace ID: $TRACE_ID"
echo "Output: $OUT_DIR"
echo "Top N symbols: $TOP_N"
echo "Timeout: ${TIMEOUT_SEC}s"
printf 'Command:'
printf ' %q' "${PYTHON_ARGV[@]}"
printf '\n'
echo ""

profile_run() {
    local mode="$1"
    local label="$2"
    local perf_data="$OUT_DIR/${label}.perf.data"
    local report_txt="$OUT_DIR/${label}.report.txt"
    local hot_symbols="$OUT_DIR/${label}.hot_symbols.json"
    local timing_json="$OUT_DIR/${label}.timing.json"

    echo "--- Profiling: $label ---"

    local env_cmd=()
    case "$mode" in
        baseline)
            ;;
        strict)
            env_cmd=(FRANKENLIBC_MODE=strict LD_PRELOAD="$PRELOAD_LIB")
            ;;
        hardened)
            env_cmd=(FRANKENLIBC_MODE=hardened LD_PRELOAD="$PRELOAD_LIB")
            ;;
    esac

    # Warm-up run to ensure caches are populated
    if [[ "$mode" == "baseline" ]]; then
        timeout "$TIMEOUT_SEC" "${PYTHON_ARGV[@]}" >/dev/null 2>&1 || true
    else
        timeout "$TIMEOUT_SEC" env "${env_cmd[@]}" "${PYTHON_ARGV[@]}" >/dev/null 2>&1 || true
    fi

    # Timed run
    local start_ns
    start_ns=$(python3 -c "import time; print(time.time_ns())")

    # Profile with perf
    # Use -g for call graph, --call-graph dwarf for better stack traces
    local profile_rc=0
    if [[ "$mode" == "baseline" ]]; then
        timeout "$TIMEOUT_SEC" perf record -g -o "$perf_data" -- "${PYTHON_ARGV[@]}" >/dev/null 2>&1 || profile_rc=$?
    else
        timeout "$TIMEOUT_SEC" perf record -g -o "$perf_data" -- env "${env_cmd[@]}" "${PYTHON_ARGV[@]}" >/dev/null 2>&1 || profile_rc=$?
    fi

    local end_ns
    end_ns=$(python3 -c "import time; print(time.time_ns())")
    local duration_ns=$((end_ns - start_ns))
    local duration_ms=$((duration_ns / 1000000))

    echo "  Duration: ${duration_ms}ms"
    if [[ "$profile_rc" -ne 0 ]]; then
        echo "  Profile exit: ${profile_rc}"
    fi

    # Generate report
    if [[ -f "$perf_data" ]]; then
        perf report -i "$perf_data" --stdio --no-children --percent-limit 0.1 > "$report_txt" 2>/dev/null || true

        # Extract hot symbols as JSON
        python3 - "$report_txt" "$hot_symbols" "$TOP_N" "$label" "$duration_ms" "$TRACE_ID" <<'PY'
import json
import re
import sys

report_path = sys.argv[1]
output_path = sys.argv[2]
top_n = int(sys.argv[3])
label = sys.argv[4]
duration_ms = int(sys.argv[5])
trace_id = sys.argv[6]

symbols = []
# Parse perf report output
# Format: "  XX.XX%  command  shared_object  [.] symbol_name"
pattern = re.compile(r'^\s*(\d+\.\d+)%\s+\S+\s+(\S+)\s+\[.\]\s+(.+)$')

try:
    with open(report_path, 'r') as f:
        for line in f:
            match = pattern.match(line)
            if match:
                pct = float(match.group(1))
                obj = match.group(2)
                sym = match.group(3).strip()
                symbols.append({
                    "rank": len(symbols) + 1,
                    "percent": pct,
                    "object": obj,
                    "symbol": sym,
                })
                if len(symbols) >= top_n:
                    break
except Exception as e:
    symbols = [{"error": str(e)}]

result = {
    "trace_id": trace_id,
    "label": label,
    "duration_ms": duration_ms,
    "top_n": top_n,
    "symbol_count": len(symbols),
    "symbols": symbols,
}

with open(output_path, 'w') as f:
    json.dump(result, f, indent=2)
PY
        echo "  Hot symbols: $hot_symbols"
    else
        echo "  Warning: perf data not captured"
        python3 -c "import json; json.dump({'trace_id': '$TRACE_ID', 'label': '$label', 'error': 'perf data not captured'}, open('$hot_symbols', 'w'), indent=2)"
    fi

    # Write timing JSON
    python3 -c "import json; json.dump({'trace_id': '$TRACE_ID', 'label': '$label', 'duration_ms': $duration_ms}, open('$timing_json', 'w'), indent=2)"
}

# Run profiles
profile_run "baseline" "baseline"
profile_run "strict" "strict"
profile_run "hardened" "hardened"

# Generate comparison summary
echo ""
echo "=== Generating comparison summary ==="

python3 - "$OUT_DIR" "$TRACE_ID" <<'SUMMARY'
import json
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
trace_id = sys.argv[2]

baseline = json.loads((out_dir / "baseline.hot_symbols.json").read_text())
strict = json.loads((out_dir / "strict.hot_symbols.json").read_text())
hardened = json.loads((out_dir / "hardened.hot_symbols.json").read_text())

baseline_timing = json.loads((out_dir / "baseline.timing.json").read_text())
strict_timing = json.loads((out_dir / "strict.timing.json").read_text())
hardened_timing = json.loads((out_dir / "hardened.timing.json").read_text())

# Calculate slowdown ratios
baseline_ms = baseline_timing.get("duration_ms", 1)
strict_ms = strict_timing.get("duration_ms", 1)
hardened_ms = hardened_timing.get("duration_ms", 1)

strict_ratio = strict_ms / max(baseline_ms, 1)
hardened_ratio = hardened_ms / max(baseline_ms, 1)

# Find symbols unique to preload modes (potential hot spots)
baseline_syms = {s["symbol"] for s in baseline.get("symbols", [])}
strict_syms = {s["symbol"]: s for s in strict.get("symbols", [])}
hardened_syms = {s["symbol"]: s for s in hardened.get("symbols", [])}

# Symbols in strict but not baseline (membrane overhead)
strict_only = []
for sym, data in strict_syms.items():
    if sym not in baseline_syms:
        strict_only.append(data)

# Symbols in hardened but not baseline
hardened_only = []
for sym, data in hardened_syms.items():
    if sym not in baseline_syms:
        hardened_only.append(data)

summary = {
    "trace_id": trace_id,
    "schema_version": "v1",
    "bead": "bd-35hjg.1",
    "timing": {
        "baseline_ms": baseline_ms,
        "strict_ms": strict_ms,
        "hardened_ms": hardened_ms,
        "strict_ratio": round(strict_ratio, 2),
        "hardened_ratio": round(hardened_ratio, 2),
    },
    "hot_symbol_counts": {
        "baseline": baseline.get("symbol_count", 0),
        "strict": strict.get("symbol_count", 0),
        "hardened": hardened.get("symbol_count", 0),
    },
    "strict_only_hot_symbols": strict_only[:10],
    "hardened_only_hot_symbols": hardened_only[:10],
    "baseline_top5": baseline.get("symbols", [])[:5],
    "strict_top5": strict.get("symbols", [])[:5],
    "hardened_top5": hardened.get("symbols", [])[:5],
}

summary_path = out_dir / "python3_preload_profile_summary.json"
summary_path.write_text(json.dumps(summary, indent=2))
print(f"Summary written to: {summary_path}")
print(f"\nTiming:")
print(f"  Baseline: {baseline_ms}ms")
print(f"  Strict:   {strict_ms}ms ({strict_ratio:.1f}x slowdown)")
print(f"  Hardened: {hardened_ms}ms ({hardened_ratio:.1f}x slowdown)")
print(f"\nStrict-only hot symbols (membrane overhead candidates):")
for s in strict_only[:5]:
    print(f"  {s.get('percent', 0):.1f}%  {s.get('symbol', 'unknown')}")
SUMMARY

echo ""
echo "=== Profiling complete ==="
echo "Results in: $OUT_DIR"
exit 0
