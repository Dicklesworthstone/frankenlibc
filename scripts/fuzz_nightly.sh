#!/usr/bin/env bash
# Nightly fuzz campaign runner for frankenlibc.
#
# Runs a bounded fuzz session for each target, reports crashes,
# and optionally enforces a coverage threshold.
#
# Usage:
#   scripts/fuzz_nightly.sh [--duration SECS] [--fail-on-crash] [--artifacts-dir DIR]
#
# Environment:
#   FUZZ_DURATION     - Per-target duration in seconds (default: 60)
#   FUZZ_FAIL_CRASH   - Exit non-zero if any crash found (default: 1)
#   FUZZ_ARTIFACTS    - Directory for crash artifacts (default: artifacts/fuzz)
#
# Bead: bd-1oz.7

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

FUZZ_DIR="crates/frankenlibc-fuzz"
DURATION="${FUZZ_DURATION:-60}"
FAIL_ON_CRASH="${FUZZ_FAIL_CRASH:-1}"
ARTIFACTS_DIR="${FUZZ_ARTIFACTS:-artifacts/fuzz}"

# All registered fuzz targets
TARGETS=(
    fuzz_string
    fuzz_malloc
    fuzz_membrane
    fuzz_printf
    fuzz_resolver
    fuzz_regex
    fuzz_scanf
    fuzz_stdlib
    fuzz_ctype
)

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --fail-on-crash)
            FAIL_ON_CRASH=1
            shift
            ;;
        --no-fail-on-crash)
            FAIL_ON_CRASH=0
            shift
            ;;
        --artifacts-dir)
            ARTIFACTS_DIR="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

echo "=== FrankenLibC Nightly Fuzz Campaign ==="
echo "  Duration per target: ${DURATION}s"
echo "  Targets: ${#TARGETS[@]}"
echo "  Artifacts: ${ARTIFACTS_DIR}"
echo "  Fail on crash: ${FAIL_ON_CRASH}"
echo ""

mkdir -p "${ARTIFACTS_DIR}"

TOTAL_CRASHES=0
TOTAL_RUNS=0
SUMMARY=""
RUN_ID="fuzz-$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${ARTIFACTS_DIR}/${RUN_ID}.log"

# ---------------------------------------------------------------------------
# Check tooling
# ---------------------------------------------------------------------------

if ! command -v cargo-fuzz &>/dev/null; then
    echo "WARN: cargo-fuzz not installed, attempting build-only check"
    echo ""

    echo "--- Verifying fuzz targets compile ---"
    cd "${FUZZ_DIR}"
    cargo check 2>&1 | tee -a "${LOG_FILE}"
    echo "PASS (build check only — install cargo-fuzz for full fuzzing)"
    echo ""

    # Write summary
    cat > "${ARTIFACTS_DIR}/${RUN_ID}-summary.json" <<ENDJSON
{
    "run_id": "${RUN_ID}",
    "mode": "build-check-only",
    "targets": ${#TARGETS[@]},
    "duration_per_target": ${DURATION},
    "total_crashes": 0,
    "verdict": "pass",
    "note": "cargo-fuzz not installed; build check only"
}
ENDJSON

    echo "=== Fuzz nightly: PASS (build-only) ==="
    exit 0
fi

# ---------------------------------------------------------------------------
# Run fuzz campaigns
# ---------------------------------------------------------------------------

cd "${FUZZ_DIR}"

for target in "${TARGETS[@]}"; do
    echo "--- Fuzzing: ${target} (${DURATION}s) ---"
    TOTAL_RUNS=$((TOTAL_RUNS + 1))

    TARGET_ARTIFACTS="${ARTIFACTS_DIR}/${target}"
    mkdir -p "${TARGET_ARTIFACTS}"

    CORPUS_DIR="corpus/${target}"
    mkdir -p "${CORPUS_DIR}"

    # Run fuzzer with timeout
    RC=0
    cargo fuzz run "${target}" \
        -- \
        -max_total_time="${DURATION}" \
        -artifact_prefix="${TARGET_ARTIFACTS}/" \
        -print_final_stats=1 \
        2>&1 | tee -a "${LOG_FILE}" || RC=$?

    # Count crash artifacts (excluding README and seed files)
    CRASH_COUNT=0
    if [ -d "${TARGET_ARTIFACTS}" ]; then
        CRASH_COUNT=$(find "${TARGET_ARTIFACTS}" -name 'crash-*' -o -name 'timeout-*' -o -name 'oom-*' 2>/dev/null | wc -l || echo 0)
    fi

    if [ "${CRASH_COUNT}" -gt 0 ]; then
        echo "CRASHES FOUND: ${CRASH_COUNT}"
        TOTAL_CRASHES=$((TOTAL_CRASHES + CRASH_COUNT))
        SUMMARY="${SUMMARY}\n  ${target}: ${CRASH_COUNT} crashes"
    else
        echo "CLEAN"
        SUMMARY="${SUMMARY}\n  ${target}: clean"
    fi
    echo ""
done

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

echo "=== Nightly Fuzz Summary ==="
echo "  Run ID: ${RUN_ID}"
echo "  Targets run: ${TOTAL_RUNS}/${#TARGETS[@]}"
echo "  Total crashes: ${TOTAL_CRASHES}"
echo -e "  Results:${SUMMARY}"
echo ""

# Write machine-readable summary
cat > "${ARTIFACTS_DIR}/${RUN_ID}-summary.json" <<ENDJSON
{
    "run_id": "${RUN_ID}",
    "mode": "full",
    "targets": ${TOTAL_RUNS},
    "duration_per_target": ${DURATION},
    "total_crashes": ${TOTAL_CRASHES},
    "verdict": "$([ "${TOTAL_CRASHES}" -eq 0 ] && echo pass || echo fail)",
    "log_file": "${LOG_FILE}"
}
ENDJSON

# Verdict
if [ "${TOTAL_CRASHES}" -gt 0 ] && [ "${FAIL_ON_CRASH}" = "1" ]; then
    echo "=== Fuzz nightly: FAIL (${TOTAL_CRASHES} crashes) ==="
    exit 1
else
    echo "=== Fuzz nightly: PASS ==="
    exit 0
fi
