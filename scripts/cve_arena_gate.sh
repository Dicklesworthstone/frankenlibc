#!/usr/bin/env bash
# A2: CI gate for CVE Arena.
#
# Runs the CVE Arena test suite (at minimum the glibc-internal category),
# parses the summary JSON, and enforces:
#   - Zero REGRESSION verdicts
#   - Prevention rate >= configurable threshold (default 100% for glibc-internal)
#
# Exit codes:
#   0  All checks passed
#   1  Gate failed (regressions or prevention rate below threshold)
#   2  Infrastructure error (missing tools, missing files, etc.)
#
# Environment variables:
#   CVE_ARENA_CATEGORY           Category filter (default: "glibc-internal")
#   CVE_ARENA_MIN_RATE           Minimum prevention rate 0.0-1.0 (default: 1.0)
#   CVE_ARENA_RESULTS_DIR        Results directory override
#   CVE_ARENA_SKIP_RUN           Set to 1 to skip running tests (parse existing results)
#   CVE_ARENA_RUNNER             Path to the CVE Arena runner script
#   CVE_ARENA_REPORT             Path to the CVE Arena report script
#
# Usage:
#   scripts/cve_arena_gate.sh
#   CVE_ARENA_MIN_RATE=0.90 scripts/cve_arena_gate.sh
set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED="" GREEN="" YELLOW="" BOLD="" RESET=""
fi

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATEGORY="${CVE_ARENA_CATEGORY:-glibc-internal}"
MIN_RATE="${CVE_ARENA_MIN_RATE:-1.0}"
RESULTS_DIR="${CVE_ARENA_RESULTS_DIR:-${ROOT}/tests/cve_arena/results}"
SKIP_RUN="${CVE_ARENA_SKIP_RUN:-0}"
RUNNER="${CVE_ARENA_RUNNER:-${ROOT}/tests/cve_arena/run.sh}"
REPORTER="${CVE_ARENA_REPORT:-${ROOT}/tests/cve_arena/report.sh}"
SUMMARY_JSON="${RESULTS_DIR}/summary.json"

echo "${BOLD}=== CVE Arena CI Gate ===${RESET}"
echo "category=${CATEGORY}"
echo "min_prevention_rate=${MIN_RATE}"
echo "results_dir=${RESULTS_DIR}"
echo "skip_run=${SKIP_RUN}"
echo ""

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    echo "${RED}cve_arena_gate: jq is required but not found${RESET}" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Step 1: Run the CVE Arena test suite (unless skipped)
# ---------------------------------------------------------------------------
if [[ "${SKIP_RUN}" != "1" ]]; then
    if [[ ! -x "${RUNNER}" ]]; then
        echo "${YELLOW}cve_arena_gate: runner not found at ${RUNNER}; looking for cargo test fallback${RESET}" >&2
        # Fallback: attempt to run CVE arena tests via cargo
        echo "cve_arena_gate: running CVE arena tests via cargo..."
        mkdir -p "${RESULTS_DIR}"
        set +e
        cargo test -p glibc-rs-membrane --test 'cve_arena*' -- --test-threads=1 2>&1 | \
            tee "${RESULTS_DIR}/cargo_test_output.log"
        CARGO_RC=${PIPESTATUS[0]}
        set -e
        if [[ "${CARGO_RC}" -ne 0 ]]; then
            echo "${YELLOW}cve_arena_gate: cargo test exited ${CARGO_RC} (some CVE tests may intentionally fail on stock)${RESET}"
        fi
    else
        echo "cve_arena_gate: running CVE Arena suite..."
        if [[ -n "${CATEGORY}" && "${CATEGORY}" != "all" ]]; then
            "${RUNNER}" --category "${CATEGORY}" --results-dir "${RESULTS_DIR}" || true
        else
            "${RUNNER}" --results-dir "${RESULTS_DIR}" || true
        fi
    fi
fi

# ---------------------------------------------------------------------------
# Step 2: Generate the report (produces summary.json)
# ---------------------------------------------------------------------------
if [[ -x "${REPORTER}" ]]; then
    echo ""
    echo "cve_arena_gate: generating report..."
    "${REPORTER}" "${RESULTS_DIR}" || true
fi

# ---------------------------------------------------------------------------
# Step 3: Parse summary JSON
# ---------------------------------------------------------------------------
if [[ ! -f "${SUMMARY_JSON}" ]]; then
    echo "${RED}cve_arena_gate: summary.json not found at ${SUMMARY_JSON}${RESET}" >&2
    echo "Hint: ensure the CVE Arena runner and reporter have been executed." >&2
    exit 2
fi

TOTAL="$(jq -r '.total_cves // 0' "${SUMMARY_JSON}")"
PREVENTED="$(jq -r '.prevented // 0' "${SUMMARY_JSON}")"
DETECTED="$(jq -r '.detected // 0' "${SUMMARY_JSON}")"
REGRESSIONS="$(jq -r '.regressions // 0' "${SUMMARY_JSON}")"
BASELINE="$(jq -r '.baseline // 0' "${SUMMARY_JSON}")"
RATE="$(jq -r '.prevention_rate // 0' "${SUMMARY_JSON}")"

echo ""
echo "${BOLD}Gate Evaluation${RESET}"
echo "  total_cves:       ${TOTAL}"
echo "  prevented:        ${PREVENTED}"
echo "  detected:         ${DETECTED}"
echo "  regressions:      ${REGRESSIONS}"
echo "  baseline:         ${BASELINE}"
echo "  prevention_rate:  ${RATE}"
echo ""

FAILURES=0

# ---------------------------------------------------------------------------
# Check 1: No regressions allowed
# ---------------------------------------------------------------------------
if [[ "${REGRESSIONS}" -gt 0 ]]; then
    echo "${RED}FAIL: ${REGRESSIONS} regression(s) found${RESET}"
    # List the regressed CVEs for clarity.
    echo "  Regressed CVEs:"
    jq -r '.results[] | select(.verdict == "REGRESSION") | "    - \(.cve) (\(.category), CVSS \(.cvss))"' \
        "${SUMMARY_JSON}"
    FAILURES=$((FAILURES + 1))
else
    echo "${GREEN}PASS: zero regressions${RESET}"
fi

# ---------------------------------------------------------------------------
# Check 2: Prevention rate meets threshold
# ---------------------------------------------------------------------------
RATE_OK="$(awk -v rate="${RATE}" -v min="${MIN_RATE}" 'BEGIN { print (rate >= min) ? "1" : "0" }')"

if [[ "${RATE_OK}" != "1" ]]; then
    RATE_PCT="$(awk -v r="${RATE}" 'BEGIN { printf "%.1f", r * 100 }')"
    MIN_PCT="$(awk -v r="${MIN_RATE}" 'BEGIN { printf "%.1f", r * 100 }')"
    echo "${RED}FAIL: prevention rate ${RATE_PCT}% is below threshold ${MIN_PCT}%${RESET}"
    FAILURES=$((FAILURES + 1))
else
    RATE_PCT="$(awk -v r="${RATE}" 'BEGIN { printf "%.1f", r * 100 }')"
    MIN_PCT="$(awk -v r="${MIN_RATE}" 'BEGIN { printf "%.1f", r * 100 }')"
    echo "${GREEN}PASS: prevention rate ${RATE_PCT}% >= ${MIN_PCT}% threshold${RESET}"
fi

# ---------------------------------------------------------------------------
# Check 3: At least one result file was processed
# ---------------------------------------------------------------------------
if [[ "${TOTAL}" -eq 0 ]]; then
    echo "${RED}FAIL: no CVE results found (zero total)${RESET}"
    FAILURES=$((FAILURES + 1))
fi

echo ""

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${RED}${BOLD}CVE Arena Gate: FAIL (${FAILURES} check(s) failed)${RESET}"
    exit 1
fi

echo "${GREEN}${BOLD}CVE Arena Gate: PASS${RESET}"
echo "  ${PREVENTED} prevented + ${DETECTED} detected out of ${TOTAL} CVEs (${RATE_PCT}%)"
exit 0
