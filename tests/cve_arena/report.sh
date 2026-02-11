#!/usr/bin/env bash
# F2: CVE Arena comparison reporter.
#
# Consumes JSON results from the CVE Arena runner and produces:
#   1. Per-CVE pass/fail table (stock glibc: exploitable? glibc_rust: prevented?)
#   2. TSM feature attribution (which healing action fired per CVE)
#   3. Aggregate coverage matrix (CVE category vs TSM feature)
#   4. Markdown report suitable for docs (REPORT.md)
#   5. Machine-readable summary JSON for CI gating (summary.json)
#
# Usage:
#   tests/cve_arena/report.sh [results_dir]
#
# Defaults to tests/cve_arena/results/ if no argument supplied.
set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers (suppressed when stdout is not a terminal or NO_COLOR is set)
# ---------------------------------------------------------------------------
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    RED=$'\033[0;31m'
    GREEN=$'\033[0;32m'
    YELLOW=$'\033[0;33m'
    CYAN=$'\033[0;36m'
    BOLD=$'\033[1m'
    RESET=$'\033[0m'
else
    RED="" GREEN="" YELLOW="" CYAN="" BOLD="" RESET=""
fi

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="${1:-${ROOT}/tests/cve_arena/results}"
REPORT_MD="${RESULTS_DIR}/REPORT.md"
SUMMARY_JSON="${RESULTS_DIR}/summary.json"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    echo "${RED}report: jq is required but not found${RESET}" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Discover result files
# ---------------------------------------------------------------------------
shopt -s nullglob
RESULT_FILES=("${RESULTS_DIR}"/*.result.json)
shopt -u nullglob

if [[ ${#RESULT_FILES[@]} -eq 0 ]]; then
    echo "${RED}report: no .result.json files found in ${RESULTS_DIR}${RESET}" >&2
    echo "Hint: run the CVE Arena test suite first." >&2
    exit 2
fi

echo "${BOLD}=== CVE Arena Report ===${RESET}"
echo "results_dir=${RESULTS_DIR}"
echo "result_files=${#RESULT_FILES[@]}"
echo ""

# ---------------------------------------------------------------------------
# Merge all result files into a single JSON array (robust against missing
# fields by providing defaults via jq)
# ---------------------------------------------------------------------------
MERGED="$(jq -s '
  [ .[] | {
    cve:           (.cve           // "UNKNOWN"),
    category:      (.category      // "unknown"),
    cvss:          (.cvss          // 0),
    stock_exit:    (.stock_exit    // null),
    stock_signal:  (.stock_signal  // null),
    stock_output:  (.stock_output  // ""),
    rust_exit:     (.rust_exit     // null),
    rust_signal:   (.rust_signal   // null),
    rust_output:   (.rust_output   // ""),
    tsm_features:  (.tsm_features  // []),
    verdict:       (.verdict       // "UNKNOWN"),
    narrative:     (.narrative     // ""),
    description:   (.description   // "")
  } ]
' "${RESULT_FILES[@]}")"

TOTAL="$(echo "${MERGED}" | jq 'length')"
PREVENTED="$(echo "${MERGED}" | jq '[ .[] | select(.verdict == "PREVENTED") ] | length')"
DETECTED="$(echo "${MERGED}" | jq '[ .[] | select(.verdict == "DETECTED") ] | length')"
REGRESSIONS="$(echo "${MERGED}" | jq '[ .[] | select(.verdict == "REGRESSION") ] | length')"
BASELINE="$(echo "${MERGED}" | jq '[ .[] | select(.verdict == "BASELINE") ] | length')"
UNKNOWN_V="$(echo "${MERGED}" | jq '[ .[] | select(.verdict == "UNKNOWN") ] | length')"

# Prevention rate: (prevented + detected) / (total - baseline) -- avoid division by zero.
EFFECTIVE_TOTAL="$(( TOTAL - BASELINE ))"
if [[ "${EFFECTIVE_TOTAL}" -gt 0 ]]; then
    PREVENTION_RATE="$(awk -v p="${PREVENTED}" -v d="${DETECTED}" -v t="${EFFECTIVE_TOTAL}" \
        'BEGIN { printf "%.3f", (p + d) / t }')"
    PREVENTION_PCT="$(awk -v r="${PREVENTION_RATE}" 'BEGIN { printf "%.1f", r * 100 }')"
else
    PREVENTION_RATE="0.000"
    PREVENTION_PCT="0.0"
fi

# ---------------------------------------------------------------------------
# Build TSM feature coverage map
# ---------------------------------------------------------------------------
FEATURE_COVERAGE="$(echo "${MERGED}" | jq '
  reduce (.[] | select(.tsm_features != null) |
    .cve as $cve | .cvss as $cvss |
    .tsm_features[] |
    { feature: ., cve: $cve, cvss: $cvss }
  ) as $entry (
    {};
    .[$entry.feature] //= { count: 0, cves: [], min_cvss: 99, max_cvss: 0 } |
    .[$entry.feature].count += 1 |
    .[$entry.feature].cves += [$entry.cve] |
    (if $entry.cvss < .[$entry.feature].min_cvss then
       .[$entry.feature].min_cvss = $entry.cvss
     else . end) |
    (if $entry.cvss > .[$entry.feature].max_cvss then
       .[$entry.feature].max_cvss = $entry.cvss
     else . end)
  )
')"

# ---------------------------------------------------------------------------
# Print stdout summary table
# ---------------------------------------------------------------------------
stock_label() {
    local exit_code="${1:-}" signal="${2:-}"
    if [[ -n "${signal}" && "${signal}" != "null" ]]; then
        echo "SIG${signal} (exit ${exit_code})"
    elif [[ -n "${exit_code}" && "${exit_code}" != "null" ]]; then
        echo "exit ${exit_code}"
    else
        echo "N/A"
    fi
}

rust_label() {
    local exit_code="${1:-}" signal="${2:-}"
    if [[ "${exit_code}" == "0" ]]; then
        echo "Clean (exit 0)"
    elif [[ -n "${signal}" && "${signal}" != "null" ]]; then
        echo "SIG${signal} (exit ${exit_code})"
    elif [[ -n "${exit_code}" && "${exit_code}" != "null" ]]; then
        echo "exit ${exit_code}"
    else
        echo "N/A"
    fi
}

verdict_color() {
    case "$1" in
        PREVENTED)  echo "${GREEN}PREVENTED${RESET}" ;;
        DETECTED)   echo "${YELLOW}DETECTED${RESET}" ;;
        REGRESSION) echo "${RED}REGRESSION${RESET}" ;;
        BASELINE)   echo "${CYAN}BASELINE${RESET}" ;;
        *)          echo "$1" ;;
    esac
}

echo "${BOLD}Summary${RESET}"
echo "  Total CVEs tested:  ${TOTAL}"
echo "  Prevented by TSM:   ${GREEN}${PREVENTED}${RESET}"
echo "  Detected by TSM:    ${YELLOW}${DETECTED}${RESET}"
echo "  Regressions:        ${RED}${REGRESSIONS}${RESET}"
echo "  Baseline (no-op):   ${BASELINE}"
echo "  Prevention rate:    ${PREVENTION_PCT}%"
echo ""

# Print per-CVE table.
printf "${BOLD}%-18s %-18s %6s  %-24s %-24s %-30s %s${RESET}\n" \
    "CVE" "Category" "CVSS" "Stock glibc" "glibc_rust" "TSM Features" "Verdict"
printf "%-18s %-18s %6s  %-24s %-24s %-30s %s\n" \
    "---" "--------" "----" "-----------" "----------" "------------" "-------"

echo "${MERGED}" | jq -r '.[] | [.cve, .category, (.cvss|tostring),
    ((.stock_signal // empty | "SIG\(.)") // "exit \(.stock_exit // "N/A")"),
    (if .rust_exit == 0 then "Clean (exit 0)"
     elif .rust_signal then "SIG\(.rust_signal) (exit \(.rust_exit))"
     else "exit \(.rust_exit // "N/A")" end),
    (.tsm_features | join(", ")),
    .verdict
  ] | @tsv' | while IFS=$'\t' read -r cve cat cvss stock rust features verdict; do
    colored_verdict="$(verdict_color "${verdict}")"
    printf "%-18s %-18s %6s  %-24s %-24s %-30s %s\n" \
        "${cve}" "${cat}" "${cvss}" "${stock}" "${rust}" "${features}" "${colored_verdict}"
done

echo ""

# ---------------------------------------------------------------------------
# Generate Markdown report (REPORT.md)
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

{
cat <<MDHEADER
# CVE Arena Security Validation Report

Generated: ${TIMESTAMP}

## Summary

| Metric | Count |
|--------|-------|
| Total CVEs tested | ${TOTAL} |
| Prevented by TSM | ${PREVENTED} |
| Detected by TSM | ${DETECTED} |
| Regressions | ${REGRESSIONS} |
| Baseline (no-op) | ${BASELINE} |
| Prevention rate | ${PREVENTION_PCT}% |

## Per-CVE Results

| CVE | Category | CVSS | Stock glibc | glibc_rust | TSM Feature | Verdict |
|-----|----------|------|-------------|------------|-------------|---------|
MDHEADER

echo "${MERGED}" | jq -r '.[] | "| \(.cve) | \(.category) | \(.cvss) | " +
    (if .stock_signal then "SIG\(.stock_signal) (exit \(.stock_exit))"
     elif .stock_exit then "exit \(.stock_exit)"
     else "N/A" end) + " | " +
    (if .rust_exit == 0 then "Clean (exit 0)"
     elif .rust_signal then "SIG\(.rust_signal) (exit \(.rust_exit))"
     elif .rust_exit then "exit \(.rust_exit)"
     else "N/A" end) + " | " +
    (.tsm_features | join(", ")) + " | " +
    .verdict + " |"'

cat <<'MDSEP'

## TSM Feature Coverage Matrix

| TSM Feature | CVEs Covered | Severity Range |
|-------------|-------------|----------------|
MDSEP

echo "${FEATURE_COVERAGE}" | jq -r '
  to_entries | sort_by(.key) | .[] |
  "| \(.key) | \(.value.cves | join(", ")) | \(.value.min_cvss)-\(.value.max_cvss) |"
'

cat <<'MDSEP2'

## Detailed Results

MDSEP2

echo "${MERGED}" | jq -r '.[] |
  "### \(.cve) -- \(.verdict)\n\n" +
  "**Category:** \(.category)  \n" +
  "**CVSS:** \(.cvss)  \n" +
  (if .description != "" then "**Description:** \(.description)  \n" else "" end) +
  "**Stock glibc:** " +
    (if .stock_signal then "SIG\(.stock_signal) (exit \(.stock_exit))"
     elif .stock_exit then "exit \(.stock_exit)"
     else "N/A" end) + "  \n" +
  "**glibc_rust:** " +
    (if .rust_exit == 0 then "Clean (exit 0)"
     elif .rust_signal then "SIG\(.rust_signal) (exit \(.rust_exit))"
     elif .rust_exit then "exit \(.rust_exit)"
     else "N/A" end) + "  \n" +
  "**TSM Features:** \(.tsm_features | join(", "))  \n" +
  (if .narrative != "" then "\n\(.narrative)\n" else "" end) +
  "\n---\n"
'

} > "${REPORT_MD}"

echo "${BOLD}Markdown report:${RESET}  ${REPORT_MD}"

# ---------------------------------------------------------------------------
# Generate machine-readable summary JSON (summary.json)
# ---------------------------------------------------------------------------
jq -n \
    --arg ts "${TIMESTAMP}" \
    --argjson total "${TOTAL}" \
    --argjson prevented "${PREVENTED}" \
    --argjson detected "${DETECTED}" \
    --argjson regressions "${REGRESSIONS}" \
    --argjson baseline "${BASELINE}" \
    --argjson prevention_rate "${PREVENTION_RATE}" \
    --argjson feature_coverage "${FEATURE_COVERAGE}" \
    --argjson results "${MERGED}" \
    '{
        timestamp: $ts,
        total_cves: $total,
        prevented: $prevented,
        detected: $detected,
        regressions: $regressions,
        baseline: $baseline,
        prevention_rate: $prevention_rate,
        feature_coverage: $feature_coverage,
        results: $results
    }' > "${SUMMARY_JSON}"

echo "${BOLD}Summary JSON:${RESET}     ${SUMMARY_JSON}"
echo ""

# ---------------------------------------------------------------------------
# Final verdict
# ---------------------------------------------------------------------------
if [[ "${REGRESSIONS}" -gt 0 ]]; then
    echo "${RED}${BOLD}FAIL: ${REGRESSIONS} regression(s) detected${RESET}"
    exit 1
fi

echo "${GREEN}${BOLD}PASS: ${PREVENTED} prevented, ${DETECTED} detected, 0 regressions (${PREVENTION_PCT}% rate)${RESET}"
