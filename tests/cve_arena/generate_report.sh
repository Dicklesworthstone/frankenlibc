#!/usr/bin/env bash
# A3: Public security report generator for CVE Arena.
#
# Produces a polished, publication-quality Markdown report from CVE Arena
# results suitable for:
#   - README inclusion
#   - Security advisories
#   - Stakeholder communication
#
# The report includes:
#   1. Executive summary with headline numbers
#   2. Per-CVE narratives explaining vulnerability + TSM prevention
#   3. TSM feature attribution table
#   4. Aggregate statistics
#
# Usage:
#   tests/cve_arena/generate_report.sh [results_dir] [output_file]
#
# Defaults:
#   results_dir  = tests/cve_arena/results/
#   output_file  = tests/cve_arena/results/SECURITY_REPORT.md
set -euo pipefail

# ---------------------------------------------------------------------------
# Color helpers
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
OUTPUT_FILE="${2:-${RESULTS_DIR}/SECURITY_REPORT.md}"
SUMMARY_JSON="${RESULTS_DIR}/summary.json"

# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------
if ! command -v jq >/dev/null 2>&1; then
    echo "${RED}generate_report: jq is required but not found${RESET}" >&2
    exit 2
fi

# If summary.json does not exist, try to generate it first.
if [[ ! -f "${SUMMARY_JSON}" ]]; then
    REPORTER="${ROOT}/tests/cve_arena/report.sh"
    if [[ -x "${REPORTER}" ]]; then
        echo "${YELLOW}generate_report: summary.json not found; running report.sh first...${RESET}"
        "${REPORTER}" "${RESULTS_DIR}"
    fi
fi

if [[ ! -f "${SUMMARY_JSON}" ]]; then
    echo "${RED}generate_report: summary.json not found at ${SUMMARY_JSON}${RESET}" >&2
    echo "Hint: run the CVE Arena test suite and report.sh first." >&2
    exit 2
fi

echo "${BOLD}=== CVE Arena Public Security Report Generator ===${RESET}"
echo "results_dir=${RESULTS_DIR}"
echo "output=${OUTPUT_FILE}"
echo ""

# ---------------------------------------------------------------------------
# Read summary data
# ---------------------------------------------------------------------------
TIMESTAMP="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
TOTAL="$(jq -r '.total_cves // 0' "${SUMMARY_JSON}")"
PREVENTED="$(jq -r '.prevented // 0' "${SUMMARY_JSON}")"
DETECTED="$(jq -r '.detected // 0' "${SUMMARY_JSON}")"
REGRESSIONS="$(jq -r '.regressions // 0' "${SUMMARY_JSON}")"
BASELINE="$(jq -r '.baseline // 0' "${SUMMARY_JSON}")"
RATE="$(jq -r '.prevention_rate // 0' "${SUMMARY_JSON}")"
RATE_PCT="$(awk -v r="${RATE}" 'BEGIN { printf "%.1f", r * 100 }')"

# Compute severity stats from results array.
MAX_CVSS="$(jq -r '[.results[].cvss] | max // 0' "${SUMMARY_JSON}")"
MIN_CVSS="$(jq -r '[.results[].cvss] | min // 0' "${SUMMARY_JSON}")"
AVG_CVSS="$(jq -r '[.results[].cvss] | add / length // 0 | . * 10 | round / 10' "${SUMMARY_JSON}")"

# Count categories.
CATEGORY_COUNTS="$(jq -r '
  [.results[].category] | group_by(.) | map({key: .[0], value: length}) |
  from_entries
' "${SUMMARY_JSON}")"

# Count unique TSM features.
FEATURE_COUNT="$(jq -r '.feature_coverage | keys | length // 0' "${SUMMARY_JSON}")"

# ---------------------------------------------------------------------------
# Determine severity breakdown.
# ---------------------------------------------------------------------------
CRITICAL_COUNT="$(jq -r '[.results[] | select(.cvss >= 9.0)] | length' "${SUMMARY_JSON}")"
HIGH_COUNT="$(jq -r '[.results[] | select(.cvss >= 7.0 and .cvss < 9.0)] | length' "${SUMMARY_JSON}")"
MEDIUM_COUNT="$(jq -r '[.results[] | select(.cvss >= 4.0 and .cvss < 7.0)] | length' "${SUMMARY_JSON}")"
LOW_COUNT="$(jq -r '[.results[] | select(.cvss < 4.0)] | length' "${SUMMARY_JSON}")"

CRITICAL_PREVENTED="$(jq -r '[.results[] | select(.cvss >= 9.0 and (.verdict == "PREVENTED" or .verdict == "DETECTED"))] | length' "${SUMMARY_JSON}")"
HIGH_PREVENTED="$(jq -r '[.results[] | select(.cvss >= 7.0 and .cvss < 9.0 and (.verdict == "PREVENTED" or .verdict == "DETECTED"))] | length' "${SUMMARY_JSON}")"
MEDIUM_PREVENTED="$(jq -r '[.results[] | select(.cvss >= 4.0 and .cvss < 7.0 and (.verdict == "PREVENTED" or .verdict == "DETECTED"))] | length' "${SUMMARY_JSON}")"
LOW_PREVENTED="$(jq -r '[.results[] | select(.cvss < 4.0 and (.verdict == "PREVENTED" or .verdict == "DETECTED"))] | length' "${SUMMARY_JSON}")"

# ---------------------------------------------------------------------------
# Generate the polished Markdown report
# ---------------------------------------------------------------------------
{

cat <<HEADER
# glibc_rust Security Validation Report

> Automated CVE Arena assessment of Transparent Safety Membrane (TSM) effectiveness

**Generated:** ${TIMESTAMP}

---

## Executive Summary

The glibc_rust Transparent Safety Membrane (TSM) was tested against **${TOTAL} real-world CVEs**
spanning multiple vulnerability categories. The TSM achieved a **${RATE_PCT}% prevention rate**,
successfully preventing or detecting **$((PREVENTED + DETECTED))** out of **${TOTAL}** tested
vulnerabilities without requiring application recompilation.

### Headline Numbers

| Metric | Value |
|--------|-------|
| Total CVEs tested | **${TOTAL}** |
| Prevented (exploit neutralized) | **${PREVENTED}** |
| Detected (flagged before damage) | **${DETECTED}** |
| Regressions (new failures) | **${REGRESSIONS}** |
| Prevention rate | **${RATE_PCT}%** |
| CVSS range covered | ${MIN_CVSS} -- ${MAX_CVSS} (avg ${AVG_CVSS}) |
| TSM features exercised | **${FEATURE_COUNT}** |

### Severity Breakdown

| Severity | Total | Prevented/Detected | Coverage |
|----------|-------|--------------------|----------|
HEADER

# Emit severity rows, handling zero-division safely.
for severity_name in Critical High Medium Low; do
    case "${severity_name}" in
        Critical) cnt="${CRITICAL_COUNT}"; prev="${CRITICAL_PREVENTED}" ;;
        High)     cnt="${HIGH_COUNT}"; prev="${HIGH_PREVENTED}" ;;
        Medium)   cnt="${MEDIUM_COUNT}"; prev="${MEDIUM_PREVENTED}" ;;
        Low)      cnt="${LOW_COUNT}"; prev="${LOW_PREVENTED}" ;;
    esac
    if [[ "${cnt}" -gt 0 ]]; then
        pct="$(awk -v p="${prev}" -v t="${cnt}" 'BEGIN { printf "%.0f", (p/t)*100 }')"
        echo "| ${severity_name} ($(case "${severity_name}" in Critical) echo '>=9.0';; High) echo '7.0-8.9';; Medium) echo '4.0-6.9';; Low) echo '<4.0';; esac)) | ${cnt} | ${prev} | ${pct}% |"
    else
        echo "| ${severity_name} | 0 | 0 | N/A |"
    fi
done

cat <<'SEP1'

---

## Per-CVE Results

SEP1

echo '| CVE | Category | CVSS | Stock glibc | glibc_rust | TSM Features | Verdict |'
echo '|-----|----------|------|-------------|------------|-------------|---------|'

jq -r '.results | sort_by(-.cvss) | .[] |
  "| \(.cve) | \(.category) | \(.cvss) | " +
  (if .stock_signal then "SIG\(.stock_signal) (exit \(.stock_exit))"
   elif .stock_exit then "exit \(.stock_exit)"
   else "N/A" end) + " | " +
  (if .rust_exit == 0 then "Clean (exit 0)"
   elif .rust_signal then "SIG\(.rust_signal) (exit \(.rust_exit))"
   elif .rust_exit then "exit \(.rust_exit)"
   else "N/A" end) + " | " +
  (.tsm_features | join(", ")) + " | " +
  (if .verdict == "PREVENTED" then "PREVENTED"
   elif .verdict == "DETECTED" then "DETECTED"
   elif .verdict == "REGRESSION" then "**REGRESSION**"
   else .verdict end) + " |"
' "${SUMMARY_JSON}"

cat <<'SEP2'

---

## TSM Feature Attribution

The following TSM features contributed to CVE prevention. Each feature operates
transparently within the membrane, requiring zero changes to application code.

| TSM Feature | Description | CVEs Covered | Count | Severity Range |
|-------------|-------------|-------------|-------|----------------|
SEP2

# Feature descriptions (best-effort; extend as new features are added).
feature_description() {
    case "$1" in
        ClampSize)           echo "Bounds-clamp oversized allocation/copy requests" ;;
        TruncateWithNull)    echo "Truncate output with null termination on overflow" ;;
        Canary|CanaryDetection)  echo "Trailing canary detects heap buffer overwrites" ;;
        Quarantine)          echo "Temporal quarantine prevents use-after-free reuse" ;;
        GenerationCheck)     echo "Generation counter detects stale pointer dereference" ;;
        Fingerprint|FingerprintVerify) echo "SipHash fingerprint verifies allocation integrity" ;;
        IgnoreDoubleFree)    echo "Silently absorb double-free without corruption" ;;
        IgnoreForeignFree)   echo "Reject free of untracked/foreign pointers" ;;
        ReallocAsMalloc)     echo "Treat realloc of freed pointer as fresh malloc" ;;
        ReturnSafeDefault)   echo "Return safe default value on invalid operation" ;;
        UpgradeToSafeVariant) echo "Transparently upgrade unsafe API to bounded variant" ;;
        BoundsCheck)         echo "Runtime bounds validation on pointer arithmetic" ;;
        NullGuard)           echo "Intercept null pointer dereference before fault" ;;
        BloomFilter)         echo "Bloom filter fast-rejects unknown pointers" ;;
        TLSCache)            echo "Thread-local cache with epoch invalidation" ;;
        PageOracle)          echo "Page-level ownership tracking" ;;
        *)                   echo "TSM safety feature" ;;
    esac
}

jq -r '.feature_coverage | to_entries | sort_by(.key) | .[] |
  "\(.key)\t\(.value.cves | join(", "))\t\(.value.count)\t\(.value.min_cvss)-\(.value.max_cvss)"
' "${SUMMARY_JSON}" | while IFS=$'\t' read -r feature cves count severity; do
    desc="$(feature_description "${feature}")"
    echo "| ${feature} | ${desc} | ${cves} | ${count} | ${severity} |"
done

cat <<'SEP3'

---

## Vulnerability Narratives

Detailed per-CVE analysis explaining each vulnerability, how stock glibc is affected,
and how the TSM prevents exploitation.

SEP3

jq -r '.results | sort_by(-.cvss) | .[] |
  "### \(.cve) (\(.category), CVSS \(.cvss))\n\n" +
  (if .description and .description != "" then "**Vulnerability:** \(.description)\n\n" else "" end) +
  "**Stock glibc behavior:** " +
  (if .stock_signal then "Process terminated with SIG\(.stock_signal) (exit code \(.stock_exit)). "
   elif .stock_exit and .stock_exit != 0 then "Process exited with code \(.stock_exit). "
   else "Process behavior undefined or exploitable. " end) +
  "This indicates the vulnerability is exploitable under stock glibc.\n\n" +
  "**glibc_rust behavior:** " +
  (if .rust_exit == 0 then "Process completed cleanly (exit 0). "
   elif .rust_signal then "Process received SIG\(.rust_signal) (exit code \(.rust_exit)). "
   elif .rust_exit then "Process exited with code \(.rust_exit). "
   else "N/A. " end) +
  "The TSM " +
  (if .verdict == "PREVENTED" then "**prevented** the exploit entirely"
   elif .verdict == "DETECTED" then "**detected** the attack before damage occurred"
   elif .verdict == "REGRESSION" then "**failed to prevent** this vulnerability (REGRESSION)"
   else "produced an indeterminate result" end) + ".\n\n" +
  (if (.tsm_features | length) > 0 then
    "**TSM features activated:** " + (.tsm_features | join(", ")) + "\n\n"
   else "" end) +
  (if .narrative and .narrative != "" then "\(.narrative)\n\n" else "" end) +
  "---\n"
' "${SUMMARY_JSON}"

cat <<SEP4

## Aggregate Statistics

- **Total CVEs:** ${TOTAL}
- **Prevention rate:** ${RATE_PCT}%
- **Categories tested:** $(echo "${CATEGORY_COUNTS}" | jq -r 'keys | join(", ")')
- **TSM features exercised:** ${FEATURE_COUNT}
- **CVSS range:** ${MIN_CVSS} -- ${MAX_CVSS} (mean ${AVG_CVSS})
- **Zero regressions:** $(if [[ "${REGRESSIONS}" -eq 0 ]]; then echo "Yes"; else echo "No (${REGRESSIONS} regressions)"; fi)

## Methodology

The CVE Arena test suite reproduces real-world CVE exploit patterns against both
stock glibc and the glibc_rust Transparent Safety Membrane. Each test case:

1. Constructs the minimal trigger condition for the CVE
2. Runs the trigger under stock glibc (expected: crash or exploitable behavior)
3. Runs the same trigger under glibc_rust TSM (expected: safe healing or detection)
4. Records exit codes, signals, TSM feature activations, and healing actions
5. Classifies the result as PREVENTED, DETECTED, BASELINE, or REGRESSION

All tests run in isolated processes with deterministic inputs. Results are
reproducible across environments.

---

*This report was automatically generated by the glibc_rust CVE Arena test infrastructure.*
SEP4

} > "${OUTPUT_FILE}"

echo "${GREEN}${BOLD}Security report generated:${RESET} ${OUTPUT_FILE}"
echo ""

# Print a brief summary to stdout.
echo "${BOLD}Report Summary${RESET}"
echo "  CVEs:             ${TOTAL}"
echo "  Prevention rate:  ${RATE_PCT}%"
echo "  Regressions:      ${REGRESSIONS}"
echo "  Features tested:  ${FEATURE_COUNT}"
echo "  Severity range:   ${MIN_CVSS} -- ${MAX_CVSS}"
echo ""

if [[ "${REGRESSIONS}" -gt 0 ]]; then
    echo "${RED}WARNING: ${REGRESSIONS} regression(s) present in results${RESET}"
fi

echo "${GREEN}Done.${RESET}"
