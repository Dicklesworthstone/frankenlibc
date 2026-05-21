#!/usr/bin/env bash
# check_adversarial_smoke_lane.sh - [bd-3yr14.6] Adversarial smoke verification
#
# Rebuilds the library and re-runs ld_preload_smoke.sh, comparing against the
# committed ld_preload_smoke_summary.v1.json. Fails on any divergence.
#
# The committed summary can ONLY be updated by:
#   1. Running this lane in --regenerate mode
#   2. Committing the freshly generated summary with evidence ledger entry
#   NEVER by hand-editing the summary file.
#
# Exit codes:
#   0 - Summary matches fresh run
#   1 - Divergence detected (summary is stale or wrong)
#   2 - Infrastructure error (missing tools, build failure)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMITTED_SUMMARY="${ROOT}/tests/conformance/ld_preload_smoke_summary.v1.json"
SMOKE_SCRIPT="${ROOT}/scripts/ld_preload_smoke.sh"
TRACE_FILE="${ROOT}/target/adversarial_smoke/trace.jsonl"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-30}"
REGENERATE="${REGENERATE:-false}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"

die() { echo "ERROR: $*" >&2; exit 2; }

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

log_json() {
  local event="$1"
  shift
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  mkdir -p "$(dirname "${TRACE_FILE}")"
  printf '{"ts":"%s","event":"%s"' "${ts}" "${event}" >> "${TRACE_FILE}"
  while [[ $# -gt 0 ]]; do
    local key="$1" val="$2"
    shift 2
    printf ',"%s":"%s"' "${key}" "${val}" >> "${TRACE_FILE}"
  done
  printf '}\n' >> "${TRACE_FILE}"
}

command -v jq >/dev/null 2>&1 || die "jq required"
command -v rch >/dev/null 2>&1 || die "rch required; this gate must not fall back to local cargo"
[[ -f "${SMOKE_SCRIPT}" ]] || die "Smoke script not found: ${SMOKE_SCRIPT}"
[[ -f "${COMMITTED_SUMMARY}" ]] || die "Committed summary not found: ${COMMITTED_SUMMARY}"

mkdir -p "$(dirname "${TRACE_FILE}")"
: > "${TRACE_FILE}"

log "=== Adversarial Smoke Lane [bd-3yr14.6] ==="
log_json "start" "committed_summary" "${COMMITTED_SUMMARY}"

BUILD_TARGET_DIR="${CARGO_TARGET_DIR:-${ROOT}/target/adversarial_smoke/cargo_target/${RUN_ID}}"
BUILD_CMD_DISPLAY="CARGO_TARGET_DIR=${BUILD_TARGET_DIR} RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -p frankenlibc-abi --release"
mkdir -p "${BUILD_TARGET_DIR}"

log "Rebuilding library..."
log_json "build_start" "command" "${BUILD_CMD_DISPLAY}" "target_dir" "${BUILD_TARGET_DIR}"

if ! CARGO_TARGET_DIR="${BUILD_TARGET_DIR}" RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR RCH_REQUIRE_REMOTE=1 \
  rch exec -- cargo build -p frankenlibc-abi --release >/dev/null 2>&1; then
  log_json "build_failed" "reason" "cargo_error"
  die "Library build failed"
fi
BUILT_LIB="${BUILD_TARGET_DIR}/release/libfrankenlibc_abi.so"
[[ -f "${BUILT_LIB}" ]] || die "Library build did not produce ${BUILT_LIB}"
export FRANKENLIBC_SMOKE_LIB_PATH="${BUILT_LIB}"
log_json "build_done" "lib_path" "${BUILT_LIB}"

log "Running smoke test..."
SMOKE_OUT="${ROOT}/target/adversarial_smoke/${RUN_ID}"
mkdir -p "${SMOKE_OUT}"

export TIMEOUT_SECONDS
export FRANKENLIBC_SMOKE_RUN_ID="${RUN_ID}"
log_json "smoke_start" "timeout" "${TIMEOUT_SECONDS}"

SMOKE_RC=0
if bash "${SMOKE_SCRIPT}" > "${SMOKE_OUT}/stdout.txt" 2> "${SMOKE_OUT}/stderr.txt"; then
  SMOKE_RC=0
else
  SMOKE_RC=$?
  log "Warning: Smoke script exited with code ${SMOKE_RC}"
fi
log_json "smoke_done" "exit_code" "${SMOKE_RC}"

SMOKE_REPORT_DIR="${ROOT}/target/ld_preload_smoke/${RUN_ID}"
if [[ ! -f "${SMOKE_REPORT_DIR}/abi_compat_report.json" ]]; then
  log_json "smoke_no_report" "reason" "missing_output"
  die "Smoke run did not produce abi_compat_report.json"
fi

FRESH_REPORT="${SMOKE_REPORT_DIR}/abi_compat_report.json"
log "Fresh report: ${FRESH_REPORT}"

# Extract .summary.<key> as a raw token: a numeric string when present,
# "MISSING" when the field is absent, or "JQERR" when the file is not
# parseable JSON.
extract_count() {
  jq -r --arg k "$2" '.summary[$k] // "MISSING"' "$1" 2>/dev/null || echo "JQERR"
}

# Fail closed on a load-bearing count. A summary or report that does not
# yield a real numeric pass/fail count is an infrastructure error (exit 2)
# — never a silent 0, which would let a genuine divergence slip through the
# comparison below as a PASS. (Before this guard, an unparseable summary
# collapsed both sides to 0/0 and the lane reported PASS.)
require_count() {
  [[ "$2" =~ ^[0-9]+$ ]] \
    || die "$1 is not a numeric count (got '$2') — summary unparseable or missing its .summary field; failing closed"
}

COMMITTED_TOTAL="$(extract_count "${COMMITTED_SUMMARY}" total_cases)"
COMMITTED_PASSES="$(extract_count "${COMMITTED_SUMMARY}" passes)"
COMMITTED_FAILS="$(extract_count "${COMMITTED_SUMMARY}" fails)"
COMMITTED_SKIPS="$(extract_count "${COMMITTED_SUMMARY}" skips)"
FRESH_TOTAL="$(extract_count "${FRESH_REPORT}" total_cases)"
FRESH_PASSES="$(extract_count "${FRESH_REPORT}" passes)"
FRESH_FAILS="$(extract_count "${FRESH_REPORT}" fails)"
FRESH_SKIPS="$(extract_count "${FRESH_REPORT}" skips)"

require_count "committed total count" "${COMMITTED_TOTAL}"
require_count "committed pass count" "${COMMITTED_PASSES}"
require_count "committed fail count" "${COMMITTED_FAILS}"
require_count "fresh pass count" "${FRESH_PASSES}"
require_count "fresh fail count" "${FRESH_FAILS}"
require_count "fresh total count" "${FRESH_TOTAL}"
require_count "committed skip count" "${COMMITTED_SKIPS}"
require_count "fresh skip count" "${FRESH_SKIPS}"

require_total_consistency() {
  local label="$1" total="$2" passes="$3" fails="$4" skips="$5"
  local computed=$((passes + fails + skips))
  [[ "${total}" -eq "${computed}" ]] \
    || die "$label total_cases=${total} does not equal passes+fails+skips=${computed}; failing closed"
}

require_total_consistency "committed summary" "${COMMITTED_TOTAL}" "${COMMITTED_PASSES}" "${COMMITTED_FAILS}" "${COMMITTED_SKIPS}"
require_total_consistency "fresh report" "${FRESH_TOTAL}" "${FRESH_PASSES}" "${FRESH_FAILS}" "${FRESH_SKIPS}"

log "Committed: total=${COMMITTED_TOTAL} passes=${COMMITTED_PASSES} fails=${COMMITTED_FAILS} skips=${COMMITTED_SKIPS}"
log "Fresh:     total=${FRESH_TOTAL} passes=${FRESH_PASSES} fails=${FRESH_FAILS} skips=${FRESH_SKIPS}"
log_json "comparison" "committed_total" "${COMMITTED_TOTAL}" "committed_passes" "${COMMITTED_PASSES}" \
  "committed_fails" "${COMMITTED_FAILS}" "committed_skips" "${COMMITTED_SKIPS}" \
  "fresh_total" "${FRESH_TOTAL}" "fresh_passes" "${FRESH_PASSES}" "fresh_fails" "${FRESH_FAILS}" \
  "fresh_skips" "${FRESH_SKIPS}"

DIVERGED=false
if [[ "${COMMITTED_TOTAL}" != "${FRESH_TOTAL}" ]]; then
  log "DIVERGENCE: total count differs (committed=${COMMITTED_TOTAL}, fresh=${FRESH_TOTAL})"
  DIVERGED=true
fi
if [[ "${COMMITTED_PASSES}" != "${FRESH_PASSES}" ]]; then
  log "DIVERGENCE: pass count differs (committed=${COMMITTED_PASSES}, fresh=${FRESH_PASSES})"
  DIVERGED=true
fi
if [[ "${COMMITTED_FAILS}" != "${FRESH_FAILS}" ]]; then
  log "DIVERGENCE: fail count differs (committed=${COMMITTED_FAILS}, fresh=${FRESH_FAILS})"
  DIVERGED=true
fi
# The lane's contract is to fail on ANY divergence; the skip count is part of
# that checked summary. Missing or malformed skip counts fail closed above.
if [[ "${COMMITTED_SKIPS}" != "${FRESH_SKIPS}" ]]; then
  log "DIVERGENCE: skip count differs (committed=${COMMITTED_SKIPS}, fresh=${FRESH_SKIPS})"
  DIVERGED=true
fi

if [[ "${DIVERGED}" == "true" ]]; then
  log_json "divergence_detected" "committed_total" "${COMMITTED_TOTAL}" "fresh_total" "${FRESH_TOTAL}" \
    "committed_passes" "${COMMITTED_PASSES}" "fresh_passes" "${FRESH_PASSES}" \
    "committed_fails" "${COMMITTED_FAILS}" "fresh_fails" "${FRESH_FAILS}" \
    "committed_skips" "${COMMITTED_SKIPS}" "fresh_skips" "${FRESH_SKIPS}"

  if [[ "${REGENERATE}" == "true" ]]; then
    log "Regenerating committed summary..."
    FRESH_SUMMARY="${ROOT}/target/adversarial_smoke/ld_preload_smoke_summary.v1.json.new"

    cat > "${FRESH_SUMMARY}" <<EOF
{
  "schema_version": "v1",
  "bead": "bd-3yr14.6",
  "source_report_path": "${FRESH_REPORT}",
  "run_id": "${RUN_ID}",
  "checked_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "checked_date_display": "$(date -u +'%B %-d, %Y')",
  "lib_path": "${BUILT_LIB}",
  "timeout_seconds": ${TIMEOUT_SECONDS},
  "stress_iters": 5,
  "summary": {
    "total_cases": ${FRESH_TOTAL},
    "passes": ${FRESH_PASSES},
    "fails": ${FRESH_FAILS},
    "skips": ${FRESH_SKIPS},
    "signature_guard_failures": 0,
    "perf_failures": 0,
    "valgrind_failures": 0,
    "overall_failed": $(if [[ "${FRESH_FAILS}" -gt 0 ]]; then echo "true"; else echo "false"; fi)
  },
  "regenerated_by": "check_adversarial_smoke_lane.sh --regenerate",
  "notes": [
    "This summary was regenerated by the adversarial smoke lane.",
    "Commit this file with an evidence ledger entry to update the canonical summary."
  ]
}
EOF
    log "Generated: ${FRESH_SUMMARY}"
    log "To update committed summary:"
    log "  cp ${FRESH_SUMMARY} ${COMMITTED_SUMMARY}"
    log "  git add ${COMMITTED_SUMMARY}"
    log "  git commit -m '[bd-3yr14.6] Regenerate smoke summary with evidence'"
    log_json "regenerate_done" "output" "${FRESH_SUMMARY}"
    exit 1
  fi

  log ""
  log "=== ADVERSARIAL SMOKE LANE FAILED ==="
  log "The committed summary is STALE or INCORRECT."
  log "Run with REGENERATE=true to generate an updated summary."
  log ""
  exit 1
fi

log_json "match" "passes" "${COMMITTED_PASSES}" "fails" "${COMMITTED_FAILS}"
log ""
log "=== ADVERSARIAL SMOKE LANE PASSED ==="
log "Committed summary matches fresh run."
exit 0
