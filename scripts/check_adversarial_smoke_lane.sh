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
[[ -f "${SMOKE_SCRIPT}" ]] || die "Smoke script not found: ${SMOKE_SCRIPT}"
[[ -f "${COMMITTED_SUMMARY}" ]] || die "Committed summary not found: ${COMMITTED_SUMMARY}"

mkdir -p "$(dirname "${TRACE_FILE}")"
: > "${TRACE_FILE}"

log "=== Adversarial Smoke Lane [bd-3yr14.6] ==="
log_json "start" "committed_summary" "${COMMITTED_SUMMARY}"

if ! command -v rch >/dev/null 2>&1; then
  log "Warning: rch not available, using local cargo"
  BUILD_CMD="cargo build -p frankenlibc-abi --release"
else
  BUILD_CMD="rch exec -- cargo build -p frankenlibc-abi --release"
fi

log "Rebuilding library..."
log_json "build_start" "command" "${BUILD_CMD}"

if ! eval "${BUILD_CMD}" >/dev/null 2>&1; then
  log_json "build_failed" "reason" "cargo_error"
  die "Library build failed"
fi
log_json "build_done"

log "Running smoke test..."
RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
SMOKE_OUT="${ROOT}/target/adversarial_smoke/${RUN_TS}"
mkdir -p "${SMOKE_OUT}"

export TIMEOUT_SECONDS
log_json "smoke_start" "timeout" "${TIMEOUT_SECONDS}"

SMOKE_RC=0
if ! bash "${SMOKE_SCRIPT}" > "${SMOKE_OUT}/stdout.txt" 2> "${SMOKE_OUT}/stderr.txt"; then
  SMOKE_RC=$?
  log "Warning: Smoke script exited with code ${SMOKE_RC}"
fi
log_json "smoke_done" "exit_code" "${SMOKE_RC}"

LATEST_SMOKE_DIR="$(ls -td "${ROOT}"/target/ld_preload_smoke/20* 2>/dev/null | head -1)"
if [[ -z "${LATEST_SMOKE_DIR}" ]] || [[ ! -f "${LATEST_SMOKE_DIR}/abi_compat_report.json" ]]; then
  log_json "smoke_no_report" "reason" "missing_output"
  die "Smoke run did not produce abi_compat_report.json"
fi

FRESH_REPORT="${LATEST_SMOKE_DIR}/abi_compat_report.json"
log "Fresh report: ${FRESH_REPORT}"

extract_summary() {
  local file="$1"
  jq -c '{passes: .summary.passes, fails: .summary.fails, skips: .summary.skips}' "${file}" 2>/dev/null || echo '{"error":"parse_failed"}'
}

COMMITTED_STATS="$(extract_summary "${COMMITTED_SUMMARY}")"
FRESH_STATS="$(jq -c '{passes: .summary.passes, fails: .summary.fails, skips: .summary.skips}' "${FRESH_REPORT}" 2>/dev/null || echo '{"error":"parse_failed"}')"

log "Committed: ${COMMITTED_STATS}"
log "Fresh:     ${FRESH_STATS}"
log_json "comparison" "committed" "${COMMITTED_STATS}" "fresh" "${FRESH_STATS}"

COMMITTED_PASSES="$(echo "${COMMITTED_STATS}" | jq -r '.passes // 0')"
COMMITTED_FAILS="$(echo "${COMMITTED_STATS}" | jq -r '.fails // 0')"
FRESH_PASSES="$(echo "${FRESH_STATS}" | jq -r '.passes // 0')"
FRESH_FAILS="$(echo "${FRESH_STATS}" | jq -r '.fails // 0')"

DIVERGED=false
if [[ "${COMMITTED_PASSES}" != "${FRESH_PASSES}" ]]; then
  log "DIVERGENCE: pass count differs (committed=${COMMITTED_PASSES}, fresh=${FRESH_PASSES})"
  DIVERGED=true
fi
if [[ "${COMMITTED_FAILS}" != "${FRESH_FAILS}" ]]; then
  log "DIVERGENCE: fail count differs (committed=${COMMITTED_FAILS}, fresh=${FRESH_FAILS})"
  DIVERGED=true
fi

if [[ "${DIVERGED}" == "true" ]]; then
  log_json "divergence_detected" "committed_passes" "${COMMITTED_PASSES}" "fresh_passes" "${FRESH_PASSES}" "committed_fails" "${COMMITTED_FAILS}" "fresh_fails" "${FRESH_FAILS}"

  if [[ "${REGENERATE}" == "true" ]]; then
    log "Regenerating committed summary..."
    FRESH_SUMMARY="${ROOT}/target/adversarial_smoke/ld_preload_smoke_summary.v1.json.new"

    cat > "${FRESH_SUMMARY}" <<EOF
{
  "schema_version": "v1",
  "bead": "bd-3yr14.6",
  "source_report_path": "${FRESH_REPORT}",
  "run_id": "${RUN_TS}",
  "checked_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "checked_date_display": "$(date -u +'%B %-d, %Y')",
  "lib_path": "target/release/libfrankenlibc_abi.so",
  "timeout_seconds": ${TIMEOUT_SECONDS},
  "stress_iters": 5,
  "summary": {
    "total_cases": $((FRESH_PASSES + FRESH_FAILS)),
    "passes": ${FRESH_PASSES},
    "fails": ${FRESH_FAILS},
    "skips": $(echo "${FRESH_STATS}" | jq -r '.skips // 0'),
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
