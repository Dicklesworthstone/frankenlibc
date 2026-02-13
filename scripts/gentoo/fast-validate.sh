#!/usr/bin/env bash
# Tier 1 fast validation for FrankenLibC Gentoo ecosystem testing.
# Bead: bd-2icq.18
#
# Runs FrankenLibC validation against a curated 5-package mini set designed to
# cover the core libc surface areas (string, malloc, IO, regex, threading/TLS)
# in under 10 minutes.
#
# Usage:
#   scripts/gentoo/fast-validate.sh              # Full Docker-based validation
#   scripts/gentoo/fast-validate.sh --dry-run    # Synthetic pass (no Docker)
#   scripts/gentoo/fast-validate.sh --local      # LD_PRELOAD smoke only (no Docker)
#
# Exit codes:
#   0  All packages passed
#   1  One or more packages failed
#   2  Environment/prerequisite error

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIER1_FILE="${ROOT}/configs/gentoo/tier1-mini.txt"
EXCLUSIONS_FILE="${ROOT}/configs/gentoo/exclusions.json"
BUILD_CONFIG="${ROOT}/configs/gentoo/build-config.toml"

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
RESULTS_DIR="${ROOT}/artifacts/gentoo-builds/fast-validate/${TIMESTAMP}"
SUMMARY_FILE="${RESULTS_DIR}/summary.json"
LOG_FILE="${RESULTS_DIR}/fast-validate.log"

# Defaults
TIMEOUT_PER_PKG="${FAST_VALIDATE_TIMEOUT:-900}"   # 15 min per package
TOTAL_TIMEOUT="${FAST_VALIDATE_TOTAL_TIMEOUT:-600}" # 10 min total
MODE="${FRANKENLIBC_MODE:-hardened}"
DRY_RUN=0
LOCAL_ONLY=0
FAIL_FAST="${FAST_VALIDATE_FAIL_FAST:-1}"
PARALLELISM="${FAST_VALIDATE_PARALLELISM:-1}"

# ── Argument parsing ─────────────────────────────────────────────────────────
for arg in "$@"; do
  case "${arg}" in
    --dry-run)   DRY_RUN=1 ;;
    --local)     LOCAL_ONLY=1 ;;
    --no-fail-fast) FAIL_FAST=0 ;;
    --parallel)  PARALLELISM=4 ;;
    --strict)    MODE="strict" ;;
    --hardened)  MODE="hardened" ;;
    --help|-h)
      echo "Usage: $0 [--dry-run] [--local] [--no-fail-fast] [--parallel] [--strict|--hardened]"
      exit 0
      ;;
    *)
      echo "fast-validate: unknown argument '${arg}'" >&2
      exit 2
      ;;
  esac
done

# ── Color helpers (disabled outside tty) ─────────────────────────────────────
if [[ -t 1 ]]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

log() { echo -e "$(date -u +%Y-%m-%dT%H:%M:%SZ) [$1] $2" | tee -a "${LOG_FILE}"; }
log_info()    { log "INFO" "$*"; }
log_success() { log "${GREEN}PASS${NC}" "$*"; }
log_error()   { log "${RED}FAIL${NC}" "$*"; }
log_warn()    { log "${YELLOW}WARN${NC}" "$*"; }

# ── Load package list ────────────────────────────────────────────────────────
load_packages() {
  if [[ ! -f "${TIER1_FILE}" ]]; then
    echo "fast-validate: tier1-mini.txt not found at ${TIER1_FILE}" >&2
    exit 2
  fi
  # Strip comments and blank lines
  grep -v '^\s*#' "${TIER1_FILE}" | grep -v '^\s*$'
}

# ── Check exclusions ────────────────────────────────────────────────────────
check_not_excluded() {
  local pkg="$1"
  if [[ -f "${EXCLUSIONS_FILE}" ]]; then
    if python3 -c "
import json, sys
data = json.load(open('${EXCLUSIONS_FILE}'))
excluded = {e['package'] for e in data.get('exclusions', [])}
sys.exit(0 if '${pkg}' not in excluded else 1)
" 2>/dev/null; then
      return 0
    else
      return 1
    fi
  fi
  return 0
}

# ── Ensure prerequisites ────────────────────────────────────────────────────
check_prereqs() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log_info "Dry-run mode: skipping prerequisite checks"
    return 0
  fi

  if [[ "${LOCAL_ONLY}" -eq 1 ]]; then
    # Local mode just needs the LD_PRELOAD smoke test
    if [[ ! -f "${ROOT}/scripts/ld_preload_smoke.sh" ]]; then
      log_error "ld_preload_smoke.sh not found"
      exit 2
    fi
    return 0
  fi

  # Docker mode requires Docker + build-runner
  if ! command -v docker &>/dev/null; then
    log_error "Docker is not installed or not in PATH"
    log_warn "Use --local for LD_PRELOAD-only validation or --dry-run for synthetic pass"
    exit 2
  fi
  if ! docker info &>/dev/null 2>&1; then
    log_error "Docker daemon is not running"
    exit 2
  fi
  if [[ ! -f "${ROOT}/scripts/gentoo/build-runner.py" ]]; then
    log_error "build-runner.py not found"
    exit 2
  fi
}

# ── Single-package validation (Docker mode) ─────────────────────────────────
validate_package_docker() {
  local pkg="$1"
  local pkg_dir="${RESULTS_DIR}/packages/$(echo "${pkg}" | tr '/' '__')"
  mkdir -p "${pkg_dir}"

  local start_epoch
  start_epoch="$(date +%s)"

  log_info "Building ${pkg} (timeout=${TIMEOUT_PER_PKG}s, mode=${MODE})"

  local exit_code=0
  if python3 "${ROOT}/scripts/gentoo/build-runner.py" \
    --config "${BUILD_CONFIG}" \
    --packages "${pkg}" \
    --timeout "${TIMEOUT_PER_PKG}" \
    --mode "${MODE}" \
    --results-dir "${pkg_dir}" \
    --max-retries 1 \
    --fail-fast \
    >> "${LOG_FILE}" 2>&1; then
    exit_code=0
  else
    exit_code=$?
  fi

  local end_epoch
  end_epoch="$(date +%s)"
  local duration=$(( end_epoch - start_epoch ))

  # Write per-package result
  local result="failed"
  [[ "${exit_code}" -eq 0 ]] && result="success"
  [[ "${exit_code}" -eq 124 ]] && result="timeout"

  cat > "${pkg_dir}/fast_validate_result.json" <<EOF
{
  "package": "${pkg}",
  "result": "${result}",
  "exit_code": ${exit_code},
  "duration_seconds": ${duration},
  "mode": "${MODE}",
  "timeout_per_pkg": ${TIMEOUT_PER_PKG},
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

  if [[ "${exit_code}" -eq 0 ]]; then
    log_success "${pkg} (${duration}s)"
  else
    log_error "${pkg} (exit=${exit_code}, ${duration}s)"
    if [[ -f "${pkg_dir}/build.log" ]]; then
      log_info "  Last 5 lines of build log:"
      tail -5 "${pkg_dir}/build.log" 2>/dev/null | while IFS= read -r line; do
        log_info "    ${line}"
      done
    fi
  fi

  return "${exit_code}"
}

# ── Single-package validation (dry-run mode) ────────────────────────────────
validate_package_dry() {
  local pkg="$1"
  local pkg_dir="${RESULTS_DIR}/packages/$(echo "${pkg}" | tr '/' '__')"
  mkdir -p "${pkg_dir}"

  log_info "[dry-run] ${pkg}: synthetic PASS"
  cat > "${pkg_dir}/fast_validate_result.json" <<EOF
{
  "package": "${pkg}",
  "result": "success",
  "exit_code": 0,
  "duration_seconds": 0,
  "mode": "${MODE}",
  "dry_run": true,
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
  return 0
}

# ── Local-only validation (LD_PRELOAD smoke) ────────────────────────────────
run_local_validation() {
  log_info "Running LD_PRELOAD smoke test (local-only mode)"

  local exit_code=0
  FRANKENLIBC_MODE="${MODE}" TIMEOUT_SECONDS=30 \
    bash "${ROOT}/scripts/ld_preload_smoke.sh" >> "${LOG_FILE}" 2>&1 || exit_code=$?

  if [[ "${exit_code}" -eq 0 ]]; then
    log_success "LD_PRELOAD smoke test passed"
  else
    log_error "LD_PRELOAD smoke test failed (exit=${exit_code})"
  fi

  return "${exit_code}"
}

# ── Main ─────────────────────────────────────────────────────────────────────
main() {
  mkdir -p "${RESULTS_DIR}/packages"
  : > "${LOG_FILE}"

  log_info "=== FrankenLibC Tier 1 Fast Validation ==="
  log_info "Mode:       ${MODE}"
  log_info "Dry-run:    ${DRY_RUN}"
  log_info "Local-only: ${LOCAL_ONLY}"
  log_info "Fail-fast:  ${FAIL_FAST}"
  log_info "Results:    ${RESULTS_DIR}"
  log_info ""

  check_prereqs

  # Local-only mode: just run LD_PRELOAD smoke
  if [[ "${LOCAL_ONLY}" -eq 1 ]]; then
    run_local_validation
    local rc=$?
    write_summary 0 0 0 "${rc}"
    exit "${rc}"
  fi

  # Load and validate package list
  local -a packages=()
  while IFS= read -r pkg; do
    if check_not_excluded "${pkg}"; then
      packages+=("${pkg}")
    else
      log_warn "Skipping excluded package: ${pkg}"
    fi
  done < <(load_packages)

  local total=${#packages[@]}
  log_info "Packages to validate: ${total}"
  for pkg in "${packages[@]}"; do
    log_info "  - ${pkg}"
  done
  log_info ""

  # Run validation
  local passed=0
  local failed=0
  local skipped=0
  local overall_start
  overall_start="$(date +%s)"

  for pkg in "${packages[@]}"; do
    # Check total timeout
    local elapsed=$(( $(date +%s) - overall_start ))
    if [[ "${elapsed}" -gt "${TOTAL_TIMEOUT}" ]]; then
      log_warn "Total timeout (${TOTAL_TIMEOUT}s) exceeded after ${elapsed}s"
      skipped=$(( total - passed - failed ))
      break
    fi

    local rc=0
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      validate_package_dry "${pkg}" || rc=$?
    else
      validate_package_docker "${pkg}" || rc=$?
    fi

    if [[ "${rc}" -eq 0 ]]; then
      passed=$(( passed + 1 ))
    else
      failed=$(( failed + 1 ))
      if [[ "${FAIL_FAST}" -eq 1 ]]; then
        log_warn "Fail-fast: stopping after first failure"
        skipped=$(( total - passed - failed ))
        break
      fi
    fi
  done

  local overall_elapsed=$(( $(date +%s) - overall_start ))

  # Write summary
  write_summary "${passed}" "${failed}" "${skipped}" "$([ "${failed}" -gt 0 ] && echo 1 || echo 0)"

  log_info ""
  log_info "=== Fast Validation Summary ==="
  log_info "Total:   ${total}"
  log_info "Passed:  ${passed}"
  log_info "Failed:  ${failed}"
  log_info "Skipped: ${skipped}"
  log_info "Time:    ${overall_elapsed}s"
  log_info "Results: ${RESULTS_DIR}"

  if [[ "${failed}" -gt 0 ]]; then
    log_error "FAST VALIDATION FAILED (${failed} package(s) failed)"
    exit 1
  fi

  log_success "FAST VALIDATION PASSED"
  exit 0
}

write_summary() {
  local passed="$1"
  local failed="$2"
  local skipped="$3"
  local exit_code="$4"
  local total=$(( passed + failed + skipped ))

  cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "v1",
  "bead": "bd-2icq.18",
  "test": "tier1-fast-validation",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "mode": "${MODE}",
  "dry_run": $([ "${DRY_RUN}" -eq 1 ] && echo true || echo false),
  "local_only": $([ "${LOCAL_ONLY}" -eq 1 ] && echo true || echo false),
  "total_packages": ${total},
  "passed": ${passed},
  "failed": ${failed},
  "skipped": ${skipped},
  "exit_code": ${exit_code},
  "timeout_per_pkg_seconds": ${TIMEOUT_PER_PKG},
  "total_timeout_seconds": ${TOTAL_TIMEOUT},
  "tier1_file": "configs/gentoo/tier1-mini.txt",
  "results_dir": "${RESULTS_DIR}"
}
EOF
}

main
