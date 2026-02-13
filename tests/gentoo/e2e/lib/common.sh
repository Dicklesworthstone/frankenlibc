#!/usr/bin/env bash
# Common functions for Gentoo E2E tests
# shellcheck disable=SC2034

set -euo pipefail

# Colors (disabled if not a terminal)
if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# Get repository root
E2E_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${E2E_ROOT}/../../.." && pwd)"

# Default configuration
: "${FRANKENLIBC_IMAGE:=frankenlibc/gentoo-frankenlibc:latest}"
: "${FRANKENLIBC_MODE:=hardened}"
: "${E2E_TIMEOUT:=1800}"
: "${E2E_ARTIFACTS:=/tmp/frankenlibc-e2e}"

# Test state
E2E_TEST_NAME=""
E2E_LOG_FILE=""
E2E_RESULT_DIR=""
E2E_START_TIME=""
E2E_STEP_CURRENT=0
E2E_STEP_TOTAL=0

# Logging functions
log_timestamp() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

log() {
    local level="$1"
    shift
    echo -e "$(log_timestamp) [${level}] $*" | tee -a "${E2E_LOG_FILE:-/dev/null}"
}

log_info() {
    log "INFO" "$@"
}

log_warn() {
    log "${YELLOW}WARN${NC}" "$@"
}

log_error() {
    log "${RED}ERROR${NC}" "$@"
}

log_success() {
    log "${GREEN}OK${NC}" "$@"
}

log_step() {
    E2E_STEP_CURRENT=$((E2E_STEP_CURRENT + 1))
    log "INFO" "[Step ${E2E_STEP_CURRENT}/${E2E_STEP_TOTAL}] $*"
}

# Initialize test environment
e2e_init() {
    local test_name="$1"
    local step_count="${2:-5}"

    E2E_TEST_NAME="${test_name}"
    E2E_STEP_TOTAL="${step_count}"
    E2E_STEP_CURRENT=0
    E2E_START_TIME=$(date +%s)

    local timestamp
    timestamp=$(date +%Y%m%d-%H%M%S)

    E2E_RESULT_DIR="${E2E_ARTIFACTS}/${test_name}-${timestamp}"
    E2E_LOG_FILE="${E2E_RESULT_DIR}/test.log"

    mkdir -p "${E2E_RESULT_DIR}"

    log_info "=== E2E Test: ${test_name} ==="
    log_info "Timestamp: $(log_timestamp)"
    log_info "Result directory: ${E2E_RESULT_DIR}"
    log_info "Image: ${FRANKENLIBC_IMAGE}"
    log_info "Mode: ${FRANKENLIBC_MODE}"
    log_info ""
}

# Finalize test with result
e2e_finish() {
    local result="$1"
    local end_time
    local duration

    end_time=$(date +%s)
    duration=$((end_time - E2E_START_TIME))

    log_info ""
    if [[ "${result}" == "pass" ]]; then
        log_info "=== E2E Test ${GREEN}PASSED${NC} ==="
    else
        log_info "=== E2E Test ${RED}FAILED${NC} ==="
    fi
    log_info "Duration: ${duration}s"
    log_info "Results in: ${E2E_RESULT_DIR}"
    log_info "Log file: ${E2E_LOG_FILE}"

    # Write summary JSON
    cat > "${E2E_RESULT_DIR}/summary.json" <<EOF
{
    "test_name": "${E2E_TEST_NAME}",
    "result": "${result}",
    "duration_seconds": ${duration},
    "timestamp": "$(log_timestamp)",
    "log_file": "${E2E_LOG_FILE}",
    "image": "${FRANKENLIBC_IMAGE}",
    "mode": "${FRANKENLIBC_MODE}"
}
EOF

    if [[ "${result}" == "pass" ]]; then
        return 0
    else
        return 1
    fi
}

# Run a command with logging
run_cmd() {
    local description="$1"
    shift
    local cmd_start
    local cmd_end
    local cmd_duration
    local exit_code

    log_info "  Command: $*"
    cmd_start=$(date +%s)

    set +e
    "$@" >> "${E2E_LOG_FILE}" 2>&1
    exit_code=$?
    set -e

    cmd_end=$(date +%s)
    cmd_duration=$((cmd_end - cmd_start))

    log_info "  Exit code: ${exit_code}"
    log_info "  Duration: ${cmd_duration}s"

    return ${exit_code}
}

# Check if Docker is available
check_docker() {
    if ! command -v docker &>/dev/null; then
        log_error "Docker is not installed or not in PATH"
        return 1
    fi

    if ! docker info &>/dev/null; then
        log_error "Docker daemon is not running"
        return 1
    fi

    return 0
}

# Check if image exists, build if not
ensure_image() {
    local image="${1:-${FRANKENLIBC_IMAGE}}"

    if docker image inspect "${image}" &>/dev/null; then
        log_success "Image ${image} exists"
        return 0
    fi

    log_warn "Image ${image} not found, building..."
    if [[ -f "${REPO_ROOT}/docker/gentoo/Dockerfile.frankenlibc" ]]; then
        docker build \
            -f "${REPO_ROOT}/docker/gentoo/Dockerfile.frankenlibc" \
            -t "${image}" \
            "${REPO_ROOT}" >> "${E2E_LOG_FILE}" 2>&1
        log_success "Image ${image} built successfully"
    else
        log_error "Dockerfile not found at ${REPO_ROOT}/docker/gentoo/Dockerfile.frankenlibc"
        return 1
    fi
}

# Build FrankenLibC if needed
ensure_frankenlibc() {
    local lib_path="${REPO_ROOT}/target/release/libfrankenlibc_abi.so"

    if [[ -f "${lib_path}" ]]; then
        log_success "FrankenLibC library exists at ${lib_path}"
        return 0
    fi

    log_warn "FrankenLibC library not found, building..."
    (cd "${REPO_ROOT}" && cargo build --release -p frankenlibc-abi) >> "${E2E_LOG_FILE}" 2>&1
    log_success "FrankenLibC built successfully"
}

# Run emerge in container with FrankenLibC
run_emerge() {
    local package="$1"
    local result_dir="$2"
    local timeout="${3:-${E2E_TIMEOUT}}"
    local enable_frankenlibc="${4:-1}"

    local env_opts=()
    if [[ "${enable_frankenlibc}" == "1" ]]; then
        env_opts+=(
            -e "FRANKENLIBC_MODE=${FRANKENLIBC_MODE}"
            -e "FRANKENLIBC_LOG_FILE=/results/frankenlibc.jsonl"
            -e "FRANKENLIBC_PORTAGE_ENABLE=1"
        )
    else
        env_opts+=(-e "FRANKENLIBC_PORTAGE_ENABLE=0")
    fi

    docker run --rm \
        "${env_opts[@]}" \
        -v "${result_dir}:/results:rw" \
        "${FRANKENLIBC_IMAGE}" \
        bash -lc "timeout --signal=TERM --kill-after=30 ${timeout} emerge --quiet ${package} > /results/build.log 2>&1"
}

# Validate JSONL log file
validate_jsonl() {
    local file="$1"

    if [[ ! -f "${file}" ]]; then
        log_error "Log file not found: ${file}"
        return 1
    fi

    if [[ ! -s "${file}" ]]; then
        log_warn "Log file is empty: ${file}"
        return 0
    fi

    local line_num=0
    local errors=0
    while IFS= read -r line; do
        line_num=$((line_num + 1))
        if [[ -n "${line}" ]] && ! echo "${line}" | jq empty 2>/dev/null; then
            log_error "Invalid JSON at line ${line_num}: ${line:0:50}..."
            errors=$((errors + 1))
        fi
    done < "${file}"

    if [[ ${errors} -gt 0 ]]; then
        log_error "Found ${errors} invalid JSON lines"
        return 1
    fi

    log_success "Log file valid: ${file} (${line_num} lines)"
    return 0
}

# Count healing actions in log
count_healing_actions() {
    local file="$1"

    if [[ ! -f "${file}" ]] || [[ ! -s "${file}" ]]; then
        echo 0
        return
    fi

    jq -s 'length' "${file}" 2>/dev/null || echo 0
}

# Skip test if preconditions not met
skip_test() {
    local reason="$1"
    log_warn "SKIP: ${reason}"
    exit 0
}

# Assert condition
assert() {
    local condition="$1"
    local message="${2:-Assertion failed}"

    if ! eval "${condition}"; then
        log_error "${message}"
        return 1
    fi
    return 0
}

# Assert file exists
assert_file_exists() {
    local file="$1"
    local message="${2:-File not found: ${file}}"

    if [[ ! -f "${file}" ]]; then
        log_error "${message}"
        return 1
    fi
    log_success "File exists: ${file}"
    return 0
}

# Assert directory exists
assert_dir_exists() {
    local dir="$1"
    local message="${2:-Directory not found: ${dir}}"

    if [[ ! -d "${dir}" ]]; then
        log_error "${message}"
        return 1
    fi
    log_success "Directory exists: ${dir}"
    return 0
}

# Assert command succeeds
assert_cmd() {
    local message="$1"
    shift

    if ! "$@" >> "${E2E_LOG_FILE}" 2>&1; then
        log_error "${message}"
        return 1
    fi
    log_success "${message}"
    return 0
}

# Cleanup old test artifacts (keep last N)
cleanup_old_artifacts() {
    local keep="${1:-5}"
    local pattern="${2:-*}"

    if [[ ! -d "${E2E_ARTIFACTS}" ]]; then
        return 0
    fi

    # Find and remove old directories
    find "${E2E_ARTIFACTS}" -maxdepth 1 -type d -name "${pattern}-*" | \
        sort -r | \
        tail -n +$((keep + 1)) | \
        xargs -r rm -rf
}
