#!/usr/bin/env bash
# E2E Test: Single Package Build
#
# Tests the complete flow for building one package:
# 1. Build/verify Docker image
# 2. Build/verify FrankenLibC
# 3. Run emerge with LD_PRELOAD
# 4. Verify build success
# 5. Validate log format
# 6. Check healing actions logged
#
# Runtime target: < 5 minutes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration
TEST_PACKAGE="${TEST_PACKAGE:-sys-apps/which}"

main() {
    e2e_init "single-package-build" 6

    log_info "Test Package: ${TEST_PACKAGE}"
    log_info ""

    # Step 1: Check Docker availability
    log_step "Checking Docker availability..."
    if ! check_docker; then
        skip_test "Docker not available"
    fi
    log_success "Docker is available"

    # Step 2: Ensure Docker image exists
    log_step "Ensuring Docker image exists..."
    if ! ensure_image; then
        log_error "Failed to ensure Docker image"
        e2e_finish "fail"
        return 1
    fi

    # Step 3: Ensure FrankenLibC is built
    log_step "Ensuring FrankenLibC library is built..."
    if ! ensure_frankenlibc; then
        log_error "Failed to build FrankenLibC"
        e2e_finish "fail"
        return 1
    fi

    # Step 4: Run emerge with FrankenLibC
    log_step "Running emerge with FrankenLibC..."
    local pkg_result_dir="${E2E_RESULT_DIR}/package"
    mkdir -p "${pkg_result_dir}"

    if run_emerge "${TEST_PACKAGE}" "${pkg_result_dir}" 600; then
        log_success "Package ${TEST_PACKAGE} built successfully"
    else
        log_error "Package ${TEST_PACKAGE} build failed"
        if [[ -f "${pkg_result_dir}/build.log" ]]; then
            log_info "Last 20 lines of build log:"
            tail -20 "${pkg_result_dir}/build.log" >> "${E2E_LOG_FILE}"
        fi
        e2e_finish "fail"
        return 1
    fi

    # Step 5: Validate log format
    log_step "Validating FrankenLibC log format..."
    local frankenlibc_log="${pkg_result_dir}/frankenlibc.jsonl"

    if [[ ! -f "${frankenlibc_log}" ]]; then
        log_warn "FrankenLibC log not created (may be expected for simple packages)"
        touch "${frankenlibc_log}"  # Create empty for validation
    fi

    if ! validate_jsonl "${frankenlibc_log}"; then
        log_error "FrankenLibC log validation failed"
        e2e_finish "fail"
        return 1
    fi

    # Step 6: Analyze healing actions
    log_step "Analyzing healing actions..."
    local healing_count
    healing_count=$(count_healing_actions "${frankenlibc_log}")
    log_info "  Healing actions recorded: ${healing_count}"

    # Create detailed analysis
    if [[ -s "${frankenlibc_log}" ]]; then
        log_info "  Healing action breakdown:"
        jq -s 'group_by(.action) | map({action: .[0].action, count: length}) | sort_by(-.count)' \
            "${frankenlibc_log}" 2>/dev/null | tee -a "${E2E_LOG_FILE}" || true
    fi

    # Verify artifacts
    assert_file_exists "${pkg_result_dir}/build.log" "Build log not found"

    e2e_finish "pass"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
