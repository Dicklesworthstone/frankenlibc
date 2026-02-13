#!/usr/bin/env bash
# E2E Test: Full Pipeline Mini
#
# Tests complete pipeline with 5 packages:
# 1. Run build phase for 5 packages
# 2. Run test phase for 5 packages
# 3. Analyze results
# 4. Generate report
# 5. Validate all artifacts created
#
# Runtime target: < 30 minutes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration - 5 carefully selected packages for coverage
PIPELINE_PACKAGES=(
    "sys-apps/which"
    "app-arch/gzip"
    "dev-libs/json-c"
    "sys-apps/grep"
    "app-misc/jq"
)

main() {
    e2e_init "full-pipeline" 5

    log_info "Pipeline packages: ${PIPELINE_PACKAGES[*]}"
    log_info ""

    # Step 1: Check prerequisites and run builds
    log_step "Building ${#PIPELINE_PACKAGES[@]} packages..."
    if ! check_docker; then
        skip_test "Docker not available"
    fi
    if ! ensure_image; then
        log_error "Failed to ensure Docker image"
        e2e_finish "fail"
        return 1
    fi

    local build_results=()
    local build_success=0
    local build_failed=0

    for pkg in "${PIPELINE_PACKAGES[@]}"; do
        local pkg_safe="${pkg//\//__}"
        local pkg_dir="${E2E_RESULT_DIR}/build/${pkg_safe}"
        mkdir -p "${pkg_dir}"

        log_info "  Building ${pkg}..."
        local build_start build_end
        build_start=$(date +%s)

        if run_emerge "${pkg}" "${pkg_dir}" 900; then
            build_end=$(date +%s)
            log_success "    ${pkg} built in $((build_end - build_start))s"
            build_results+=("${pkg}:success")
            build_success=$((build_success + 1))
        else
            build_end=$(date +%s)
            log_error "    ${pkg} failed after $((build_end - build_start))s"
            build_results+=("${pkg}:failed")
            build_failed=$((build_failed + 1))
        fi
    done

    log_info "  Build results: ${build_success} success, ${build_failed} failed"

    # Step 2: Run test phase (only for successfully built packages)
    log_step "Running tests for built packages..."
    local test_results=()
    local test_success=0
    local test_failed=0

    for result in "${build_results[@]}"; do
        local pkg="${result%:*}"
        local status="${result#*:}"

        if [[ "${status}" != "success" ]]; then
            log_warn "  Skipping tests for ${pkg} (build failed)"
            test_results+=("${pkg}:skipped")
            continue
        fi

        local pkg_safe="${pkg//\//__}"
        local test_dir="${E2E_RESULT_DIR}/test/${pkg_safe}"
        mkdir -p "${test_dir}"

        log_info "  Testing ${pkg}..."
        local test_start test_end
        test_start=$(date +%s)

        local env_opts=(
            -e "FRANKENLIBC_MODE=${FRANKENLIBC_MODE}"
            -e "FRANKENLIBC_LOG_FILE=/results/frankenlibc.jsonl"
            -e "FRANKENLIBC_PORTAGE_ENABLE=1"
        )

        if docker run --rm "${env_opts[@]}" \
            -v "${test_dir}:/results:rw" \
            "${FRANKENLIBC_IMAGE}" \
            bash -lc "timeout 600 emerge --test ${pkg} > /results/test.log 2>&1"; then
            test_end=$(date +%s)
            log_success "    ${pkg} tests passed in $((test_end - test_start))s"
            test_results+=("${pkg}:passed")
            test_success=$((test_success + 1))
        else
            test_end=$(date +%s)
            log_warn "    ${pkg} tests failed in $((test_end - test_start))s"
            test_results+=("${pkg}:failed")
            test_failed=$((test_failed + 1))
        fi
    done

    log_info "  Test results: ${test_success} passed, ${test_failed} failed"

    # Step 3: Analyze results
    log_step "Analyzing results..."
    local total_healing=0
    local healing_by_package=()

    for pkg in "${PIPELINE_PACKAGES[@]}"; do
        local pkg_safe="${pkg//\//__}"
        local healing_count=0

        # Check build log
        local build_log="${E2E_RESULT_DIR}/build/${pkg_safe}/frankenlibc.jsonl"
        if [[ -f "${build_log}" ]]; then
            healing_count=$((healing_count + $(count_healing_actions "${build_log}")))
        fi

        # Check test log
        local test_log="${E2E_RESULT_DIR}/test/${pkg_safe}/frankenlibc.jsonl"
        if [[ -f "${test_log}" ]]; then
            healing_count=$((healing_count + $(count_healing_actions "${test_log}")))
        fi

        total_healing=$((total_healing + healing_count))
        healing_by_package+=("${pkg}:${healing_count}")
        log_info "  ${pkg}: ${healing_count} healing actions"
    done

    log_info "  Total healing actions: ${total_healing}"

    # Step 4: Generate report
    log_step "Generating report..."
    local report_file="${E2E_RESULT_DIR}/pipeline_report.json"

    cat > "${report_file}" <<EOF
{
    "timestamp": "$(log_timestamp)",
    "packages": $(printf '%s\n' "${PIPELINE_PACKAGES[@]}" | jq -R . | jq -s .),
    "build_phase": {
        "total": ${#PIPELINE_PACKAGES[@]},
        "success": ${build_success},
        "failed": ${build_failed}
    },
    "test_phase": {
        "total": ${build_success},
        "passed": ${test_success},
        "failed": ${test_failed}
    },
    "healing_actions": {
        "total": ${total_healing},
        "by_package": $(printf '%s\n' "${healing_by_package[@]}" | \
            jq -R 'split(":") | {(.[0]): (.[1] | tonumber)}' | \
            jq -s 'add')
    }
}
EOF

    log_info "  Report written to: ${report_file}"
    cat "${report_file}" | tee -a "${E2E_LOG_FILE}"

    # Step 5: Validate artifacts
    log_step "Validating artifacts..."
    local missing_artifacts=0

    for pkg in "${PIPELINE_PACKAGES[@]}"; do
        local pkg_safe="${pkg//\//__}"

        # Check build artifacts
        if [[ ! -f "${E2E_RESULT_DIR}/build/${pkg_safe}/build.log" ]]; then
            log_warn "  Missing: build/${pkg_safe}/build.log"
            missing_artifacts=$((missing_artifacts + 1))
        fi
    done

    if [[ ! -f "${report_file}" ]]; then
        log_error "  Missing: pipeline_report.json"
        missing_artifacts=$((missing_artifacts + 1))
    fi

    if [[ ${missing_artifacts} -gt 0 ]]; then
        log_warn "  ${missing_artifacts} artifacts missing"
    else
        log_success "  All expected artifacts present"
    fi

    # Overall result
    if [[ ${build_failed} -gt 2 ]]; then
        log_error "Too many build failures (${build_failed}/${#PIPELINE_PACKAGES[@]})"
        e2e_finish "fail"
        return 1
    fi

    e2e_finish "pass"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
