#!/usr/bin/env bash
# E2E Test: Build Wave Execution
#
# Tests parallel build of independent packages:
# 1. Select 3 independent packages
# 2. Run parallel builds
# 3. Verify all complete
# 4. Check no resource conflicts
# 5. Validate results collected correctly
#
# Runtime target: < 10 minutes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration - 3 small independent packages
WAVE_PACKAGES=(
    "sys-apps/which"
    "app-misc/screen"
    "sys-process/htop"
)

main() {
    e2e_init "build-wave" 5

    log_info "Wave packages: ${WAVE_PACKAGES[*]}"
    log_info ""

    # Step 1: Check prerequisites
    log_step "Checking prerequisites..."
    if ! check_docker; then
        skip_test "Docker not available"
    fi
    if ! ensure_image; then
        log_error "Failed to ensure Docker image"
        e2e_finish "fail"
        return 1
    fi
    if ! ensure_frankenlibc; then
        log_error "Failed to build FrankenLibC"
        e2e_finish "fail"
        return 1
    fi
    log_success "All prerequisites met"

    # Step 2: Run parallel builds
    log_step "Running parallel builds..."
    local pids=()
    local results_dirs=()

    for pkg in "${WAVE_PACKAGES[@]}"; do
        local pkg_safe="${pkg//\//__}"
        local pkg_dir="${E2E_RESULT_DIR}/${pkg_safe}"
        mkdir -p "${pkg_dir}"
        results_dirs+=("${pkg_dir}")

        log_info "  Starting build: ${pkg}"
        (
            run_emerge "${pkg}" "${pkg_dir}" 600
            echo $? > "${pkg_dir}/exit_code"
        ) &
        pids+=($!)
    done

    log_info "  Waiting for ${#pids[@]} parallel builds..."

    # Wait for all builds
    local failed=0
    for i in "${!pids[@]}"; do
        local pid="${pids[$i]}"
        local pkg="${WAVE_PACKAGES[$i]}"

        if wait "${pid}"; then
            log_success "  ${pkg} completed"
        else
            log_error "  ${pkg} failed"
            failed=$((failed + 1))
        fi
    done

    # Step 3: Verify all completed
    log_step "Verifying build results..."
    local success_count=0
    for i in "${!results_dirs[@]}"; do
        local dir="${results_dirs[$i]}"
        local pkg="${WAVE_PACKAGES[$i]}"

        if [[ -f "${dir}/exit_code" ]]; then
            local exit_code
            exit_code=$(cat "${dir}/exit_code")
            if [[ "${exit_code}" == "0" ]]; then
                success_count=$((success_count + 1))
                log_success "  ${pkg}: success"
            else
                log_error "  ${pkg}: failed (exit ${exit_code})"
            fi
        else
            log_error "  ${pkg}: no exit code recorded"
        fi
    done

    log_info "  Results: ${success_count}/${#WAVE_PACKAGES[@]} succeeded"

    # Step 4: Check for resource conflicts
    log_step "Checking for resource conflicts..."
    local conflict_found=false

    # Check if any build logs mention lock/conflict issues
    for dir in "${results_dirs[@]}"; do
        if [[ -f "${dir}/build.log" ]]; then
            if grep -qi "lock\|conflict\|blocked\|waiting" "${dir}/build.log" 2>/dev/null; then
                log_warn "  Potential conflict detected in ${dir}/build.log"
                conflict_found=true
            fi
        fi
    done

    if [[ "${conflict_found}" == "true" ]]; then
        log_warn "  Resource conflicts may have occurred (check logs)"
    else
        log_success "  No obvious resource conflicts detected"
    fi

    # Step 5: Validate results collection
    log_step "Validating results collection..."
    for i in "${!results_dirs[@]}"; do
        local dir="${results_dirs[$i]}"
        local pkg="${WAVE_PACKAGES[$i]}"

        if [[ -f "${dir}/build.log" ]]; then
            log_success "  ${pkg}: build.log present"
        else
            log_error "  ${pkg}: build.log missing"
        fi

        if [[ -f "${dir}/frankenlibc.jsonl" ]]; then
            local count
            count=$(count_healing_actions "${dir}/frankenlibc.jsonl")
            log_info "  ${pkg}: ${count} healing actions"
        fi
    done

    # Create wave summary
    cat > "${E2E_RESULT_DIR}/wave_summary.json" <<EOF
{
    "packages": $(printf '%s\n' "${WAVE_PACKAGES[@]}" | jq -R . | jq -s .),
    "total": ${#WAVE_PACKAGES[@]},
    "succeeded": ${success_count},
    "failed": ${failed},
    "parallel": true
}
EOF

    if [[ ${failed} -gt 0 ]]; then
        log_error "${failed} packages failed"
        e2e_finish "fail"
        return 1
    fi

    e2e_finish "pass"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
