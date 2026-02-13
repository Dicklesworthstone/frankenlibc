#!/usr/bin/env bash
# E2E Test: Test Suite Execution
#
# Tests baseline vs instrumented comparison:
# 1. Run package tests without FrankenLibC (baseline)
# 2. Run package tests with FrankenLibC (instrumented)
# 3. Compare results
# 4. Verify verdict calculation
# 5. Check healing actions during tests
#
# Runtime target: < 15 minutes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration
TEST_PACKAGE="${TEST_PACKAGE:-app-arch/gzip}"

run_tests() {
    local mode="$1"
    local result_dir="$2"
    local enable_franken="$3"

    local env_opts=()
    if [[ "${enable_franken}" == "1" ]]; then
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
        bash -lc "timeout --signal=TERM --kill-after=30 ${E2E_TIMEOUT} emerge --test ${TEST_PACKAGE} > /results/test.log 2>&1; echo \$? > /results/exit_code"
}

parse_test_results() {
    local log_file="$1"

    if [[ ! -f "${log_file}" ]]; then
        echo '{"total": 0, "passed": 0, "failed": 0, "skipped": 0}'
        return
    fi

    local passed failed skipped
    passed=$(grep -c "^PASS:" "${log_file}" 2>/dev/null || echo 0)
    failed=$(grep -c "^FAIL:" "${log_file}" 2>/dev/null || echo 0)
    skipped=$(grep -c "^SKIP:" "${log_file}" 2>/dev/null || echo 0)
    local total=$((passed + failed + skipped))

    # Fallback for non-standard logs
    if [[ ${total} -eq 0 ]]; then
        if grep -q "All.*tests.*passed" "${log_file}" 2>/dev/null; then
            passed=1
            total=1
        elif grep -q "FAILED" "${log_file}" 2>/dev/null; then
            failed=1
            total=1
        fi
    fi

    cat <<EOF
{"total": ${total}, "passed": ${passed}, "failed": ${failed}, "skipped": ${skipped}}
EOF
}

main() {
    e2e_init "test-suite" 5

    log_info "Test Package: ${TEST_PACKAGE}"
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
    log_success "All prerequisites met"

    # Step 2: Run baseline tests
    log_step "Running baseline tests (without FrankenLibC)..."
    local baseline_dir="${E2E_RESULT_DIR}/baseline"
    mkdir -p "${baseline_dir}"

    local baseline_start baseline_end baseline_duration
    baseline_start=$(date +%s)
    run_tests "baseline" "${baseline_dir}" "0" || true
    baseline_end=$(date +%s)
    baseline_duration=$((baseline_end - baseline_start))

    local baseline_exit
    baseline_exit=$(cat "${baseline_dir}/exit_code" 2>/dev/null || echo 1)
    log_info "  Baseline exit code: ${baseline_exit}"
    log_info "  Baseline duration: ${baseline_duration}s"

    local baseline_results
    baseline_results=$(parse_test_results "${baseline_dir}/test.log")
    log_info "  Baseline results: ${baseline_results}"

    # Step 3: Run instrumented tests
    log_step "Running instrumented tests (with FrankenLibC)..."
    local instrumented_dir="${E2E_RESULT_DIR}/instrumented"
    mkdir -p "${instrumented_dir}"

    local instrumented_start instrumented_end instrumented_duration
    instrumented_start=$(date +%s)
    run_tests "instrumented" "${instrumented_dir}" "1" || true
    instrumented_end=$(date +%s)
    instrumented_duration=$((instrumented_end - instrumented_start))

    local instrumented_exit
    instrumented_exit=$(cat "${instrumented_dir}/exit_code" 2>/dev/null || echo 1)
    log_info "  Instrumented exit code: ${instrumented_exit}"
    log_info "  Instrumented duration: ${instrumented_duration}s"

    local instrumented_results
    instrumented_results=$(parse_test_results "${instrumented_dir}/test.log")
    log_info "  Instrumented results: ${instrumented_results}"

    # Step 4: Compare results and calculate verdict
    log_step "Comparing results and calculating verdict..."

    local baseline_failed instrumented_failed
    baseline_failed=$(echo "${baseline_results}" | jq '.failed')
    instrumented_failed=$(echo "${instrumented_results}" | jq '.failed')

    local verdict="NEUTRAL"
    local overhead_percent=0

    if [[ ${baseline_duration} -gt 0 ]]; then
        overhead_percent=$(( (instrumented_duration - baseline_duration) * 100 / baseline_duration ))
    fi

    if [[ ${instrumented_failed} -gt ${baseline_failed} ]]; then
        verdict="REGRESSION"
        log_error "  Verdict: REGRESSION (new test failures)"
    elif [[ ${instrumented_failed} -lt ${baseline_failed} ]]; then
        verdict="IMPROVEMENT"
        log_success "  Verdict: IMPROVEMENT (fewer failures)"
    else
        verdict="NEUTRAL"
        log_success "  Verdict: NEUTRAL (same results)"
    fi

    log_info "  Performance overhead: ${overhead_percent}%"

    # Step 5: Check healing actions
    log_step "Analyzing healing actions during tests..."
    local frankenlibc_log="${instrumented_dir}/frankenlibc.jsonl"

    if [[ -f "${frankenlibc_log}" ]] && [[ -s "${frankenlibc_log}" ]]; then
        if validate_jsonl "${frankenlibc_log}"; then
            local healing_count
            healing_count=$(count_healing_actions "${frankenlibc_log}")
            log_info "  Healing actions during tests: ${healing_count}"

            if [[ ${healing_count} -gt 0 ]]; then
                log_info "  Healing action breakdown:"
                jq -s 'group_by(.action) | map({action: .[0].action, count: length}) | sort_by(-.count)' \
                    "${frankenlibc_log}" 2>/dev/null | head -20 | tee -a "${E2E_LOG_FILE}" || true
            fi
        fi
    else
        log_info "  No healing actions recorded"
    fi

    # Create comparison report
    cat > "${E2E_RESULT_DIR}/comparison.json" <<EOF
{
    "package": "${TEST_PACKAGE}",
    "baseline": {
        "exit_code": ${baseline_exit},
        "duration_seconds": ${baseline_duration},
        "results": ${baseline_results}
    },
    "instrumented": {
        "exit_code": ${instrumented_exit},
        "duration_seconds": ${instrumented_duration},
        "results": ${instrumented_results}
    },
    "comparison": {
        "verdict": "${verdict}",
        "overhead_percent": ${overhead_percent}
    }
}
EOF

    # Only fail on regression
    if [[ "${verdict}" == "REGRESSION" ]]; then
        e2e_finish "fail"
        return 1
    fi

    e2e_finish "pass"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
