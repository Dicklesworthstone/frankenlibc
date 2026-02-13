#!/usr/bin/env bash
# Run all Gentoo E2E tests
#
# Usage:
#   ./run_all_e2e.sh              # Run all tests
#   ./run_all_e2e.sh --fast       # Run only fast tests (< 10 min)
#   ./run_all_e2e.sh --single     # Run only single package test
#   ./run_all_e2e.sh test_name    # Run specific test

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
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

# Test definitions (name, script, expected_duration_minutes)
ALL_TESTS=(
    "single_package:test_single_package.sh:5"
    "build_wave:test_build_wave.sh:10"
    "test_suite:test_test_suite.sh:15"
    "full_pipeline:test_full_pipeline.sh:30"
    "failure_recovery:test_failure_recovery.sh:10"
    "progress_reporting:test_progress_reporting.sh:5"
)

FAST_TESTS=(
    "single_package:test_single_package.sh:5"
    "failure_recovery:test_failure_recovery.sh:10"
    "progress_reporting:test_progress_reporting.sh:5"
)

log_header() {
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  FrankenLibC Gentoo E2E Test Suite${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "  Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    echo "  Script dir: ${SCRIPT_DIR}"
    echo ""
}

run_test() {
    local name="$1"
    local script="$2"
    local expected_duration="$3"

    local script_path="${SCRIPT_DIR}/${script}"

    if [[ ! -x "${script_path}" ]]; then
        echo -e "  ${YELLOW}SKIP${NC} ${name}: script not executable"
        return 2
    fi

    echo -e "  ${BLUE}RUN${NC}  ${name} (expected: ~${expected_duration}m)"

    local start_time end_time duration
    start_time=$(date +%s)

    local exit_code=0
    if "${script_path}" > /dev/null 2>&1; then
        exit_code=0
    else
        exit_code=$?
    fi

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    if [[ ${exit_code} -eq 0 ]]; then
        echo -e "  ${GREEN}PASS${NC} ${name} (${duration}s)"
        return 0
    elif [[ ${exit_code} -eq 2 ]]; then
        echo -e "  ${YELLOW}SKIP${NC} ${name} (${duration}s)"
        return 2
    else
        echo -e "  ${RED}FAIL${NC} ${name} (${duration}s, exit ${exit_code})"
        return 1
    fi
}

main() {
    local mode="all"
    local specific_test=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --fast)
                mode="fast"
                shift
                ;;
            --single)
                specific_test="single_package"
                shift
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS] [TEST_NAME]"
                echo ""
                echo "Options:"
                echo "  --fast      Run only fast tests (< 10 minutes)"
                echo "  --single    Run only single package test"
                echo "  --help      Show this help"
                echo ""
                echo "Available tests:"
                for test_def in "${ALL_TESTS[@]}"; do
                    local name="${test_def%%:*}"
                    local rest="${test_def#*:}"
                    local duration="${rest#*:}"
                    echo "  ${name} (~${duration}m)"
                done
                exit 0
                ;;
            *)
                specific_test="$1"
                shift
                ;;
        esac
    done

    log_header

    # Select test set
    local tests=()
    if [[ -n "${specific_test}" ]]; then
        for test_def in "${ALL_TESTS[@]}"; do
            local name="${test_def%%:*}"
            if [[ "${name}" == "${specific_test}" ]]; then
                tests+=("${test_def}")
                break
            fi
        done
        if [[ ${#tests[@]} -eq 0 ]]; then
            echo -e "${RED}ERROR${NC}: Unknown test '${specific_test}'"
            exit 1
        fi
    elif [[ "${mode}" == "fast" ]]; then
        tests=("${FAST_TESTS[@]}")
        echo "  Mode: FAST (tests < 10 minutes)"
    else
        tests=("${ALL_TESTS[@]}")
        echo "  Mode: ALL tests"
    fi

    echo "  Tests to run: ${#tests[@]}"
    echo ""
    echo -e "${BLUE}Running tests...${NC}"
    echo ""

    # Run tests
    local passed=0
    local failed=0
    local skipped=0
    local total_start
    total_start=$(date +%s)

    for test_def in "${tests[@]}"; do
        local name="${test_def%%:*}"
        local rest="${test_def#*:}"
        local script="${rest%%:*}"
        local duration="${rest#*:}"

        if run_test "${name}" "${script}" "${duration}"; then
            passed=$((passed + 1))
        else
            local exit_code=$?
            if [[ ${exit_code} -eq 2 ]]; then
                skipped=$((skipped + 1))
            else
                failed=$((failed + 1))
            fi
        fi
    done

    local total_end total_duration
    total_end=$(date +%s)
    total_duration=$((total_end - total_start))

    # Summary
    echo ""
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}  Summary${NC}"
    echo -e "${BLUE}========================================${NC}"
    echo ""
    echo "  Total tests: ${#tests[@]}"
    echo -e "  ${GREEN}Passed${NC}:  ${passed}"
    echo -e "  ${RED}Failed${NC}:  ${failed}"
    echo -e "  ${YELLOW}Skipped${NC}: ${skipped}"
    echo "  Duration: ${total_duration}s"
    echo ""

    # Write summary JSON
    local summary_file="/tmp/frankenlibc-e2e/e2e_summary.json"
    mkdir -p "$(dirname "${summary_file}")"
    cat > "${summary_file}" <<EOF
{
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "mode": "${mode}",
    "total_tests": ${#tests[@]},
    "passed": ${passed},
    "failed": ${failed},
    "skipped": ${skipped},
    "duration_seconds": ${total_duration}
}
EOF
    echo "  Summary written to: ${summary_file}"
    echo ""

    # Exit code
    if [[ ${failed} -gt 0 ]]; then
        echo -e "${RED}E2E TESTS FAILED${NC}"
        exit 1
    else
        echo -e "${GREEN}E2E TESTS PASSED${NC}"
        exit 0
    fi
}

main "$@"
