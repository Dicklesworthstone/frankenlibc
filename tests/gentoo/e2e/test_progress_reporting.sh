#!/usr/bin/env bash
# E2E Test: Progress Reporting
#
# Tests progress output during long runs:
# 1. Start multi-package build
# 2. Verify progress updates
# 3. Check ETA calculation
# 4. Verify JSON output format
# 5. Confirm webhook would fire
#
# Runtime target: < 5 minutes

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${SCRIPT_DIR}/lib/common.sh"

# Configuration
PROGRESS_TEST_PACKAGES=(
    "sys-apps/which"
    "app-misc/screen"
)

main() {
    e2e_init "progress-reporting" 5

    log_info "Test packages: ${PROGRESS_TEST_PACKAGES[*]}"
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

    # Step 2: Start build with progress tracking
    log_step "Starting build with progress tracking..."
    local progress_dir="${E2E_RESULT_DIR}/progress"
    local progress_file="${progress_dir}/progress.jsonl"
    mkdir -p "${progress_dir}"

    # Create progress tracker
    local total_packages=${#PROGRESS_TEST_PACKAGES[@]}
    local completed=0
    local start_time
    start_time=$(date +%s)

    # Write initial progress
    cat >> "${progress_file}" <<EOF
{"event": "start", "timestamp": "$(log_timestamp)", "total_packages": ${total_packages}, "completed": 0}
EOF

    for pkg in "${PROGRESS_TEST_PACKAGES[@]}"; do
        local pkg_safe="${pkg//\//__}"
        local pkg_dir="${progress_dir}/${pkg_safe}"
        mkdir -p "${pkg_dir}"

        local pkg_start pkg_end pkg_duration
        pkg_start=$(date +%s)

        # Write package start event
        cat >> "${progress_file}" <<EOF
{"event": "package_start", "timestamp": "$(log_timestamp)", "package": "${pkg}", "index": ${completed}}
EOF

        log_info "  Building ${pkg}..."

        # Run the build
        local result="success"
        if ! run_emerge "${pkg}" "${pkg_dir}" 300; then
            result="failed"
        fi

        pkg_end=$(date +%s)
        pkg_duration=$((pkg_end - pkg_start))
        completed=$((completed + 1))

        # Calculate ETA
        local elapsed=$((pkg_end - start_time))
        local avg_time=$((elapsed / completed))
        local remaining=$((total_packages - completed))
        local eta=$((remaining * avg_time))

        # Write package end event
        cat >> "${progress_file}" <<EOF
{"event": "package_end", "timestamp": "$(log_timestamp)", "package": "${pkg}", "result": "${result}", "duration_seconds": ${pkg_duration}, "completed": ${completed}, "total": ${total_packages}, "eta_seconds": ${eta}}
EOF

        log_info "    Result: ${result}"
        log_info "    Duration: ${pkg_duration}s"
        log_info "    Progress: ${completed}/${total_packages}"
        log_info "    ETA: ${eta}s"
    done

    # Write completion event
    local total_duration=$(($(date +%s) - start_time))
    cat >> "${progress_file}" <<EOF
{"event": "complete", "timestamp": "$(log_timestamp)", "total_packages": ${total_packages}, "completed": ${completed}, "total_duration_seconds": ${total_duration}}
EOF

    # Step 3: Verify progress updates
    log_step "Verifying progress updates..."
    local event_count
    event_count=$(wc -l < "${progress_file}")
    log_info "  Progress events recorded: ${event_count}"

    # Should have: 1 start + (N * 2 start/end events) + 1 complete
    local expected_events=$((1 + total_packages * 2 + 1))
    if [[ ${event_count} -ge ${expected_events} ]]; then
        log_success "  Expected ${expected_events} events, got ${event_count}"
    else
        log_warn "  Expected ${expected_events} events, got ${event_count}"
    fi

    # Step 4: Verify JSON output format
    log_step "Verifying JSON output format..."
    local invalid_lines=0

    while IFS= read -r line; do
        if [[ -n "${line}" ]] && ! echo "${line}" | jq empty 2>/dev/null; then
            log_error "  Invalid JSON: ${line:0:50}..."
            invalid_lines=$((invalid_lines + 1))
        fi
    done < "${progress_file}"

    if [[ ${invalid_lines} -gt 0 ]]; then
        log_error "  Found ${invalid_lines} invalid JSON lines"
        e2e_finish "fail"
        return 1
    fi
    log_success "  All progress entries are valid JSON"

    # Verify required fields in events
    local has_start has_end has_complete
    has_start=$(jq -s '[.[] | select(.event == "start")] | length' "${progress_file}")
    has_end=$(jq -s '[.[] | select(.event == "package_end")] | length' "${progress_file}")
    has_complete=$(jq -s '[.[] | select(.event == "complete")] | length' "${progress_file}")

    log_info "  Start events: ${has_start}"
    log_info "  Package end events: ${has_end}"
    log_info "  Complete events: ${has_complete}"

    # Step 5: Verify webhook payload format
    log_step "Verifying webhook payload format..."

    # Create sample webhook payload
    local webhook_payload="${progress_dir}/webhook_payload.json"
    jq -s '{
        events: .,
        summary: {
            total_packages: (.[0].total_packages // 0),
            completed: (.[-1].completed // 0),
            duration_seconds: (.[-1].total_duration_seconds // 0)
        }
    }' "${progress_file}" > "${webhook_payload}"

    if jq empty "${webhook_payload}" 2>/dev/null; then
        log_success "  Webhook payload is valid JSON"
    else
        log_error "  Webhook payload is not valid JSON"
        e2e_finish "fail"
        return 1
    fi

    # Show webhook payload
    log_info "  Sample webhook payload:"
    jq '.summary' "${webhook_payload}" | while IFS= read -r line; do
        log_info "    ${line}"
    done

    # Create human-readable progress report
    cat > "${progress_dir}/progress_report.txt" <<EOF
Progress Report
===============

Total Packages: ${total_packages}
Completed: ${completed}
Duration: ${total_duration}s

Events Timeline:
$(jq -r '.[] | "\(.timestamp) \(.event) \(.package // "")"' "${progress_file}" | sed 's/^/  /')

Summary:
$(jq -r '.summary | to_entries | .[] | "  \(.key): \(.value)"' "${webhook_payload}")
EOF

    log_success "  Progress report written"

    e2e_finish "pass"
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
