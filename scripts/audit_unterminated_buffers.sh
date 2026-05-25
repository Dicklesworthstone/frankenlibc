#!/bin/bash
# bd-gq1kz7.6: Cross-family tracked unterminated-buffer sweep
# Audits tests and ABI helpers for tracked C-string/buffer handling.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Families to audit
FAMILIES=(
    "dlfcn"
    "libgen"
    "search"
    "string"
    "startup"
)

# Patterns indicating tracked buffer handling
TRACKED_PATTERNS=(
    "scan_c_string"
    "bounded_c_string"
    "tracked_allocation"
    "TrackedAllocation"
    "c_str_to_slice"
    "CStr::from_ptr"
    "strlen"
    "strnlen"
    "NUL.terminated"
    "unterminated"
)

# Patterns indicating skip/expected failure
SKIP_PATTERNS=(
    "#\\[ignore"
    "skip"
    "SKIP"
    "expected.failure"
    "known.issue"
    "TODO"
    "FIXME"
)

audit_family() {
    local family="$1"
    local files found_tracked=0 found_skips=0

    # Find relevant files
    files=$(find "$PROJECT_ROOT/crates" -name "*.rs" -type f | xargs grep -l "$family" 2>/dev/null || true)

    for file in $files; do
        # Check for tracked buffer patterns
        for pat in "${TRACKED_PATTERNS[@]}"; do
            if grep -q "$pat" "$file" 2>/dev/null; then
                ((found_tracked++)) || true
            fi
        done

        # Check for skip patterns
        for pat in "${SKIP_PATTERNS[@]}"; do
            if grep -q "$pat" "$file" 2>/dev/null; then
                ((found_skips++)) || true
            fi
        done
    done

    echo "{\"family\": \"$family\", \"tracked_patterns\": $found_tracked, \"skip_patterns\": $found_skips}"
}

generate_report() {
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Find all files with unterminated buffer handling
    local unterminated_files
    unterminated_files=$(
        { grep -r -E "unterminated|NUL.*terminated" "$PROJECT_ROOT/crates" --include="*.rs" -l 2>/dev/null || true; } |
            wc -l |
            tr -d '[:space:]'
    )

    # Find all skipped tests related to buffers
    local skipped_buffer_tests
    skipped_buffer_tests=$(
        { grep -r "#\[ignore\]" "$PROJECT_ROOT/crates" --include="*.rs" -A5 2>/dev/null || true; } |
            grep -Ec "buffer|string|c_str" ||
            true
    )

    # Audit each family
    local family_results=""
    for family in "${FAMILIES[@]}"; do
        result=$(audit_family "$family")
        if [[ -n "$family_results" ]]; then
            family_results="$family_results, $result"
        else
            family_results="$result"
        fi
    done

    # Check for specific unsupported contracts
    local unsupported_contracts
    unsupported_contracts=$(grep -r "unsupported\|not.supported" "$PROJECT_ROOT/crates" --include="*.rs" -c 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}')

    local status="pass"
    [[ $skipped_buffer_tests -gt 0 ]] && status="needs_review"

    cat <<EOF
{
  "status": "$status",
  "timestamp": "$timestamp",
  "gate": "bd-gq1kz7.6",
  "summary": {
    "files_with_unterminated_handling": $unterminated_files,
    "skipped_buffer_tests": $skipped_buffer_tests,
    "unsupported_contract_mentions": $unsupported_contracts
  },
  "families": [$family_results],
  "recommendation": "Review files with unterminated buffer handling to ensure strict/hardened behavior is intentional"
}
EOF
}

generate_report | jq .
