#!/bin/bash
# bd-gq1kz7.10: Zero-host-reference nm/readelf gate preflight
# Fail-closed scanner for standalone artifacts that reports residual host-glibc symbol references.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Find standalone artifact
find_artifact() {
    local paths=(
        "$PROJECT_ROOT/target/standalone_replacement_artifact/cargo-target/release/libfrankenlibc_replace.so"
        "$PROJECT_ROOT/target/release/libfrankenlibc_abi.so"
        "$PROJECT_ROOT/target/release/deps/libfrankenlibc_abi.so"
    )
    for p in "${paths[@]}"; do
        if [[ -f "$p" ]] && [[ -s "$p" ]]; then
            echo "$p"
            return 0
        fi
    done
    return 1
}

# Allowed undefined symbols (kernel ABI, compiler features - not glibc)
ALLOWED_PATTERNS=(
    "^__kernel_"           # vDSO kernel symbols
    "^__vdso_"             # vDSO symbols
    "^SYS_"                # syscall numbers (shouldn't appear, but safe)
    "^_DYNAMIC$"           # ELF dynamic section
    "^_GLOBAL_OFFSET_TABLE_$"  # GOT
    "^__tls_get_addr$"     # TLS (may need host, but categorize separately)
    "^__stack_chk_fail$"   # Stack protector (compiler builtin)
    "^__stack_chk_guard$"  # Stack protector guard
    "^_ITM_"               # Intel Transactional Memory (compiler feature)
    "^__gmon_start__$"     # gprof profiling hook (optional)
    "^_Unwind_"            # libgcc_s/compiler-rt unwinder (not glibc)
)

# Disallowed patterns (explicit glibc dependencies)
DISALLOWED_PATTERNS=(
    "@GLIBC_"              # Versioned glibc symbols
    "^__libc_"             # Internal libc symbols
    "^__GI_"               # glibc internal aliases
    "^_IO_"                # stdio internals
    "^__pthread_"          # pthread internals not owned
)

classify_symbol() {
    local sym="$1"

    # Check allowed patterns first
    for pat in "${ALLOWED_PATTERNS[@]}"; do
        if [[ "$sym" =~ $pat ]]; then
            echo "allowed_kernel"
            return
        fi
    done

    # Check explicit disallowed patterns
    for pat in "${DISALLOWED_PATTERNS[@]}"; do
        if [[ "$sym" =~ $pat ]]; then
            echo "disallowed_glibc"
            return
        fi
    done

    # Default: unknown (needs investigation)
    echo "unknown"
}

main() {
    local artifact
    artifact=$(find_artifact) || {
        echo '{"status":"error","message":"no standalone artifact found","artifacts_checked":["target/standalone_replacement_artifact/cargo-target/release/libfrankenlibc_replace.so","target/release/libfrankenlibc_abi.so"]}'
        exit 1
    }

    local undefined_syms
    undefined_syms=$(nm -u "$artifact" 2>/dev/null | awk '{print $NF}' | sort -u)

    local allowed_count=0
    local disallowed_count=0
    local unknown_count=0
    local disallowed_list=()
    local unknown_list=()

    while IFS= read -r sym; do
        [[ -z "$sym" ]] && continue
        local class
        class=$(classify_symbol "$sym")
        case "$class" in
            allowed_kernel)
                ((allowed_count++)) || true
                ;;
            disallowed_glibc)
                ((disallowed_count++)) || true
                disallowed_list+=("$sym")
                ;;
            unknown)
                ((unknown_count++)) || true
                unknown_list+=("$sym")
                ;;
        esac
    done <<< "$undefined_syms"

    local pass="true"
    if [[ $disallowed_count -gt 0 ]]; then
        pass="false"
    fi

    # Emit JSON
    local disallowed_json
    if [[ ${#disallowed_list[@]} -eq 0 ]]; then
        disallowed_json="[]"
    else
        disallowed_json=$(printf '%s\n' "${disallowed_list[@]}" | jq -R . | jq -s .)
    fi

    local unknown_json
    if [[ ${#unknown_list[@]} -eq 0 ]]; then
        unknown_json="[]"
    else
        unknown_json=$(printf '%s\n' "${unknown_list[@]}" | jq -R . | jq -s .)
    fi

    cat <<EOF
{
  "status": "$([ "$pass" = "true" ] && echo "pass" || echo "fail")",
  "artifact": "$artifact",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "summary": {
    "allowed_kernel_symbols": $allowed_count,
    "disallowed_glibc_symbols": $disallowed_count,
    "unknown_symbols": $unknown_count
  },
  "disallowed": $disallowed_json,
  "unknown": $unknown_json,
  "gate": "bd-gq1kz7.10"
}
EOF

    if [[ "$pass" = "false" ]]; then
        exit 1
    fi
}

main "$@"
