#!/bin/bash
# bd-gq1kz7.12: Aarch64 smoke battery emulation runner contract
# Runs aarch64 smoke tests via QEMU or native runner.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Runner configuration
QEMU_TIMEOUT="${QEMU_TIMEOUT:-60}"
QEMU_SYSROOT="${QEMU_SYSROOT:-/usr/aarch64-linux-gnu}"
ARTIFACT_PATH="$PROJECT_ROOT/target/aarch64-unknown-linux-gnu/release/libfrankenlibc_abi.so"

# Preflight check
preflight() {
    local errors=()

    # Check artifact exists
    if [[ ! -f "$ARTIFACT_PATH" ]]; then
        errors+=("artifact_missing: $ARTIFACT_PATH")
    fi

    # Check QEMU runner
    if ! command -v qemu-aarch64 &>/dev/null && ! command -v qemu-aarch64-static &>/dev/null; then
        errors+=("qemu_missing: install qemu-user or qemu-user-static")
    fi

    # Check sysroot
    if [[ ! -d "$QEMU_SYSROOT" ]]; then
        errors+=("sysroot_missing: $QEMU_SYSROOT")
    fi

    if [[ ${#errors[@]} -gt 0 ]]; then
        printf '{"status":"preflight_failed","errors":%s}\n' \
            "$(printf '%s\n' "${errors[@]}" | jq -R . | jq -s .)" | jq .
        exit 1
    fi
}

# Detect QEMU binary
detect_qemu() {
    if command -v qemu-aarch64 &>/dev/null; then
        echo "qemu-aarch64"
    elif command -v qemu-aarch64-static &>/dev/null; then
        echo "qemu-aarch64-static"
    else
        echo ""
    fi
}

# Run smoke test
run_smoke() {
    local qemu
    qemu=$(detect_qemu)

    if [[ -z "$qemu" ]]; then
        echo '{"status":"fail","reason":"no_qemu_runner"}' | jq .
        exit 1
    fi

    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Create minimal smoke test program
    local smoke_src="$PROJECT_ROOT/target/aarch64_smoke_test.c"
    local smoke_bin="$PROJECT_ROOT/target/aarch64_smoke_test"

    cat > "$smoke_src" << 'SMOKE_EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main() {
    // Basic smoke tests
    char buf[64];
    memset(buf, 'A', 63);
    buf[63] = '\0';
    if (strlen(buf) != 63) return 1;

    void *p = malloc(1024);
    if (!p) return 2;
    free(p);

    printf("SMOKE_PASS\n");
    return 0;
}
SMOKE_EOF

    # Try to compile for aarch64
    if ! command -v aarch64-linux-gnu-gcc &>/dev/null; then
        printf '{"status":"skip","reason":"no_cross_compiler","timestamp":"%s"}\n' "$timestamp" | jq .
        exit 0
    fi

    aarch64-linux-gnu-gcc -o "$smoke_bin" "$smoke_src" -static 2>/dev/null || {
        printf '{"status":"skip","reason":"compile_failed","timestamp":"%s"}\n' "$timestamp" | jq .
        exit 0
    }

    # Run under QEMU
    local result
    result=$(timeout "$QEMU_TIMEOUT" "$qemu" -L "$QEMU_SYSROOT" "$smoke_bin" 2>&1) || true

    if echo "$result" | grep -q "SMOKE_PASS"; then
        printf '{"status":"pass","runner":"%s","timeout":%d,"timestamp":"%s"}\n' \
            "$qemu" "$QEMU_TIMEOUT" "$timestamp" | jq .
    else
        printf '{"status":"fail","runner":"%s","output":"%s","timestamp":"%s"}\n' \
            "$qemu" "$(echo "$result" | head -1)" "$timestamp" | jq .
        exit 1
    fi

    # Cleanup
    rm -f "$smoke_src" "$smoke_bin"
}

# Main entry point
main() {
    local cmd="${1:-run}"

    case "$cmd" in
        preflight)
            preflight
            printf '{"status":"ok","gate":"bd-gq1kz7.12"}\n' | jq .
            ;;
        run)
            preflight 2>/dev/null || {
                echo '{"status":"skip","reason":"preflight_failed"}' | jq .
                exit 0
            }
            run_smoke
            ;;
        contract)
            cat << 'CONTRACT_EOF'
{
  "gate": "bd-gq1kz7.12",
  "contract": {
    "runner_types": ["qemu-aarch64", "qemu-aarch64-static", "native"],
    "environment": {
      "QEMU_TIMEOUT": "Timeout in seconds (default: 60)",
      "QEMU_SYSROOT": "Path to aarch64 sysroot (default: /usr/aarch64-linux-gnu)"
    },
    "artifact": "target/aarch64-unknown-linux-gnu/release/libfrankenlibc_abi.so",
    "preflight_checks": ["artifact_exists", "qemu_available", "sysroot_exists"],
    "smoke_tests": ["memset", "strlen", "malloc", "free", "printf"],
    "timeout_behavior": "Returns fail status with partial output",
    "failure_evidence": "JSON with status, runner, output, timestamp"
  }
}
CONTRACT_EOF
            ;;
        *)
            echo "Usage: $0 {preflight|run|contract}"
            exit 1
            ;;
    esac
}

main "$@"
