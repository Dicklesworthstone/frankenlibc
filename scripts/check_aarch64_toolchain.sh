#!/bin/bash
# bd-gq1kz7.11: Aarch64 runtime artifact toolchain preflight
# Distinguishes missing prerequisites for aarch64 cross-compilation.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

check_gcc() {
    if command -v aarch64-linux-gnu-gcc &>/dev/null; then
        local version
        version=$(aarch64-linux-gnu-gcc --version 2>/dev/null | head -1)
        echo "{\"available\": true, \"version\": \"$version\"}"
    else
        echo "{\"available\": false, \"install_hint\": \"sudo apt install gcc-aarch64-linux-gnu\"}"
    fi
}

check_rust_target() {
    if rustup target list --installed 2>/dev/null | grep -q "aarch64-unknown-linux-gnu"; then
        echo "{\"available\": true}"
    else
        echo "{\"available\": false, \"install_hint\": \"rustup target add aarch64-unknown-linux-gnu\"}"
    fi
}

check_sysroot() {
    local sysroot="/usr/aarch64-linux-gnu"
    if [[ -d "$sysroot" ]] && [[ -f "$sysroot/lib/libc.so.6" || -f "$sysroot/lib/libc.so" ]]; then
        echo "{\"available\": true, \"path\": \"$sysroot\"}"
    else
        echo "{\"available\": false, \"path\": \"$sysroot\", \"install_hint\": \"sudo apt install libc6-dev-arm64-cross\"}"
    fi
}

check_linker() {
    if command -v aarch64-linux-gnu-ld &>/dev/null; then
        echo "{\"available\": true}"
    else
        echo "{\"available\": false, \"install_hint\": \"sudo apt install binutils-aarch64-linux-gnu\"}"
    fi
}

check_qemu() {
    if command -v qemu-aarch64 &>/dev/null; then
        local version
        version=$(qemu-aarch64 --version 2>/dev/null | head -1)
        echo "{\"available\": true, \"version\": \"$version\"}"
    elif command -v qemu-aarch64-static &>/dev/null; then
        local version
        version=$(qemu-aarch64-static --version 2>/dev/null | head -1)
        echo "{\"available\": true, \"binary\": \"qemu-aarch64-static\", \"version\": \"$version\"}"
    else
        echo "{\"available\": false, \"install_hint\": \"sudo apt install qemu-user qemu-user-static\"}"
    fi
}

check_artifact() {
    local artifact="$PROJECT_ROOT/target/aarch64-unknown-linux-gnu/release/libfrankenlibc_abi.so"
    if [[ -f "$artifact" ]]; then
        local file_type
        file_type=$(file "$artifact" 2>/dev/null | grep -o "ARM aarch64" || echo "unknown")
        echo "{\"available\": true, \"path\": \"$artifact\", \"arch\": \"$file_type\"}"
    else
        echo "{\"available\": false, \"expected_path\": \"$artifact\"}"
    fi
}

generate_report() {
    local timestamp
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    local gcc_result linker_result rust_result sysroot_result qemu_result artifact_result
    gcc_result=$(check_gcc)
    linker_result=$(check_linker)
    rust_result=$(check_rust_target)
    sysroot_result=$(check_sysroot)
    qemu_result=$(check_qemu)
    artifact_result=$(check_artifact)

    # Determine overall status
    local all_prereqs_met="true"
    local missing_prereqs=()

    if ! echo "$gcc_result" | jq -e '.available' &>/dev/null; then
        all_prereqs_met="false"
        missing_prereqs+=("gcc-aarch64-linux-gnu")
    fi
    if ! echo "$linker_result" | jq -e '.available' &>/dev/null; then
        all_prereqs_met="false"
        missing_prereqs+=("binutils-aarch64-linux-gnu")
    fi
    if ! echo "$rust_result" | jq -e '.available' &>/dev/null; then
        all_prereqs_met="false"
        missing_prereqs+=("rustup-target-aarch64")
    fi
    if ! echo "$sysroot_result" | jq -e '.available' &>/dev/null; then
        all_prereqs_met="false"
        missing_prereqs+=("aarch64-sysroot")
    fi

    local missing_json
    missing_json=$(printf '%s\n' "${missing_prereqs[@]}" 2>/dev/null | jq -R . | jq -s . 2>/dev/null || echo "[]")

    cat <<EOF
{
  "status": "$([ "$all_prereqs_met" = "true" ] && echo "ready" || echo "blocked")",
  "timestamp": "$timestamp",
  "gate": "bd-gq1kz7.11",
  "prerequisites": {
    "gcc": $gcc_result,
    "linker": $linker_result,
    "rust_target": $rust_result,
    "sysroot": $sysroot_result,
    "qemu_runner": $qemu_result
  },
  "artifact": $artifact_result,
  "missing": $missing_json,
  "blocker_for": "bd-38x82.2"
}
EOF
}

generate_report | jq .
