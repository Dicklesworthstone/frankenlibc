#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building frankenlibc for aarch64-unknown-linux-gnu..."

# Check for cross-compiler
if ! command -v aarch64-linux-gnu-gcc &>/dev/null; then
    echo "ERROR: aarch64-linux-gnu-gcc not found"
    echo "Install with: sudo apt install gcc-aarch64-linux-gnu"
    exit 1
fi

# Set up cross-compilation environment
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc

cd "$PROJECT_ROOT"

# Build for aarch64
echo "Building standalone artifact..."
if command -v rch &>/dev/null; then
    rch exec -- cargo build \
        --target aarch64-unknown-linux-gnu \
        --release \
        --features standalone,owned-unwind-stub,owned-tls-cache \
        --manifest-path crates/frankenlibc-abi/Cargo.toml
else
    cargo build \
        --target aarch64-unknown-linux-gnu \
        --release \
        --features standalone,owned-unwind-stub,owned-tls-cache \
        --manifest-path crates/frankenlibc-abi/Cargo.toml
fi

ARTIFACT="$PROJECT_ROOT/target/aarch64-unknown-linux-gnu/release/libfrankenlibc_abi.so"
if [[ ! -f "$ARTIFACT" ]]; then
    echo "ERROR: aarch64 artifact not built"
    exit 1
fi

echo ""
echo "SUCCESS: aarch64 artifact built"
echo "  Artifact: $ARTIFACT"
echo "  Size: $(du -h "$ARTIFACT" | cut -f1)"

# Verify it's actually aarch64
FILE_TYPE=$(file "$ARTIFACT")
if ! echo "$FILE_TYPE" | grep -q "ARM aarch64"; then
    echo "WARNING: Artifact may not be aarch64:"
    echo "  $FILE_TYPE"
fi

# Check for undefined GLIBC symbols
if nm -u "$ARTIFACT" 2>/dev/null | grep -q "GLIBC"; then
    echo "WARNING: Artifact has undefined GLIBC symbols"
    nm -u "$ARTIFACT" 2>/dev/null | grep "GLIBC" | head -5
fi

echo ""
echo "To run smoke tests on aarch64 hardware or qemu-aarch64:"
echo "  qemu-aarch64 -L /usr/aarch64-linux-gnu ./test_binary"
