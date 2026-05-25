#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$PROJECT_ROOT/target/debian-build"

echo "Building Debian package for frankenlibc..."

# Create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/lib/frankenlibc"

# Check for pre-built artifact in order of preference
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

ARTIFACT=$(find_artifact || echo "")

if [[ -z "$ARTIFACT" ]]; then
    echo "Building standalone artifact via rch..."
    cd "$PROJECT_ROOT"
    if command -v rch &>/dev/null; then
        rch exec -- cargo build --release --features standalone,owned-unwind-stub,owned-tls-cache \
            --manifest-path crates/frankenlibc-abi/Cargo.toml
    else
        cargo build --release --features standalone,owned-unwind-stub,owned-tls-cache \
            --manifest-path crates/frankenlibc-abi/Cargo.toml
    fi
    ARTIFACT=$(find_artifact || echo "")
fi

if [[ ! -f "$ARTIFACT" ]]; then
    echo "ERROR: Could not find standalone artifact"
    exit 1
fi

# Copy artifact
cp "$ARTIFACT" "$BUILD_DIR/usr/lib/frankenlibc/libfrankenlibc_replace.so"

# Verify no glibc dependencies
echo "Verifying no glibc dependencies..."
if nm -u "$BUILD_DIR/usr/lib/frankenlibc/libfrankenlibc_replace.so" 2>/dev/null | grep -q "GLIBC"; then
    echo "ERROR: Artifact has GLIBC dependencies"
    exit 1
fi

# Create control file
cat > "$BUILD_DIR/DEBIAN/control" << 'EOF'
Package: libfrankenlibc
Version: 0.1.0-1
Section: libs
Priority: optional
Architecture: amd64
Maintainer: FrankenLibC Maintainers <noreply@example.com>
Description: Standalone glibc replacement library
 FrankenLibC is a standalone glibc-compatible library that provides
 libc functionality without depending on host glibc.
EOF

# Build the package
DEB_FILE="$PROJECT_ROOT/target/libfrankenlibc_0.1.0-1_amd64.deb"
dpkg-deb --build "$BUILD_DIR" "$DEB_FILE"

echo "Package built: $DEB_FILE"

# Verify package
echo "Verifying package..."
dpkg-deb --info "$DEB_FILE"
dpkg-deb --contents "$DEB_FILE"

echo "SUCCESS: Debian package built and verified"
