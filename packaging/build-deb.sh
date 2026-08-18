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

# The ONLY acceptable artifact is the standalone replacement object.
#
# This used to accept three paths in "order of preference", the second and third
# being target/release/libfrankenlibc_abi.so and .../deps/. Those are the
# ORDINARY object — what `cargo build --release -p frankenlibc-abi` produces —
# and it is NOT the deployed configuration: build.rs applies
# version_scripts/libc.map only when standalone + owned-unwind-stub are on and
# debug_assertions are off. So on any machine that had ever run a plain release
# build, this script found that object, copied it to
# libfrankenlibc_replace.so, and packaged a NON-standalone library with no
# version script under the replacement's name, reporting SUCCESS.
#
# That is why the broken build command in this script went unnoticed: the build
# only ran when nothing was found, and something was almost always found.
# bd-haor6r.
STANDALONE_ARTIFACT="$PROJECT_ROOT/target/standalone_replacement_artifact/cargo-target/release/libfrankenlibc_replace.so"

find_artifact() {
    if [[ -f "$STANDALONE_ARTIFACT" ]] && [[ -s "$STANDALONE_ARTIFACT" ]]; then
        echo "$STANDALONE_ARTIFACT"
        return 0
    fi
    return 1
}

ARTIFACT=$(find_artifact || echo "")

if [[ -z "$ARTIFACT" ]]; then
    echo "No standalone artifact found; building it."
    cd "$PROJECT_ROOT"
    # NO `|| true`, and no fallback to a different object: if this fails the
    # script must stop. `set -e` is in force, and the standalone policy gate in
    # build.rs currently exits 1 from a clean tree (1154 interpose-only symbols
    # in support_matrix.json, plus host call-through sites). That failure is
    # REAL and packaging must surface it rather than route around it.
    if command -v rch &>/dev/null; then
        rch exec -- cargo build --release --features standalone,owned-unwind-stub,owned-tls-cache \
            --manifest-path crates/frankenlibc-abi/Cargo.toml
    else
        cargo build --release --features standalone,owned-unwind-stub,owned-tls-cache \
            --manifest-path crates/frankenlibc-abi/Cargo.toml
    fi
    ARTIFACT=$(find_artifact || echo "")
fi

if [[ -z "$ARTIFACT" ]] || [[ ! -f "$ARTIFACT" ]]; then
    echo "ERROR: no standalone artifact at $STANDALONE_ARTIFACT" >&2
    echo "       The build above either failed or produced a different object." >&2
    echo "       This script will NOT package target/release/libfrankenlibc_abi.so" >&2
    echo "       in its place: that object is built without the version script" >&2
    echo "       and is not the deployed configuration (bd-haor6r)." >&2
    exit 1
fi

echo "Using standalone artifact: $ARTIFACT"

# Copy artifact
cp "$ARTIFACT" "$BUILD_DIR/usr/lib/frankenlibc/libfrankenlibc_replace.so"

# Verify no glibc dependencies.
#
# This check FAILS CLOSED. It used to be `nm -u ... 2>/dev/null | grep -q GLIBC`,
# which reports "no glibc dependencies" in three cases: the artifact genuinely
# has none, nm could not read the file at all, and nm is not installed. Two of
# those three are the check being broken, and its own error output was sent to
# /dev/null so nobody would see which. bd-haor6r.
echo "Verifying no glibc dependencies..."
PACKAGED_SO="$BUILD_DIR/usr/lib/frankenlibc/libfrankenlibc_replace.so"
if ! command -v nm &>/dev/null; then
    echo "ERROR: nm is not available, so the glibc-dependency check cannot run." >&2
    echo "       Refusing to package an unverified artifact." >&2
    exit 1
fi
if ! NM_OUTPUT=$(nm -u "$PACKAGED_SO" 2>&1); then
    echo "ERROR: nm could not read $PACKAGED_SO:" >&2
    echo "$NM_OUTPUT" >&2
    exit 1
fi
if grep -q "GLIBC" <<<"$NM_OUTPUT"; then
    echo "ERROR: Artifact has GLIBC dependencies" >&2
    grep "GLIBC" <<<"$NM_OUTPUT" | head -20 >&2
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
