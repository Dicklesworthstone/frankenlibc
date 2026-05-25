#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DEB_FILE="$PROJECT_ROOT/target/libfrankenlibc_0.1.0-1_amd64.deb"

if [[ ! -f "$DEB_FILE" ]]; then
    echo "ERROR: Package not found at $DEB_FILE"
    echo "Run ./build-deb.sh first"
    exit 1
fi

# Create a temporary installation prefix
TEST_PREFIX=$(mktemp -d)
trap "rm -rf $TEST_PREFIX" EXIT

echo "Testing package installation to $TEST_PREFIX..."

# Extract package to test prefix
dpkg-deb -x "$DEB_FILE" "$TEST_PREFIX"

# Verify files are installed
INSTALLED_LIB="$TEST_PREFIX/usr/lib/frankenlibc/libfrankenlibc_replace.so"
if [[ ! -f "$INSTALLED_LIB" ]]; then
    echo "ERROR: Library not installed at expected path"
    exit 1
fi

echo "Library installed at: $INSTALLED_LIB"

# Verify library properties
echo "Checking library properties..."

# Check for undefined GLIBC symbols
GLIBC_SYMS=$(nm -u "$INSTALLED_LIB" 2>/dev/null | grep "GLIBC" || true)
if [[ -n "$GLIBC_SYMS" ]]; then
    echo "ERROR: Library has undefined GLIBC symbols:"
    echo "$GLIBC_SYMS"
    exit 1
fi
echo "  - No undefined GLIBC symbols"

# Check for NEEDED host libraries
NEEDED=$(readelf -d "$INSTALLED_LIB" 2>/dev/null | grep "NEEDED" || true)
if echo "$NEEDED" | grep -qE "lib(c|pthread|dl)\.so"; then
    echo "ERROR: Library has NEEDED host libc dependencies:"
    echo "$NEEDED"
    exit 1
fi
echo "  - No NEEDED host libc dependencies"

# Check library is executable
if [[ ! -x "$INSTALLED_LIB" ]] && [[ ! -r "$INSTALLED_LIB" ]]; then
    echo "WARNING: Library may not have correct permissions"
fi

# Count exported symbols
EXPORT_COUNT=$(nm -D "$INSTALLED_LIB" 2>/dev/null | grep -c " T " || echo "0")
echo "  - $EXPORT_COUNT exported symbols"

if [[ "$EXPORT_COUNT" -lt 1000 ]]; then
    echo "WARNING: Expected 1000+ exported symbols, got $EXPORT_COUNT"
fi

echo ""
echo "SUCCESS: Package installation test passed"
echo "  Package: $DEB_FILE"
echo "  Library: $INSTALLED_LIB"
echo "  Size: $(du -h "$INSTALLED_LIB" | cut -f1)"
