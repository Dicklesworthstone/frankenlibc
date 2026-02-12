#!/usr/bin/env bash
# Compare ABI symbols between our libc.so and host libc.
set -euo pipefail

OUR_LIB="${1:-target/release/libfrankenlibc_abi.so}"
HOST_LIB="${2:-/usr/lib/x86_64-linux-gnu/libc.so.6}"

if [ ! -f "${OUR_LIB}" ]; then
    echo "ERROR: Our library not found at ${OUR_LIB}"
    echo "Build with: cargo build --release -p frankenlibc-abi"
    exit 1
fi

echo "=== ABI Comparison ==="
echo "Our:  ${OUR_LIB}"
echo "Host: ${HOST_LIB}"
echo ""

# Extract our symbols
our_syms=$(nm -D --defined-only "${OUR_LIB}" 2>/dev/null | awk '{print $NF}' | sort)
our_count=$(echo "${our_syms}" | wc -l)

# Extract host symbols
host_syms=$(nm -D --defined-only "${HOST_LIB}" 2>/dev/null | awk '{print $NF}' | sort)
host_count=$(echo "${host_syms}" | wc -l)

echo "Our symbols:  ${our_count}"
echo "Host symbols: ${host_count}"
echo ""

# Find symbols we export that host also has
common=$(comm -12 <(echo "${our_syms}") <(echo "${host_syms}"))
common_count=$(echo "${common}" | grep -c . || true)
echo "Common symbols: ${common_count}"

# Find symbols we're missing
missing=$(comm -23 <(echo "${host_syms}") <(echo "${our_syms}"))
missing_count=$(echo "${missing}" | grep -c . || true)
echo "Missing from ours: ${missing_count}"

echo ""
echo "=== Coverage: ${common_count}/${host_count} ==="
