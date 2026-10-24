#!/usr/bin/env bash
# Build the clean-room C probes, then test host glibc or one explicit candidate DSO.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
    printf 'Usage: %s --host|/absolute/path/to/libfrankenlibc_abi.so [1|2|all]\n' "$0" >&2
    exit 2
fi
tests_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/frankenlibc-resolver-tests.XXXXXX")
printf 'Regression binaries/logs: %s\n' "$build_dir"
cc=${CC:-cc}
flags=(-std=c11 -O2 -g -Wall -Wextra -Werror -pthread)
if [[ ${SANITIZE:-0} == 1 ]]; then
    flags+=(-O1 -fsanitize=address,undefined -fno-omit-frame-pointer)
fi
case ${2:-all} in
    1) names=(native_reverse_ipv6) ;;
    2) names=(native_dns_cursor) ;;
    all) names=(native_reverse_ipv6 native_dns_cursor) ;;
    *) printf 'Batch must be 1, 2, or all\n' >&2; exit 2 ;;
esac
for name in "${names[@]}"; do
    "$cc" "${flags[@]}" "$tests_dir/$name.c" -ldl -o "$build_dir/$name"
    "$build_dir/$name" "$1" | tee "$build_dir/$name.log"
done
