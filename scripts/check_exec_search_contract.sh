#!/usr/bin/env bash
# Host oracle plus the actual public ABI under strict/hardened interposition.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${EXEC_CONTRACT_BUILD_DIR:-"$root/target/exec-search-contract"}
mkdir -p -- "$output"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 \
    "$root/tests/c_abi/exec_search_contract.c" -o "$output/probe"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 -fno-builtin \
    -DFRANKENLIBC_ASYNC_ALLOCATOR_PROBE -Wl,-z,now \
    "$root/tests/c_abi/exec_search_contract.c" -ldl -o "$output/async-probe"

check_async_process() {
    local label=$1
    shift
    local status context operation expected count=0
    # Prove the application allocator detects reentry instead of silently
    # passing a test that never armed the observer.
    status=0
    timeout 15 env -u LD_PRELOAD "$@" "$output/async-probe" a direct || status=$?
    if [[ $status -ne 91 ]]; then
        printf 'FAIL: %s allocator control returned %s, expected 91\n' "$label" "$status" >&2
        return 1
    fi
    for context in direct signal; do
        for operation in x X e f; do
            expected=43
            if [[ $operation == e ]]; then expected=0; fi
            status=0
            timeout 15 env -u LD_PRELOAD "$@" "$output/async-probe" \
                "$operation" "$context" || status=$?
            if [[ $status -ne $expected ]]; then
                printf 'FAIL: %s async process %s/%s returned %s, expected %s\n' \
                    "$label" "$context" "$operation" "$status" "$expected" >&2
                return 1
            fi
            count=$((count + 1))
        done
    done
    printf 'ASYNC PROCESS: %s %s cases and allocator negative control passed\n' "$label" "$count"
}

printf '\n== host libc reference ==\n'
env -u LD_PRELOAD "$output/probe" | tee "$output/host.log"
check_async_process host | tee "$output/async-host.log"
if [[ $# -eq 0 ]]; then
    printf '\nHost reference only; pass the rebuilt ABI library to exercise frankenlibc.\n'
    exit 0
fi
if [[ $# -ne 1 ]]; then printf 'Usage: bash %s [path/to/libfrankenlibc_abi.so]\n' "$0" >&2; exit 2; fi
library=$(realpath -- "$1")
if [[ ! -f $library ]]; then printf 'Library not found: %s\n' "$library" >&2; exit 2; fi
# The same symbol-ownership check must reject a host-only invocation.
status=0
env -u LD_PRELOAD "$output/async-probe" provider "$library" || status=$?
if [[ $status -ne 92 ]]; then
    printf 'FAIL: async process provider negative returned %s, expected 92\n' "$status" >&2
    exit 1
fi
for mode in strict hardened; do
    printf '\n== frankenlibc %s ==\n' "$mode"
    FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" "$output/probe" | tee "$output/$mode.log"
    FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" \
        "$output/async-probe" provider "$library"
    check_async_process "$mode" FRANKENLIBC_MODE="$mode" FRANKENLIBC_RUNTIME_MATH=on \
        LD_PRELOAD="$library" | tee "$output/async-$mode.log"
done
