#!/usr/bin/env bash
# Exercise the same executable against live glibc and the supplied libc artifact.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
library=${1:-"$root/target/release/libfrankenlibc_abi.so"}
library=$(realpath "$library")
[[ -f "$library" ]] || { echo "missing artifact: $library" >&2; exit 1; }
out=$(mktemp -d)
cc -O2 -pthread "$root/tests/integration/fixture_semaphore_interop.c" -ldl -o "$out/interop"
passed=0
for backend in host strict hardened; do
    run=(env -u LD_PRELOAD -u FL_REQUIRE_INTERPOSE)
    if [[ "$backend" != host ]]; then
        run+=("LD_PRELOAD=$library" "FRANKENLIBC_MODE=$backend" FL_REQUIRE_INTERPOSE=1)
    fi
    for spec in 'layout 0' 'mixed 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15' 'exchange 0 1 2 3 4 5 6 7' 'named 0 1 2 3' 'release 0 1'; do
        read -r -a arguments <<< "$spec"
        operation=${arguments[0]}
        for selection in "${arguments[@]:1}"; do
            printf '%s/%s/%s: ' "$backend" "$operation" "$selection"
            timeout --kill-after=2s 15s "${run[@]}" "$out/interop" "$operation" "$selection"
            passed=$((passed + 1))
        done
    done
done
[[ $passed -eq 93 ]] || { echo "incomplete matrix: $passed" >&2; exit 1; }
printf 'SEMAPHORE_INTEROP_PASSED=%s\n' "$passed"
