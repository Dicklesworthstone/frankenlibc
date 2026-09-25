#!/usr/bin/env bash
# Host oracle plus the actual public ABI under strict/hardened interposition.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${EXEC_CONTRACT_BUILD_DIR:-"$root/target/exec-search-contract"}
mkdir -p -- "$output"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 \
    "$root/tests/c_abi/exec_search_contract.c" -o "$output/probe"
printf '\n== host libc reference ==\n'
env -u LD_PRELOAD "$output/probe" | tee "$output/host.log"
if [[ $# -eq 0 ]]; then
    printf '\nHost reference only; pass the rebuilt ABI library to exercise frankenlibc.\n'
    exit 0
fi
if [[ $# -ne 1 ]]; then printf 'Usage: bash %s [path/to/libfrankenlibc_abi.so]\n' "$0" >&2; exit 2; fi
library=$(realpath -- "$1")
if [[ ! -f $library ]]; then printf 'Library not found: %s\n' "$library" >&2; exit 2; fi
for mode in strict hardened; do
    printf '\n== frankenlibc %s ==\n' "$mode"
    FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" "$output/probe" | tee "$output/$mode.log"
done
