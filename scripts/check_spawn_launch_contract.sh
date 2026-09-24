#!/usr/bin/env bash
# Compile the original C probe, then compare the host and the supplied ABI .so.
# This script intentionally does not build Rust or claim a host run validates it.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${SPAWN_CONTRACT_BUILD_DIR:-"$root/target/spawn-launch-contract"}
mkdir -p -- "$output"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 \
    "$root/tests/c_abi/spawn_launch_contract.c" -o "$output/probe"
args=()
if [[ ${SPAWN_CONTRACT_SUITE:-all} == descriptors ]]; then args+=(--descriptors); fi
printf '\n== host libc reference ==\n'
env -u LD_PRELOAD "$output/probe" "${args[@]}" | tee "$output/host.log"
if [[ $# -eq 0 ]]; then
    printf '\nHost reference only. Pass the absolute ABI library path to exercise frankenlibc.\n'
    exit 0
fi
if [[ $# -ne 1 ]]; then printf 'Usage: bash %s [absolute/path/to/libfrankenlibc_abi.so]\n' "$0" >&2; exit 2; fi
library=$(realpath -- "$1")
if [[ ! -f $library ]]; then printf 'Library not found: %s\n' "$library" >&2; exit 2; fi
for mode in strict hardened; do
    printf '\n== frankenlibc %s ==\n' "$mode"
    FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" "$output/probe" "${args[@]}" | tee "$output/$mode.log"
done
