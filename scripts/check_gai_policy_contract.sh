#!/usr/bin/env bash
# Black-box host and preload checks in private chroots; never changes real /etc.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${GAI_POLICY_BUILD_DIR:-"$root/target/gai-policy-contract"}
if [[ $# -gt 1 ]]; then
    printf 'Usage: bash %s [absolute/path/to/libfrankenlibc_abi.so]\n' "$0" >&2
    exit 2
fi
mkdir -p -- "$output"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 \
    "$root/tests/c_abi/gai_policy_contract.c" -o "$output/probe"
printf '\n== host libc reference ==\n'
env -u LD_PRELOAD "$output/probe" | tee "$output/host.log"
if [[ $# -eq 0 ]]; then
    printf '\nHost reference only; a rebuilt ABI library is required for frankenlibc validation.\n'
    exit 0
fi
library=$(realpath -- "$1")
[[ -f $library ]] || { printf 'Library not found: %s\n' "$library" >&2; exit 2; }
for mode in strict hardened; do
    printf '\n== frankenlibc %s ==\n' "$mode"
    FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" "$output/probe" | tee "$output/$mode.log"
done
