#!/usr/bin/env bash
# Compile the original C probe, then compare the host and the supplied ABI .so.
# This script intentionally does not build Rust or claim a host run validates it.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output=${SPAWN_CONTRACT_BUILD_DIR:-"$root/target/spawn-launch-contract"}
mkdir -p -- "$output"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 \
    "$root/tests/c_abi/spawn_launch_contract.c" -ldl -o "$output/probe"
if [[ ${SPAWN_CONTRACT_SUITE:-all} == clone-fallback ]]; then
    if [[ $# -ne 1 ]]; then
        printf 'clone-fallback requires one absolute ABI library path\n' >&2
        exit 2
    fi
    library=$(realpath -- "$1")
    if [[ ! -f $library ]]; then printf 'Library not found: %s\n' "$library" >&2; exit 2; fi
    host_provider=$(env -u LD_PRELOAD ldd "$output/probe" | awk '$1 == "libc.so.6" { print $3 }')
    if [[ ! -f $host_provider ]]; then printf 'Cannot identify live GNU provider\n' >&2; exit 2; fi
    sha256sum "$library" | tee "$output/library.sha256"
    host_cases=0
    native_cases=0
    for scenario in native enosys eperm eagain legacy-eperm; do
        expected=30
        if [[ $scenario == eperm || $scenario == eagain || $scenario == legacy-eperm ]]; then expected=6; fi
        host_stdout="$output/clone-$scenario.host.stdout.log"
        host_stderr="$output/clone-$scenario.host.stderr.log"
        env -u LD_PRELOAD -u FRANKENLIBC_MODE timeout --kill-after=2s 35s \
            "$output/probe" --clone-contract "$scenario" "$host_provider" \
            >"$host_stdout" 2>"$host_stderr"
        grep -Fx "SUMMARY tests=$expected failed=0 skipped=0" "$host_stdout"
        [[ $(grep -c '^PASS ' "$host_stdout") -eq $expected ]]
        # Preserve the GNU descriptor observation independently: some releases
        # leak internal pidfds on failed exec. Native cleanup must still be zero.
        printf 'GNU %s ' "$scenario"
        grep -E '^OBSERVE descriptor_delta=-?[0-9]+$' "$host_stderr"
        host_cases=$((host_cases + expected))
        for mode in strict hardened; do
            native_stdout="$output/clone-$scenario.$mode.stdout.log"
            native_stderr="$output/clone-$scenario.$mode.stderr.log"
            timeout --kill-after=2s 35s env FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" \
                "$output/probe" --clone-contract "$scenario" "$library" \
                >"$native_stdout" 2>"$native_stderr"
            grep -Fx "SUMMARY tests=$expected failed=0 skipped=0" "$native_stdout"
            [[ $(grep -c '^PASS ' "$native_stdout") -eq $expected ]]
            cmp "$host_stdout" "$native_stdout"
            grep -Fx 'OBSERVE descriptor_delta=0' "$native_stderr"
            native_cases=$((native_cases + expected))
        done
    done
    # A passing host run must never substitute for a missing preload.
    set +e
    env -u LD_PRELOAD -u FRANKENLIBC_MODE timeout --kill-after=2s 35s \
        "$output/probe" --clone-contract native "$library" \
        >"$output/clone-provider-negative.stdout.log" 2>"$output/clone-provider-negative.stderr.log"
    status=$?
    set -e
    [[ $status -eq 2 ]]
    grep -Fx 'FAIL wrong spawn provider: posix_spawn' "$output/clone-provider-negative.stderr.log"
    printf 'check_spawn_launch_contract clone-fallback: PASS (%d live GNU cases, %d native cases, 10 native fd cleanup checks, 1 provider negative)\n' \
        "$host_cases" "$native_cases"
    exit 0
fi
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
