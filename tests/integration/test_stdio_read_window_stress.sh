#!/usr/bin/env bash
# Run the host oracle and both FrankenLibC modes; an absent preload must fail.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
lib="${1:-${root}/target/release/libfrankenlibc_abi.so}"
if [[ ! -f "${lib}" ]]; then
    printf 'FrankenLibC shared library not found: %s\n' "${lib}" >&2
    exit 2
fi
lib="$(realpath "${lib}")"
work="$(mktemp -d "${TMPDIR:-/tmp}/frankenlibc-read-window.XXXXXX")"
printf 'Read-window stress artifacts: %s\n' "${work}"
binary="${work}/fixture_stdio_read_window_stress"
env -u LD_PRELOAD -u FRANKENLIBC_MODE "${CC:-cc}" \
    -std=c11 -O2 -Wall -Wextra -Werror -pthread \
    "${root}/tests/integration/fixture_stdio_read_window_stress.c" \
    -ldl -o "${binary}"
env -u LD_PRELOAD -u FRANKENLIBC_MODE timeout 30 "${binary}"
if env -u LD_PRELOAD -u FRANKENLIBC_MODE timeout 30 \
    "${binary}" --require-frankenlibc >"${work}/missing-preload.log" 2>&1; then
    missing_status=0
else
    missing_status=$?
fi
if [[ "${missing_status}" -ne 1 ]]; then
    printf 'ERROR: missing-preload probe returned %s, expected 1\n' "${missing_status}" >&2
    exit 1
fi
for mode in strict hardened; do
    printf 'Testing FrankenLibC mode: %s\n' "${mode}"
    env -u LD_PRELOAD timeout 30 env \
        FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${lib}" \
        "${binary}" --require-frankenlibc
done
