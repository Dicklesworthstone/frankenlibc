#!/usr/bin/env bash
# Execute real foreign exceptions against host glibc and an already-built
# FrankenLibC shared library. A missing library or wrong symbol binding fails.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 /absolute/path/to/libfrankenlibc_abi.so [new-output-directory]" >&2
    exit 2
fi
if [[ ! -f "$1" ]]; then
    echo "FAIL: candidate library does not exist: $1" >&2
    exit 2
fi
library=$(realpath -- "$1")
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_file="$root/tests/integration/fixture_pthread_once_unwind.cpp"
if [[ $# -eq 2 ]]; then
    # Never overwrite a previous run's evidence.
    mkdir -- "$2"
    output=$(realpath -- "$2")
else
    output=$(mktemp -d "${TMPDIR:-/tmp}/frankenlibc-once-unwind.XXXXXX")
fi
echo "Evidence directory: $output"
trap 'rc=$?; if (( rc != 0 )); then echo "FAIL: exit $rc; logs retained in $output" >&2; fi' EXIT

compiler=${CXX:-c++}
env -u LD_PRELOAD "$compiler" -std=c++17 -O2 -Wall -Wextra -Werror -pedantic \
    -pthread "$source_file" -ldl -o "$output/fixture"
sha256sum -- "$library" "$source_file" "$output/fixture" > "$output/sha256.txt"
env -u LD_PRELOAD "$compiler" --version > "$output/compiler.txt"

# Keep timeout itself outside the preload so an interposer cannot disable the
# watchdog. All timeout, signal, compile, and program failures propagate.
env -u LD_PRELOAD timeout --kill-after=2s 25s \
    "$output/fixture" > "$output/glibc.stdout" 2> "$output/glibc.stderr"
for test_name in sequential-retry nested-retry caught-in-initializer std-call-once; do
    grep -Fx -- "PASS $test_name" "$output/glibc.stdout" > /dev/null
done
grep -Fx -- "PASS contended-retry: 16 rounds, 8 waiters per round" \
    "$output/glibc.stdout" > /dev/null
[[ $(grep -c '^PASS ' "$output/glibc.stdout") -eq 5 ]]

for mode in strict hardened; do
    env -u LD_PRELOAD timeout --kill-after=2s 25s \
        env -u FRANKENLIBC_THREAD_NATIVE -u FRANKENLIBC_THREAD_DELEGATE \
        FRANKENLIBC_MODE="$mode" LD_PRELOAD="$library" \
        "$output/fixture" "$library" \
        > "$output/$mode.stdout" 2> "$output/$mode.stderr"
    cmp -- "$output/glibc.stdout" "$output/$mode.stdout"
    echo "PASS $mode: five groups, including 16 contended retries with 8 waiters"
done
echo "PASS pthread_once foreign-unwind parity: strict, hardened"
