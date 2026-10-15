#!/usr/bin/env bash
# Exercise the deployed C ABI, not Rust test-profile exports or a host delegate.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ne 1 || ! -f $1 ]]; then
  echo "usage: $0 /absolute/path/to/libfrankenlibc_abi.so" >&2
  exit 2
fi
library=$(realpath -e -- "$1")
out=${C11_CANCEL_OUTPUT_DIR:-"$root/target/c11-thread-cancellation"}
mkdir -p -- "$out"
binary="$out/fixture"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_c11_thread_cancel.c" -ldl -o "$binary"
cases=(sleep-values sleep-pending sleep-blocked sleep-disabled sleep-signal)
for case in "${cases[@]}"; do
  env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_TEST_LIBRARY \
    timeout 12s "$binary" "$case" > "$out/host-$case.out" 2> "$out/host-$case.err"
  for mode in strict hardened; do
    if ! timeout 12s env LD_PRELOAD="$library" FRANKENLIBC_MODE="$mode" \
      FRANKENLIBC_THREAD_NATIVE=0 FRANKENLIBC_TEST_LIBRARY="$library" \
      "$binary" "$case" > "$out/$mode-$case.out" 2> "$out/$mode-$case.err"; then
      cat "$out/$mode-$case.err" >&2
      echo "FAIL $mode/$case (nonzero exit or timeout)" >&2
      exit 1
    fi
    diff -u "$out/host-$case.out" "$out/$mode-$case.out"
    diff -u "$out/host-$case.err" "$out/$mode-$case.err"
    echo "PASS $mode/$case"
  done
done
echo "C11 cancellation: ${#cases[@]} host cases and $((${#cases[@]} * 2)) candidate cases passed"
