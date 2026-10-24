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
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_c11_thread_cancel_lifecycle.c" -ldl -o "$out/lifecycle"
"${CXX:-c++}" -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_c11_thread_cancel_cpp.cpp" -ldl -o "$out/cpp"
count=0
run_case() {
  local binary=$1 case=$2 mode
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
  count=$((count + 1))
}
for case in sleep-values sleep-pending sleep-blocked sleep-disabled sleep-signal; do
  run_case "$binary" "$case"
done
for case in create-return create-exit create-pthread-exit create-cancel-pending \
  create-cancel-blocked join-pending join-blocked; do
  run_case "$out/lifecycle" "$case"
done
for case in cpp-return cpp-exit cpp-cancel; do
  run_case "$out/cpp" "$case"
done
echo "C11 cancellation: $count host cases and $((count * 2)) candidate cases passed"
