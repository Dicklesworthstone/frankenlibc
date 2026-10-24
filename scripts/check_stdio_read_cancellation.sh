#!/usr/bin/env bash
# Exercise real native stdio cancellation, GNU behavior, and unwind cleanup.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -ne 1 || ! -f $1 ]]; then
  echo "usage: $0 /absolute/path/to/libfrankenlibc_abi.so" >&2
  exit 2
fi
library=$(realpath -e -- "$1")
out=${FRANKENLIBC_STDIO_CANCEL_OUT_DIR:-"$root/target/stdio-read-cancellation"}
mkdir -p -- "$out"
"${CC:-cc}" -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_stdio_cancel.c" -ldl -o "$out/fixture-c"
"${CXX:-c++}" -x c++ -std=c++17 -O2 -Wall -Wextra -Werror -pthread \
  "$root/tests/integration/fixture_stdio_cancel.c" -ldl -o "$out/fixture-cpp"
sha256sum "$library" "$root/tests/integration/fixture_stdio_cancel.c" \
  "$out/fixture-c" "$out/fixture-cpp" > "$out/input-sha256.txt"

cases=(fgetc getc fgetc_unlocked getc_unlocked macro-getc_unlocked
  getchar getchar_unlocked macro-getchar_unlocked fgets fgets_unlocked
  fread fread-large fread_unlocked getline __getline getdelim __getdelim
  __fgets_chk __fgets_unlocked_chk __fread_chk __fread_unlocked_chk
  __uflow __underflow)
count=0
run_case() {
  local language=$1 symbol=$2 phase=$3 path=$4 mode
  local prefix="$out/$language-$symbol-$phase-$path"
  env -u LD_PRELOAD -u FRANKENLIBC_MODE -u FRANKENLIBC_TEST_LIBRARY \
    timeout --kill-after=2s 8s "$out/fixture-$language" "$symbol" "$phase" "$path" \
    > "$prefix-host.out" 2> "$prefix-host.err"
  grep -qx "PASS $symbol $phase $path" "$prefix-host.out"
  test ! -s "$prefix-host.err"
  for mode in strict hardened; do
    if ! timeout --kill-after=2s 8s env LD_PRELOAD="$library" \
      FRANKENLIBC_MODE="$mode" FRANKENLIBC_THREAD_NATIVE=0 \
      FRANKENLIBC_TEST_LIBRARY="$library" \
      "$out/fixture-$language" "$symbol" "$phase" "$path" \
      > "$prefix-$mode.out" 2> "$prefix-$mode.err"; then
      cat "$prefix-$mode.err" >&2
      echo "FAIL $language/$symbol/$phase/$path/$mode" >&2
      exit 1
    fi
    cmp "$prefix-host.out" "$prefix-$mode.out"
    cmp "$prefix-host.err" "$prefix-$mode.err"
    echo "PASS $language/$symbol/$phase/$path/$mode"
  done
  count=$((count + 1))
}

for language in c cpp; do
  for symbol in "${cases[@]}"; do
    run_case "$language" "$symbol" blocked warm
    run_case "$language" "$symbol" pending cold
    run_case "$language" "$symbol" disabled warm
    run_case "$language" "$symbol" buffered warm
  done
  for symbol in fgetc fgets fread getdelim macro-getc_unlocked macro-getchar_unlocked; do
    run_case "$language" "$symbol" blocked unbuffered
  done
  # An omitted candidate must not silently qualify host libc as native code.
  set +e
  env -u LD_PRELOAD -u FRANKENLIBC_MODE FRANKENLIBC_TEST_LIBRARY="$library" \
    timeout --kill-after=2s 8s "$out/fixture-$language" fgetc blocked cold \
    > "$out/provider-negative-$language.out" 2> "$out/provider-negative-$language.err"
  status=$?
  set -e
  if [[ $status -ne 90 ]]; then
    echo "FAIL $language provider negative: expected 90, got $status" >&2
    exit 1
  fi
  grep -qx 'stdio cancellation: wrong symbol provider' "$out/provider-negative-$language.err"
done
test "$count" -eq 196
echo "Native stdio read cancellation: $count GNU oracle cases, $((count * 2)) candidate cases, 2 provider negatives passed"
