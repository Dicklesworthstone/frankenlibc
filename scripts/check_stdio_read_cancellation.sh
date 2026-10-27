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
  __uflow __underflow
  fscanf scanf vfscanf vscanf __isoc99_fscanf __isoc99_scanf
  __isoc99_vfscanf __isoc99_vscanf _IO_vfscanf
  fgetwc getwc fgetwc_unlocked getwc_unlocked getwchar getwchar_unlocked
  fgetws fgetws_unlocked __fgetws_chk __fgetws_unlocked_chk
  fwscanf wscanf vfwscanf vwscanf __isoc99_fwscanf __isoc99_wscanf
  __isoc99_vfwscanf __isoc99_vwscanf __wuflow __wunderflow)
outputs=(fputc putc fputc_unlocked putc_unlocked putchar putchar_unlocked
  macro-putc_unlocked macro-putchar_unlocked fputs fputs_unlocked puts
  fwrite fwrite-large fwrite_unlocked fflush fflush_unlocked fclose putw
  fprintf printf vfprintf vprintf dprintf vdprintf __fprintf_chk __printf_chk
  __vfprintf_chk __vprintf_chk __dprintf_chk __vdprintf_chk __overflow
  _IO_putc _IO_puts _IO_fputs _IO_fwrite _IO_fflush _IO_fclose _IO_printf
  _IO_fprintf _IO_vfprintf fputwc putwc fputwc_unlocked putwc_unlocked
  putwchar putwchar_unlocked fputws fputws_unlocked fputws-large fwprintf
  wprintf vfwprintf vwprintf __fwprintf_chk __wprintf_chk __vfwprintf_chk
  __vwprintf_chk __woverflow)
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
  for symbol in fgetwc fgetws fwscanf; do
    run_case "$language" "$symbol" blocked partial
  done
  for symbol in "${outputs[@]}"; do
    run_case "$language" "$symbol" blocked warm
    run_case "$language" "$symbol" pending cold
    run_case "$language" "$symbol" disabled warm
    case "$symbol" in
      fflush|fflush_unlocked|fclose|_IO_fflush|_IO_fclose|dprintf|vdprintf|__dprintf_chk|__vdprintf_chk|fwrite-large|fputws-large)
        ;;
      *) run_case "$language" "$symbol" buffered warm ;;
    esac
    case "$symbol" in
      dprintf|vdprintf|__dprintf_chk|__vdprintf_chk|fwrite-large|fputws-large)
        ;;
      *) run_case "$language" "$symbol" buffered memory ;;
    esac
  done
  for symbol in fputc macro-putc_unlocked fputs fwrite fprintf fputwc fputws fwprintf; do
    run_case "$language" "$symbol" blocked line
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
test "$count" -eq 996
echo "Native stdio cancellation: $count GNU oracle cases, $((count * 2)) candidate cases, 2 provider negatives passed"
