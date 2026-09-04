#!/usr/bin/env bash
# hardened_teardown_stress.sh — Rapid exit stress test in hardened mode (bd-luqw2w)
#
# Runs fixture_startup under LD_PRELOAD repeatedly in hardened mode to ensure
# 0 SIGSEGV crashes occur during process teardown.
#
# Exit codes:
#   0 — all iterations passed cleanly
#   1 — one or more runs crashed (e.g. SIGSEGV 139) or failed
#   2 — setup error (missing compiler, library, etc.)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ITERATIONS="${ITERATIONS:-200}"
BIN_DIR="${ROOT}/target/integration_stress"
BIN="${BIN_DIR}/fixture_startup"
SRC="${ROOT}/tests/integration/fixture_startup.c"

LIB_CANDIDATES=()
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
  LIB_CANDIDATES+=(
    "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
    "${CARGO_TARGET_DIR}/debug/libfrankenlibc_abi.so"
  )
fi
LIB_CANDIDATES+=(
  "${ROOT}/target/release/libfrankenlibc_abi.so"
  "/data/tmp/rch_target_hz3/release/libfrankenlibc_abi.so"
  "/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

if [[ -z "${LIB_PATH}" ]]; then
  echo "hardened_teardown_stress: could not locate libfrankenlibc_abi.so" >&2
  exit 2
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "hardened_teardown_stress: compiler 'cc' not found" >&2
  exit 2
fi

mkdir -p "${BIN_DIR}"
echo "--- Compiling fixture_startup ---"
cc -O2 -Wall -Wextra "${SRC}" -o "${BIN}"

run_stress() {
  local mode="$1"
  local count="$2"
  local passes=0
  local fails=0
  local segfaults=0

  echo "=== Running ${count} iterations in FRANKENLIBC_MODE=${mode} ==="
  echo "Binary: ${BIN}"
  echo "Library: ${LIB_PATH}"

  for i in $(seq 1 "${count}"); do
    set +e
    out=$(env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "${BIN}" 2>&1)
    rc=$?
    set -e

    if [[ "${rc}" -eq 0 ]]; then
      passes=$((passes + 1))
    else
      fails=$((fails + 1))
      if [[ "${rc}" -eq 139 ]]; then
        segfaults=$((segfaults + 1))
        echo "Iteration ${i}: CRASH (SIGSEGV 139) - output: ${out}" >&2
      else
        echo "Iteration ${i}: FAIL (exit ${rc}) - output: ${out}" >&2
      fi
    fi

    if (( i % 50 == 0 )); then
      echo "  Progress: ${i}/${count} (passes=${passes}, fails=${fails}, sigsegv=${segfaults})"
    fi
  done

  echo "Result [${mode}]: passes=${passes}/${count}, fails=${fails}, sigsegv=${segfaults}"
  if [[ "${fails}" -gt 0 ]]; then
    return 1
  fi
  return 0
}

# Run strict mode sanity check first (20 runs)
run_stress "strict" 20

# Run hardened mode stress check
run_stress "hardened" "${ITERATIONS}"

echo "=== All teardown stress iterations completed cleanly ==="
