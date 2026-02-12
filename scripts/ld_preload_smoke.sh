#!/usr/bin/env bash
# LD_PRELOAD smoke harness for real binaries under strict + hardened modes.
#
# Runs a curated set of commands and captures deterministic diagnostics for
# any non-zero/timeout outcome.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_ROOT="${ROOT}/target/ld_preload_smoke"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${OUT_ROOT}/${RUN_ID}"
BIN_DIR="${RUN_DIR}/bin"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-10}"

LIB_CANDIDATES=(
  "${ROOT}/target/release/libfrankenlibc_abi.so"
  "/data/tmp/cargo-target/release/libfrankenlibc_abi.so"
)

LIB_PATH=""
for candidate in "${LIB_CANDIDATES[@]}"; do
  if [[ -f "${candidate}" ]]; then
    LIB_PATH="${candidate}"
    break
  fi
done

mkdir -p "${RUN_DIR}" "${BIN_DIR}"

if [[ -z "${LIB_PATH}" ]]; then
  echo "ld_preload_smoke: building frankenlibc-abi release artifact..."
  cargo build -p frankenlibc-abi --release
  for candidate in "${LIB_CANDIDATES[@]}"; do
    if [[ -f "${candidate}" ]]; then
      LIB_PATH="${candidate}"
      break
    fi
  done
fi

if [[ -z "${LIB_PATH}" ]]; then
  echo "ld_preload_smoke: could not locate libfrankenlibc_abi.so" >&2
  exit 2
fi

if ! command -v cc >/dev/null 2>&1; then
  echo "ld_preload_smoke: required compiler 'cc' not found" >&2
  exit 2
fi

INTEGRATION_BIN="${BIN_DIR}/link_test"
cc -O2 "${ROOT}/tests/integration/link_test.c" -o "${INTEGRATION_BIN}"

NONTRIVIAL_BIN=""
NONTRIVIAL_DESC=""
if command -v python3 >/dev/null 2>&1; then
  NONTRIVIAL_BIN="python3"
  NONTRIVIAL_DESC="python3 -c 'print(1)'"
elif command -v busybox >/dev/null 2>&1; then
  NONTRIVIAL_BIN="busybox"
  NONTRIVIAL_DESC="busybox uname -a"
else
  echo "ld_preload_smoke: requires python3 or busybox for non-trivial dynamic binary check" >&2
  exit 2
fi

passes=0
fails=0

record_failure_bundle() {
  local case_dir="$1"
  local mode="$2"
  local label="$3"
  local rc="$4"

  {
    echo "mode=${mode}"
    echo "case=${label}"
    echo "exit_code=${rc}"
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "lib_path=${LIB_PATH}"
    echo "timeout_seconds=${TIMEOUT_SECONDS}"
    echo "kernel=$(uname -a)"
  } > "${case_dir}/bundle.meta"

  env | sort > "${case_dir}/env.txt"
  cat /proc/self/maps > "${case_dir}/proc_self_maps.txt" || true
}

run_case() {
  local mode="$1"
  local label="$2"
  shift 2
  local case_dir="${RUN_DIR}/${mode}/${label}"
  mkdir -p "${case_dir}"

  printf '%q ' "$@" > "${case_dir}/command.shline"
  echo "" >> "${case_dir}/command.shline"

  set +e
  timeout "${TIMEOUT_SECONDS}" \
    env FRANKENLIBC_MODE="${mode}" LD_PRELOAD="${LIB_PATH}" "$@" \
    > "${case_dir}/stdout.txt" 2> "${case_dir}/stderr.txt"
  local rc=$?
  set -e

  if [[ "${rc}" -eq 0 ]]; then
    passes=$((passes + 1))
    echo "[PASS] mode=${mode} case=${label}"
    return 0
  fi

  fails=$((fails + 1))
  if [[ "${rc}" -eq 124 || "${rc}" -eq 125 ]]; then
    echo "[FAIL] mode=${mode} case=${label} (timeout ${TIMEOUT_SECONDS}s)"
  else
    echo "[FAIL] mode=${mode} case=${label} (exit ${rc})"
  fi
  record_failure_bundle "${case_dir}" "${mode}" "${label}" "${rc}"
  return 1
}

run_suite_for_mode() {
  local mode="$1"
  local mode_failed=0

  run_case "${mode}" "coreutils_ls" /bin/ls -la /tmp || mode_failed=1
  run_case "${mode}" "coreutils_cat" /bin/cat /etc/hosts || mode_failed=1
  run_case "${mode}" "coreutils_echo" /bin/echo "frankenlibc_smoke" || mode_failed=1
  run_case "${mode}" "coreutils_env" /usr/bin/env || mode_failed=1

  run_case "${mode}" "integration_link_test" "${INTEGRATION_BIN}" || mode_failed=1

  if [[ "${NONTRIVIAL_BIN}" == "python3" ]]; then
    run_case "${mode}" "nontrivial_python3" python3 -c "print(1)" || mode_failed=1
  else
    run_case "${mode}" "nontrivial_busybox" busybox uname -a || mode_failed=1
  fi

  return "${mode_failed}"
}

echo "=== LD_PRELOAD smoke ==="
echo "run_dir=${RUN_DIR}"
echo "lib=${LIB_PATH}"
echo "nontrivial=${NONTRIVIAL_DESC}"
echo "timeout_seconds=${TIMEOUT_SECONDS}"

overall_failed=0
run_suite_for_mode strict || overall_failed=1
run_suite_for_mode hardened || overall_failed=1

{
  echo "run_id=${RUN_ID}"
  echo "lib_path=${LIB_PATH}"
  echo "nontrivial=${NONTRIVIAL_DESC}"
  echo "passes=${passes}"
  echo "fails=${fails}"
  echo "overall_failed=${overall_failed}"
} > "${RUN_DIR}/summary.txt"

echo ""
echo "Summary: passes=${passes} fails=${fails}"
echo "Artifacts: ${RUN_DIR}"

if [[ "${overall_failed}" -ne 0 ]]; then
  echo "ld_preload_smoke: FAILED (see diagnostics bundles under ${RUN_DIR})" >&2
  exit 1
fi

echo "ld_preload_smoke: PASS"
