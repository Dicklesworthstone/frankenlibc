#!/usr/bin/env bash
# check_aarch64_crosscompile.sh — cross-compile gate for the aarch64 branches
# of frankenlibc-core/src/syscall/raw.rs and the cfg(target_arch = "aarch64")
# code paths elsewhere. Validates that the declared aarch64 support
# actually builds, so typos in register constraints or cfg gates are
# caught before a real aarch64 consumer trips over them. (bd-j19j6)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="aarch64-unknown-linux-gnu"
OUT_DIR="${ROOT}/target/conformance"
REPORT="${OUT_DIR}/aarch64_crosscompile.report.json"
LOG="${OUT_DIR}/aarch64_crosscompile.log"
RUN_ID="aarch64-crosscompile-$(date -u +%Y%m%dT%H%M%SZ)-$$"

mkdir -p "${OUT_DIR}"
: >"${LOG}"

now_iso_ms() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }

log_event() {
  local stage="$1" outcome="$2" msg="$3"
  printf '{"timestamp":"%s","trace_id":"bd-j19j6::%s","stage":"%s","outcome":"%s","message":"%s"}\n' \
    "$(now_iso_ms)" "${RUN_ID}" "${stage}" "${outcome}" "${msg}" >>"${LOG}"
}

# Ensure the aarch64 target is installed. `rustup target add` is idempotent
# and cheap when the target is already present.
if ! rustup target list --installed 2>/dev/null | grep -q "^${TARGET}$"; then
  log_event "install_target" "in_progress" "adding ${TARGET}"
  rustup target add "${TARGET}" >>"${LOG}" 2>&1 || {
    log_event "install_target" "fail" "rustup target add failed"
    echo "FAIL: rustup target add ${TARGET} — ensure rustup + network access" >&2
    exit 1
  }
fi

# Cross-compiling frankenlibc-core requires a sysroot (the aarch64 libstd).
# We do NOT require a full cross-linker here because `cargo check` only
# runs the front-end; linking is the consumer's job. If the host lacks
# the aarch64 linker, `cargo build` would fail but `cargo check` succeeds.
log_event "check_core" "in_progress" "cargo check --target ${TARGET} -p frankenlibc-core"
if cargo check --target "${TARGET}" -p frankenlibc-core >>"${LOG}" 2>&1; then
  log_event "check_core" "pass" "frankenlibc-core cross-checks clean"
  CORE_STATUS="pass"
else
  log_event "check_core" "fail" "frankenlibc-core cross-check failed"
  CORE_STATUS="fail"
fi

log_event "check_abi" "in_progress" "cargo check --target ${TARGET} -p frankenlibc-abi"
if cargo check --target "${TARGET}" -p frankenlibc-abi >>"${LOG}" 2>&1; then
  log_event "check_abi" "pass" "frankenlibc-abi cross-checks clean"
  ABI_STATUS="pass"
else
  log_event "check_abi" "fail" "frankenlibc-abi cross-check failed"
  ABI_STATUS="fail"
fi

cat >"${REPORT}" <<JSON
{
  "schema_version": "v1",
  "bead": "bd-j19j6",
  "run_id": "${RUN_ID}",
  "target": "${TARGET}",
  "checks": {
    "frankenlibc_core": "${CORE_STATUS}",
    "frankenlibc_abi": "${ABI_STATUS}"
  },
  "artifacts": [
    "scripts/check_aarch64_crosscompile.sh",
    "target/conformance/aarch64_crosscompile.report.json",
    "target/conformance/aarch64_crosscompile.log"
  ]
}
JSON

if [[ "${CORE_STATUS}" == "pass" && "${ABI_STATUS}" == "pass" ]]; then
  echo "check_aarch64_crosscompile: PASS"
  exit 0
fi

echo "FAIL: aarch64 cross-check reported one or more failures; see ${LOG}" >&2
exit 1
