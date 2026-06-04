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
RUN_MODE="rch"

usage() {
  cat <<'EOF'
Usage: check_aarch64_crosscompile.sh [--rch|--local]

Runs the aarch64 cross-compile cargo check gate and emits report/log artifacts.

Modes:
  --rch    Run cargo checks through remote rch execution (default).
  --local  Run cargo checks directly. Use only inside an already-remote worker
           or for deliberate local debugging.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rch)
      RUN_MODE="rch"
      ;;
    --local)
      RUN_MODE="local"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "FAIL: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

mkdir -p "${OUT_DIR}"
: >"${LOG}"

now_iso_ms() { date -u +"%Y-%m-%dT%H:%M:%S.%3NZ"; }

log_event() {
  local stage="$1" outcome="$2" msg="$3"
  printf '{"timestamp":"%s","trace_id":"bd-j19j6::%s","stage":"%s","outcome":"%s","message":"%s"}\n' \
    "$(now_iso_ms)" "${RUN_ID}" "${stage}" "${outcome}" "${msg}" >>"${LOG}"
}

cargo_check_command_for_log() {
  local package="$1"
  # The gate type-checks Rust aarch64 paths; disabling blake3's NEON C build
  # avoids requiring a worker-local aarch64 C cross-compiler for cargo check.
  if [[ "${RUN_MODE}" == "rch" ]]; then
    printf 'RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=%s rch exec -- env CARGO_FEATURE_NO_NEON=1 cargo check --target %s -p %s' \
      "${RCH_VISIBILITY:-summary}" "${TARGET}" "${package}"
  else
    printf 'CARGO_FEATURE_NO_NEON=1 cargo check --target %s -p %s' "${TARGET}" "${package}"
  fi
}

run_core_cargo_check() {
  if [[ "${RUN_MODE}" == "rch" ]]; then
      RCH_REQUIRE_REMOTE=1 \
      RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
      rch exec -- env CARGO_FEATURE_NO_NEON=1 cargo check --target "${TARGET}" -p frankenlibc-core
  else
    CARGO_FEATURE_NO_NEON=1 cargo check --target "${TARGET}" -p frankenlibc-core
  fi
}

run_abi_cargo_check() {
  if [[ "${RUN_MODE}" == "rch" ]]; then
      RCH_REQUIRE_REMOTE=1 \
      RCH_VISIBILITY="${RCH_VISIBILITY:-summary}" \
      rch exec -- env CARGO_FEATURE_NO_NEON=1 cargo check --target "${TARGET}" -p frankenlibc-abi
  else
    CARGO_FEATURE_NO_NEON=1 cargo check --target "${TARGET}" -p frankenlibc-abi
  fi
}

if [[ "${RUN_MODE}" == "rch" ]] && ! command -v rch >/dev/null 2>&1; then
  log_event "rch_available" "fail" "rch not found in PATH"
  echo "FAIL: rch is required by default; rerun with --local only for manual fallback" >&2
  exit 2
fi

if [[ "${RUN_MODE}" == "local" ]]; then
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
fi

# Cross-compiling frankenlibc-core requires a sysroot (the aarch64 libstd).
# We do NOT require a full cross-linker here because `cargo check` only
# runs the front-end; linking is the consumer's job. If the host lacks
# the aarch64 linker, `cargo build` would fail but `cargo check` succeeds.
CORE_COMMAND="$(cargo_check_command_for_log frankenlibc-core)"
log_event "check_core" "in_progress" "${CORE_COMMAND}"
if run_core_cargo_check >>"${LOG}" 2>&1; then
  log_event "check_core" "pass" "frankenlibc-core cross-checks clean"
  CORE_STATUS="pass"
else
  log_event "check_core" "fail" "frankenlibc-core cross-check failed"
  CORE_STATUS="fail"
fi

ABI_COMMAND="$(cargo_check_command_for_log frankenlibc-abi)"
log_event "check_abi" "in_progress" "${ABI_COMMAND}"
if run_abi_cargo_check >>"${LOG}" 2>&1; then
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
  "maintenance_bead": "bd-l2s8x",
  "run_id": "${RUN_ID}",
  "target": "${TARGET}",
  "run_mode": "${RUN_MODE}",
  "commands": {
    "frankenlibc_core": "${CORE_COMMAND}",
    "frankenlibc_abi": "${ABI_COMMAND}"
  },
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
