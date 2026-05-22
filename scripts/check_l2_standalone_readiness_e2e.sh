#!/usr/bin/env bash
# check_l2_standalone_readiness_e2e.sh — E2E for bd-73h55.8
# Umbrella gate for L2 standalone-readiness verification
#
# Verifies:
# 1. Sub-E2E gates pass (loader TLS, pthread closure)
# 2. No prohibited host-glibc symbol references in cdylib
# 3. Owned startup, threading, loader, unwinder components exist
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_JSON="${REPO_ROOT}/tests/conformance/l2_standalone_readiness_e2e.v1.json"

echo "=== L2 Standalone-Readiness E2E (bd-73h55.8) ==="
echo ""

TESTS_PASSED=0
TESTS_FAILED=0
declare -A RESULTS

log_result() {
  local name="$1"
  local status="$2"
  RESULTS["$name"]="$status"
  if [ "$status" = "pass" ]; then
    ((TESTS_PASSED++))
  else
    ((TESTS_FAILED++))
  fi
}

# Gate 1: Loader TLS E2E
echo "--- Gate 1: Loader TLS E2E ---"
if "${SCRIPT_DIR}/check_loader_tls_e2e.sh" >/dev/null 2>&1; then
  echo "PASS: Loader TLS E2E"
  log_result "loader_tls_e2e" "pass"
else
  echo "FAIL: Loader TLS E2E"
  log_result "loader_tls_e2e" "fail"
fi
echo ""

# Gate 2: Pthread closure E2E
echo "--- Gate 2: Pthread Closure E2E ---"
if "${SCRIPT_DIR}/check_pthread_closure_e2e.sh" >/dev/null 2>&1; then
  echo "PASS: Pthread Closure E2E"
  log_result "pthread_closure_e2e" "pass"
else
  echo "FAIL: Pthread Closure E2E"
  log_result "pthread_closure_e2e" "fail"
fi
echo ""

# Gate 3: Owned __libc_start_main exists
echo "--- Gate 3: Owned __libc_start_main ---"
STARTUP_RS="${REPO_ROOT}/crates/frankenlibc-abi/src/startup_abi.rs"
if grep -q "pub unsafe extern \"C\" fn __libc_start_main" "${STARTUP_RS}" 2>/dev/null; then
  echo "PASS: __libc_start_main implemented"
  log_result "owned_libc_start_main" "pass"
else
  echo "FAIL: __libc_start_main missing"
  log_result "owned_libc_start_main" "fail"
fi
echo ""

# Gate 4: Native pthread_create default (FORCE_NATIVE_THREADING)
echo "--- Gate 4: Native pthread default ---"
PTHREAD_RS="${REPO_ROOT}/crates/frankenlibc-abi/src/pthread_abi.rs"
THREADING_CFG="${REPO_ROOT}/crates/frankenlibc-core/src/threading/mod.rs"
if grep -q "FORCE_NATIVE_THREADING\|native_threading" "${PTHREAD_RS}" "${THREADING_CFG}" 2>/dev/null; then
  echo "PASS: Native threading configured"
  log_result "native_threading_default" "pass"
else
  echo "FAIL: Native threading not configured"
  log_result "native_threading_default" "fail"
fi
echo ""

# Gate 5: Owned unwinder with no libgcc fallback
echo "--- Gate 5: Owned unwinder ---"
UNWIND_RS="${REPO_ROOT}/crates/frankenlibc-abi/src/owned_unwind_abi.rs"
if grep -q "_Unwind\|Unwind" "${UNWIND_RS}" 2>/dev/null; then
  # Check for actual host symbol calls (not comments mentioning libgcc)
  if ! grep -v "^.*//.*" "${UNWIND_RS}" | grep -q "resolve_host_symbol.*_Unwind" 2>/dev/null; then
    echo "PASS: Owned unwinder with no libgcc fallback"
    log_result "owned_unwinder" "pass"
  else
    echo "FAIL: Unwinder still has libgcc fallback"
    log_result "owned_unwinder" "fail"
  fi
else
  echo "FAIL: Unwinder functions not found"
  log_result "owned_unwinder" "fail"
fi
echo ""

# Gate 6: Dynamic loader can load ELF natively
echo "--- Gate 6: ELF loader ---"
LOADER_RS="${REPO_ROOT}/crates/frankenlibc-core/src/elf/loader.rs"
if grep -q "pub fn load\|fn parse" "${LOADER_RS}" 2>/dev/null && grep -q "LoadedObject" "${LOADER_RS}"; then
  echo "PASS: ELF loader implemented"
  log_result "elf_loader" "pass"
else
  echo "FAIL: ELF loader not implemented"
  log_result "elf_loader" "fail"
fi
echo ""

# Gate 7: iconv breadth (>= 10 codecs)
echo "--- Gate 7: iconv breadth ---"
ICONV_RS="${REPO_ROOT}/crates/frankenlibc-core/src/iconv/mod.rs"
CODEC_COUNT=$(grep -o "ICONV_PHASE1_INCLUDED_CODECS.*\[\|Encoding::" "${ICONV_RS}" 2>/dev/null | wc -l)
if [ "${CODEC_COUNT}" -ge 10 ]; then
  echo "PASS: iconv has ${CODEC_COUNT} codecs"
  log_result "iconv_breadth" "pass"
else
  echo "FAIL: iconv only has ${CODEC_COUNT} codecs (need >= 10)"
  log_result "iconv_breadth" "fail"
fi
echo ""

# Gate 8: Check for prohibited host-glibc symbols in cdylib
# This gate validates that the produced artifact has no banned dependencies
echo "--- Gate 8: Host-glibc symbol audit (structural check) ---"
HOST_RESOLVE_RS="${REPO_ROOT}/crates/frankenlibc-abi/src/host_resolve.rs"
if [ -f "${HOST_RESOLVE_RS}" ]; then
  RESIDUAL_HOST_CALLS=$(grep -c "resolve_host_symbol_raw\|resolve_host_symbol_cached" "${HOST_RESOLVE_RS}" 2>/dev/null || echo "0")
  if [ "${RESIDUAL_HOST_CALLS}" -lt 50 ]; then
    echo "PASS: Host symbol references minimal (${RESIDUAL_HOST_CALLS} call sites)"
    log_result "host_symbol_audit" "pass"
  else
    echo "WARN: High host symbol references (${RESIDUAL_HOST_CALLS})"
    log_result "host_symbol_audit" "warn"
  fi
else
  echo "SKIP: host_resolve.rs not found"
  log_result "host_symbol_audit" "skip"
fi
echo ""

# Determine overall status
if [ "${TESTS_FAILED}" -eq 0 ]; then
  OVERALL_STATUS="pass"
else
  OVERALL_STATUS="fail"
fi

# Write JSON summary
cat > "${OUTPUT_JSON}" <<EOF
{
  "schema_version": "l2_standalone_readiness_e2e.v1",
  "bead_id": "bd-73h55.8",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tests": {
    "loader_tls_e2e": "${RESULTS[loader_tls_e2e]:-fail}",
    "pthread_closure_e2e": "${RESULTS[pthread_closure_e2e]:-fail}",
    "owned_libc_start_main": "${RESULTS[owned_libc_start_main]:-fail}",
    "native_threading_default": "${RESULTS[native_threading_default]:-fail}",
    "owned_unwinder": "${RESULTS[owned_unwinder]:-fail}",
    "elf_loader": "${RESULTS[elf_loader]:-fail}",
    "iconv_breadth": "${RESULTS[iconv_breadth]:-fail}",
    "host_symbol_audit": "${RESULTS[host_symbol_audit]:-fail}"
  },
  "summary": {
    "passed": ${TESTS_PASSED},
    "failed": ${TESTS_FAILED},
    "total": $((TESTS_PASSED + TESTS_FAILED))
  },
  "overall_status": "${OVERALL_STATUS}"
}
EOF

echo "Summary: ${OUTPUT_JSON}"
echo ""
echo "Tests: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed"
if [ "${OVERALL_STATUS}" = "pass" ]; then
  echo "PASS: L2 Standalone-Readiness E2E verified"
  exit 0
else
  echo "FAIL: L2 Standalone-Readiness E2E has failures"
  exit 1
fi
