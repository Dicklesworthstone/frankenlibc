#!/usr/bin/env bash
# check_loader_tls_e2e.sh — loader TLS source-structure check (bd-73h55.2.4)
#
# Verifies that:
# 1. TlsSegment struct exists in loader
# 2. TlsModuleRegistry exists for module ID allocation
# 3. __tls_get_addr is declared in ABI
# 4. PT_TLS parsing is integrated into LoadedObject
# This checks source presence only. Runtime behavior is exercised separately by
# dlfcn_native_tls_test, including its public_dynamic_tls_resolver_* cases.
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Loader TLS Source-Structure Check (bd-73h55.2.4) ==="
echo ""

# Test 1: TlsSegment struct exists
echo "--- Test 1: TlsSegment struct exists ---"
LOADER_RS="${REPO_ROOT}/crates/frankenlibc-core/src/elf/loader.rs"

if grep -q "pub struct TlsSegment" "${LOADER_RS}"; then
  echo "PASS: TlsSegment struct defined"
else
  echo "FAIL: TlsSegment struct missing"
  exit 1
fi
echo ""

# Test 2: TlsModuleRegistry exists
echo "--- Test 2: TlsModuleRegistry exists ---"
if grep -q "pub struct TlsModuleRegistry" "${LOADER_RS}"; then
  echo "PASS: TlsModuleRegistry struct defined"
else
  echo "FAIL: TlsModuleRegistry struct missing"
  exit 1
fi
echo ""

# Test 3: TlsSegment field in LoadedObject
echo "--- Test 3: LoadedObject has tls_segment field ---"
if grep -q "pub tls_segment: Option<TlsSegment>" "${LOADER_RS}"; then
  echo "PASS: tls_segment field present in LoadedObject"
else
  echo "FAIL: tls_segment field missing from LoadedObject"
  exit 1
fi
echo ""

# Test 4: PT_TLS parsing integrated
echo "--- Test 4: PT_TLS parsing integrated ---"
if grep -q "is_tls()" "${LOADER_RS}"; then
  echo "PASS: PT_TLS parsing present"
else
  echo "FAIL: PT_TLS parsing missing"
  exit 1
fi
echo ""

# Test 5: __tls_get_addr declared
echo "--- Test 5: __tls_get_addr declared ---"
GLIBC_ABI="${REPO_ROOT}/crates/frankenlibc-abi/src/glibc_internal_abi.rs"
if grep -q "pub unsafe extern \"C\" fn __tls_get_addr" "${GLIBC_ABI}"; then
  echo "PASS: __tls_get_addr declaration present"
else
  echo "FAIL: __tls_get_addr missing"
  exit 1
fi
echo ""

# Test 6: TlsIndex struct defined
echo "--- Test 6: TlsIndex struct defined ---"
if grep -q "pub struct TlsIndex" "${GLIBC_ABI}"; then
  echo "PASS: TlsIndex struct defined"
else
  echo "FAIL: TlsIndex struct missing"
  exit 1
fi
echo ""

# Test 7: public owned resolver shares the native loader registry
echo "--- Test 7: owned resolver registry bridge present ---"
DLFCN_ABI="${REPO_ROOT}/crates/frankenlibc-abi/src/dlfcn_abi.rs"
DLFCN_NATIVE="${REPO_ROOT}/crates/frankenlibc-abi/src/dlfcn_native.rs"
DLFCN_TLS="${REPO_ROOT}/crates/frankenlibc-abi/src/dlfcn_tls.rs"
if grep -q "fn owned_tls_get_addr" "${GLIBC_ABI}" \
  && grep -q "crate::dlfcn_abi::native_tls_address(module, offset)" "${GLIBC_ABI}" \
  && grep -q "native::tls_address(module_id, offset)" "${DLFCN_ABI}" \
  && grep -q "tls::module_address(module_id, offset)" "${DLFCN_NATIVE}" \
  && grep -q "fn module_address" "${DLFCN_TLS}"; then
  echo "PASS: owned resolver registry bridge present in source"
else
  echo "FAIL: owned resolver registry bridge missing from source"
  exit 1
fi
echo ""

# Test 8: TLS relocations defined
echo "--- Test 8: TLS relocations defined ---"
RELOC_RS="${REPO_ROOT}/crates/frankenlibc-core/src/elf/relocation.rs"
if grep -q "DtpMod64" "${RELOC_RS}" && grep -q "DtpOff64" "${RELOC_RS}" && grep -q "TpOff64" "${RELOC_RS}"; then
  echo "PASS: TLS relocation types defined"
else
  echo "FAIL: TLS relocation types missing"
  exit 1
fi
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/loader_tls_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "loader_tls_e2e.v1",
  "bead_id": "bd-73h55.2.4",
  "evidence_kind": "source_structure_only",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tests": {
    "tls_segment_struct": "pass",
    "tls_module_registry": "pass",
    "loaded_object_tls_field": "pass",
    "pt_tls_parsing": "pass",
    "tls_get_addr_impl": "pass",
    "tls_index_struct": "pass",
    "dtv_management": "pass",
    "tls_relocations_defined": "pass"
  },
  "implementation_status": {
    "pt_tls_parsing": "integrated into LoadedObject.tls_segment",
    "module_id_allocation": "core TlsModuleRegistry declaration present",
    "dtv_management": "native loader module_address() registry lookup",
    "tls_get_addr": "standalone owned registry bridge; interpose host dispatch",
    "tls_relocations": "core TLS relocation variants present (execution not checked)"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: Loader TLS source structure verified (runtime execution not checked)"
exit 0
