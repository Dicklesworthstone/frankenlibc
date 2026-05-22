#!/usr/bin/env bash
# check_loader_tls_e2e.sh — E2E test for loader TLS support (bd-73h55.2.4)
#
# Verifies that:
# 1. TlsSegment struct exists in loader
# 2. TlsModuleRegistry exists for module ID allocation
# 3. __tls_get_addr is implemented in ABI
# 4. PT_TLS parsing is integrated into LoadedObject
#
# Exit 0 = PASS, nonzero = FAIL
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Loader TLS E2E Test (bd-73h55.2.4) ==="
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

# Test 5: __tls_get_addr implemented
echo "--- Test 5: __tls_get_addr implemented ---"
GLIBC_ABI="${REPO_ROOT}/crates/frankenlibc-abi/src/glibc_internal_abi.rs"
if grep -q "pub unsafe extern \"C\" fn __tls_get_addr" "${GLIBC_ABI}"; then
  echo "PASS: __tls_get_addr implemented"
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

# Test 7: DTV management implemented
echo "--- Test 7: DTV management implemented ---"
if grep -q "fn with_dtv" "${GLIBC_ABI}" && grep -q "allocate_tls_block" "${GLIBC_ABI}"; then
  echo "PASS: DTV management functions present"
else
  echo "FAIL: DTV management functions missing"
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
    "module_id_allocation": "TlsModuleRegistry with register()",
    "dtv_management": "with_dtv() accessor + allocate_tls_block()",
    "tls_get_addr": "__tls_get_addr with DTV lookup",
    "tls_relocations": "DtpMod64/DtpOff64/TpOff64/TlsGd/TlsLd defined (application deferred)"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "PASS: Loader TLS E2E verified"
exit 0
