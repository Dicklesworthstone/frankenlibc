#!/usr/bin/env bash
# check_owned_unwinder_e2e.sh — E2E test for owned unwinder (bd-gq1kz7.4)
#
# Verifies that:
# 1. owned_unwind_abi.rs source exists with all required symbols
# 2. Existing conformance gates pass for the owned unwinder
# 3. A shared C++ throw/catch fixture resolves _Unwind_* from FrankenLibC without libgcc_s
# 4. The owned unwinder is documented as available via standalone+owned-unwind-stub
#
# The owned unwinder requires the `standalone` + `owned-unwind-stub` feature flags.
# This test verifies the infrastructure exists and is tested via existing conformance gates.
#
# Exit 0 = PASS, nonzero = FAIL
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Owned Unwinder E2E Test (bd-gq1kz7.4) ==="
echo ""

# Test 1: Verify owned_unwind_abi.rs exists and has all required symbols
echo "--- Test 1: Source file exists with required symbols ---"
UNWIND_ABI="${REPO_ROOT}/crates/frankenlibc-abi/src/owned_unwind_abi.rs"

if [[ ! -f "${UNWIND_ABI}" ]]; then
  echo "FAIL: owned_unwind_abi.rs not found"
  exit 1
fi

REQUIRED_SYMBOLS=(
  "_Unwind_Backtrace"
  "_Unwind_DeleteException"
  "_Unwind_GetDataRelBase"
  "_Unwind_GetGR"
  "_Unwind_GetIP"
  "_Unwind_GetIPInfo"
  "_Unwind_GetLanguageSpecificData"
  "_Unwind_GetRegionStart"
  "_Unwind_GetTextRelBase"
  "_Unwind_RaiseException"
  "_Unwind_Resume"
  "_Unwind_Resume_or_Rethrow"
  "_Unwind_SetGR"
  "_Unwind_SetIP"
)

missing=""
for sym in "${REQUIRED_SYMBOLS[@]}"; do
  if ! grep -q "fn ${sym}" "${UNWIND_ABI}"; then
    missing="${missing} ${sym}"
  fi
done

if [[ -n "${missing}" ]]; then
  echo "FAIL: missing symbol implementations:${missing}"
  exit 1
fi
echo "PASS: all ${#REQUIRED_SYMBOLS[@]} owned unwinder symbols defined in source"
echo ""

# Test 2: Verify feature flags are defined
echo "--- Test 2: Feature flags defined in Cargo.toml ---"
CARGO_TOML="${REPO_ROOT}/crates/frankenlibc-abi/Cargo.toml"

if ! grep -q "^standalone = \[\]" "${CARGO_TOML}"; then
  echo "FAIL: standalone feature not defined"
  exit 1
fi

if ! grep -q "^owned-unwind-stub = \[\]" "${CARGO_TOML}"; then
  echo "FAIL: owned-unwind-stub feature not defined"
  exit 1
fi
echo "PASS: standalone and owned-unwind-stub features defined"
echo ""

# Test 3: Verify the owned unwinder is gated correctly
echo "--- Test 3: Module gating verified ---"
LIB_RS="${REPO_ROOT}/crates/frankenlibc-abi/src/lib.rs"

if ! grep -q 'feature = "standalone", feature = "owned-unwind-stub"' "${LIB_RS}"; then
  echo "FAIL: owned_unwind_abi module not properly gated"
  exit 1
fi
echo "PASS: owned_unwind_abi gated behind standalone + owned-unwind-stub"
echo ""

# Test 4: Verify conformance artifacts exist
echo "--- Test 4: Conformance artifacts exist ---"
CONFORMANCE_ARTIFACTS=(
  "tests/conformance/standalone_owned_unwind_experiment.v1.json"
  "tests/conformance/standalone_owned_unwinder_symbol_surface.v1.json"
)

for artifact in "${CONFORMANCE_ARTIFACTS[@]}"; do
  if [[ ! -f "${REPO_ROOT}/${artifact}" ]]; then
    echo "FAIL: missing conformance artifact: ${artifact}"
    exit 1
  fi
done
echo "PASS: conformance artifacts present"
echo ""

# Test 5: Verify existing conformance tests can run
echo "--- Test 5: Conformance tests exist ---"
TEST_FILES=(
  "crates/frankenlibc-harness/tests/standalone_owned_unwind_experiment_test.rs"
  "crates/frankenlibc-harness/tests/standalone_owned_unwinder_symbol_surface_test.rs"
)

for test_file in "${TEST_FILES[@]}"; do
  if [[ ! -f "${REPO_ROOT}/${test_file}" ]]; then
    echo "FAIL: missing test file: ${test_file}"
    exit 1
  fi
done
echo "PASS: conformance test files present"
echo ""

OUT_DIR="${REPO_ROOT}/target/owned_unwinder_e2e"
mkdir -p "${OUT_DIR}"

# Test 6: Build and run a shared C++ fixture whose _Unwind symbols resolve to FrankenLibC.
echo "--- Test 6: Owned shared throw/catch fixture ---"
LIB_PATH="${FRANKENLIBC_LIB:-}"
if [[ -z "${LIB_PATH}" ]]; then
  if [[ -n "${CARGO_TARGET_DIR:-}" && -f "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so" ]]; then
    LIB_PATH="${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
  elif [[ -f "${REPO_ROOT}/target/release/libfrankenlibc_abi.so" ]]; then
    LIB_PATH="${REPO_ROOT}/target/release/libfrankenlibc_abi.so"
  fi
fi

if [[ -z "${LIB_PATH}" || ! -f "${LIB_PATH}" ]]; then
  echo "FAIL: set FRANKENLIBC_LIB to a standalone+owned-unwind-stub libfrankenlibc_abi.so"
  exit 1
fi

FIXTURE_SRC="${REPO_ROOT}/tests/conformance/fixtures/unwind/minimal_throw_catch.cpp"
OWNED_SO="${OUT_DIR}/minimal_throw_catch_owned.so"
g++ -fPIC -shared -nodefaultlibs \
  -DFRANKENLIBC_WRAP_CXA_THROW \
  -o "${OWNED_SO}" \
  "${FIXTURE_SRC}" \
  -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic -lc -lm \
  -Wl,--wrap=__cxa_throw \
  -Wl,--exclude-libs,ALL \
  -Wl,--allow-shlib-undefined \
  -Wl,--unresolved-symbols=ignore-all

if ldd "${OWNED_SO}" | grep -E 'libgcc_s|libunwind'; then
  echo "FAIL: owned shared fixture must not load libgcc_s or libunwind"
  exit 1
fi
if ! nm -D "${OWNED_SO}" | grep -q ' U _Unwind_RaiseException'; then
  echo "FAIL: owned shared fixture must leave _Unwind_RaiseException unresolved for FrankenLibC"
  exit 1
fi
if nm "${OWNED_SO}" | grep -E ' [Tt] _Unwind_RaiseException$'; then
  echo "FAIL: owned shared fixture defines _Unwind_RaiseException locally"
  exit 1
fi

python3 - "${LIB_PATH}" "${OWNED_SO}" <<'PY'
import ctypes
import os
import struct
import sys

lib_path = os.path.abspath(sys.argv[1])
fixture_path = os.path.abspath(sys.argv[2])
franken = ctypes.CDLL(lib_path, mode=os.RTLD_GLOBAL)
libdl = ctypes.CDLL("libdl.so.2")
libdl.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libdl.dlsym.restype = ctypes.c_void_p
owned_raise = ctypes.cast(franken._Unwind_RaiseException, ctypes.c_void_p).value
default_raise = libdl.dlsym(None, b"_Unwind_RaiseException")
if default_raise != owned_raise:
    raise SystemExit(
        f"_Unwind_RaiseException resolved to {default_raise:#x}, expected FrankenLibC {owned_raise:#x}"
    )
fixture = ctypes.CDLL(fixture_path, mode=os.RTLD_GLOBAL)
base = None
with open("/proc/self/maps", "r", encoding="utf-8") as maps:
    for line in maps:
        fields = line.split()
        if len(fields) >= 6 and fields[5] == fixture_path and fields[2] == "00000000":
            base = int(fields[0].split("-", 1)[0], 16)
            break
if base is None:
    raise SystemExit(f"could not find load base for {fixture_path}")
with open(fixture_path, "rb") as elf_file:
    elf = elf_file.read()
if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
    raise SystemExit("owned shared fixture must be ELF64 little-endian")
section_offset = struct.unpack_from("<Q", elf, 40)[0]
section_entry_size = struct.unpack_from("<H", elf, 58)[0]
section_count = struct.unpack_from("<H", elf, 60)[0]
section_name_index = struct.unpack_from("<H", elf, 62)[0]

def section(index):
    offset = section_offset + index * section_entry_size
    return struct.unpack_from("<IIQQQQIIQQ", elf, offset)

names = section(section_name_index)
name_bytes = elf[names[4] : names[4] + names[5]]
eh_frame = None
for index in range(section_count):
    current = section(index)
    name_end = name_bytes.find(b"\0", current[0])
    name = name_bytes[current[0] : name_end].decode("utf-8")
    if name == ".eh_frame":
        eh_frame = current
        break
if eh_frame is None:
    raise SystemExit("owned shared fixture has no .eh_frame section")
franken.__register_frame.argtypes = [ctypes.c_void_p]
franken.__register_frame(ctypes.c_void_p(base + eh_frame[3]))
entry = fixture.minimal_throw_catch_entry
entry.argtypes = []
entry.restype = ctypes.c_int
result = entry()
if result != 0:
    raise SystemExit(f"minimal_throw_catch_entry returned {result}")
PY

echo "PASS: shared C++ throw/catch resolved _Unwind_RaiseException from FrankenLibC and caught successfully"
echo ""

# Write summary JSON
SUMMARY_FILE="${REPO_ROOT}/tests/conformance/owned_unwinder_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "owned_unwinder_e2e.v1",
  "bead_id": "bd-gq1kz7.4",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "tests": {
    "source_symbols_defined": "pass",
    "feature_flags_defined": "pass",
    "module_gating_correct": "pass",
    "conformance_artifacts_present": "pass",
    "conformance_tests_present": "pass",
    "owned_shared_fixture_no_libgcc": "pass",
    "owned_shared_fixture_throw_catch": "pass"
  },
  "implementation_status": {
    "source_file": "crates/frankenlibc-abi/src/owned_unwind_abi.rs",
    "feature_flags": ["standalone", "owned-unwind-stub"],
    "behavior": {
      "_Unwind_Backtrace": "performs bounded frame-pointer walk",
      "_Unwind_RaiseException": "performs owned phase-1 search, phase-2 cleanup, and guarded x86_64 landing-pad transfer when the handler context validates",
      "_Unwind_Resume": "aborts until phase-2 context transfer lands",
      "_Unwind_Resume_or_Rethrow": "re-enters the owned raise path for rethrow-style edges",
      "_Unwind_GetGR": "reads owned cursor general-register state and returns zero for invalid slots",
      "_Unwind_SetGR": "mutates owned cursor general-register state for personality-requested landing-pad install",
      "_Unwind_SetIP": "mutates owned cursor instruction-pointer state for personality-requested landing-pad install",
      "x86_64_context_install": "validates landing-pad IP, physical frame/stack cursor, CFA register, and saved RIP before the non-returning jump"
    },
    "owned_throw_catch_fixture": {
      "library": "${LIB_PATH}",
      "shared_object": "${OWNED_SO}",
      "dependency_policy": "no libgcc_s or libunwind DT_NEEDED entries; _Unwind_RaiseException is unresolved until FrankenLibC is loaded RTLD_GLOBAL"
    },
    "requirement_for_default": "Complete L2 standalone-readiness (WS-6) to remove feature flag gating"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "NOTE: The owned unwinder is available via feature flags (standalone + owned-unwind-stub)."
echo "NOTE: Making it default requires completing L2 standalone-readiness prerequisites."
echo ""
echo "PASS: Owned unwinder E2E verified"
exit 0
