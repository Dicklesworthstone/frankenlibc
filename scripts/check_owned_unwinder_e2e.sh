#!/usr/bin/env bash
# check_owned_unwinder_e2e.sh — E2E test for owned unwinder (bd-gq1kz7.4)
#
# Verifies that:
# 1. owned_unwind_abi.rs source exists with all required symbols
# 2. Required feature gating and existing conformance references are present
# 3. Real C++ cleanup landing pads, Resume, forced stops and stack termination
#    work with and without frame pointers, using only the owned _Unwind symbols
# 4. The same fixture assertions pass against the host unwinder
#
# The owned unwinder requires the `standalone` + `owned-unwind-stub` feature flags.
# FRANKENLIBC_UNWIND_COMPONENT=1 labels an exact-source component library test;
# this does not establish that the complete standalone product builds or passes.
# With no FRANKENLIBC_LIB, this mode builds the production module using RUSTC
# (default rustc) and FRANKENLIBC_UNWIND_LIBC_RLIB from the repository toolchain.
# Build that small dependency with `cargo build -p libc --release` if necessary.
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
  "_Unwind_ForcedUnwind"
  "_Unwind_GetCFA"
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

OUT_DIR="${FRANKENLIBC_UNWIND_OUT_DIR:-${REPO_ROOT}/target/owned_unwinder_e2e}"
mkdir -p "${OUT_DIR}"
if [[ "${FRANKENLIBC_UNWIND_COMPONENT:-0}" == 1 ]]; then
  VALIDATION_SCOPE="exact_source_component"
else
  VALIDATION_SCOPE="supplied_standalone_artifact"
fi

# Test 6: Build and run a shared C++ fixture whose _Unwind symbols resolve to FrankenLibC.
echo "--- Test 6: Physical C++ unwinding (${VALIDATION_SCOPE}) ---"
LIB_PATH="${FRANKENLIBC_LIB:-}"
if [[ -z "${LIB_PATH}" && "${FRANKENLIBC_UNWIND_COMPONENT:-0}" == 1 ]]; then
  LIBC_RLIB="${FRANKENLIBC_UNWIND_LIBC_RLIB:-}"
  if [[ -z "${LIBC_RLIB}" || ! -f "${LIBC_RLIB}" ]]; then
    echo "FAIL: component build requires FRANKENLIBC_UNWIND_LIBC_RLIB from the pinned repository toolchain"
    echo "Build only libc with cargo build -p libc --release, then supply its liblibc-*.rlib path."
    exit 1
  fi
  LIBC_ARGS=(--extern "libc=${LIBC_RLIB}")
  # Newer Cargo can emit a separate metadata sidecar beside an otherwise
  # metadata-only rlib. Pass it when present; ordinary rlibs need no sidecar.
  if [[ -f "${LIBC_RLIB%.rlib}.rmeta" ]]; then
    LIBC_ARGS+=(--extern "libc=${LIBC_RLIB%.rlib}.rmeta")
  fi
  COMPONENT_SOURCE="${OUT_DIR}/owned_unwind_component.rs"
  LIB_PATH="${OUT_DIR}/libowned_unwind_component.so"
  cat > "${COMPONENT_SOURCE}" <<EOF
// Exact production module with the real host loader's public ABI catalog.
// This does not build the standalone libc or substitute synthetic frame data.
pub mod dlfcn_abi {
    use std::ffi::{c_int, c_void};
    unsafe extern "C-unwind" {
        pub fn dl_iterate_phdr(
            callback: Option<
                unsafe extern "C-unwind" fn(*mut libc::dl_phdr_info, usize, *mut c_void) -> c_int,
            >,
            data: *mut c_void,
        ) -> c_int;
    }
}
#[path = "${UNWIND_ABI}"]
pub mod owned_unwind_abi;
EOF
  sha256sum "${UNWIND_ABI}" > "${OUT_DIR}/component-source-before.sha256"
  "${RUSTC:-rustc}" --edition=2024 --crate-name owned_unwind_component --crate-type=cdylib \
    -O -Zthreads=1 -Dwarnings -Cdebug-assertions=no -Cpanic=abort \
    -Cforce-unwind-tables=yes -Clink-arg=-Wl,--as-needed \
    --cfg 'feature="standalone"' --cfg 'feature="owned-unwind-stub"' \
    "${LIBC_ARGS[@]}" "${COMPONENT_SOURCE}" -o "${LIB_PATH}"
  sha256sum "${UNWIND_ABI}" > "${OUT_DIR}/component-source-after.sha256"
  cmp "${OUT_DIR}/component-source-before.sha256" "${OUT_DIR}/component-source-after.sha256"
  sha256sum "${LIB_PATH}" > "${OUT_DIR}/component-artifact.sha256"
fi
if [[ -z "${LIB_PATH}" ]]; then
  if [[ -n "${CARGO_TARGET_DIR:-}" && -f "${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so" ]]; then
    LIB_PATH="${CARGO_TARGET_DIR}/release/libfrankenlibc_abi.so"
  elif [[ -f "${REPO_ROOT}/target/release/libfrankenlibc_abi.so" ]]; then
    LIB_PATH="${REPO_ROOT}/target/release/libfrankenlibc_abi.so"
  fi
fi

if [[ -z "${LIB_PATH}" || ! -f "${LIB_PATH}" ]]; then
  echo "FAIL: set FRANKENLIBC_LIB to a standalone+owned-unwind-stub library or an explicitly labeled exact-source component"
  exit 1
fi

FIXTURE_SRC="${REPO_ROOT}/tests/conformance/fixtures/unwind/minimal_throw_catch.cpp"
for variant in frame_pointer omit_frame_pointer; do
  if [[ "${variant}" == frame_pointer ]]; then
    FRAME_FLAG=-fno-omit-frame-pointer
  else
    FRAME_FLAG=-fomit-frame-pointer
  fi
  OWNED_SO="${OUT_DIR}/minimal_throw_catch_${variant}.so"
  HOST_BIN="${OUT_DIR}/minimal_throw_catch_host_${variant}"
  FIXTURE_FLAGS=(-std=c++17 -O2 "${FRAME_FLAG}" -DFRANKENLIBC_WRAP_CXA_THROW
                 -DFRANKENLIBC_WRAP_PERSONALITY -Wl,--wrap=__cxa_throw
                 -Wl,--wrap=__gxx_personality_v0)
  g++ "${FIXTURE_FLAGS[@]}" -static-libstdc++ "${FIXTURE_SRC}" -o "${HOST_BIN}"
  g++ "${FIXTURE_FLAGS[@]}" -fPIC -shared -nodefaultlibs \
    -o "${OWNED_SO}" "${FIXTURE_SRC}" \
    -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic -lc -lm \
    -Wl,--exclude-libs,ALL -Wl,--allow-shlib-undefined

  if ldd "${OWNED_SO}" | grep -E 'libgcc_s|libunwind'; then
    echo "FAIL: owned shared fixture must not load libgcc_s or libunwind"
    exit 1
  fi
  for sym in _Unwind_RaiseException _Unwind_Resume _Unwind_ForcedUnwind _Unwind_GetCFA; do
    if ! nm -D "${OWNED_SO}" | grep -q " U ${sym}$"; then
      echo "FAIL: owned shared fixture must leave ${sym} unresolved for the owned library"
      exit 1
    fi
  done
  if nm --defined-only "${OWNED_SO}" | grep -E ' [Tt] _Unwind_'; then
    echo "FAIL: owned shared fixture defines an unwinder locally"
    exit 1
  fi

  for case_name in ordinary forced rethrow end negative missing_fde boundary; do
    if [[ "${case_name}" != missing_fde && "${case_name}" != boundary ]]; then
      echo "Running ${variant}/${case_name} host reference"
      "${HOST_BIN}" "${case_name}" > "${OUT_DIR}/host_${variant}_${case_name}.log"
      cat "${OUT_DIR}/host_${variant}_${case_name}.log"
    else
      echo "Checking owned unsupported-input policy: stop may consume an absent-FDE cursor; otherwise it is an error"
    fi
    echo "Running ${variant}/${case_name} owned unwinder"
    python3 - "${LIB_PATH}" "${OWNED_SO}" "${case_name}" > "${OUT_DIR}/owned_${variant}_${case_name}.log" <<'PY'
import ctypes
import os
import struct
import subprocess
import sys

lib_path = os.path.abspath(sys.argv[1])
fixture_path = os.path.abspath(sys.argv[2])
case_name = sys.argv[3]

def reject_host_unwinder(stage):
    with open("/proc/self/maps", encoding="utf-8") as maps:
        forbidden = [line.strip() for line in maps
                     if "libgcc_s" in line or "libunwind" in line]
    if forbidden:
        raise SystemExit(f"host unwinder mapped {stage}: {forbidden}")

reject_host_unwinder("before loading candidate")
franken = ctypes.CDLL(lib_path, mode=os.RTLD_GLOBAL)
libdl = ctypes.CDLL("libdl.so.2")
libdl.dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
libdl.dlsym.restype = ctypes.c_void_p

class DlInfo(ctypes.Structure):
    _fields_ = [("filename", ctypes.c_char_p), ("base", ctypes.c_void_p),
                ("symbol", ctypes.c_char_p), ("address", ctypes.c_void_p)]

libdl.dladdr.argtypes = [ctypes.c_void_p, ctypes.POINTER(DlInfo)]
libdl.dladdr.restype = ctypes.c_int
undefined = subprocess.check_output(["nm", "-D", "--undefined-only", fixture_path], text=True)
unwind_symbols = sorted({line.split()[-1] for line in undefined.splitlines()
                         if line.split() and line.split()[-1].startswith("_Unwind_")})
for name in unwind_symbols:
    owned_address = libdl.dlsym(franken._handle, name.encode())
    default_address = libdl.dlsym(None, name.encode())
    info = DlInfo()
    if (not owned_address or owned_address != default_address or
        not libdl.dladdr(default_address, ctypes.byref(info)) or
        not info.filename or not os.path.samefile(os.fsdecode(info.filename), lib_path)):
        raise SystemExit(f"{name} did not resolve to the supplied owned library")
fixture = ctypes.CDLL(fixture_path, mode=os.RTLD_GLOBAL)
reject_host_unwinder("after loading fixture")
with open(fixture_path, "rb") as elf_file:
    elf = elf_file.read()
if elf[:4] != b"\x7fELF" or elf[4] != 2 or elf[5] != 1:
    raise SystemExit("owned shared fixture must be ELF64 little-endian")
program_offset = struct.unpack_from("<Q", elf, 32)[0]
program_entry_size = struct.unpack_from("<H", elf, 54)[0]
program_count = struct.unpack_from("<H", elf, 56)[0]
gnu_eh_frame = False
for index in range(program_count):
    offset = program_offset + index * program_entry_size
    p_type = struct.unpack_from("<I", elf, offset)[0]
    if p_type == 0x6474E550:
        gnu_eh_frame = True
        break
if not gnu_eh_frame:
    raise SystemExit("owned shared fixture has no PT_GNU_EH_FRAME header")
entries = {
    "ordinary": "minimal_throw_catch_entry",
    "forced": "owned_forced_unwind_entry",
    "rethrow": "owned_forced_unwind_rethrow_entry",
    "end": "owned_forced_unwind_end_entry",
    "negative": "owned_unwind_negative_entry",
    "missing_fde": "owned_unwind_missing_fde_entry",
    "boundary": "owned_forced_unwind_boundary_entry",
}
entry_name = entries[case_name]
entry = getattr(fixture, entry_name)
entry.argtypes = []
entry.restype = ctypes.c_int
result = entry()
if result != 0:
    raise SystemExit(f"{entry_name} returned {result}")
reject_host_unwinder("after executing fixture")
PY
    cat "${OUT_DIR}/owned_${variant}_${case_name}.log"
  done
done

echo "PASS: C++ cleanup/resume, forced stop ordering, terminal callbacks and errors passed in both frame layouts"
echo ""

# Write summary JSON
SUMMARY_FILE="${OUT_DIR}/owned_unwinder_e2e.v1.json"
cat > "${SUMMARY_FILE}" <<EOF
{
  "schema_version": "owned_unwinder_e2e.v1",
  "bead_id": "bd-b2m2h6",
  "generated_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "validation_scope": "${VALIDATION_SCOPE}",
  "tests": {
    "source_symbols_defined": "pass",
    "feature_flags_defined": "pass",
    "module_gating_correct": "pass",
    "conformance_artifacts_present": "pass",
    "conformance_tests_present": "pass",
    "owned_shared_fixture_no_libgcc": "pass",
    "owned_shared_fixture_pt_gnu_eh_frame": "pass",
    "owned_shared_fixture_throw_catch": "pass",
    "owned_nested_raii_cleanup_resume": "pass",
    "owned_callee_saved_cleanup_values": "pass",
    "owned_resume_without_phase1_rerun": "pass",
    "owned_forced_stop_before_personality": "pass",
    "owned_forced_catch_rethrow_preserves_state": "pass",
    "owned_forced_cfa_matches_suspended_stack": "pass",
    "owned_forced_terminal_callback": "pass",
    "owned_stop_error_normalization": "pass",
    "owned_missing_fde_fails_without_false_terminal_callback": "pass",
    "owned_stop_can_finish_at_native_style_no_cfi_boundary": "pass",
    "owned_exception_cleanup_exactly_once": "pass",
    "all_used_unwind_symbols_owned": "pass",
    "no_host_unwinder_mapped": "pass",
    "host_reference_assertions": "pass",
    "optimized_frame_pointer_and_omitted_frame_pointer": "pass"
  },
  "implementation_status": {
    "source_file": "crates/frankenlibc-abi/src/owned_unwind_abi.rs",
    "feature_flags": ["standalone", "owned-unwind-stub"],
    "owned_throw_catch_fixture": {
      "library": "${LIB_PATH}",
      "variants": ["frame_pointer", "omit_frame_pointer"],
      "dependency_policy": "no libgcc_s or libunwind dependencies or runtime mappings; every used _Unwind symbol resolves inside the supplied library",
      "loaded_object_catalog_policy": "no manual __register_frame call; discover the fixture PT_GNU_EH_FRAME through the supplied library's loader catalog"
    },
    "scope_limit": "Component validation does not establish full standalone product readiness, native pthread cancellation integration, or Rust Drop behavior"
  },
  "overall_status": "pass"
}
EOF

echo "Summary: ${SUMMARY_FILE}"
echo ""
echo "Validation scope: ${VALIDATION_SCOPE}; full standalone readiness and native pthread/Rust integration require their own gates."
echo ""
echo "PASS: Owned unwinder E2E verified"
exit 0
