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
# For split metadata, supply FRANKENLIBC_UNWIND_LIBC_RMETA from the same Cargo
# compiler-artifact message; a same-name sibling remains the local fallback.
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
  # Cargo can publish liblibc.rlib at the profile root while retaining its
  # full metadata and hashed link artifact in a different output directory.
  # Use the matching filename Cargo reported, not a guessed top-level sidecar.
  LIBC_RMETA="${FRANKENLIBC_UNWIND_LIBC_RMETA:-${LIBC_RLIB%.rlib}.rmeta}"
  if [[ -n "${FRANKENLIBC_UNWIND_LIBC_RMETA:-}" && ! -f "${LIBC_RMETA}" ]]; then
    echo "FAIL: FRANKENLIBC_UNWIND_LIBC_RMETA does not name an existing metadata artifact"
    exit 1
  fi
  if [[ -f "${LIBC_RMETA}" ]]; then
    LIBC_ARGS+=(--extern "libc=${LIBC_RMETA}" -L "dependency=$(dirname "${LIBC_RMETA}")")
  fi
  COMPONENT_SOURCE="${OUT_DIR}/owned_unwind_component.rs"
  LIB_PATH="${OUT_DIR}/libowned_unwind_component.so"
  cat > "${COMPONENT_SOURCE}" <<EOF
// Exact production unwinder with host boundaries for this component test.
// Frame decoding, personalities, register recovery, and context installation
// all execute the production module below. This does not build standalone libc.
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
pub mod pthread_abi {
    pub fn address_is_inside_this_object(address: usize) -> bool {
        // dladdr describes the actual loaded component, not a synthetic range.
        unsafe {
            let mut own: libc::Dl_info = std::mem::zeroed();
            let mut target: libc::Dl_info = std::mem::zeroed();
            libc::dladdr(address_is_inside_this_object as *const () as *const _, &mut own) != 0
                && libc::dladdr(address as *const _, &mut target) != 0
                && !own.dli_fbase.is_null()
                && own.dli_fbase == target.dli_fbase
        }
    }
}
pub mod malloc_abi {
    pub fn in_allocator_reentry_context() -> bool {
        // This component uses the host allocator, which does not enter the
        // full ABI crate's allocator reentry guard. No allocator is emulated.
        false
    }
    pub fn known_remaining(_address: usize) -> Option<usize> {
        // Host allocations have no entry in the standalone allocator's table.
        // The unwinder calls copy_user_bytes_raw, which bypasses that table.
        None
    }
}
pub mod stdlib_abi {
    pub unsafe fn native_getenv(name: &[u8]) -> *mut libc::c_char {
        let Ok(name) = std::ffi::CString::new(name) else {
            return std::ptr::null_mut();
        };
        unsafe { libc::getenv(name.as_ptr()) }
    }
}
pub mod signal_abi {
    // A real Linux restorer entry for this object's identity. Signals installed
    // by the host fixture use their host restorer, recognized by the production
    // unwinder's fault-checked instruction decoder.
    #[unsafe(naked)]
    unsafe extern "C" fn component_rt_sigreturn() -> ! {
        std::arch::naked_asm!("mov rax, 15", "syscall");
    }
    pub fn signal_restorer_trampoline_addr() -> usize {
        component_rt_sigreturn as *const () as usize
    }
}
// Compile the actual production byte importer, including its bounded private
// pipe fallback when a sandbox denies process_vm_readv. Its only core imports
// here are Linux errno values and raw kernel calls; no copy behavior is stubbed.
extern crate self as frankenlibc_core;
pub mod errno {
    pub use libc::{EACCES, EFAULT, EINVAL, EIO, ENOMEM, ENOSYS, EPERM};
}
pub mod syscall {
    pub unsafe fn syscall6(nr: usize, a1: usize, a2: usize, a3: usize,
                           a4: usize, a5: usize, a6: usize) -> usize {
        let result;
        unsafe {
            std::arch::asm!(
                "syscall", inlateout("rax") nr => result,
                in("rdi") a1, in("rsi") a2, in("rdx") a3,
                in("r10") a4, in("r8") a5, in("r9") a6,
                lateout("rcx") _, lateout("r11") _, options(nostack),
            );
        }
        result
    }
    pub unsafe fn syscall0(nr: usize) -> usize {
        unsafe { syscall6(nr, 0, 0, 0, 0, 0, 0) }
    }
    pub unsafe fn syscall1(nr: usize, a1: usize) -> usize {
        unsafe { syscall6(nr, a1, 0, 0, 0, 0, 0) }
    }
    pub unsafe fn syscall2(nr: usize, a1: usize, a2: usize) -> usize {
        unsafe { syscall6(nr, a1, a2, 0, 0, 0, 0) }
    }
    pub unsafe fn syscall3(nr: usize, a1: usize, a2: usize, a3: usize) -> usize {
        unsafe { syscall6(nr, a1, a2, a3, 0, 0, 0) }
    }
}
pub mod io_abi {
    #[allow(dead_code)]
    #[path = "${REPO_ROOT}/crates/frankenlibc-abi/src/iov_snapshot.rs"]
    pub mod iov_snapshot;
}
#[path = "${UNWIND_ABI}"]
pub mod owned_unwind_abi;
EOF
  sha256sum "${UNWIND_ABI}" "${REPO_ROOT}/crates/frankenlibc-abi/src/iov_snapshot.rs" \
    > "${OUT_DIR}/component-source-before.sha256"
  "${RUSTC:-rustc}" --edition=2024 --crate-name owned_unwind_component --crate-type=cdylib \
    -O -Zthreads=1 -Ccodegen-units=1 -Dwarnings -Cdebug-assertions=no -Cpanic=abort \
    -Cforce-unwind-tables=yes -Clink-arg=-Wl,--as-needed \
    --cfg 'feature="standalone"' --cfg 'feature="owned-unwind-stub"' \
    "${LIBC_ARGS[@]}" "${COMPONENT_SOURCE}" -o "${LIB_PATH}"
  sha256sum "${UNWIND_ABI}" "${REPO_ROOT}/crates/frankenlibc-abi/src/iov_snapshot.rs" \
    > "${OUT_DIR}/component-source-after.sha256"
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
  FIXTURE_FLAGS=(-std=c++17 -O2 -fPIC "${FRAME_FLAG}" -DFRANKENLIBC_WRAP_CXA_THROW
                 -DFRANKENLIBC_WRAP_PERSONALITY -Wl,--wrap=__cxa_throw
                 -Wl,--wrap=__gxx_personality_v0)
  g++ "${FIXTURE_FLAGS[@]}" -static-libstdc++ "${FIXTURE_SRC}" -o "${HOST_BIN}"
  g++ "${FIXTURE_FLAGS[@]}" -shared -nodefaultlibs \
    -o "${OWNED_SO}" "${FIXTURE_SRC}" \
    -Wl,-Bstatic -lstdc++ -Wl,-Bdynamic -lc -lm \
    -Wl,--exclude-libs,ALL -Wl,--allow-shlib-undefined

  # Verify the compiler retained the call-site condition this regression needs.
  readelf --debug-dump=frames "${OWNED_SO}" > "${OUT_DIR}/frames_${variant}.txt"
  python3 - "${OWNED_SO}" "${OUT_DIR}/frames_${variant}.txt" <<'PY'
import re
import subprocess
import sys

symbols = subprocess.check_output(
    ["nm", "--defined-only", "--demangle", sys.argv[1]], text=True)
addresses = [int(fields[0], 16) for line in symbols.splitlines()
             if len(fields := line.split(maxsplit=2)) == 3
             and fields[2] == "(anonymous namespace)::stack_argument_frame(unsigned int)"]
if len(addresses) != 1:
    raise SystemExit("FAIL: expected one stack_argument_frame implementation")
with open(sys.argv[2], encoding="utf-8") as stream:
    frames = stream.read()
for record in frames.split("\n\n"):
    pc = re.search(r"FDE.*\bpc=([0-9a-f]+)\.\.([0-9a-f]+)", record)
    if pc and int(pc[1], 16) <= addresses[0] < int(pc[2], 16):
        if re.search(r"DW_CFA_GNU_args_size: [1-9][0-9]*", record):
            break
else:
    raise SystemExit("FAIL: stack_argument_frame has no nonzero DW_CFA_GNU_args_size")
PY

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

  for case_name in ordinary forced rethrow signal signal_altstack end negative missing_fde boundary deep_ordinary deep_forced stack_arguments_ordinary stack_arguments_forced; do
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
    "signal": "owned_signal_unwind_entry",
    "signal_altstack": "owned_signal_unwind_entry",
    "end": "owned_forced_unwind_end_entry",
    "negative": "owned_unwind_negative_entry",
    "missing_fde": "owned_unwind_missing_fde_entry",
    "boundary": "owned_forced_unwind_boundary_entry",
    "deep_ordinary": "owned_deep_ordinary_entry",
    "deep_forced": "owned_deep_forced_entry",
    "stack_arguments_ordinary": "owned_stack_arguments_ordinary_entry",
    "stack_arguments_forced": "owned_stack_arguments_forced_entry",
}
entry_name = entries[case_name]
entry = getattr(fixture, entry_name)
entry.restype = ctypes.c_int
if case_name in ("signal", "signal_altstack"):
    entry.argtypes = [ctypes.c_int]
    result = entry(int(case_name == "signal_altstack"))
else:
    entry.argtypes = []
    result = entry()
if result != 0:
    raise SystemExit(f"{entry_name} returned {result}")
reject_host_unwinder("after executing fixture")
PY
    cat "${OUT_DIR}/owned_${variant}_${case_name}.log"
    if [[ "${case_name}" == deep_ordinary || "${case_name}" == deep_forced ||
          "${case_name}" == stack_arguments_ordinary || "${case_name}" == stack_arguments_forced ]]; then
      cmp "${OUT_DIR}/host_${variant}_${case_name}.log" \
          "${OUT_DIR}/owned_${variant}_${case_name}.log"
    fi
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
    "owned_signal_frame_cfi_and_interrupted_gprs": "pass",
    "owned_signal_frame_ip_info": "pass",
    "owned_signal_altstack_transition": "pass",
    "owned_forced_cfa_matches_suspended_stack": "pass",
    "owned_forced_terminal_callback": "pass",
    "owned_stop_error_normalization": "pass",
    "owned_missing_fde_fails_without_false_terminal_callback": "pass",
    "owned_stop_can_finish_at_native_style_no_cfi_boundary": "pass",
    "owned_exception_cleanup_exactly_once": "pass",
    "nonzero_gnu_args_size_cfi_present": "pass",
    "owned_stack_arguments_cleanup_matches_host": "pass",
    "owned_stack_arguments_forced_resume_matches_host": "pass",
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
