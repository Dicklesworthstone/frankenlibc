#![feature(c_variadic)]
#![feature(f128)]
#![feature(portable_simd)]
#![cfg_attr(target_arch = "x86_64", feature(rtm_target_feature))]
#![cfg_attr(target_arch = "x86_64", feature(stdarch_x86_rtm))]
#![feature(thread_local)]
#![allow(unused_features)]
// All extern "C" ABI exports accept raw pointers from C callers; the membrane
// validates at runtime, so per-function safety docs would be redundant boilerplate.
#![allow(clippy::missing_safety_doc)]
#![allow(invalid_runtime_symbol_definitions)]
//! # frankenlibc-abi
//!
//! ABI-compatible extern "C" boundary layer for frankenlibc.
//!
//! This crate produces a `cdylib` (`libc.so`) that exposes POSIX/C standard library
//! functions via `extern "C"` symbols. Each function passes through the membrane
//! validation pipeline before delegating to the safe implementations in `frankenlibc-core`.
//!
//! # Architecture
//!
//! ```text
//! C caller -> ABI entry (this crate) -> Membrane validation -> Core impl -> return
//! ```
//!
//! In **strict** mode, the membrane validates but does not silently rewrite operations.
//! Invalid operations produce POSIX-correct error returns.
//!
//! In **hardened** mode, the membrane validates AND applies deterministic healing
//! (clamp, truncate, quarantine, safe-default) for unsafe patterns.

// Architecture support matrix (bd-10pq). The ABI has inline asm
// (setjmp_abi.rs global_asm!), x86-specific intrinsics (RTM in
// htm_fast_path), and raw-syscall sequences that assume a
// specific ABI register layout. Until each ISA has its own
// validated code-path, fail at compile time with a clear
// message rather than silently producing a broken .so.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "frankenlibc-abi currently supports only target_arch = \"x86_64\" \
    (primary) and \"aarch64\" (active bring-up). RISC-V and other \
    ISAs are tracked under bd-10pq — they need per-ISA inline asm \
    (setjmp_abi), intrinsic replacements (htm_fast_path), and \
    raw-syscall sequences before this crate can build on them."
);

#[cfg(all(feature = "owned-unwind-stub", not(feature = "standalone")))]
compile_error!("owned-unwind-stub is only valid for opt-in standalone experiments");

#[macro_use]
mod macros;

pub(crate) mod host_resolve;
#[doc(hidden)]
pub mod htm_fast_path;
mod membrane_state;
#[cfg(feature = "owned-tls-cache")]
mod owned_tls_cache;
mod runtime_policy;
/// Address-derived slab ownership test (bd-e0y02p).
///
/// `pub` rather than `pub(crate)` because the design's first measurement has to
/// come from an integration test or bench: this crate gates its inline
/// `#[cfg(test)]` modules behind `cfg(not(test))`, so a unit test written here
/// would never compile (bd-0z7a1y). Not yet reachable from `malloc`/`free` --
/// the ownership test is measured before the allocator is rewired.
pub mod slab_region;

#[cfg(feature = "conformance-testing")]
pub use runtime_policy::conformance_testing;

// Bootstrap ABI modules (Phase 1 - implemented)
// Gated behind cfg(not(test)) because these modules export #[no_mangle] symbols
// (malloc, free, memcpy, strlen, ...) that would shadow the system allocator and
// libc in the test binary, causing infinite recursion or deadlock.
#[cfg(not(test))]
pub mod malloc_abi;
#[cfg(all(not(test), feature = "standalone", feature = "owned-unwind-stub"))]
pub mod owned_unwind_abi;
#[cfg(not(test))]
pub mod stdlib_abi;
#[cfg(not(test))]
pub mod string_abi;
#[cfg(not(test))]
pub mod wchar_abi;

// Phase 2 ABI modules — pure Rust delegates (safe in test mode)
pub mod ctype_abi;
mod erf_tables;
pub mod errno_abi;
mod expl_table;
pub mod locale_abi;
pub mod math_abi;
pub mod startup_helpers;
pub mod stdbit_abi;
mod trig_tables;

/// A build compiled for x86-64-v3 (`+avx2,+fma` in `.cargo/config.toml`)
/// executes AVX2 instructions throughout, so on an older CPU the process
/// died of SIGILL inside memcpy, before main and even before this library's
/// constructors: another library's constructor (libselinux's) calls our
/// `sysconf` first. Refuse with a message instead (bd-rc0923-epic-eeuy4f.13).
///
/// The check runs as the resolver of a hidden IFUNC that a `#[used]` static
/// points at: the loader resolves that IRELATIVE relocation while relocating
/// this object, before any constructor anywhere. The resolver is
/// integer-only (`cpuid`, `xgetbv`, raw syscalls).
#[cfg(all(
    not(test),
    target_os = "linux",
    target_arch = "x86_64",
    any(target_feature = "avx2", target_feature = "fma")
))]
mod cpu_guard {
    core::arch::global_asm!(
        ".globl __frankenlibc_cpu_guard",
        ".hidden __frankenlibc_cpu_guard",
        ".type __frankenlibc_cpu_guard, @gnu_indirect_function",
        ".set __frankenlibc_cpu_guard, {resolver}",
        resolver = sym resolve,
    );

    unsafe extern "C" {
        fn __frankenlibc_cpu_guard();
    }

    #[used]
    static FORCE_IRELATIVE: unsafe extern "C" fn() = __frankenlibc_cpu_guard;

    extern "C" fn noop() {}

    #[inline(never)]
    extern "C" fn resolve() -> usize {
        const MESSAGE: &[u8] = b"frankenlibc: this libfrankenlibc_abi.so was built for x86-64-v3 \
(AVX2 + FMA), which this CPU does not support; use a build without \
-Ctarget-feature=+avx2,+fma\n";
        // SAFETY: cpuid is available on every x86_64 CPU.
        let leaf1 = unsafe { core::arch::x86_64::__cpuid_count(1, 0) };
        // SAFETY: as above.
        let leaf7 = unsafe { core::arch::x86_64::__cpuid_count(7, 0) };
        let fma = leaf1.ecx & (1 << 12) != 0;
        let osxsave = leaf1.ecx & (1 << 27) != 0;
        let avx = leaf1.ecx & (1 << 28) != 0;
        let avx2 = leaf7.ebx & (1 << 5) != 0;
        // The OS must also save the YMM state (XCR0 bits 1 and 2).
        let ymm_state = osxsave && {
            let low: u32;
            // SAFETY: xgetbv(0) is valid when OSXSAVE is set, checked above.
            unsafe {
                core::arch::asm!(
                    "xgetbv",
                    in("ecx") 0u32,
                    out("eax") low,
                    out("edx") _,
                    options(nomem, nostack, preserves_flags),
                );
            }
            low & 0b110 == 0b110
        };
        if !(fma && avx && avx2 && ymm_state) {
            // SAFETY: write(2) of a static buffer, then exit_group.
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") 1usize => _,
                    in("rdi") 2usize,
                    in("rsi") MESSAGE.as_ptr(),
                    in("rdx") MESSAGE.len(),
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack),
                );
                core::arch::asm!(
                    "syscall",
                    in("rax") 231usize,
                    in("rdi") 127usize,
                    options(noreturn, nostack),
                );
            }
        }
        noop as usize
    }
}

#[cfg(all(not(test), target_os = "linux"))]
#[used]
#[unsafe(link_section = ".init_array")]
static FRANKENLIBC_ABI_INIT_ARRAY: extern "C" fn() = frankenlibc_abi_stdio_init_entry;

#[cfg(all(not(test), target_os = "linux"))]
#[inline(never)]
extern "C" fn frankenlibc_abi_stdio_init_entry() {
    // SAFETY: this runs during process initialization before user code and
    // publishes the stdio globals/aliases onto stable NativeFile storage while
    // patching host libio exit handling for the exported _IO symbols.
    stdio_abi::init_host_stdio_streams();
    runtime_policy::signal_runtime_ready();
    // Hardened mode: build the ~79 KB validation pipeline now, on the main
    // thread's stack, instead of lazily inside whichever thread first
    // validates — which may be a 32 KiB-stack worker (bd-rc0923-epic-eeuy4f.9).
    if runtime_policy::mode().heals_enabled() {
        let _ = membrane_state::try_global_pipeline();
    }
}

// Phase 2+ ABI modules — call libc syscalls, gated to prevent symbol recursion in tests
#[cfg(not(test))]
pub mod c11threads_abi;
#[cfg(not(test))]
pub mod dirent_abi;
#[cfg(not(test))]
pub mod dlfcn_abi;
#[cfg(not(test))]
pub mod efun_abi;
#[cfg(not(test))]
pub mod err_abi;
#[cfg(not(test))]
pub mod fenv_abi;
#[cfg(not(test))]
pub mod fortify_abi;
#[cfg(not(test))]
pub mod grp_abi;
#[cfg(not(test))]
pub mod iconv_abi;
#[cfg(not(test))]
pub mod inet_abi;
#[cfg(not(test))]
pub mod io_abi;
#[cfg(not(test))]
pub mod isoc_abi;
#[cfg(not(test))]
pub mod mmap_abi;
#[cfg(not(test))]
pub mod nlist_abi;
#[cfg(not(test))]
pub mod poll_abi;
#[cfg(not(test))]
pub mod process_abi;
#[cfg(not(test))]
pub mod pthread_abi;
#[cfg(not(test))]
pub mod pwd_abi;
#[cfg(not(test))]
pub mod resolv_abi;
#[cfg(not(test))]
pub mod resource_abi;
#[cfg(not(test))]
pub mod search_abi;
pub mod setjmp_abi;
#[cfg(not(test))]
pub mod signal_abi;
#[cfg(not(test))]
pub mod socket_abi;
#[cfg(not(test))]
pub mod startup_abi;
#[cfg(not(test))]
pub mod stdio_abi;
#[cfg(not(test))]
pub mod termios_abi;
#[cfg(not(test))]
pub mod time_abi;
#[cfg(not(test))]
pub mod unistd_abi;

// Massive glibc internal symbol coverage
#[cfg(not(test))]
pub mod glibc_internal_abi;
#[cfg(not(test))]
pub mod io_internal_abi;
#[cfg(not(test))]
pub mod rpc_abi;

pub mod util;
