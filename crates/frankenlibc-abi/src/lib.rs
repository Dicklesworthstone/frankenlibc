#![feature(c_variadic)]
#![feature(rtm_target_feature)]
#![feature(stdarch_x86_rtm)]
#![allow(unused_features)]
// All extern "C" ABI exports accept raw pointers from C callers; the membrane
// validates at runtime, so per-function safety docs would be redundant boilerplate.
#![allow(clippy::missing_safety_doc)]
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

#[macro_use]
mod macros;

pub(crate) mod host_resolve;
#[doc(hidden)]
pub mod htm_fast_path;
mod membrane_state;
mod runtime_policy;

#[cfg(feature = "conformance-testing")]
pub use runtime_policy::conformance_testing;

// Bootstrap ABI modules (Phase 1 - implemented)
// Gated behind cfg(not(test)) because these modules export #[no_mangle] symbols
// (malloc, free, memcpy, strlen, ...) that would shadow the system allocator and
// libc in the test binary, causing infinite recursion or deadlock.
#[cfg(not(test))]
pub mod malloc_abi;
#[cfg(not(test))]
pub mod stdlib_abi;
#[cfg(not(test))]
pub mod string_abi;
#[cfg(not(test))]
pub mod wchar_abi;

// Phase 2 ABI modules — pure Rust delegates (safe in test mode)
pub mod ctype_abi;
pub mod errno_abi;
pub mod locale_abi;
pub mod math_abi;
pub mod startup_helpers;
pub mod stdbit_abi;

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
