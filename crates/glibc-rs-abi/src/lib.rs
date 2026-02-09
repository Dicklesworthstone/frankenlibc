//! # glibc-rs-abi
//!
//! ABI-compatible extern "C" boundary layer for glibc_rust.
//!
//! This crate produces a `cdylib` (`libc.so`) that exposes POSIX/C standard library
//! functions via `extern "C"` symbols. Each function passes through the membrane
//! validation pipeline before delegating to the safe implementations in `glibc-rs-core`.
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

#[macro_use]
mod macros;

mod runtime_policy;

// Bootstrap ABI modules (Phase 1 - implemented)
// Gated behind cfg(not(test)) because these modules export #[no_mangle] symbols
// (malloc, free, memcpy, strlen, ...) that would shadow the system allocator and
// libc in the test binary, causing infinite recursion or deadlock.
#[cfg(not(test))]
pub mod malloc_abi;
#[cfg(not(test))]
pub mod string_abi;

// Stub ABI modules (Phase 2+ - pending implementation)
pub mod ctype_abi;
pub mod dirent_abi;
pub mod dlfcn_abi;
pub mod errno_abi;
pub mod iconv_abi;
pub mod inet_abi;
pub mod io_abi;
pub mod locale_abi;
pub mod math_abi;
#[cfg(not(test))]
pub mod pthread_abi;
#[cfg(not(test))]
pub mod resolv_abi;
pub mod resource_abi;
pub mod setjmp_abi;
pub mod signal_abi;
pub mod socket_abi;
pub mod stdio_abi;
pub mod stdlib_abi;
pub mod termios_abi;
pub mod time_abi;
pub mod unistd_abi;
