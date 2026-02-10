#![feature(c_variadic)]
// All extern "C" ABI exports accept raw pointers from C callers; the membrane
// validates at runtime, so per-function safety docs would be redundant boilerplate.
#![allow(clippy::missing_safety_doc)]
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

mod membrane_state;
mod runtime_policy;

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
pub mod math_abi;

// Phase 2+ ABI modules — call libc syscalls, gated to prevent symbol recursion in tests
#[cfg(not(test))]
pub mod dirent_abi;
#[cfg(not(test))]
pub mod dlfcn_abi;
pub mod iconv_abi;
#[cfg(not(test))]
pub mod inet_abi;
#[cfg(not(test))]
pub mod io_abi;
#[cfg(not(test))]
pub mod locale_abi;
#[cfg(not(test))]
pub mod mmap_abi;
#[cfg(not(test))]
pub mod poll_abi;
#[cfg(not(test))]
pub mod process_abi;
#[cfg(not(test))]
pub mod pthread_abi;
#[cfg(not(test))]
pub mod resolv_abi;
#[cfg(not(test))]
pub mod resource_abi;
pub mod setjmp_abi;
#[cfg(not(test))]
pub mod signal_abi;
#[cfg(not(test))]
pub mod socket_abi;
#[cfg(not(test))]
pub mod stdio_abi;
#[cfg(not(test))]
pub mod termios_abi;
#[cfg(not(test))]
pub mod time_abi;
#[cfg(not(test))]
pub mod unistd_abi;

pub mod util;
