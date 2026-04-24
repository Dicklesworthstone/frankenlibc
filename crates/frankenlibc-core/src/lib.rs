//! # frankenlibc-core
//!
//! Safe Rust implementations of C standard library (libc) functions.
//!
//! This crate provides pure-Rust, safe implementations of POSIX and C standard
//! library functions. No `unsafe` code is permitted at the crate level.

#![deny(unsafe_code)]

// Architecture support (bd-10pq): the `syscall` module gates below
// on x86_64 / aarch64 because each ISA needs its own validated
// register layout. Fail fast on other ISAs with a pointer to the
// tracking bead so build output is actionable.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!(
    "frankenlibc-core currently supports only target_arch = \"x86_64\" \
    and \"aarch64\". Multi-ISA tracking: bd-10pq. Each new ISA needs \
    per-arch raw-syscall register conventions in src/syscall/ before \
    this crate can build on it."
);

pub mod aliases;
pub mod ctype;
pub mod dirent;
pub mod dlfcn;
pub mod elf;
pub mod err;
pub mod errno;
pub mod ether;
pub mod ftw;
pub mod getopt;
pub mod grp;
pub mod iconv;
pub mod inet;
pub mod io;
pub mod locale;
pub mod malloc;
pub mod math;
pub mod mmap;
pub mod mntent;
pub mod netgroup;
pub mod poll;
pub mod process;
pub mod pthread;
pub mod pwd;
#[allow(unsafe_code)]
pub mod rcu;
pub mod resolv;
pub mod rpc;
pub mod resource;
pub mod search;
pub mod setjmp;
pub mod signal;
pub mod socket;
pub mod stdio;
pub mod stdlib;
pub mod string;
#[allow(unsafe_code)]
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub mod syscall;
pub mod termios;
pub mod time;
pub mod unistd;
