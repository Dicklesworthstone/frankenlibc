//! # frankenlibc-core
//!
//! Safe Rust implementations of C standard library (libc) functions.
//!
//! This crate provides pure-Rust, safe implementations of POSIX and C standard
//! library functions. No `unsafe` code is permitted at the crate level.

#![deny(unsafe_code)]

pub mod ctype;
pub mod dirent;
pub mod dlfcn;
pub mod elf;
pub mod errno;
pub mod grp;
pub mod iconv;
pub mod inet;
pub mod io;
pub mod locale;
pub mod malloc;
pub mod math;
pub mod mmap;
pub mod poll;
pub mod process;
pub mod pthread;
pub mod pwd;
#[allow(unsafe_code)]
pub mod rcu;
pub mod resolv;
pub mod resource;
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
