//! Descriptor and errno frontends for natively loaded plugins.
//!
//! Reuse the existing ABI implementations, including their cancellation,
//! membrane, descriptor-offset tracking and errno behavior. In particular,
//! never bind native IO to one errno provider and __errno_location to another.
//! This table is consumed by both relocation and caller-relative lookup.

use crate::{errno_abi as errno, io_abi as io, unistd_abi as unistd};

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    // The newer *at and pipe2/dup3 interfaces predate AArch64's baseline,
    // but have their own compatibility versions on x86-64.
    let introduced = match name {
        "openat" | "openat64" => "GLIBC_2.4",
        "pipe2" | "dup3" => "GLIBC_2.9",
        _ => "GLIBC_2.2.5",
    };
    let supported = if cfg!(target_arch = "aarch64") { "GLIBC_2.17" } else { introduced };
    if version.is_some_and(|version| version != supported) { return None; }
    // Taking a function address preserves its actual ABI: open/openat remain
    // C-variadic and cancellation points remain extern "C-unwind". There is
    // no fixed-arity shim that could read a nonexistent mode argument.
    let address = match name {
        "__errno_location" => errno::__errno_location as *const (),
        "open" => unistd::open as *const (),
        "open64" => unistd::open64 as *const (),
        "openat" => unistd::openat as *const (),
        "openat64" => unistd::openat64 as *const (),
        "creat" => unistd::creat as *const (),
        "read" => unistd::read as *const (),
        "write" => unistd::write as *const (),
        "close" => unistd::close as *const (),
        "lseek" => unistd::lseek as *const (),
        "lseek64" => unistd::lseek64 as *const (),
        "pread" => io::pread as *const (),
        "pread64" => io::pread64 as *const (),
        "pwrite" => io::pwrite as *const (),
        "pwrite64" => io::pwrite64 as *const (),
        "readv" => io::readv as *const (),
        "writev" => io::writev as *const (),
        "ftruncate" => io::ftruncate as *const (),
        "ftruncate64" => io::ftruncate64 as *const (),
        "fsync" => unistd::fsync as *const (),
        "fdatasync" => unistd::fdatasync as *const (),
        "dup" => io::dup as *const (),
        "dup2" => io::dup2 as *const (),
        "dup3" => io::dup3 as *const (),
        "pipe" => io::pipe as *const (),
        "pipe2" => io::pipe2 as *const (),
        _ => return None,
    };
    Some(address as usize as u64)
}
