//! Descriptor, pathname, file metadata and errno frontends for native plugins.
//!
//! Reuse the existing ABI implementations, including their cancellation,
//! membrane, descriptor-offset tracking and errno behavior. In particular,
//! never bind native IO to one errno provider and __errno_location to another.
//! This table is consumed by both relocation and caller-relative lookup.

use crate::{errno_abi as errno, io_abi as io, unistd_abi as unistd};

#[path = "dlfcn_socket.rs"]
mod socket;

#[path = "dlfcn_event.rs"]
mod event;

#[path = "dlfcn_resolv.rs"]
mod resolv;

pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    if let Some(address) = socket::address(name, version) {
        return Some(address);
    }
    if let Some(address) = event::address(name, version) {
        return Some(address);
    }
    if let Some(address) = resolv::address(name, version) {
        return Some(address);
    }
    // The newer *at and pipe2/dup3 interfaces predate AArch64's baseline,
    // but have their own compatibility versions on x86-64.
    let introduced = match name {
        "openat" | "openat64" | "faccessat" | "readlinkat" => "GLIBC_2.4",
        "pipe2" | "dup3" => "GLIBC_2.9",
        _ => "GLIBC_2.2.5",
    };
    let supported = if matches!(name, "fcntl64" | "statx") {
        // These public interfaces postdate both architecture baselines.
        "GLIBC_2.28"
    } else if name == "execveat" {
        // Added after both architecture baselines.
        "GLIBC_2.34"
    } else if matches!(
        name,
        "stat" | "fstat" | "lstat" | "fstatat" | "stat64" | "fstat64" | "lstat64" | "fstatat64"
    ) {
        // Modern public stat entrypoints replaced the older __*xstat ABI on
        // both x86-64 and AArch64 in glibc 2.33.
        "GLIBC_2.33"
    } else if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        introduced
    };
    if version.is_some_and(|version| version != supported) {
        return None;
    }
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
        "creat64" => unistd::creat64 as *const (),
        "access" => unistd::access as *const (),
        "faccessat" => unistd::faccessat as *const (),
        "getcwd" => unistd::getcwd as *const (),
        "chdir" => unistd::chdir as *const (),
        "fchdir" => unistd::fchdir as *const (),
        "readlink" => unistd::readlink as *const (),
        "readlinkat" => unistd::readlinkat as *const (),
        "read" => unistd::read as *const (),
        "write" => unistd::write as *const (),
        "close" => unistd::close as *const (),
        "lseek" => unistd::lseek as *const (),
        "lseek64" => unistd::lseek64 as *const (),
        "pread" => io::pread as *const (),
        "pread64" => unistd::pread64 as *const (),
        "pwrite" => io::pwrite as *const (),
        "pwrite64" => unistd::pwrite64 as *const (),
        "readv" => io::readv as *const (),
        "writev" => io::writev as *const (),
        "ftruncate" => unistd::ftruncate as *const (),
        "ftruncate64" => unistd::ftruncate64 as *const (),
        "fsync" => unistd::fsync as *const (),
        "fdatasync" => unistd::fdatasync as *const (),
        "dup" => io::dup as *const (),
        "dup2" => io::dup2 as *const (),
        "dup3" => io::dup3 as *const (),
        "pipe" => io::pipe as *const (),
        "pipe2" => io::pipe2 as *const (),
        // On ELF64 both names have the same layout. Preserve the existing
        // variadic C-unwind entry rather than turning optional integer or
        // flock-pointer arguments into a fixed-arity function-pointer call.
        // Both routes retain the shared descriptor ledger and cancellation
        // handling used by the rest of native plugin IO.
        "fcntl" | "fcntl64" => unistd::fcntl64 as *const (),
        "flock" => unistd::flock as *const (),
        "lockf" => unistd::lockf as *const (),
        "lockf64" => unistd::lockf64 as *const (),
        "posix_fadvise" => unistd::posix_fadvise as *const (),
        "posix_fadvise64" => unistd::posix_fadvise64 as *const (),
        "posix_fallocate" => unistd::posix_fallocate as *const (),
        "posix_fallocate64" => unistd::posix_fallocate64 as *const (),
        "fexecve" => unistd::fexecve as *const (),
        "execveat" => unistd::execveat as *const (),
        "stat" => unistd::stat as *const (),
        "fstat" => unistd::fstat as *const (),
        "lstat" => unistd::lstat as *const (),
        "fstatat" => unistd::fstatat as *const (),
        "stat64" => unistd::stat64 as *const (),
        "fstat64" => unistd::fstat64 as *const (),
        "lstat64" => unistd::lstat64 as *const (),
        "fstatat64" => unistd::fstatat64 as *const (),
        "statx" => unistd::statx as *const (),
        _ => return None,
    };
    Some(address as usize as u64)
}
