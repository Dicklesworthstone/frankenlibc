//! Descriptor, pathname, process and errno frontends for native plugins.
//!
//! Reuse the existing ABI implementations, including their cancellation,
//! membrane, descriptor-offset tracking and errno behavior. In particular,
//! never bind native IO to one errno provider and __errno_location to another.
//! This table is consumed by both relocation and caller-relative lookup.

use crate::{
    dirent_abi as dirs, errno_abi as errno, glibc_internal_abi as internal, io_abi as io,
    process_abi as process, stdlib_abi as stdlib, unistd_abi as unistd,
};

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
        "openat" | "openat64" | "faccessat" | "readlinkat" | "fdopendir" => "GLIBC_2.4",
        "pipe2" | "dup3" => "GLIBC_2.9",
        "execvpe" => "GLIBC_2.11",
        // Only the modern default spawn ABI is provided. Do not advertise
        // the separate x86-64 GLIBC_2.2.5 compatibility implementations.
        "scandirat" | "scandirat64" | "posix_spawn" | "posix_spawnp" => "GLIBC_2.15",
        "nftw" | "nftw64" => "GLIBC_2.3.3",
        _ => "GLIBC_2.2.5",
    };
    let supported = if name == "getentropy" {
        "GLIBC_2.25"
    } else if name == "gettid" {
        // The public thread-ID wrapper arrived after both architecture
        // baselines. Native clones need the kernel TID, never a cached PID or
        // a host TLS identity inherited from their creator.
        "GLIBC_2.30"
    } else if matches!(name, "arc4random" | "arc4random_buf" | "arc4random_uniform") {
        // Entropy interfaces postdate both architecture baselines; do not
        // lower these versions to AArch64's initial GLIBC_2.17 namespace.
        "GLIBC_2.36"
    } else if matches!(name, "fcntl64" | "statx") {
        // These public interfaces postdate both architecture baselines.
        "GLIBC_2.28"
    } else if matches!(
        name,
        "posix_spawn_file_actions_addchdir_np" | "posix_spawn_file_actions_addfchdir_np"
    ) {
        "GLIBC_2.29"
    } else if matches!(
        name,
        "execveat" | "_Fork" | "posix_spawn_file_actions_addclosefrom_np"
    ) {
        // Added after both architecture baselines.
        "GLIBC_2.34"
    } else if name == "posix_spawn_file_actions_addtcsetpgrp_np" {
        "GLIBC_2.35"
    } else if matches!(
        name,
        "pidfd_spawn"
            | "pidfd_spawnp"
            | "posix_spawnattr_getcgroup_np"
            | "posix_spawnattr_setcgroup_np"
    ) {
        "GLIBC_2.39"
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
        "getentropy" => unistd::getentropy as *const (),
        "arc4random" => unistd::arc4random as *const (),
        "arc4random_buf" => unistd::arc4random_buf as *const (),
        "arc4random_uniform" => unistd::arc4random_uniform as *const (),
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
        "opendir" => dirs::opendir as *const (),
        "fdopendir" => dirs::fdopendir as *const (),
        "readdir" => dirs::readdir as *const (),
        "readdir64" => dirs::readdir64 as *const (),
        "readdir_r" => dirs::readdir_r as *const (),
        "readdir64_r" => unistd::readdir64_r as *const (),
        "closedir" => dirs::closedir as *const (),
        "dirfd" => dirs::dirfd as *const (),
        "rewinddir" => dirs::rewinddir as *const (),
        "telldir" => dirs::telldir as *const (),
        "seekdir" => dirs::seekdir as *const (),
        "scandir" => dirs::scandir as *const (),
        "scandir64" => dirs::scandir64 as *const (),
        "scandirat" => internal::scandirat as *const (),
        "scandirat64" => internal::scandirat64 as *const (),
        "alphasort" => dirs::alphasort as *const (),
        "alphasort64" => unistd::alphasort64 as *const (),
        "versionsort" => dirs::versionsort as *const (),
        "versionsort64" => unistd::versionsort64 as *const (),
        "ftw" => unistd::ftw as *const (),
        "ftw64" => unistd::ftw64 as *const (),
        "nftw" => unistd::nftw as *const (),
        "nftw64" => unistd::nftw64 as *const (),
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
        // Spawn attributes and actions carry native-owned allocation state.
        // Keep every initializer, accessor, mutator and consumer together;
        // mixing even one host entry would reinterpret an incompatible object.
        "posix_spawn" => process::posix_spawn as *const (),
        "posix_spawnp" => process::posix_spawnp as *const (),
        "pidfd_spawn" => internal::pidfd_spawn as *const (),
        "pidfd_spawnp" => internal::pidfd_spawnp as *const (),
        "posix_spawnattr_init" => process::posix_spawnattr_init as *const (),
        "posix_spawnattr_destroy" => process::posix_spawnattr_destroy as *const (),
        "posix_spawnattr_getflags" => process::posix_spawnattr_getflags as *const (),
        "posix_spawnattr_setflags" => process::posix_spawnattr_setflags as *const (),
        "posix_spawnattr_getsigdefault" => process::posix_spawnattr_getsigdefault as *const (),
        "posix_spawnattr_setsigdefault" => process::posix_spawnattr_setsigdefault as *const (),
        "posix_spawnattr_getsigmask" => process::posix_spawnattr_getsigmask as *const (),
        "posix_spawnattr_setsigmask" => process::posix_spawnattr_setsigmask as *const (),
        "posix_spawnattr_getpgroup" => process::posix_spawnattr_getpgroup as *const (),
        "posix_spawnattr_setpgroup" => process::posix_spawnattr_setpgroup as *const (),
        "posix_spawnattr_getschedparam" => process::posix_spawnattr_getschedparam as *const (),
        "posix_spawnattr_setschedparam" => process::posix_spawnattr_setschedparam as *const (),
        "posix_spawnattr_getschedpolicy" => process::posix_spawnattr_getschedpolicy as *const (),
        "posix_spawnattr_setschedpolicy" => process::posix_spawnattr_setschedpolicy as *const (),
        "posix_spawnattr_getcgroup_np" => unistd::posix_spawnattr_getcgroup_np as *const (),
        "posix_spawnattr_setcgroup_np" => unistd::posix_spawnattr_setcgroup_np as *const (),
        "posix_spawn_file_actions_init" => process::posix_spawn_file_actions_init as *const (),
        "posix_spawn_file_actions_destroy" => {
            process::posix_spawn_file_actions_destroy as *const ()
        }
        "posix_spawn_file_actions_addclose" => {
            process::posix_spawn_file_actions_addclose as *const ()
        }
        "posix_spawn_file_actions_adddup2" => {
            process::posix_spawn_file_actions_adddup2 as *const ()
        }
        "posix_spawn_file_actions_addopen" => {
            process::posix_spawn_file_actions_addopen as *const ()
        }
        "posix_spawn_file_actions_addchdir_np" => {
            process::posix_spawn_file_actions_addchdir_np as *const ()
        }
        "posix_spawn_file_actions_addfchdir_np" => {
            process::posix_spawn_file_actions_addfchdir_np as *const ()
        }
        "posix_spawn_file_actions_addclosefrom_np" => {
            unistd::posix_spawn_file_actions_addclosefrom_np as *const ()
        }
        "posix_spawn_file_actions_addtcsetpgrp_np" => {
            unistd::posix_spawn_file_actions_addtcsetpgrp_np as *const ()
        }
        "wait" => process::wait as *const (),
        "waitpid" => process::waitpid as *const (),
        "wait3" => process::wait3 as *const (),
        "wait4" => process::wait4 as *const (),
        "waitid" => process::waitid as *const (),
        "getpid" => unistd::getpid as *const (),
        "getppid" => unistd::getppid as *const (),
        "gettid" => internal::gettid as *const (),
        "getpgrp" => unistd::getpgrp as *const (),
        "getpgid" => unistd::getpgid as *const (),
        "getsid" => unistd::getsid as *const (),
        "fork" => process::fork as *const (),
        "_Fork" => unistd::_Fork as *const (),
        "execve" => process::execve as *const (),
        "execv" => unistd::execv as *const (),
        "execvp" => process::execvp as *const (),
        "execvpe" => process::execvpe as *const (),
        "execl" => unistd::execl as *const (),
        "execlp" => unistd::execlp as *const (),
        "execle" => unistd::execle as *const (),
        "system" => stdlib::system as *const (),
        "setpgid" => unistd::setpgid as *const (),
        "setpgrp" => unistd::setpgrp as *const (),
        "setsid" => unistd::setsid as *const (),
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
