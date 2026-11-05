//! Allocation, virtual memory, string and scalar entry points for the native loader.
//!
//! Bind to FrankenLibC's existing ABI bodies, never to host allocator addresses
//! discovered by symbol name. In particular, calloc/realloc/strdup results must
//! remain compatible with the free already supplied to native plugins.
//! This is a bounded addition to the runtime surface, not a new libc engine.

use crate::{
    ctype_abi as ctype, malloc_abi as allocation, mmap_abi as mapping, stdlib_abi as stdlib,
    string_abi as strings, unistd_abi as unistd,
};

#[path = "dlfcn_io.rs"]
mod io;

#[path = "dlfcn_stdio.rs"]
mod stdio;

#[path = "dlfcn_pthread.rs"]
mod pthread;

#[path = "dlfcn_fortify.rs"]
mod fortify;
#[path = "dlfcn_semaphore.rs"]
mod semaphore;
#[path = "dlfcn_thread_control.rs"]
mod thread_control;

/// Only the real baseline symbol version for this target is advertised. A
/// private/future version is not interchangeable with an unversioned lookup.
/// Callers perform native DSO scope/preemption checks before this fallback.
pub(super) fn address(name: &str, version: Option<&str>) -> Option<u64> {
    if let Some(address) = semaphore::address(name, version) {
        return Some(address);
    }
    if let Some(address) = thread_control::address(name, version) {
        return Some(address);
    }
    if let Some(address) = fortify::address(name, version) {
        return Some(address);
    }
    if let Some(address) = io::address(name, version) {
        return Some(address);
    }
    if let Some(address) = stdio::address(name, version) {
        return Some(address);
    }
    if let Some(address) = pthread::address(name, version) {
        return Some(address);
    }
    let baseline = if cfg!(target_arch = "aarch64") {
        "GLIBC_2.17"
    } else {
        "GLIBC_2.2.5"
    };
    // mlock2 postdates both architecture baselines. A known name with an
    // unsupported version must stay rejected by runtime_export, rather than
    // escaping into host lookup and a different errno/policy domain.
    if name == "mlock2" {
        return version
            .is_none_or(|version| version == "GLIBC_2.27")
            .then_some(mapping::mlock2 as *const () as usize as u64);
    }
    // The table accessors were introduced after the x86-64 baseline. Keep
    // their real version separate from the ordinary byte-ctype functions.
    let ctype_table = match name {
        "__ctype_b_loc" => Some(ctype::__ctype_b_loc as *const ()),
        "__ctype_tolower_loc" => Some(ctype::__ctype_tolower_loc as *const ()),
        "__ctype_toupper_loc" => Some(ctype::__ctype_toupper_loc as *const ()),
        _ => None,
    };
    if let Some(function) = ctype_table {
        let table_version = if cfg!(target_arch = "aarch64") {
            baseline
        } else {
            "GLIBC_2.3"
        };
        return version
            .is_none_or(|version| version == table_version)
            .then_some(function as usize as u64);
    }
    if version.is_some_and(|version| version != baseline) {
        return None;
    }
    let function = match name {
        // These two were already direct-import builtins. Dynamic lookup must
        // use the same frontends as the newly admitted allocation functions.
        "malloc" => allocation::malloc as *const (),
        "free" => allocation::free as *const (),
        "calloc" => allocation::calloc as *const (),
        "realloc" => allocation::realloc as *const (),
        "malloc_usable_size" => allocation::malloc_usable_size as *const (),
        // Native plugins share the ABI's VM policy, syscall and errno paths.
        // Taking the real function address also retains msync's unwind ABI.
        "mmap" => mapping::mmap as *const (),
        "mmap64" => unistd::mmap64 as *const (),
        "munmap" => mapping::munmap as *const (),
        "mprotect" => mapping::mprotect as *const (),
        "msync" => mapping::msync as *const (),
        "madvise" => mapping::madvise as *const (),
        "posix_madvise" => unistd::posix_madvise as *const (),
        "mincore" => unistd::mincore as *const (),
        "mremap" => mapping::mremap as *const (),
        "mlock" => mapping::mlock as *const (),
        "munlock" => mapping::munlock as *const (),
        "mlockall" => mapping::mlockall as *const (),
        "munlockall" => mapping::munlockall as *const (),
        "atoi" => stdlib::atoi as *const (),
        "atol" => stdlib::atol as *const (),
        "atoll" => stdlib::atoll as *const (),
        "strtol" => stdlib::strtol as *const (),
        "strtoul" => stdlib::strtoul as *const (),
        "strtoll" => stdlib::strtoll as *const (),
        "strtoull" => stdlib::strtoull as *const (),
        "strtoimax" => stdlib::strtoimax as *const (),
        "strtoumax" => stdlib::strtoumax as *const (),
        "isalnum" => ctype::isalnum as *const (),
        "isalpha" => ctype::isalpha as *const (),
        "isblank" => ctype::isblank as *const (),
        "iscntrl" => ctype::iscntrl as *const (),
        "isdigit" => ctype::isdigit as *const (),
        "isgraph" => ctype::isgraph as *const (),
        "islower" => ctype::islower as *const (),
        "isprint" => ctype::isprint as *const (),
        "ispunct" => ctype::ispunct as *const (),
        "isspace" => ctype::isspace as *const (),
        "isupper" => ctype::isupper as *const (),
        "isxdigit" => ctype::isxdigit as *const (),
        "isascii" => ctype::isascii as *const (),
        "toascii" => ctype::toascii as *const (),
        "tolower" => ctype::tolower as *const (),
        "toupper" => ctype::toupper as *const (),
        "memchr" => strings::memchr as *const (),
        "memrchr" => strings::memrchr as *const (),
        "memcmp" => strings::memcmp as *const (),
        "strchr" => strings::strchr as *const (),
        "strrchr" => strings::strrchr as *const (),
        "strncmp" => strings::strncmp as *const (),
        "strnlen" => strings::strnlen as *const (),
        "strstr" => strings::strstr as *const (),
        "strdup" => strings::strdup as *const (),
        "strndup" => strings::strndup as *const (),
        "strcpy" => strings::strcpy as *const (),
        "strncpy" => strings::strncpy as *const (),
        "strcat" => strings::strcat as *const (),
        "strncat" => strings::strncat as *const (),
        "strspn" => strings::strspn as *const (),
        "strcspn" => strings::strcspn as *const (),
        "strpbrk" => strings::strpbrk as *const (),
        _ => return None,
    };
    Some(function as usize as u64)
}
