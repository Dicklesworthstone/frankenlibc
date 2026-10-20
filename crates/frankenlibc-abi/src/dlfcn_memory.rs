//! Additional allocation and byte-string entry points for the native loader.
//!
//! Bind to FrankenLibC's existing ABI bodies, never to host allocator addresses
//! discovered by symbol name. In particular, calloc/realloc/strdup results must
//! remain compatible with the free already supplied to native plugins.
//! This is a bounded addition to the runtime surface, not a new libc engine.

use crate::{malloc_abi as allocation, string_abi as strings};

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
