//! ABI layer for `<errno.h>` — thread-local errno storage.
//!
//! No membrane routing for errno: this is a pure thread-local accessor
//! with no security surface.

use std::ffi::c_int;

#[cfg(not(feature = "owned-tls-cache"))]
use std::cell::UnsafeCell;
#[cfg(not(feature = "owned-tls-cache"))]
use std::sync::{LazyLock, Mutex};

#[cfg(feature = "owned-tls-cache")]
static ERRNO_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<c_int> =
    crate::owned_tls_cache::OwnedTlsCache::new(zero_c_int);

#[cfg(feature = "owned-tls-cache")]
fn zero_c_int() -> c_int {
    0
}

#[cfg(not(feature = "owned-tls-cache"))]
thread_local! {
    static ERRNO: UnsafeCell<c_int> = const { UnsafeCell::new(0) };
}

#[cfg(not(feature = "owned-tls-cache"))]
static FALLBACK_ERRNO_SLOTS: LazyLock<
    Mutex<std::collections::HashMap<std::thread::ThreadId, Box<c_int>>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

#[cfg(not(feature = "owned-tls-cache"))]
fn fallback_errno_slot_for_current_thread() -> *mut c_int {
    let thread_id = std::thread::current().id();
    let mut slots = FALLBACK_ERRNO_SLOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let slot = slots.entry(thread_id).or_insert_with(|| Box::new(0));
    slot.as_mut() as *mut c_int
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    #[cfg(feature = "owned-tls-cache")]
    {
        ERRNO_OWNED_TLS.with(|slot| slot as *mut c_int)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        match ERRNO.try_with(|cell| cell.get()) {
            Ok(ptr) => ptr,
            Err(_) => fallback_errno_slot_for_current_thread(),
        }
    }
}

/// Set the thread-local errno value.
///
/// In interpose mode, sets BOTH our internal errno and the host libc's errno
/// to ensure the value is visible regardless of which `__errno_location` the
/// caller reads from. In standalone mode, we are the only libc, so only our
/// internal errno is updated.
///
/// Uses volatile write to prevent the LTO optimizer from eliminating the store.
#[inline]
pub unsafe fn set_abi_errno(val: c_int) {
    unsafe { set_abi_errno_local(val) };

    // In interpose mode, also set libc's errno so callers using
    // the host libc's errno slot see the same value. In standalone mode,
    // we are the sole libc implementation, so this is unnecessary.
    #[cfg(not(feature = "standalone"))]
    unsafe {
        crate::host_resolve::write_host_errno_if_available(val)
    };
}

/// Set only FrankenLibC's own thread-local errno slot.
///
/// Native replacement-clean paths use this when host errno mirroring would be
/// the only remaining host-libc dependency for the symbol.
#[inline]
pub(crate) unsafe fn set_abi_errno_local(val: c_int) {
    let p = unsafe { __errno_location() };
    unsafe { std::ptr::write_volatile(p, val) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(feature = "owned-tls-cache"))]
    fn fallback_errno_slot_is_stable_per_thread() {
        let p1 = fallback_errno_slot_for_current_thread();
        let p2 = fallback_errno_slot_for_current_thread();
        assert_eq!(p1, p2);
    }

    #[test]
    #[cfg(not(feature = "owned-tls-cache"))]
    fn fallback_errno_slot_isolated_across_threads() {
        let main_ptr = fallback_errno_slot_for_current_thread() as usize;
        let handle = std::thread::spawn(|| fallback_errno_slot_for_current_thread() as usize);
        let other_ptr = handle.join().unwrap();
        assert_ne!(main_ptr, other_ptr);
    }

    #[test]
    fn set_abi_errno_updates_thread_local_slot() {
        let ptr = unsafe { __errno_location() };
        let original = unsafe { std::ptr::read_volatile(ptr) };

        unsafe { set_abi_errno(libc::ENOENT) };
        assert_eq!(unsafe { std::ptr::read_volatile(ptr) }, libc::ENOENT);

        unsafe { set_abi_errno(original) };
    }
}
