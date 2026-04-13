//! ABI layer for `<errno.h>` — thread-local errno storage.
//!
//! No membrane routing for errno: this is a pure thread-local accessor
//! with no security surface.

use std::cell::UnsafeCell;
use std::ffi::c_int;
use std::sync::{LazyLock, Mutex};

static FALLBACK_ERRNO_SLOTS: LazyLock<
    Mutex<std::collections::HashMap<std::thread::ThreadId, Box<c_int>>>,
> = LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));

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
    thread_local! {
        static ERRNO: UnsafeCell<c_int> = const { UnsafeCell::new(0) };
    }
    match ERRNO.try_with(|cell| cell.get()) {
        Ok(ptr) => ptr,
        Err(_) => fallback_errno_slot_for_current_thread(),
    }
}

/// Set the thread-local errno value.
///
/// Sets BOTH our internal errno and the host libc's errno to ensure the value
/// is visible regardless of which `__errno_location` the caller reads from.
/// Uses volatile write to prevent the LTO optimizer from eliminating the store.
#[inline]
pub unsafe fn set_abi_errno(val: c_int) {
    // Set our internal errno.
    let p = unsafe { __errno_location() };
    unsafe { std::ptr::write_volatile(p, val) };
    // Also set libc's errno so callers using libc::__errno_location see it.
    unsafe { std::ptr::write_volatile(libc::__errno_location(), val) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_errno_slot_is_stable_per_thread() {
        let p1 = fallback_errno_slot_for_current_thread();
        let p2 = fallback_errno_slot_for_current_thread();
        assert_eq!(p1, p2);
    }

    #[test]
    fn fallback_errno_slot_isolated_across_threads() {
        let main_ptr = fallback_errno_slot_for_current_thread() as usize;
        let handle = std::thread::spawn(|| fallback_errno_slot_for_current_thread() as usize);
        let other_ptr = handle.join().unwrap();
        assert_ne!(main_ptr, other_ptr);
    }
}
