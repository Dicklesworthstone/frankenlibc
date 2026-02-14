//! ABI layer for `<errno.h>` — thread-local errno storage.
//!
//! No membrane routing for errno: this is a pure thread-local accessor
//! with no security surface.

use std::cell::UnsafeCell;
use std::ffi::c_int;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __errno_location() -> *mut c_int {
    static mut FALLBACK_ERRNO: c_int = 0;
    thread_local! {
        static ERRNO: UnsafeCell<c_int> = const { UnsafeCell::new(0) };
    }
    match ERRNO.try_with(|cell| cell.get()) {
        Ok(ptr) => ptr,
        Err(_) => core::ptr::addr_of_mut!(FALLBACK_ERRNO),
    }
}
