#![cfg(target_os = "linux")]

use std::ffi::{CStr, c_void};
use std::sync::Mutex;

use frankenlibc_abi::dlfcn_abi::{dl_iterate_phdr, dladdr, dlerror};

static TEST_GUARD: Mutex<()> = Mutex::new(());

#[test]
fn dl_iterate_phdr_native_fallback_returns_zero_without_callback() {
    let _guard = TEST_GUARD.lock().unwrap();

    // SAFETY: no callback is provided and no pointers are dereferenced.
    let rc = unsafe { dl_iterate_phdr(None, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

#[test]
fn dladdr_null_inputs_return_zero_and_publish_invalid_handle_error() {
    let _guard = TEST_GUARD.lock().unwrap();

    // SAFETY: reading/clearing thread-local dlerror state is valid.
    unsafe {
        let _ = dlerror();
        let rc = dladdr(std::ptr::null(), std::ptr::null_mut());
        assert_eq!(rc, 0);
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        let err = CStr::from_ptr(err_ptr).to_string_lossy();
        assert!(
            err.contains("invalid handle"),
            "unexpected dlerror payload: {err}"
        );
    }
}

#[test]
fn dladdr_non_null_inputs_return_zero_and_publish_unavailable_error() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut out_slot: usize = 0;
    let addr = (&out_slot as *const usize).cast::<c_void>();
    let info = (&mut out_slot as *mut usize).cast::<c_void>();

    // SAFETY: pointers refer to stack-owned storage for this test scope.
    unsafe {
        let _ = dlerror();
        let rc = dladdr(addr, info);
        assert_eq!(rc, 0);
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        let err = CStr::from_ptr(err_ptr).to_string_lossy();
        assert!(
            err.contains("operation unavailable"),
            "unexpected dlerror payload: {err}"
        );
    }
}
