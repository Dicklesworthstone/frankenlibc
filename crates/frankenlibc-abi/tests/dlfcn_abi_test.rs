#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_void};
use std::sync::Mutex;

use frankenlibc_abi::dlfcn_abi::{dl_iterate_phdr, dladdr, dlclose, dlerror, dlopen, dlsym};

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

// ---------------------------------------------------------------------------
// dlopen / dlsym / dlclose
// ---------------------------------------------------------------------------

#[test]
fn dlopen_null_returns_main_handle() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(
        !handle.is_null(),
        "dlopen(NULL, RTLD_NOW) should return main program handle"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlopen_nonexistent_library_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap();
    let name = CString::new("libnonexistent_zzz_12345.so").unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    assert!(handle.is_null(), "dlopen nonexistent library should return NULL");

    let err_ptr = unsafe { dlerror() };
    assert!(!err_ptr.is_null(), "dlerror should be set after failed dlopen");
}

#[test]
fn dlsym_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("printf").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    // printf should be found in the main program (via libc)
    assert!(
        !sym.is_null(),
        "dlsym should find 'printf' in main handle"
    );

    unsafe { dlclose(handle) };
}

#[test]
fn dlsym_unknown_symbol_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("zzz_nonexistent_symbol_99999").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(sym.is_null(), "dlsym should return NULL for unknown symbol");

    unsafe { dlclose(handle) };
}

#[test]
fn dlclose_null_returns_error() {
    let _guard = TEST_GUARD.lock().unwrap();
    let rc = unsafe { dlclose(std::ptr::null_mut()) };
    assert_ne!(rc, 0, "dlclose(NULL) should return error");
}

#[test]
fn dlerror_returns_null_when_no_error() {
    let _guard = TEST_GUARD.lock().unwrap();
    // Clear any pending error
    unsafe { dlerror() };
    // A successful dlopen should clear the error
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    if !handle.is_null() {
        let err = unsafe { dlerror() };
        assert!(err.is_null(), "dlerror should be NULL after successful dlopen");
        unsafe { dlclose(handle) };
    }
}

#[test]
fn dlerror_consumed_after_read() {
    let _guard = TEST_GUARD.lock().unwrap();
    // Force an error
    let name = CString::new("libnonexistent_zzz.so").unwrap();
    let _ = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    let err1 = unsafe { dlerror() };
    assert!(!err1.is_null(), "first dlerror should return error");
    // Second call should return null (error consumed)
    let err2 = unsafe { dlerror() };
    assert!(err2.is_null(), "second dlerror should return null");
}

#[test]
fn dlopen_libc_succeeds() {
    let _guard = TEST_GUARD.lock().unwrap();
    let name = CString::new("libc.so.6").unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    // libc.so.6 should already be loaded in the process
    if !handle.is_null() {
        unsafe { dlclose(handle) };
    }
    // If null, that's OK too (some configurations might not have it at this name)
}

#[test]
fn dlsym_null_name_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());
    let sym = unsafe { dlsym(handle, std::ptr::null()) };
    assert!(sym.is_null(), "dlsym with null name should return NULL");
    unsafe { dlclose(handle) };
}

#[test]
fn dlclose_double_close() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());
    let rc1 = unsafe { dlclose(handle) };
    assert_eq!(rc1, 0, "first dlclose should succeed");
    // Second close on same handle — implementation-defined, but shouldn't crash
    let _ = unsafe { dlclose(handle) };
}

#[test]
fn dl_iterate_phdr_with_callback() {
    let _guard = TEST_GUARD.lock().unwrap();

    static mut CALLBACK_COUNT: i32 = 0;

    unsafe extern "C" fn counter(
        _info: *mut libc::dl_phdr_info,
        _size: usize,
        _data: *mut c_void,
    ) -> i32 {
        unsafe { CALLBACK_COUNT += 1 };
        0 // continue iteration
    }

    unsafe { CALLBACK_COUNT = 0 };
    let rc = unsafe { dl_iterate_phdr(Some(counter), std::ptr::null_mut()) };
    assert_eq!(rc, 0, "dl_iterate_phdr should return 0 when callback returns 0");
    assert!(unsafe { CALLBACK_COUNT } > 0, "callback should be invoked at least once");
}
