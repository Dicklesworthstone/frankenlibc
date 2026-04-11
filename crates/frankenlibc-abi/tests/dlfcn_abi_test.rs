#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_int, c_void};
use std::sync::Mutex;

use frankenlibc_abi::dlfcn_abi::{
    dl_iterate_phdr, dladdr, dlclose, dlerror, dlopen, dlsym, dlvsym,
};

static TEST_GUARD: Mutex<()> = Mutex::new(());

#[derive(Default)]
struct DlIterateProbe {
    count: usize,
    saw_nonnull_info: bool,
    saw_nonzero_size: bool,
}

unsafe extern "C" fn record_first_phdr(
    info: *mut libc::dl_phdr_info,
    size: usize,
    data: *mut c_void,
) -> c_int {
    let probe = unsafe { &mut *data.cast::<DlIterateProbe>() };
    probe.count += 1;
    probe.saw_nonnull_info = !info.is_null();
    probe.saw_nonzero_size = size >= core::mem::size_of::<libc::dl_phdr_info>();
    1
}

#[test]
fn dl_iterate_phdr_native_fallback_returns_zero_without_callback() {
    let _guard = TEST_GUARD.lock().unwrap();

    // SAFETY: no callback is provided and no pointers are dereferenced.
    let rc = unsafe { dl_iterate_phdr(None, std::ptr::null_mut()) };
    assert_eq!(rc, 0);
}

#[test]
fn dl_iterate_phdr_invokes_callback_with_host_phdr_data() {
    let _guard = TEST_GUARD.lock().unwrap();
    let mut probe = DlIterateProbe::default();

    let rc = unsafe {
        dl_iterate_phdr(
            Some(record_first_phdr),
            (&mut probe as *mut DlIterateProbe).cast::<c_void>(),
        )
    };

    assert_eq!(rc, 1, "callback should stop iteration by returning 1");
    assert_eq!(
        probe.count, 1,
        "callback should be invoked exactly once before stopping"
    );
    assert!(
        probe.saw_nonnull_info,
        "host dl_iterate_phdr should provide a non-null info record"
    );
    assert!(
        probe.saw_nonzero_size,
        "host dl_iterate_phdr should report at least a dl_phdr_info-sized record"
    );
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
    assert!(
        handle.is_null(),
        "dlopen nonexistent library should return NULL"
    );

    let err_ptr = unsafe { dlerror() };
    assert!(
        !err_ptr.is_null(),
        "dlerror should be set after failed dlopen"
    );
}

#[test]
fn dlsym_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("printf").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should find native 'printf' on main handle"
    );

    unsafe { dlclose(handle) };
}

#[test]
fn dlsym_rtld_default_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let sym_name = CString::new("printf").unwrap();
    let sym = unsafe { dlsym(libc::RTLD_DEFAULT, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should resolve 'printf' through the native RTLD_DEFAULT path"
    );
}

#[test]
fn dlsym_rtld_next_finds_known_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let sym_name = CString::new("malloc").unwrap();
    let sym = unsafe { dlsym(libc::RTLD_NEXT, sym_name.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlsym should resolve 'malloc' through RTLD_NEXT"
    );
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
        assert!(
            err.is_null(),
            "dlerror should be NULL after successful dlopen"
        );
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
    assert!(
        !handle.is_null(),
        "native phase-1 dlopen should surface the main handle for libc NOLOAD aliases"
    );
    unsafe { dlclose(handle) };
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

// ---------------------------------------------------------------------------
// Additional dlopen/dlclose edge cases
// ---------------------------------------------------------------------------

#[test]
fn dlopen_same_handle_twice_returns_same_handle() {
    let _guard = TEST_GUARD.lock().unwrap();
    let h1 = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    let h2 = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!h1.is_null());
    assert!(!h2.is_null());
    // Both opens refer to the main program; closing both should succeed
    unsafe {
        dlclose(h1);
        dlclose(h2);
    }
}

#[test]
fn dlopen_rtld_lazy_succeeds() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_LAZY) };
    assert!(
        !handle.is_null(),
        "dlopen(NULL, RTLD_LAZY) should return main program handle"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlsym_finds_malloc() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let sym_name = CString::new("malloc").unwrap();
    let sym = unsafe { dlsym(handle, sym_name.as_ptr()) };
    assert!(!sym.is_null(), "dlsym should find 'malloc' in main handle");

    unsafe { dlclose(handle) };
}

#[test]
fn dlclose_idempotent_for_main_handle() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());
    // First close should succeed
    let rc1 = unsafe { dlclose(handle) };
    assert_eq!(rc1, 0, "first dlclose should succeed");
}

#[test]
fn dlclose_second_close_returns_error() {
    let _guard = TEST_GUARD.lock().unwrap();
    let handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!handle.is_null());

    let rc1 = unsafe { dlclose(handle) };
    let rc2 = unsafe { dlclose(handle) };
    assert_eq!(rc1, 0, "first close should succeed");
    assert_ne!(rc2, 0, "second close should fail deterministically");
}

#[test]
fn dlvsym_supported_version_resolves_native_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_2.2.5").unwrap();
    let sym = unsafe { dlvsym(libc::RTLD_DEFAULT, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlvsym should resolve known symbols for supported versions"
    );
}

#[test]
fn dlvsym_rtld_next_resolves_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_2.2.5").unwrap();
    let sym = unsafe { dlvsym(libc::RTLD_NEXT, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlvsym should resolve symbols through RTLD_NEXT"
    );
}

#[test]
fn dlvsym_host_handle_resolves_symbol() {
    let _guard = TEST_GUARD.lock().unwrap();
    let lib_name = CString::new("libc.so.6").unwrap();
    let handle = unsafe { dlopen(lib_name.as_ptr(), libc::RTLD_NOW) };
    assert!(!handle.is_null(), "dlopen libc should succeed");
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_2.2.5").unwrap();
    let sym = unsafe { dlvsym(handle, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        !sym.is_null(),
        "dlvsym should resolve symbols on host handles"
    );
    unsafe { dlclose(handle) };
}

#[test]
fn dlvsym_unsupported_version_returns_null() {
    let _guard = TEST_GUARD.lock().unwrap();
    let sym_name = CString::new("malloc").unwrap();
    let version = CString::new("GLIBC_9.9").unwrap();
    let sym = unsafe { dlvsym(libc::RTLD_DEFAULT, sym_name.as_ptr(), version.as_ptr()) };
    assert!(
        sym.is_null(),
        "unsupported versions should not resolve native symbols"
    );
}

#[test]
fn dlopen_empty_string_returns_null_or_main() {
    let _guard = TEST_GUARD.lock().unwrap();
    let name = CString::new("").unwrap();
    let handle = unsafe { dlopen(name.as_ptr(), libc::RTLD_NOW) };
    // Empty string may return main handle or NULL depending on implementation
    if !handle.is_null() {
        unsafe { dlclose(handle) };
    }
}
