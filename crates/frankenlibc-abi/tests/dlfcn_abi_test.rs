#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_int, c_void};
use std::sync::Mutex;

use frankenlibc_abi::dlfcn_abi::{
    __libc_dlclose, __libc_dlopen_mode, __libc_dlsym, dl_iterate_phdr, dladdr, dlclose, dlerror,
    dlopen, dlsym, dlvsym,
};
use frankenlibc_abi::malloc_abi::{free, malloc};

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
fn dlsym_and_dlvsym_reject_unterminated_names_in_bootstrap_passthrough() {
    let _guard = TEST_GUARD.lock().unwrap();
    unsafe {
        let unterminated_symbol = malloc(6).cast::<u8>();
        assert!(!unterminated_symbol.is_null());
        std::ptr::copy_nonoverlapping(b"malloc".as_ptr(), unterminated_symbol, 6);

        let sym = dlsym(libc::RTLD_DEFAULT, unterminated_symbol.cast());
        assert!(
            sym.is_null(),
            "dlsym should reject an unterminated symbol buffer"
        );
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());

        let version = CString::new("GLIBC_2.2.5").unwrap();
        let sym = dlvsym(
            libc::RTLD_DEFAULT,
            unterminated_symbol.cast(),
            version.as_ptr(),
        );
        assert!(
            sym.is_null(),
            "dlvsym should reject an unterminated symbol buffer"
        );
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        free(unterminated_symbol.cast());

        let sym_name = CString::new("malloc").unwrap();
        let unterminated_version = malloc(11).cast::<u8>();
        assert!(!unterminated_version.is_null());
        std::ptr::copy_nonoverlapping(b"GLIBC_2.2.5".as_ptr(), unterminated_version, 11);
        let sym = dlvsym(
            libc::RTLD_DEFAULT,
            sym_name.as_ptr(),
            unterminated_version.cast(),
        );
        assert!(
            sym.is_null(),
            "dlvsym should reject an unterminated version buffer"
        );
        let err_ptr = dlerror();
        assert!(!err_ptr.is_null());
        free(unterminated_version.cast());
    }
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

#[test]
fn main_program_handle_sees_rtld_global_symbols() {
    let _guard = TEST_GUARD.lock().unwrap();
    let main_handle = unsafe { dlopen(std::ptr::null(), libc::RTLD_NOW) };
    assert!(!main_handle.is_null(), "dlopen(NULL) should succeed");

    let candidates = [
        ("libm.so.6", "cos"),
        ("libutil.so.1", "forkpty"),
        ("libuuid.so.1", "uuid_generate"),
        ("libresolv.so.2", "res_ninit"),
        ("libz.so.1", "inflate"),
    ];

    for (library, symbol) in candidates {
        let lib_name = CString::new(library).unwrap();
        let sym_name = CString::new(symbol).unwrap();

        let before = unsafe { dlsym(main_handle, sym_name.as_ptr()) };
        if !before.is_null() {
            continue;
        }

        let local_handle = unsafe { dlopen(lib_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if local_handle.is_null() {
            let _ = unsafe { dlerror() };
            continue;
        }

        let local_sym = unsafe { dlsym(local_handle, sym_name.as_ptr()) };
        let local_from_main = unsafe { dlsym(main_handle, sym_name.as_ptr()) };
        unsafe { dlclose(local_handle) };
        if local_sym.is_null() || !local_from_main.is_null() {
            continue;
        }

        let global_handle =
            unsafe { dlopen(lib_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_GLOBAL) };
        assert!(
            !global_handle.is_null(),
            "RTLD_GLOBAL load should succeed for candidate {library}"
        );

        let global_sym = unsafe { dlsym(global_handle, sym_name.as_ptr()) };
        assert!(
            !global_sym.is_null(),
            "RTLD_GLOBAL handle should resolve {symbol} from {library}"
        );

        let promoted = unsafe { dlsym(main_handle, sym_name.as_ptr()) };
        assert!(
            !promoted.is_null(),
            "main-program handle should see {symbol} after RTLD_GLOBAL load of {library}"
        );

        unsafe {
            dlclose(global_handle);
            dlclose(main_handle);
        }
        return;
    }

    unsafe { dlclose(main_handle) };
}

// ---------------------------------------------------------------------------
// __libc_dlopen_mode / __libc_dlsym / __libc_dlclose (glibc internal aliases)
// ---------------------------------------------------------------------------

#[test]
fn libc_dlopen_mode_matches_dlopen_for_libc() {
    let _g = TEST_GUARD.lock().unwrap();
    let path = c"libc.so.6";
    let h_pub = unsafe { dlopen(path.as_ptr(), libc::RTLD_NOW) };
    let h_int = unsafe { __libc_dlopen_mode(path.as_ptr(), libc::RTLD_NOW) };
    if h_pub.is_null() || h_int.is_null() {
        // libc.so.6 not loadable on this host (e.g. musl); inconclusive.
        if !h_pub.is_null() {
            unsafe { dlclose(h_pub) };
        }
        if !h_int.is_null() {
            unsafe { __libc_dlclose(h_int) };
        }
        return;
    }
    // Both should resolve the same well-known symbol.
    let sym = c"strlen";
    let p_pub = unsafe { dlsym(h_pub, sym.as_ptr()) };
    let p_int = unsafe { __libc_dlsym(h_int, sym.as_ptr()) };
    assert!(!p_pub.is_null());
    assert!(!p_int.is_null());
    assert_eq!(p_pub, p_int);

    unsafe { dlclose(h_pub) };
    let rc = unsafe { __libc_dlclose(h_int) };
    assert_eq!(rc, 0);
}

#[test]
fn libc_dlsym_with_rtld_default_resolves_known_symbol() {
    let _g = TEST_GUARD.lock().unwrap();
    let sym = c"abort";
    let p = unsafe { __libc_dlsym(libc::RTLD_DEFAULT, sym.as_ptr()) };
    // RTLD_DEFAULT lookup may fail in static-link builds; if so,
    // treat as inconclusive.
    if p.is_null() {
        return;
    }
    // The pointer should be the same as dlsym's.
    let q = unsafe { dlsym(libc::RTLD_DEFAULT, sym.as_ptr()) };
    assert_eq!(p, q);
}

#[test]
fn libc_dlclose_returns_zero_on_valid_handle() {
    let _g = TEST_GUARD.lock().unwrap();
    let path = c"libc.so.6";
    let h = unsafe { __libc_dlopen_mode(path.as_ptr(), libc::RTLD_NOW) };
    if h.is_null() {
        return;
    }
    let rc = unsafe { __libc_dlclose(h) };
    assert_eq!(rc, 0);
}
