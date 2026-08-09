#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-libcrypt (libxcrypt) crypt_r oracle

//! Differential gate for crypt_r (bd-c1gtzh) — the reentrant crypt had no
//! differential gate. crypt_r writes into the caller's struct crypt_data and
//! returns a pointer into it. Like crypt, the host (libxcrypt) never returns
//! NULL: unsupported/invalid settings yield the "*0"/"*1" failure token. fl's
//! crypt_r delegates to crypt (fixed in bd-r9ihvq), so it should match. Each
//! impl uses its own large data buffer (covering struct crypt_data on either
//! libc). Compares the result strings for failure tokens and a supported
//! scheme. No mocks.

use std::ffi::{CStr, CString, c_char};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: std::ffi::c_int) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const c_char) -> *mut std::ffi::c_void;
}

type CryptRFn =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut std::ffi::c_void) -> *mut c_char;

/// Resolve host libxcrypt's `crypt_r` at RUNTIME.
///
/// This target used a bare `extern "C" { fn crypt_r(..) }` and did not link:
///   rust-lld: error: undefined symbol: crypt_r
/// Nothing pulled in libcrypt, so the whole gate was DARK on the fleet — silent,
/// not green.
///
/// Linking `-lcrypt` would not have been the right fix either. fl exports its
/// own `crypt_r` under `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`,
/// so in a RELEASE build a bare extern resolves to FL'S OWN SYMBOL and the
/// "host" arm would silently compare fl against itself — a gate that can only
/// pass. dlopen/dlsym against libcrypt.so.1 is the only way to get a real
/// oracle, and it also sidesteps the missing libcrypt.so dev symlink on the
/// workers. Same approach as conformance_diff_crypt_failure_token.
fn host_crypt_r() -> CryptRFn {
    static F: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let addr = *F.get_or_init(|| {
        const RTLD_NOW: std::ffi::c_int = 2;
        // SAFETY: constant, NUL-terminated library and symbol names.
        let h = unsafe { dlopen(c"libcrypt.so.1".as_ptr(), RTLD_NOW) };
        assert!(!h.is_null(), "dlopen libcrypt.so.1 failed");
        let p = unsafe { dlsym(h, c"crypt_r".as_ptr()) };
        assert!(!p.is_null(), "dlsym crypt_r failed");
        p as usize
    });
    // SAFETY: dlsym returned a non-null pointer to crypt_r, whose signature is
    // fixed by the libxcrypt ABI.
    unsafe { std::mem::transmute::<usize, CryptRFn>(addr) }
}

/// Same call shape as the old extern, so call sites are unchanged.
unsafe fn crypt_r(
    key: *const c_char,
    salt: *const c_char,
    data: *mut std::ffi::c_void,
) -> *mut c_char {
    unsafe { host_crypt_r()(key, salt, data) }
}

// Generous buffer: glibc's struct crypt_data is ~128 KiB; libxcrypt's is small.
// 256 KiB safely covers either as the crypt_r data argument.
const DATA_SIZE: usize = 256 * 1024;

fn host(key: &str, salt: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    let mut data = vec![0u8; DATA_SIZE];
    let p = unsafe {
        crypt_r(
            k.as_ptr(),
            s.as_ptr(),
            data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}
fn fl(key: &str, salt: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    let mut data = vec![0u8; DATA_SIZE];
    let p = unsafe {
        frankenlibc_abi::unistd_abi::crypt_r(
            k.as_ptr(),
            s.as_ptr(),
            data.as_mut_ptr() as *mut std::ffi::c_void,
        )
    };
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn crypt_r_failure_token_matches_host() {
    for salt in ["$z$badscheme", "!", "", "*0", "*1"] {
        let h = host("password", salt);
        let f = fl("password", salt);
        assert!(h.is_some(), "host crypt_r(pw, {salt:?}) unexpectedly NULL");
        let ht = h.unwrap();
        assert!(
            ht.starts_with('*'),
            "host crypt_r token for {salt:?} = {ht:?}"
        );
        assert_eq!(
            f,
            Some(ht.clone()),
            "crypt_r(pw, {salt:?}): fl={f:?} host={ht:?}"
        );
    }
}

#[test]
fn crypt_r_supported_scheme_matches_host() {
    let salt = "$6$saltsalt$";
    let f = fl("password", salt).expect("fl crypt_r should hash $6$");
    assert!(
        f.starts_with(salt) && !f.starts_with('*'),
        "fl crypt_r({salt:?})={f:?}"
    );
    assert_eq!(
        Some(&f),
        host("password", salt).as_ref(),
        "fl vs host crypt_r hash for {salt:?}"
    );
}
