#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-libcrypt (libxcrypt) crypt_checksalt oracle

//! Differential gate for crypt_checksalt (bd-iu39zz). libxcrypt classifies a
//! salt setting as CRYPT_SALT_OK(0) / INVALID(1) / METHOD_DISABLED(2) /
//! METHOD_LEGACY(3). For the schemes fl recognizes, fl must match the host:
//! $5$/$6$ -> OK(0), $1$ (MD5) -> LEGACY(3), and clearly-invalid settings
//! ($z$/*0/NULL-ish) -> INVALID(1). Schemes fl cannot hash (DES, yescrypt) are
//! intentionally reported INVALID and are excluded here (bd-c6ykz1). No mocks.

use std::ffi::{CString, c_char, c_int};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut std::ffi::c_void;
    fn dlsym(handle: *mut std::ffi::c_void, symbol: *const c_char) -> *mut std::ffi::c_void;
}

type CheckSaltFn = unsafe extern "C" fn(*const c_char) -> c_int;

/// Resolve host libxcrypt's `crypt_checksalt` at RUNTIME.
///
/// The bare `extern "C" { fn crypt_checksalt(..) }` did not link —
/// "undefined symbol: crypt_checksalt" — so this gate was DARK on the fleet.
///
/// Linking `-lcrypt` would not fix it properly: fl exports its own
/// `crypt_checksalt` under `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`,
/// so in a RELEASE build the extern would bind to FL'S symbol and this gate
/// would compare fl against itself. dlopen/dlsym gives a genuine host oracle
/// and avoids the missing libcrypt.so dev symlink on the workers.
fn host_checksalt() -> CheckSaltFn {
    static F: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    let addr = *F.get_or_init(|| {
        const RTLD_NOW: c_int = 2;
        // SAFETY: constant, NUL-terminated library and symbol names.
        let h = unsafe { dlopen(c"libcrypt.so.1".as_ptr(), RTLD_NOW) };
        assert!(!h.is_null(), "dlopen libcrypt.so.1 failed");
        let p = unsafe { dlsym(h, c"crypt_checksalt".as_ptr()) };
        assert!(!p.is_null(), "dlsym crypt_checksalt failed");
        p as usize
    });
    // SAFETY: dlsym returned a non-null pointer to crypt_checksalt, whose
    // signature is fixed by the libxcrypt ABI.
    unsafe { std::mem::transmute::<usize, CheckSaltFn>(addr) }
}

/// Same call shape as the old extern, so call sites are unchanged.
unsafe fn crypt_checksalt(setting: *const c_char) -> c_int {
    unsafe { host_checksalt()(setting) }
}

fn host(s: &str) -> c_int {
    let c = CString::new(s).unwrap();
    unsafe { crypt_checksalt(c.as_ptr()) }
}
fn fl(s: &str) -> c_int {
    let c = CString::new(s).unwrap();
    unsafe { frankenlibc_abi::unistd_abi::crypt_checksalt(c.as_ptr()) }
}

#[test]
fn crypt_checksalt_recognized_settings_match_host() {
    // Settings where fl's recognition aligns with the host's classification.
    for s in [
        "$6$abcdefgh$",
        "$5$abcdefgh$",
        "$1$abcdefgh$",
        "$z$bad",
        "*0",
        "*1",
        "$$",
    ] {
        let h = host(s);
        let f = fl(s);
        assert_eq!(f, h, "crypt_checksalt({s:?}): fl={f} host={h}");
    }
    // Pin the key reference outcomes so a host change is visible.
    assert_eq!(host("$6$abcdefgh$"), 0, "host $6$ should be OK(0)");
    assert_eq!(
        host("$1$abcdefgh$"),
        3,
        "host $1$ should be METHOD_LEGACY(3)"
    );
    assert_eq!(
        host("$z$bad"),
        1,
        "host unknown scheme should be INVALID(1)"
    );
}
