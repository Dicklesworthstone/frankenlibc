#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-libxcrypt oracle

//! Differential gate for `crypt`'s FAILURE contract (bd-r9ihvq).
//!
//! libxcrypt never returns NULL. When it rejects a setting it returns the
//! two-character failure token `*0` — or `*1` when the setting itself begins
//! with `*0` — and sets `EINVAL`. The token is chosen so the result can never
//! compare equal to the setting that produced it, which is what makes
//! `strcmp(crypt(pw, stored), stored)` safe as an authentication test.
//!
//! fl returned NULL, so a caller written against that contract dereferenced
//! NULL on any bad salt. Measured on this host before the fix (libcrypt.so.1):
//!   "$9$saltsalt$" -> *0 EINVAL      "" -> *0 EINVAL       "x" -> *0 EINVAL
//!   "!!!not-a-salt!!!" -> *0 EINVAL  "*0" -> *1 EINVAL     "*1" -> *0 EINVAL
//!
//! Scope note: this gate covers the FAILURE contract only. libxcrypt also
//! *supports* algorithms fl does not yet implement ($2b$ bcrypt, $7$ scrypt,
//! classic DES), where it returns a real hash and fl returns the token. That
//! gap is bd-c6ykz1 and is deliberately NOT asserted here — asserting it would
//! either fail for a reason this bead is not about, or bake in the wrong answer.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::OnceLock;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
        pub fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
        pub fn __errno_location() -> *mut c_int;
    }

    pub type CryptFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

    /// Resolve host libxcrypt at RUNTIME rather than link time: the worker
    /// images carry `libcrypt.so.1` but not the `libcrypt.so` development
    /// symlink, so `#[link(name = "crypt")]` fails to link there.
    pub fn crypt_fn() -> CryptFn {
        static F: OnceLock<usize> = OnceLock::new();
        let addr = *F.get_or_init(|| {
            const RTLD_NOW: c_int = 2;
            // SAFETY: constant, NUL-terminated library and symbol names.
            let h = unsafe { dlopen(c"libcrypt.so.1".as_ptr(), RTLD_NOW) };
            assert!(!h.is_null(), "dlopen libcrypt.so.1 failed");
            let p = unsafe { dlsym(h, c"crypt".as_ptr()) };
            assert!(!p.is_null(), "dlsym crypt failed");
            p as usize
        });
        // SAFETY: dlsym returned a non-null pointer to `crypt`, whose signature
        // is fixed by POSIX.
        unsafe { std::mem::transmute::<usize, CryptFn>(addr) }
    }
}

/// Settings libxcrypt REJECTS. Verified case by case against the live library
/// below, so the list cannot silently rot into "settings it happens to accept".
const REJECTED: &[&str] = &["$9$saltsalt$", "", "x", "!!!not-a-salt!!!", "*0", "*1"];

fn host_crypt(key: &str, salt: &str) -> (Option<String>, c_int) {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    unsafe { *host::__errno_location() = 0 };
    // SAFETY: both pointers are valid NUL-terminated strings for the call.
    let p = unsafe { (host::crypt_fn())(k.as_ptr(), s.as_ptr()) };
    let e = unsafe { *host::__errno_location() };
    let out = if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    };
    (out, e)
}

fn fl_crypt(key: &str, salt: &str) -> (Option<String>, c_int) {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    unsafe { *host::__errno_location() = 0 };
    // SAFETY: both pointers are valid NUL-terminated strings for the call.
    let p = unsafe { frankenlibc_abi::unistd_abi::crypt(k.as_ptr(), s.as_ptr()) };
    let e = unsafe { *host::__errno_location() };
    let out = if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    };
    (out, e)
}

#[test]
fn crypt_rejected_settings_match_libxcrypt_failure_token() {
    for &salt in REJECTED {
        let (h_out, h_err) = host_crypt("password", salt);

        // Oracle first: confirm libxcrypt really rejects this setting with a
        // token, so a setting that silently became VALID upstream turns into a
        // loud failure here instead of a vacuous pass.
        let h = h_out
            .clone()
            .unwrap_or_else(|| panic!("oracle: libxcrypt returned NULL for salt {salt:?}"));
        assert!(
            h == "*0" || h == "*1",
            "oracle: libxcrypt did not reject salt {salt:?} (returned {h:?}); \
             the REJECTED list is stale"
        );
        assert_eq!(h_err, libc::EINVAL, "oracle: expected EINVAL for salt {salt:?}");

        let (f_out, f_err) = fl_crypt("password", salt);
        let f = f_out
            .unwrap_or_else(|| panic!("fl returned NULL for salt {salt:?}; libxcrypt never does"));
        assert_eq!(f, h, "crypt({salt:?}) token: fl={f:?} libxcrypt={h:?}");
        assert_eq!(f_err, h_err, "crypt({salt:?}) errno: fl={f_err} libxcrypt={h_err}");
    }
}

/// The property the token exists for, asserted directly rather than only via
/// fl==libxcrypt: a rejected setting must never produce a result equal to
/// itself, or `strcmp(crypt(pw, stored), stored)` would authenticate anyone
/// whose stored field is unparseable.
#[test]
fn crypt_failure_token_never_equals_the_setting() {
    for &salt in REJECTED {
        let (out, _) = fl_crypt("password", salt);
        let out = out.unwrap_or_else(|| panic!("fl returned NULL for salt {salt:?}"));
        assert_ne!(
            out, salt,
            "crypt({salt:?}) returned a value equal to the setting — \
             strcmp-based authentication would accept any password"
        );
    }
    // The specific inversion that makes this work for the two token values.
    let (t0, _) = fl_crypt("password", "*0");
    let (t1, _) = fl_crypt("password", "*1");
    assert_eq!(t0.as_deref(), Some("*1"), "salt *0 must yield *1");
    assert_eq!(t1.as_deref(), Some("*0"), "salt *1 must yield *0");
}

/// fl's digests must be BYTE-IDENTICAL to libxcrypt's for every algorithm it
/// implements. This is the property `crypt` exists for: its only real use is
/// `strcmp(crypt(password, stored), stored)`, so a digest that is merely
/// well-formed authenticates nobody.
///
/// This arm was shape-only while bd-9n50f2 was open — fl's digests were the
/// right length, prefix and alphabet but the wrong content for all three
/// algorithms, because the shared crypt-base64 encoder packed each 3-byte group
/// in reverse. It is equality now that the encoder is fixed.
///
/// The matrix deliberately includes the cases most likely to expose a padding or
/// grouping error rather than only the happy path: an empty key, a key longer
/// than one digest block, a short salt, a full-length salt, and an explicit
/// `rounds=` parameter.
#[test]
fn crypt_supported_algorithms_match_libxcrypt_byte_for_byte() {
    let keys: &[&str] = &["", "a", "password", &"x".repeat(200)];
    let salts: &[&str] = &[
        "$1$saltsalt$",
        "$1$ab$",
        "$5$saltsalt$",
        "$5$ab$",
        "$5$rounds=1000$saltsalt$",
        "$6$saltsalt$",
        "$6$ab$",
        "$6$rounds=1000$saltsalt$",
    ];
    let mut compared = 0usize;
    for &salt in salts {
        for &key in keys {
            let (h_out, _) = host_crypt(key, salt);
            let h = h_out.unwrap_or_else(|| panic!("oracle: libxcrypt NULL for {salt:?}"));
            // Only compare where the oracle actually produced a hash; if a
            // setting is rejected upstream it belongs to the other test.
            if h == "*0" || h == "*1" {
                continue;
            }
            let (f_out, _) = fl_crypt(key, salt);
            let f = f_out.unwrap_or_else(|| panic!("fl returned NULL for {salt:?}"));
            assert_ne!(f, "*0", "crypt(key.len={}, {salt:?}) returned the failure token", key.len());
            assert_ne!(f, "*1", "crypt(key.len={}, {salt:?}) returned the failure token", key.len());
            assert_eq!(
                f,
                h,
                "crypt(key.len={}, {salt:?}) digest mismatch\n  fl:        {f}\n  libxcrypt: {h}",
                key.len()
            );
            compared += 1;
        }
    }
    // Guard against the whole matrix being skipped by an oracle change.
    assert!(
        compared >= 20,
        "only {compared} (key, salt) pairs were actually compared; the matrix went inert"
    );
}
