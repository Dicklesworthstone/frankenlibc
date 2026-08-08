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

/// fl must not have regressed the SUCCESS path into the token: for the
/// algorithms it implements it must still return a real hash. Without this,
/// returning `*0` unconditionally would satisfy every assertion above.
///
/// This asserts SHAPE, not byte-equality with libxcrypt. fl's `$6$` digest is
/// currently well-formed but content-different from libxcrypt's — a separate and
/// much larger defect (fl cannot verify a real /etc/shadow entry), filed on its
/// own bead. Asserting equality here would make this gate fail for a reason
/// bd-r9ihvq is not about; asserting nothing would let the token swallow the
/// success path. Shape is the property this bead needs, so shape is what it
/// checks, and the divergence is printed for the record rather than hidden.
#[test]
fn crypt_supported_algorithms_still_produce_real_hashes() {
    for salt in ["$6$saltsalt$", "$5$saltsalt$", "$1$saltsalt$"] {
        let (h_out, _) = host_crypt("password", salt);
        let (f_out, _) = fl_crypt("password", salt);
        let h = h_out.expect("libxcrypt hash");
        let f = f_out.expect("fl hash");

        assert!(
            h.starts_with(salt),
            "oracle: libxcrypt hash {h:?} should carry its setting {salt:?}"
        );
        // The anti-vacuity core: a real hash, not the failure token, and not a
        // bare echo of the setting.
        assert_ne!(f, "*0", "crypt({salt:?}) returned the failure token");
        assert_ne!(f, "*1", "crypt({salt:?}) returned the failure token");
        assert!(
            f.starts_with(salt) && f.len() > salt.len() + 10,
            "crypt({salt:?}) did not return a real hash: {f:?}"
        );
        assert_eq!(
            f.len(),
            h.len(),
            "crypt({salt:?}) hash length differs from libxcrypt: fl={} host={}",
            f.len(),
            h.len()
        );

        if f != h {
            eprintln!("NOTE crypt({salt:?}) digest differs from libxcrypt (separate defect):");
            eprintln!("  fl:        {f}");
            eprintln!("  libxcrypt: {h}");
        }
    }
}
