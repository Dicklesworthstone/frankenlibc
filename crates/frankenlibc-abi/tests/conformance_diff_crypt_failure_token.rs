#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-libcrypt (libxcrypt) oracle

//! Differential gate for crypt's failure-token behaviour (bd-r9ihvq). The host
//! libcrypt (libxcrypt) NEVER returns NULL: for a setting it cannot hash
//! (unsupported scheme, malformed salt) it returns "*0" — or "*1" when the
//! setting already begins with "*0" — and sets EINVAL. fl previously returned
//! NULL (a caller NULL-deref hazard). This pins, for each unsupported/invalid
//! setting, that fl returns the SAME non-NULL token as the host. (Schemes the
//! host hashes but fl doesn't — DES/yescrypt — are tracked separately as
//! bd-c6ykz1 and excluded here.) No mocks.

use std::ffi::{c_char, CStr, CString};

unsafe extern "C" {
    fn crypt(key: *const c_char, salt: *const c_char) -> *mut c_char;
}

fn host(key: &str, salt: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    let p = unsafe { crypt(k.as_ptr(), s.as_ptr()) };
    if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) }
}
fn fl(key: &str, salt: &str) -> Option<String> {
    let k = CString::new(key).unwrap();
    let s = CString::new(salt).unwrap();
    let p = unsafe { frankenlibc_abi::unistd_abi::crypt(k.as_ptr(), s.as_ptr()) };
    if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) }
}

#[test]
fn crypt_failure_token_matches_host() {
    // Settings the host cannot hash -> it returns "*0"/"*1", never NULL.
    let cases = ["$z$badscheme", "!", "", "*0", "*1", "$ ", "$$"];
    for salt in cases {
        let h = host("password", salt);
        let f = fl("password", salt);
        // Host must produce a non-NULL token here (sanity of the oracle).
        assert!(h.is_some(), "host crypt(pw, {salt:?}) unexpectedly NULL");
        let ht = h.unwrap();
        assert!(ht.starts_with('*'), "host token for {salt:?} = {ht:?} (expected *0/*1)");
        assert_eq!(f, Some(ht.clone()), "crypt(pw, {salt:?}): fl={f:?} host={ht:?}");
    }
}

#[test]
fn crypt_supported_schemes_still_hash() {
    // Regression guard: $1$/$5$/$6$ must still produce a real hash, not a token.
    for salt in ["$1$abcdefgh$", "$5$saltsalt$", "$6$saltsalt$"] {
        let f = fl("password", salt).expect("fl crypt should hash a supported scheme");
        assert!(f.starts_with(salt) && !f.starts_with('*'), "fl crypt({salt:?})={f:?}");
        assert_eq!(Some(&f), host("password", salt).as_ref(), "fl vs host hash for {salt:?}");
    }
}
