#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-libcrypt (libxcrypt) crypt_gensalt oracle

//! Differential gate for crypt_gensalt (bd-wa0cpo) — previously fl-internal
//! only. crypt_gensalt(prefix, count, rbytes, nrbytes) builds a salt SETTING by
//! encoding the random bytes into the crypt base-64 alphabet; it is
//! deterministic for fixed rbytes. For the schemes fl supports ($1$/$5$/$6$),
//! fl's setting must match host libxcrypt byte-for-byte (same salt length, same
//! alphabet, same rbytes->chars mapping); a mismatch means fl-generated salts
//! aren't interoperable. Unsupported prefixes ($y$ etc.) are out of scope here
//! (bd-c6ykz1). No mocks.

use std::ffi::{CStr, CString, c_char, c_int, c_ulong};

unsafe extern "C" {
    fn crypt_gensalt(
        prefix: *const c_char,
        count: c_ulong,
        rbytes: *const c_char,
        nrbytes: c_int,
    ) -> *mut c_char;
}

// Fixed pseudo-random bytes so both impls encode the same input.
const RBYTES: &[u8] = b"0123456789abcdef0123456789abcdef";

fn host(prefix: &str) -> Option<String> {
    let p = CString::new(prefix).unwrap();
    let r = unsafe {
        crypt_gensalt(
            p.as_ptr(),
            0,
            RBYTES.as_ptr() as *const c_char,
            RBYTES.len() as c_int,
        )
    };
    if r.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(r) }.to_string_lossy().into_owned())
    }
}
fn fl(prefix: &str) -> Option<String> {
    let p = CString::new(prefix).unwrap();
    let r = unsafe {
        frankenlibc_abi::unistd_abi::crypt_gensalt(
            p.as_ptr(),
            0,
            RBYTES.as_ptr() as *const c_char,
            RBYTES.len() as c_int,
        )
    };
    if r.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(r) }.to_string_lossy().into_owned())
    }
}

#[test]
fn crypt_gensalt_supported_prefixes_match_host() {
    for prefix in ["$1$", "$5$", "$6$"] {
        let h = host(prefix);
        let f = fl(prefix);
        assert!(h.is_some(), "host crypt_gensalt({prefix:?}) NULL");
        let ht = h.as_ref().unwrap();
        // Setting must carry the requested scheme prefix.
        assert!(
            ht.starts_with(prefix),
            "host setting {ht:?} lacks prefix {prefix:?}"
        );
        assert_eq!(f, h, "crypt_gensalt({prefix:?}): fl={f:?} host={h:?}");
    }
}

#[test]
fn crypt_gensalt_setting_round_trips_through_crypt() {
    // A salt setting fl generates for $6$ must be usable by fl::crypt and
    // produce a $6$ hash (sanity that the setting is well-formed).
    if let Some(setting) = fl("$6$") {
        let key = CString::new("password").unwrap();
        let s = CString::new(setting.clone()).unwrap();
        let h = unsafe { frankenlibc_abi::unistd_abi::crypt(key.as_ptr(), s.as_ptr()) };
        assert!(
            !h.is_null(),
            "fl::crypt rejected fl-generated $6$ setting {setting:?}"
        );
        let hs = unsafe { CStr::from_ptr(h) }.to_string_lossy();
        assert!(hs.starts_with("$6$"), "fl::crypt on {setting:?} -> {hs:?}");
    }
}
