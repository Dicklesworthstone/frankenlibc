//! Conformance gate: iconv UTF-7 (RFC 2152) codec vs host glibc, both directions.
//! fl previously failed iconv_open for UTF-7. UTF-7 is a stateful 7-bit-safe
//! shift codec (Modified Base64 of UTF-16BE). Verifies byte-exact conversion vs
//! glibc, including the end-of-input flush (iconv with NULL inbuf).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use std::os::raw::{c_char, c_void};
unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(
        cd: *mut c_void,
        i: *mut *mut c_char,
        il: *mut usize,
        o: *mut *mut c_char,
        ol: *mut usize,
    ) -> usize;
    fn iconv_close(cd: *mut c_void) -> i32;
}
use frankenlibc_abi::iconv_abi as fl;
// Convert with a trailing flush (NULL inbuf), capturing output + success.
fn conv(host: bool, from: &str, to: &str, src: &[u8]) -> (bool, Vec<u8>) {
    let cf = std::ffi::CString::new(from).unwrap();
    let ct = std::ffi::CString::new(to).unwrap();
    let cd = if host {
        unsafe { iconv_open(ct.as_ptr(), cf.as_ptr()) }
    } else {
        unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) }
    };
    assert_ne!(
        cd as isize, -1,
        "iconv_open({to}<-{from}) failed host={host}"
    );
    let mut out = vec![0u8; 512];
    let mut ip = src.as_ptr() as *mut c_char;
    let mut il = src.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r1 = if host {
        unsafe { iconv(cd, &mut ip, &mut il, &mut op, &mut ol) }
    } else {
        unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) }
    };
    // flush
    let r2 = if host {
        unsafe {
            iconv(
                cd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut op,
                &mut ol,
            )
        }
    } else {
        unsafe {
            fl::iconv(
                cd,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut op,
                &mut ol,
            )
        }
    };
    if host {
        unsafe {
            iconv_close(cd);
        }
    } else {
        unsafe {
            fl::iconv_close(cd);
        }
    }
    let ok = r1 != usize::MAX && r2 != usize::MAX;
    let n = out.len() - ol;
    out.truncate(n);
    (ok, out)
}
#[test]
fn utf7_matches_glibc_both_directions() {
    let samples: &[&[u8]] = &[
        b"A",
        b"hello world",
        b"=!#@$&*;<>[]{}|^%\"",
        "caf\u{e9}".as_bytes(),
        "\u{4e2d}\u{6587}".as_bytes(),
        "\u{1f600}".as_bytes(),
        "Hi \u{e9}! (test), a/b:c?".as_bytes(),
        b"+",
        b"a+b",
        "\u{e9}\u{e9}\u{e9}".as_bytes(),
        b"",
        "mix\u{e9}ed+text\u{4e2d}here".as_bytes(),
        "'(),-./:?".as_bytes(), // direct-set punctuation
    ];
    let mut fails = Vec::new();
    for s in samples {
        // encode UTF-8 -> UTF-7
        let h = conv(true, "UTF-8", "UTF-7", s);
        let f = conv(false, "UTF-8", "UTF-7", s);
        if h != f {
            fails.push(format!("encode {s:?}: host={h:02x?} fl={f:02x?}"));
        }
        // decode UTF-7 -> UTF-8 (round-trip glibc's encoding)
        let hd = conv(true, "UTF-7", "UTF-8", &h.1);
        let fd = conv(false, "UTF-7", "UTF-8", &h.1);
        if hd != fd {
            fails.push(format!("decode {:02x?}: host={hd:02x?} fl={fd:02x?}", h.1));
        }
    }
    // explicit decode cases incl. error
    for u7 in [
        &b"+AOk-"[..],
        b"+-",
        b"Hi+AOk-!",
        b"+AOk",
        b"a+AOk-b",
        b"+2D3YgA-",
    ] {
        let hd = conv(true, "UTF-7", "UTF-8", u7);
        let fd = conv(false, "UTF-7", "UTF-8", u7);
        if hd != fd {
            fails.push(format!(
                "decode-explicit {u7:?}: host={hd:02x?} fl={fd:02x?}"
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "UTF-7 diverged from glibc:\n{}",
        fails.join("\n")
    );
}
#[test]
fn utf7_open_succeeds() {
    for name in ["UTF-7", "UTF7", "utf-7", "UNICODE-1-1-UTF-7"] {
        let cn = std::ffi::CString::new(name).unwrap();
        let u = std::ffi::CString::new("UTF-8").unwrap();
        let cd = unsafe { fl::iconv_open(u.as_ptr(), cn.as_ptr()) };
        assert_ne!(cd as isize, -1, "iconv_open({name})");
        if cd as isize != -1 {
            unsafe { fl::iconv_close(cd) };
        }
    }
}
