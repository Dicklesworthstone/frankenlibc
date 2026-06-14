//! Conformance gate: iconv "UCS-2" / "UCS-2LE" / "UCS-2BE" charset support vs
//! host glibc. fl previously failed iconv_open for these names. UCS-2 is a
//! BMP-only fixed-16-bit codec that does NOT pair surrogates: a non-BMP scalar
//! is EILSEQ on encode, a surrogate code unit is EILSEQ on decode. Bare "UCS-2"
//! and "UCS-2LE" are little-endian; "UCS-2BE" is big-endian (verified vs host).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use std::os::raw::{c_char, c_void};

unsafe extern "C" {
    fn iconv_open(to: *const c_char, from: *const c_char) -> *mut c_void;
    fn iconv(
        cd: *mut c_void,
        inbuf: *mut *mut c_char,
        inleft: *mut usize,
        outbuf: *mut *mut c_char,
        outleft: *mut usize,
    ) -> usize;
    fn iconv_close(cd: *mut c_void) -> i32;
}
use frankenlibc_abi::iconv_abi as fl;

// Returns (ok, output_bytes). `ok` = full success (iconv returned != -1).
// output_bytes captures whatever was written (incl. partial output on EILSEQ).
fn conv(host: bool, from: &str, to: &str, input: &[u8]) -> (bool, Vec<u8>) {
    let cf = std::ffi::CString::new(from).unwrap();
    let ct = std::ffi::CString::new(to).unwrap();
    let cd = if host {
        unsafe { iconv_open(ct.as_ptr(), cf.as_ptr()) }
    } else {
        unsafe { fl::iconv_open(ct.as_ptr(), cf.as_ptr()) }
    };
    assert_ne!(
        cd as isize, -1,
        "iconv_open({to}<-{from}) failed (host={host})"
    );
    let mut out = vec![0u8; 256];
    let mut ip = input.as_ptr() as *mut c_char;
    let mut il = input.len();
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let r = if host {
        unsafe { iconv(cd, &mut ip, &mut il, &mut op, &mut ol) }
    } else {
        unsafe { fl::iconv(cd, &mut ip, &mut il, &mut op, &mut ol) }
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
    let n = out.len() - ol;
    out.truncate(n);
    (r != usize::MAX, out)
}

#[test]
fn ucs2_matches_glibc_both_directions() {
    let bmp: &[&[u8]] = &[
        b"A",
        b"hello world",
        "\u{00e9}".as_bytes(),
        "\u{4e00}\u{ff21}".as_bytes(),
        b"",
        "\u{0}\u{7f}\u{80}\u{7ff}\u{800}\u{ffff}".as_bytes(),
        "caf\u{e9}".as_bytes(),
    ];
    let astral: &[&[u8]] = &[
        "\u{1f600}".as_bytes(),
        "a\u{1f600}b".as_bytes(),
        "\u{10000}".as_bytes(),
    ];
    let names = ["UCS-2", "UCS-2LE", "UCS-2BE", "UCS2", "ucs-2be"];
    let mut fails = Vec::new();
    for name in names {
        // encode BMP: must match exactly
        for s in bmp {
            let h = conv(true, "UTF-8", name, s);
            let f = conv(false, "UTF-8", name, s);
            if h != f {
                fails.push(format!("enc-bmp {name} {s:?}: host={h:?} fl={f:?}"));
            }
            // decode round-trip
            let hd = conv(true, name, "UTF-8", &h.1);
            let fd = conv(false, name, "UTF-8", &h.1);
            if hd != fd {
                fails.push(format!("dec {name} {:?}: host={hd:?} fl={fd:?}", h.1));
            }
        }
        // encode astral: both must fail (EILSEQ), same partial output
        for s in astral {
            let h = conv(true, "UTF-8", name, s);
            let f = conv(false, "UTF-8", name, s);
            if h != f {
                fails.push(format!("enc-astral {name} {s:?}: host={h:?} fl={f:?}"));
            }
        }
    }
    // decode a lone surrogate unit (D800 LE) -> both EILSEQ
    let h = conv(true, "UCS-2LE", "UTF-8", &[0x00, 0xD8]);
    let f = conv(false, "UCS-2LE", "UTF-8", &[0x00, 0xD8]);
    if h != f {
        fails.push(format!("dec-surrogate: host={h:?} fl={f:?}"));
    }

    assert!(
        fails.is_empty(),
        "UCS-2 diverged from glibc:\n{}",
        fails.join("\n")
    );
}

#[test]
fn ucs2_open_succeeds() {
    for name in ["UCS-2", "UCS-2LE", "UCS-2BE", "UCS2", "UCS2LE", "UCS2BE"] {
        let cn = std::ffi::CString::new(name).unwrap();
        let to = std::ffi::CString::new("UTF-8").unwrap();
        let cd = unsafe { fl::iconv_open(to.as_ptr(), cn.as_ptr()) };
        assert_ne!(cd as isize, -1, "iconv_open({name}) should succeed");
        if cd as isize != -1 {
            unsafe { fl::iconv_close(cd) };
        }
    }
}
