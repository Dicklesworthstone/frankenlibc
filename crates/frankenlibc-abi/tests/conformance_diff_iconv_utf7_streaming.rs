#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc iconv oracle
//! UTF-7 SOURCE decode with the input split across multiple iconv() calls
//! (bd-s41n4a). Presents each UTF-7 byte string to a single descriptor one byte
//! at a time (growing prefix, carrying any incomplete tail forward — the real
//! iconv chunked contract), then flushes, and asserts the accumulated UTF-8
//! output + overall success matches glibc fed the SAME way, and fl's own
//! whole-buffer result.
use std::ffi::{CString, c_char, c_void};
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

fn run(host: bool, src: &[u8], byte_at_a_time: bool) -> (bool, Vec<u8>) {
    let to = CString::new("UTF-8").unwrap();
    let from = CString::new("UTF-7").unwrap();
    let cd = if host {
        unsafe { iconv_open(to.as_ptr(), from.as_ptr()) }
    } else {
        unsafe { fl::iconv_open(to.as_ptr(), from.as_ptr()) }
    };
    if cd as isize == -1 {
        return (false, vec![]);
    }
    let mut out = vec![0u8; 256];
    let mut op = out.as_mut_ptr() as *mut c_char;
    let mut ol = out.len();
    let mut ok = true;
    let call = |cd: *mut c_void,
                ip: &mut *mut c_char,
                il: &mut usize,
                op: &mut *mut c_char,
                ol: &mut usize|
     -> usize {
        if host {
            unsafe { iconv(cd, ip, il, op, ol) }
        } else {
            unsafe { fl::iconv(cd, ip, il, op, ol) }
        }
    };
    if byte_at_a_time {
        let mut consumed = 0usize;
        for end in 1..=src.len() {
            let mut chunk = src[consumed..end].to_vec();
            let mut ip = chunk.as_mut_ptr() as *mut c_char;
            let mut il = chunk.len();
            let r = call(cd, &mut ip, &mut il, &mut op, &mut ol);
            consumed += chunk.len() - il;
            if r == usize::MAX
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::EILSEQ)
            {
                ok = false;
                break;
            }
        }
    } else {
        let mut buf = src.to_vec();
        let mut ip = buf.as_mut_ptr() as *mut c_char;
        let mut il = buf.len();
        let r = call(cd, &mut ip, &mut il, &mut op, &mut ol);
        if r == usize::MAX && std::io::Error::last_os_error().raw_os_error() == Some(libc::EILSEQ) {
            ok = false;
        }
    }
    if ok {
        let r = call(cd, &mut std::ptr::null_mut(), &mut 0usize, &mut op, &mut ol);
        if r == usize::MAX {
            ok = false;
        }
    }
    if host {
        unsafe { iconv_close(cd) };
    } else {
        unsafe { fl::iconv_close(cd) };
    }
    let n = out.len() - ol;
    out.truncate(n);
    (ok, out)
}

#[test]
fn utf7_decode_byte_at_a_time_matches_glibc() {
    let cases: &[&[u8]] = &[
        b"+AOk-",
        b"+AOk",
        b"Hi+AOk-!",
        b"a+AOk-b",
        b"+-",
        b"a+-b",
        b"+2D3YgA-",
        b"+T2BZ8A-",
        b"hello world",
        b"'(),-./:?",
        b"+AOkA6QDp-",
        b"+",
        b"A+ImIDkQ-.",
        b"+AOk-+AOk-",
        b"caf+AOk-",
        b"+ImIDkQ-",
    ];
    let mut fails = Vec::new();
    for &s in cases {
        let g = run(true, s, true); // glibc, byte-at-a-time
        let f = run(false, s, true); // fl, byte-at-a-time
        if g != f {
            fails.push(format!(
                "chunked {s:?}: glibc=({},{:02x?}) fl=({},{:02x?})",
                g.0, g.1, f.0, f.1
            ));
        }
        let fw = run(false, s, false); // fl, whole-buffer
        if f != fw {
            fails.push(format!(
                "chunked!=whole {s:?}: chunked=({},{:02x?}) whole=({},{:02x?})",
                f.0, f.1, fw.0, fw.1
            ));
        }
    }
    assert!(
        fails.is_empty(),
        "UTF-7 streaming divergences:\n{}",
        fails.join("\n")
    );
}
