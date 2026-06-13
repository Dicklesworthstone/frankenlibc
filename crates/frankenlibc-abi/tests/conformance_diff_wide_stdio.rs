#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wide-stdio oracle

//! Wide-stdio (`fgetwc`/`fgetws`) decode parity vs host glibc C.UTF-8
//! (bd-2g7oyh.286). Reads the SAME on-disk file with fl's and glibc's stream
//! readers and compares the wide-char sequences, covering: ASCII/2/3/4-byte
//! UTF-8, obsolete RFC-2279 5/6-byte leads (which glibc C.UTF-8 and fl's own
//! mbrtowc decode — bd-kryp2k), invalid/incomplete/truncated sequences,
//! embedded NUL, `fgetws` newline retention + buffer clipping, and the
//! degenerate `n == 1` (read 0 chars, return an empty string, not NULL).

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Write;

use frankenlibc_abi::stdio_abi as flio;
use frankenlibc_abi::wchar_abi as flw;

unsafe extern "C" {
    fn fopen(p: *const c_char, m: *const c_char) -> *mut c_void;
    fn fclose(s: *mut c_void) -> c_int;
    fn fgetwc(s: *mut c_void) -> u32;
    fn fgetws(b: *mut i32, n: c_int, s: *mut c_void) -> *mut i32;
    fn setlocale(c: c_int, l: *const c_char) -> *mut c_char;
}
const WEOF: u32 = 0xFFFF_FFFF;

fn mkfile(tag: &str, bytes: &[u8]) -> String {
    let p = format!("/tmp/fl_wstdio_{}_{tag}.bin", std::process::id());
    std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
    p
}

fn seq(path: &str, host: bool) -> Vec<i64> {
    let cp = CString::new(path).unwrap();
    let m = CString::new("r").unwrap();
    let s = if host {
        unsafe { fopen(cp.as_ptr(), m.as_ptr()) }
    } else {
        unsafe { flio::fopen(cp.as_ptr(), m.as_ptr()) }
    };
    assert!(!s.is_null(), "fopen failed for {path}");
    let mut out = vec![];
    loop {
        let c = if host {
            unsafe { fgetwc(s) }
        } else {
            unsafe { flw::fgetwc(s) }
        };
        out.push(c as i32 as i64);
        if c == WEOF || out.len() > 256 {
            break;
        }
    }
    if host {
        unsafe { fclose(s) }
    } else {
        unsafe { flio::fclose(s) }
    };
    out
}

fn lines(path: &str, n: c_int, host: bool, cap: usize) -> Vec<Vec<i64>> {
    let cp = CString::new(path).unwrap();
    let m = CString::new("r").unwrap();
    let s = if host {
        unsafe { fopen(cp.as_ptr(), m.as_ptr()) }
    } else {
        unsafe { flio::fopen(cp.as_ptr(), m.as_ptr()) }
    };
    assert!(!s.is_null());
    let mut out = vec![];
    loop {
        let mut buf = vec![0i32; n as usize + 2];
        let r = if host {
            unsafe { fgetws(buf.as_mut_ptr(), n, s) }
        } else {
            unsafe { flw::fgetws(buf.as_mut_ptr(), n, s) }
        };
        if r.is_null() {
            break;
        }
        out.push(
            buf.iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as i64)
                .collect(),
        );
        if out.len() >= cap {
            break;
        }
    }
    if host {
        unsafe { fclose(s) }
    } else {
        unsafe { flio::fclose(s) }
    };
    out
}

#[test]
fn wide_stdio_decode_matches_glibc() {
    let loc = CString::new("C.UTF-8").unwrap();
    if unsafe { setlocale(0, loc.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }
    let cases: &[(&str, Vec<u8>)] = &[
        ("ascii_nl", b"ab\ncd\n".to_vec()),
        (
            "multibyte",
            "a\u{e9}\u{20ac}\n\u{10348}x".as_bytes().to_vec(),
        ),
        ("no_final_nl", b"xyz".to_vec()),
        ("empty", b"".to_vec()),
        ("invalid", vec![b'a', 0xFF, 0xFE, b'b']),
        ("incomplete_eof", vec![b'a', 0xE2, 0x82]),
        ("lone_cont", vec![0x80, 0x80]),
        ("nul_mid", vec![b'a', 0, b'b', b'\n']),
        ("five_byte", vec![0xF8, 0x88, 0x80, 0x80, 0x80, b'\n']),
        ("six_byte", vec![0xFC, 0x84, 0x80, 0x80, 0x80, 0x80, b'\n']),
    ];
    for (tag, bytes) in cases {
        let p = mkfile(tag, bytes);
        assert_eq!(seq(&p, false), seq(&p, true), "fgetwc diverged on {tag}");
        let _ = std::fs::remove_file(&p);
    }

    for (tag, body, n) in [
        ("lines", "a\u{e9}\u{20ac}\n\u{10348}x\ny", 5),
        ("clip", "abcdef\n", 4),
        ("n1", "ab\n", 1),
        ("n2", "ab\n", 2),
    ] {
        let p = mkfile(tag, body.as_bytes());
        // n == 1 returns an empty string forever (consumes nothing); cap the loop.
        let cap = if n == 1 { 8 } else { 50 };
        assert_eq!(
            lines(&p, n, false, cap),
            lines(&p, n, true, cap),
            "fgetws diverged on {tag} n={n}"
        );
        let _ = std::fs::remove_file(&p);
    }
}
