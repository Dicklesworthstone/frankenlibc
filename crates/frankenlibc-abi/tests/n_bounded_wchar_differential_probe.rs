//! Differential probes: FrankenLibC `mbsnrtowcs` / `wcsnrtombs` vs host glibc
//! (the source-bounded converters). These add a source limit (`nms` bytes /
//! `nwc` wide chars) on top of the `mbsrtowcs`/`wcsrtombs` behaviours, so the
//! bug-prone cases are: a source window ending mid-character (must return the
//! count, not EILSEQ, with `*src` at the incomplete char), `dst == NULL` count
//! mode, `len`-limiting, and — for `wcsnrtombs` — a 5/6-byte UTF-8 form landing
//! near the `len` boundary (the encode must never overrun `dst`).
#![allow(unsafe_code)]

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn mbsnrtowcs(
        dst: *mut libc::wchar_t,
        src: *mut *const libc::c_char,
        nms: usize,
        len: usize,
        ps: *mut libc::mbstate_t,
    ) -> usize;
    fn wcsnrtombs(
        dst: *mut libc::c_char,
        src: *mut *const libc::wchar_t,
        nwc: usize,
        len: usize,
        ps: *mut libc::mbstate_t,
    ) -> usize;
    fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Outcome {
    rc: i64,
    src_off: Option<isize>,
    out: Vec<u32>, // wide chars (mbsn) or bytes-as-u32 (wcsn)
}

fn ensure_locale() -> bool {
    let utf8 = c"C.UTF-8";
    // SAFETY: standard libc locale switch for this single-threaded test.
    !unsafe { setlocale(libc::LC_ALL, utf8.as_ptr()) }.is_null()
}

fn run_mbsn(input: &[u8], nms: usize, dst_null: bool, len: usize, use_fl: bool) -> Outcome {
    let buf = input.to_vec();
    let start = buf.as_ptr() as *const libc::c_char;
    let mut src = start;
    let mut wide = vec![0u32; len.max(1) + 4];
    let dst = if dst_null {
        std::ptr::null_mut()
    } else {
        wide.as_mut_ptr() as *mut libc::wchar_t
    };
    let rc = if use_fl {
        // SAFETY: buf/wide own storage; src into buf; dst fits len.
        unsafe {
            fl::mbsnrtowcs(
                dst as *mut libc::wchar_t,
                &mut src as *mut *const libc::c_char as *mut *const std::ffi::c_char,
                nms,
                len,
                std::ptr::null_mut(),
            )
        }
    } else {
        let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe { mbsnrtowcs(dst, &mut src, nms, len, &mut st) }
    };
    let rc_i = if rc == usize::MAX { -1 } else { rc as i64 };
    let src_off = src_offset(dst_null, src, start, rc_i);
    let n = if rc_i < 0 {
        0
    } else {
        (rc_i as usize).min(len).min(wide.len())
    };
    let out = if dst_null {
        Vec::new()
    } else {
        wide[..n].to_vec()
    };
    Outcome {
        rc: rc_i,
        src_off,
        out,
    }
}

fn run_wcsn(input: &[u32], nwc: usize, dst_null: bool, len: usize, use_fl: bool) -> Outcome {
    let buf = input.to_vec();
    let start = buf.as_ptr();
    let mut src = start;
    let mut out = vec![0u8; len.max(1) + 8];
    let dst = if dst_null {
        std::ptr::null_mut()
    } else {
        out.as_mut_ptr() as *mut libc::c_char
    };
    let rc = if use_fl {
        // SAFETY: buf/out own storage; src into buf; dst fits len.
        unsafe {
            fl::wcsnrtombs(
                dst as *mut std::ffi::c_char,
                &mut src as *mut *const u32 as *mut *const libc::wchar_t,
                nwc,
                len,
                std::ptr::null_mut(),
            )
        }
    } else {
        let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        unsafe {
            wcsnrtombs(
                dst,
                &mut src as *mut *const u32 as *mut *const libc::wchar_t,
                nwc,
                len,
                &mut st,
            )
        }
    };
    let rc_i = if rc == usize::MAX { -1 } else { rc as i64 };
    let src_off = src_offset(dst_null, src, start, rc_i);
    let n = if rc_i < 0 {
        0
    } else {
        (rc_i as usize).min(len).min(out.len())
    };
    let bytes = if dst_null {
        Vec::new()
    } else {
        out[..n].iter().map(|&b| b as u32).collect()
    };
    Outcome {
        rc: rc_i,
        src_off,
        out: bytes,
    }
}

fn src_offset<T>(dst_null: bool, src: *const T, start: *const T, rc: i64) -> Option<isize> {
    if dst_null {
        Some(0)
    } else if src.is_null() {
        None
    } else if rc < 0 {
        Some(-1) // non-NULL on error; exact byte is a glibc quirk (bd-2g7oyh.185)
    } else {
        Some(unsafe { src.offset_from(start) })
    }
}

#[test]
fn mbsnrtowcs_matches_host_glibc() {
    if !ensure_locale() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }
    let inputs: &[&[u8]] = &[
        b"\0",
        b"abc\0",
        "a€b\0".as_bytes(), // ASCII, 3-byte, ASCII
        "café\0".as_bytes(),
        "😀x\0".as_bytes(), // 4-byte then ASCII
        &[b'a', 0xFF, 0],   // invalid byte
    ];
    let mut compared = 0u64;
    let mut div: Vec<(Vec<u8>, usize, bool, usize, Outcome, Outcome)> = Vec::new();
    for input in inputs {
        for &nms in &[0usize, 1, 2, 3, 4, 6, 64] {
            for &dst_null in &[false, true] {
                for &len in &[0usize, 1, 2, 4, 64] {
                    let h = run_mbsn(input, nms, false || dst_null, len, false);
                    let f = run_mbsn(input, nms, false || dst_null, len, true);
                    compared += 1;
                    if h != f {
                        div.push((input.to_vec(), nms, dst_null, len, h, f));
                    }
                }
            }
        }
    }
    assert!(
        div.is_empty(),
        "mbsnrtowcs diverged on {}/{} cases:\n{:#?}",
        div.len(),
        compared,
        &div[..div.len().min(30)]
    );
    eprintln!("mbsnrtowcs: {compared} cases, 0 divergences");
}

#[test]
fn wcsnrtombs_matches_host_glibc() {
    if !ensure_locale() {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }
    let inputs: &[&[u32]] = &[
        &[0],
        &[0x41, 0x42, 0],
        &[0xE9, 0x41, 0],         // 2-byte then ASCII
        &[0x20AC, 0x42, 0],       // 3-byte then ASCII
        &[0x1_F600, 0x43, 0],     // 4-byte then ASCII
        &[0x20_0000, 0x44, 0],    // 5-byte form (RFC 2279) — overflow-path stress
        &[0x41, 0xD800, 0x42, 0], // surrogate mid-string
    ];
    let mut compared = 0u64;
    let mut div: Vec<(Vec<u32>, usize, bool, usize, Outcome, Outcome)> = Vec::new();
    for input in inputs {
        for &nwc in &[0usize, 1, 2, 3, 64] {
            for &dst_null in &[false, true] {
                for &len in &[0usize, 1, 2, 3, 4, 5, 6, 32] {
                    let h = run_wcsn(input, nwc, dst_null, len, false);
                    let f = run_wcsn(input, nwc, dst_null, len, true);
                    compared += 1;
                    if h != f {
                        div.push((input.to_vec(), nwc, dst_null, len, h, f));
                    }
                }
            }
        }
    }
    assert!(
        div.is_empty(),
        "wcsnrtombs diverged on {}/{} cases:\n{:#?}",
        div.len(),
        compared,
        &div[..div.len().min(30)]
    );
    eprintln!("wcsnrtombs: {compared} cases, 0 divergences");
}
