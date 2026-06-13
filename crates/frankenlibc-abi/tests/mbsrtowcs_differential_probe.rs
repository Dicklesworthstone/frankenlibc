//! Differential probe: FrankenLibC `mbsrtowcs` vs host glibc `mbsrtowcs`, the
//! bulk multibyte→wide string converter. The subtle, bug-prone behaviours are
//! the `*src` pointer update (NULL on full conversion, the offending byte on
//! EILSEQ, the next unconverted byte when `len` is hit), the `dst == NULL`
//! count-only mode, and `len`-limiting (including `len` landing exactly on the
//! terminating NUL). This compares the return value, the resulting `*src`
//! OFFSET (or NULL), and the produced wide characters, for fl and glibc fed
//! identical inputs under `LC_ALL=C.UTF-8`.
#![allow(unsafe_code)]

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn mbsrtowcs(
        dst: *mut libc::wchar_t,
        src: *mut *const libc::c_char,
        len: usize,
        ps: *mut libc::mbstate_t,
    ) -> usize;
    fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Outcome {
    rc: i64,                // count, or -1 for EILSEQ
    src_off: Option<isize>, // None == *src set to NULL, else byte offset from start
    wide: Vec<u32>,         // wide chars actually written (when converting)
}

/// `input` must include its terminating NUL.
fn run_host(input: &[u8], dst_null: bool, len: usize) -> Outcome {
    let buf: Vec<u8> = input.to_vec();
    let start = buf.as_ptr() as *const libc::c_char;
    let mut src = start;
    let mut wide = vec![0u32; len.max(1) + 4];
    let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
    let dst = if dst_null {
        std::ptr::null_mut()
    } else {
        wide.as_mut_ptr() as *mut libc::wchar_t
    };
    // SAFETY: buf/wide own the storage; src points into buf; dst fits `len`.
    let rc = unsafe { mbsrtowcs(dst, &mut src, len, &mut st) };
    finish(rc, src, start, &wide, dst_null, len)
}

fn run_fl(input: &[u8], dst_null: bool, len: usize) -> Outcome {
    let buf: Vec<u8> = input.to_vec();
    let start = buf.as_ptr() as *const libc::c_char;
    let mut src = start;
    let mut wide = vec![0u32; len.max(1) + 4];
    let dst = if dst_null {
        std::ptr::null_mut()
    } else {
        wide.as_mut_ptr() as *mut libc::wchar_t
    };
    // SAFETY: buf/wide own the storage; src points into buf; dst fits `len`.
    let rc = unsafe {
        fl::mbsrtowcs(
            dst as *mut libc::wchar_t,
            &mut src as *mut *const libc::c_char as *mut *const std::ffi::c_char,
            len,
            std::ptr::null_mut(),
        )
    };
    finish(rc, src, start, &wide, dst_null, len)
}

fn finish(
    rc: usize,
    src: *const libc::c_char,
    start: *const libc::c_char,
    wide: &[u32],
    dst_null: bool,
    len: usize,
) -> Outcome {
    let rc_i = if rc == usize::MAX { -1 } else { rc as i64 };
    // glibc leaves *src untouched in count-only (dst==NULL) mode. On EILSEQ the
    // exact *src byte is a glibc internal quirk (len-dependent and internally
    // inconsistent — see bd-2g7oyh.185), so we assert only that it is non-NULL,
    // not the exact offset; FrankenLibC consistently uses the POSIX char-start.
    let src_off = if dst_null {
        Some(0)
    } else if src.is_null() {
        None
    } else if rc_i < 0 {
        Some(-1) // non-NULL on error; exact byte not asserted
    } else {
        Some(unsafe { src.offset_from(start) })
    };
    let n = if rc_i < 0 {
        0
    } else {
        (rc_i as usize).min(len).min(wide.len())
    };
    let captured = if dst_null {
        Vec::new()
    } else {
        wide[..n].to_vec()
    };
    Outcome {
        rc: rc_i,
        src_off,
        wide: captured,
    }
}

#[test]
fn mbsrtowcs_matches_host_glibc() {
    let utf8 = c"C.UTF-8";
    // SAFETY: standard libc locale switch for this single-threaded test.
    if unsafe { setlocale(libc::LC_ALL, utf8.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 locale unavailable; skipping mbsrtowcs differential probe");
        return;
    }

    // (input-with-NUL, description)
    let inputs: &[&[u8]] = &[
        b"\0",
        b"a\0",
        b"abc\0",
        b"hello world\0",
        "café\0".as_bytes(),    // multibyte é
        "a€b\0".as_bytes(),     // 3-byte €
        "😀x\0".as_bytes(),     // 4-byte emoji
        &[b'a', 0xFF, b'b', 0], // invalid byte mid-string
        &[0xE2, 0x82, b'a', 0], // truncated € then ASCII (invalid continuation)
        &[b'x', 0xC0, 0x80, 0], // overlong NUL (invalid)
    ];

    let mut compared = 0u64;
    let mut divergences: Vec<(Vec<u8>, bool, usize, Outcome, Outcome)> = Vec::new();
    for input in inputs {
        for &dst_null in &[false, true] {
            for &len in &[0usize, 1, 2, 3, 4, 8, 64] {
                let h = run_host(input, dst_null, len);
                let f = run_fl(input, dst_null, len);
                compared += 1;
                if h != f {
                    divergences.push((input.to_vec(), dst_null, len, h, f));
                }
            }
        }
    }

    if !divergences.is_empty() {
        let shown: Vec<_> = divergences.iter().take(30).collect();
        panic!(
            "mbsrtowcs diverged from host glibc on {}/{} cases (showing up to 30):\n{:#?}",
            divergences.len(),
            compared,
            shown
        );
    }
    eprintln!("mbsrtowcs: {compared} cases, 0 divergences vs host glibc");
}
