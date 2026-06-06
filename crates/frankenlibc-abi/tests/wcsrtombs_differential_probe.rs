//! Differential probe: FrankenLibC `wcsrtombs` vs host glibc `wcsrtombs`, the
//! bulk wide→multibyte string converter (reverse of `mbsrtowcs`). Verifies the
//! `*src` update (NULL when the whole string fits, next-unconverted otherwise),
//! the `dst == NULL` byte-count mode, and `len` byte-limiting — including a
//! multibyte character that only partially fits in the remaining `len` (it must
//! NOT be split) and `len` landing exactly on the encoded length.
#![allow(unsafe_code)]

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcsrtombs(
        dst: *mut libc::c_char,
        src: *mut *const libc::wchar_t,
        len: usize,
        ps: *mut libc::mbstate_t,
    ) -> usize;
    fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, PartialEq, Eq, Clone)]
struct Outcome {
    rc: i64,
    src_off: Option<isize>, // None == *src NULL, else element offset from start
    bytes: Vec<u8>,
}

fn run(input: &[u32], dst_null: bool, len: usize, use_fl: bool) -> Outcome {
    let buf: Vec<u32> = input.to_vec(); // includes trailing 0
    let start = buf.as_ptr();
    let mut src = start;
    let mut out = vec![0u8; len.max(1) + 8];
    let dst = if dst_null {
        std::ptr::null_mut()
    } else {
        out.as_mut_ptr() as *mut libc::c_char
    };
    let rc = if use_fl {
        // SAFETY: buf/out own storage; src points into buf; dst fits `len`.
        unsafe {
            fl::wcsrtombs(
                dst as *mut std::ffi::c_char,
                &mut src as *mut *const u32 as *mut *const libc::wchar_t,
                len,
                std::ptr::null_mut(),
            )
        }
    } else {
        let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
        // SAFETY: as above; st is a valid out param.
        unsafe { wcsrtombs(dst, &mut src as *mut *const u32 as *mut *const libc::wchar_t, len, &mut st) }
    };
    let rc_i = if rc == usize::MAX { -1 } else { rc as i64 };
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
        (rc_i as usize).min(len).min(out.len())
    };
    let bytes = if dst_null { Vec::new() } else { out[..n].to_vec() };
    Outcome {
        rc: rc_i,
        src_off,
        bytes,
    }
}

#[test]
fn wcsrtombs_matches_host_glibc() {
    let utf8 = c"C.UTF-8";
    // SAFETY: standard libc locale switch for this single-threaded test.
    if unsafe { setlocale(libc::LC_ALL, utf8.as_ptr()) }.is_null() {
        eprintln!("C.UTF-8 locale unavailable; skipping wcsrtombs differential probe");
        return;
    }

    // wide strings (each with trailing NUL); mix of 1/2/3/4-byte encodings + a
    // surrogate (un-encodable → EILSEQ).
    let inputs: &[&[u32]] = &[
        &[0],
        &[0x41, 0],
        &[0x41, 0x42, 0x43, 0],
        &[0xE9, 0x41, 0],          // é (2 bytes) then 'A'
        &[0x20AC, 0x42, 0],        // € (3 bytes) then 'B'
        &[0x1_F600, 0x43, 0],      // emoji (4 bytes) then 'C'
        &[0x41, 0xD800, 0x42, 0],  // surrogate mid-string (EILSEQ)
        &[0x20AC, 0x20AC, 0],      // two 3-byte chars (partial-fit boundary)
    ];

    let mut compared = 0u64;
    let mut divergences: Vec<(Vec<u32>, bool, usize, Outcome, Outcome)> = Vec::new();
    for input in inputs {
        for &dst_null in &[false, true] {
            for &len in &[0usize, 1, 2, 3, 4, 5, 6, 16] {
                let h = run(input, dst_null, len, false);
                let f = run(input, dst_null, len, true);
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
            "wcsrtombs diverged from host glibc on {}/{} cases (showing up to 30):\n{:#?}",
            divergences.len(),
            compared,
            shown
        );
    }
    eprintln!("wcsrtombs: {compared} cases, 0 divergences vs host glibc");
}
