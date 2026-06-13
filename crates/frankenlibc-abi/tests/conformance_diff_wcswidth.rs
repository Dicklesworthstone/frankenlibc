#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcswidth oracle

//! `wcswidth` composite-logic parity gate vs host glibc under a UTF-8 locale.
//!
//! `wcwidth` itself is swept full-range elsewhere (wcwidth_sweep_explore.rs);
//! this gate exercises what `wcswidth` adds on top: summing per-char widths,
//! stopping at the terminating NUL, bounding by `n` CHARACTERS (not columns),
//! and returning -1 the moment any in-range char has a negative width (a
//! control char), even when printable chars surround it. A fixed battery of
//! known edge codepoints plus a deterministic randomized fuzz over a mixed
//! alphabet (printable / wide CJK / combining / control / astral) drive both
//! engines and compare the int result. NULL is fl-only (glibc dereferences).

use frankenlibc_abi::wchar_abi as flw;

unsafe extern "C" {
    fn wcswidth(s: *const i32, n: usize) -> i32;
    fn setlocale(c: i32, l: *const i8) -> *mut i8;
}

fn both(s: &[i32], n: usize) -> (i32, i32) {
    // `s` must be NUL-terminated within its own bounds for the glibc call to be
    // memory-safe under large `n`.
    let fl = unsafe { flw::wcswidth(s.as_ptr(), n) };
    let gl = unsafe { wcswidth(s.as_ptr(), n) };
    (fl, gl)
}

#[test]
fn wcswidth_matches_glibc() {
    let loc = std::ffi::CString::new("C.UTF-8").unwrap();
    if unsafe {
        setlocale(6 /* LC_ALL */, loc.as_ptr())
    }
    .is_null()
    {
        eprintln!("C.UTF-8 unavailable; skipping");
        return;
    }

    // Fixed battery: each ends in NUL so it is safe at any `n`.
    let battery: &[&[i32]] = &[
        &[0],                               // empty
        &[0x61, 0x62, 0x63, 0],             // ascii
        &[0x4e2d, 0x6587, 0],               // wide CJK (2+2)
        &[0x61, 0x09, 0x62, 0],             // embedded TAB (control -> -1)
        &[0x61, 0x0301, 0x62, 0],           // combining accent (width 0)
        &[0x0300, 0],                       // leading combining
        &[0x61, 0x1b, 0],                   // ESC control
        &[0x7f, 0],                         // DEL
        &[0xad, 0],                         // soft hyphen
        &[0x200b, 0],                       // zero-width space
        &[0x115f, 0],                       // hangul choseong filler
        &[0x20ac, 0x10348, 0],              // BMP + astral
        &[0x61, 0x62, 0x63, 0x64, 0x65, 0], // longer, for n-bounding
        &[0x4e2d, 0x09, 0x6587, 0],         // wide + control + wide
    ];
    for s in battery {
        for n in [0usize, 1, 2, 3, 4, 5, 64] {
            let (fl, gl) = both(s, n);
            assert_eq!(fl, gl, "wcswidth battery {s:x?} n={n}: fl={fl} glibc={gl}");
        }
    }

    // Deterministic randomized fuzz over a mixed alphabet.
    let alphabet: &[i32] = &[
        0x41, 0x7a, 0x30, 0x20, // ascii printable + space
        0x4e2d, 0xff21, 0x3042, // wide CJK / fullwidth / hiragana
        0x0301, 0x0308, 0x064b, // combining marks (width 0)
        0x09, 0x1b, 0x7f, 0x00, // control + DEL (width -1)
        0x20ac, 0x10348, 0x1f600, // euro / astral / emoji
        0xad, 0x200b, 0x115f, // soft hyphen / zwsp / jamo filler
    ];
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    for _ in 0..200_000 {
        let len = (next() % 8) as usize;
        let mut buf: Vec<i32> = (0..len)
            .map(|_| alphabet[(next() as usize) % alphabet.len()])
            .collect();
        buf.push(0); // guarantee NUL termination for the oracle's safety
        let n = (next() % 10) as usize;
        let (fl, gl) = both(&buf, n);
        assert_eq!(fl, gl, "wcswidth fuzz {buf:x?} n={n}: fl={fl} glibc={gl}");
    }

    // fl is memory-safe on NULL (returns -1, errno EINVAL) where glibc faults.
    assert_eq!(unsafe { flw::wcswidth(std::ptr::null(), 5) }, -1);
}
