//! Differential probe: FrankenLibC `wcrtomb` vs host glibc `wcrtomb` (the
//! wide→multibyte direction, pairing with `mbrtowc_differential_probe`). Sweeps
//! the encoding boundaries (1/2/3/4/5/6-byte thresholds), UTF-16 surrogates,
//! the U+10FFFF / U+7FFFFFFF edges, and negative `wchar_t` values. Compares the
//! return sentinel (byte count vs (size_t)-1 EILSEQ) AND the encoded bytes.
//!
//! FrankenLibC's `wcrtomb` is UTF-8-hardcoded; glibc consults the locale, so the
//! host side runs under `LC_ALL=C.UTF-8`.
#![allow(unsafe_code)]

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wcrtomb(s: *mut libc::c_char, wc: libc::wchar_t, ps: *mut libc::mbstate_t) -> usize;
    fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, PartialEq, Eq, Clone)]
enum EncResult {
    Ileq,         // (size_t)-1, EILSEQ
    Ok(Vec<u8>),  // the encoded bytes
    Other(usize), // unexpected count
}

fn host(wc: i64) -> EncResult {
    let mut buf = [0u8; 16];
    let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
    // SAFETY: buf is large enough for any MB_CUR_MAX; st is a valid out param.
    let rc = unsafe {
        wcrtomb(
            buf.as_mut_ptr() as *mut libc::c_char,
            wc as libc::wchar_t,
            &mut st,
        )
    };
    classify(rc, &buf)
}

fn franken(wc: i64) -> EncResult {
    let mut buf = [0u8; 16];
    // SAFETY: buf is large enough; fl::wcrtomb writes at most 6 bytes.
    let rc = unsafe {
        fl::wcrtomb(
            buf.as_mut_ptr() as *mut std::ffi::c_char,
            wc as libc::wchar_t,
            std::ptr::null_mut(),
        )
    };
    classify(rc, &buf)
}

fn classify(rc: usize, buf: &[u8]) -> EncResult {
    if rc == usize::MAX {
        EncResult::Ileq
    } else if rc <= 6 {
        EncResult::Ok(buf[..rc].to_vec())
    } else {
        EncResult::Other(rc)
    }
}

#[test]
fn wcrtomb_matches_host_glibc_over_codepoint_surface() {
    let utf8 = c"C.UTF-8";
    // SAFETY: standard libc locale switch for this single-threaded test.
    let set = unsafe { setlocale(libc::LC_ALL, utf8.as_ptr()) };
    if set.is_null() {
        eprintln!("C.UTF-8 locale unavailable; skipping wcrtomb differential probe");
        return;
    }

    let mut compared = 0u64;
    let mut divergences: Vec<(i64, EncResult, EncResult)> = Vec::new();
    let mut check = |wc: i64| {
        let h = host(wc);
        let f = franken(wc);
        compared += 1;
        if h != f {
            divergences.push((wc, h, f));
        }
    };

    // 1. Boundary code points around every UTF-8 length threshold.
    let boundaries: &[i64] = &[
        0x00,
        0x01,
        0x7F,
        0x80,
        0x81,
        0x7FF,
        0x800,
        0x801,
        0xFFFF,
        0x1_0000,
        0x1_0001,
        0x1F_FFFF,
        0x20_0000,
        0x20_0001,
        0x3FF_FFFF,
        0x400_0000,
        0x400_0001,
        0x7FFF_FFFF,
    ];
    for &b in boundaries {
        check(b);
    }

    // 2. UTF-16 surrogates (must be rejected with EILSEQ).
    for wc in 0xD800i64..=0xDFFF {
        check(wc);
    }

    // 3. The U+10FFFF Unicode ceiling and just past it.
    for wc in 0x10_FFFEi64..=0x11_0002 {
        check(wc);
    }

    // 4. Negative / out-of-range wchar_t (sign-extended huge values).
    check(-1);
    check(-2);
    check(i32::MIN as i64);

    // 5. A representative ASCII + multibyte sample (round-trippable).
    for wc in [0x41i64, 0xE9, 0x20AC, 0x1_F600, 0xFEFF, 0x10_FFFF] {
        check(wc);
    }

    // 6. Dense sweep through the BMP to catch any per-range encoding slip.
    let mut wc = 0i64;
    while wc <= 0xFFFF {
        check(wc);
        wc += 7;
    }

    if !divergences.is_empty() {
        let shown: Vec<_> = divergences.iter().take(40).collect();
        panic!(
            "wcrtomb diverged from host glibc on {}/{} cases (showing up to 40):\n{:#?}",
            divergences.len(),
            compared,
            shown
        );
    }
    eprintln!("wcrtomb: {compared} cases, 0 divergences vs host glibc");
}
