//! Differential probe: FrankenLibC `mbrtowc` vs the host glibc `mbrtowc`, over
//! the full UTF-8 decoding surface (ASCII, multi-byte, incomplete sequences,
//! invalid continuations, overlong forms, surrogates, 5/6-byte forms, and the
//! 0xFE/0xFF never-leads). FrankenLibC's `mbrtowc` is UTF-8-hardcoded; glibc's
//! consults the locale, so this test sets `LC_ALL=C.UTF-8` for the host side.
//!
//! Covers the previously-unfuzzed `mbrtowc` ABI wrapper (the incomplete-vs-error
//! decision path in particular). Returns are normalised to a small enum so the
//! three distinct sentinels — 0 (NUL), (size_t)-1 EILSEQ, (size_t)-2 incomplete —
//! and the byte count are all compared, plus the decoded wide character.
#![allow(unsafe_code)]

use std::ffi::c_int;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn mbrtowc(
        pwc: *mut libc::wchar_t,
        s: *const libc::c_char,
        n: usize,
        ps: *mut libc::mbstate_t,
    ) -> usize;
    fn setlocale(category: c_int, locale: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum MbResult {
    Nul,             // returned 0
    Ileq,            // (size_t)-1, EILSEQ
    Incomplete,      // (size_t)-2
    Ok(usize, u32),  // consumed N bytes, decoded wc
    Other(usize),    // anything unexpected
}

fn classify(rc: usize, wc: libc::wchar_t) -> MbResult {
    if rc == 0 {
        MbResult::Nul
    } else if rc == usize::MAX {
        MbResult::Ileq
    } else if rc == usize::MAX - 1 {
        MbResult::Incomplete
    } else if rc <= 6 {
        MbResult::Ok(rc, wc as u32)
    } else {
        MbResult::Other(rc)
    }
}

fn host(bytes: &[u8], n: usize) -> MbResult {
    let mut wc: libc::wchar_t = 0;
    // Fresh zeroed mbstate_t each call (initial state).
    let mut st: libc::mbstate_t = unsafe { std::mem::zeroed() };
    // SAFETY: bytes has at least `n` readable bytes; wc/st are valid out params.
    let rc = unsafe { mbrtowc(&mut wc, bytes.as_ptr() as *const libc::c_char, n, &mut st) };
    classify(rc, wc)
}

fn franken(bytes: &[u8], n: usize) -> MbResult {
    let mut wc: libc::wchar_t = 0;
    // SAFETY: bytes has at least `n` readable bytes; wc is a valid out param.
    let rc = unsafe {
        fl::mbrtowc(
            &mut wc,
            bytes.as_ptr() as *const std::ffi::c_char,
            n,
            std::ptr::null_mut(),
        )
    };
    classify(rc, wc)
}

#[test]
fn mbrtowc_matches_host_glibc_over_utf8_surface() {
    // Host glibc only decodes UTF-8 multibyte sequences in a UTF-8 locale.
    let utf8 = c"C.UTF-8";
    // SAFETY: standard libc locale switch for this single-threaded test.
    let set = unsafe { setlocale(libc::LC_ALL, utf8.as_ptr()) };
    if set.is_null() {
        eprintln!("C.UTF-8 locale unavailable; skipping mbrtowc differential probe");
        return;
    }

    let mut compared = 0u64;
    let mut divergences: Vec<(Vec<u8>, usize, MbResult, MbResult)> = Vec::new();

    let mut check = |bytes: &[u8], n: usize| {
        let h = host(bytes, n);
        let f = franken(bytes, n);
        compared += 1;
        if h != f {
            divergences.push((bytes[..n.min(bytes.len())].to_vec(), n, h, f));
        }
    };

    // 1. Every single lead/standalone byte with n = 1 (ASCII, continuations,
    //    2/3/4/5/6-byte leads, the 0xFE/0xFF never-leads).
    for b in 0u16..=255 {
        check(&[b as u8, 0x80, 0x80, 0x80, 0x80, 0x80], 1);
    }

    // 2. Two-byte space: every lead 0xC0..=0xF7 × a sample of second bytes,
    //    with n = 2 (catches overlong 0xC0/0xC1, invalid continuations, and the
    //    incomplete-vs-EILSEQ decision when only a partial sequence is present).
    let second_bytes: [u8; 12] = [
        0x00, 0x41, 0x7F, 0x80, 0x81, 0xA0, 0xBF, 0xC0, 0xE0, 0xF0, 0xFF, 0x90,
    ];
    for lead in 0xC0u16..=0xF7 {
        for &s2 in &second_bytes {
            check(&[lead as u8, s2, 0x80, 0x80, 0x80, 0x80], 2);
        }
    }

    // 3. Valid multi-byte sequences fully present (n = full length).
    let valids: &[&[u8]] = &[
        b"A",                          // U+0041
        &[0xC3, 0xA9],                 // U+00E9 é
        &[0xE2, 0x82, 0xAC],           // U+20AC €
        &[0xF0, 0x9F, 0x98, 0x80],     // U+1F600 😀
        &[0xEF, 0xBB, 0xBF],           // U+FEFF BOM
        &[0xF4, 0x8F, 0xBF, 0xBF],     // U+10FFFF (max valid)
    ];
    for v in valids {
        check(v, v.len());
    }

    // 4. Incomplete prefixes of valid sequences (n < full length): glibc returns
    //    (size_t)-2 when the available bytes are a valid partial sequence.
    check(&[0xC3, 0xA9], 1); // partial é
    check(&[0xE2, 0x82, 0xAC], 1); // partial €
    check(&[0xE2, 0x82, 0xAC], 2);
    check(&[0xF0, 0x9F, 0x98, 0x80], 1);
    check(&[0xF0, 0x9F, 0x98, 0x80], 2);
    check(&[0xF0, 0x9F, 0x98, 0x80], 3);

    // 5. Edge code points: surrogates (U+D800 = ED A0 80) and > U+10FFFF
    //    (F4 90 80 80 = U+110000), each with full length.
    check(&[0xED, 0xA0, 0x80], 3); // surrogate
    check(&[0xF4, 0x90, 0x80, 0x80], 4); // > U+10FFFF

    if !divergences.is_empty() {
        let shown: Vec<_> = divergences.iter().take(40).collect();
        panic!(
            "mbrtowc diverged from host glibc on {}/{} cases (showing up to 40):\n{:#?}",
            divergences.len(),
            compared,
            shown
        );
    }
    eprintln!("mbrtowc: {compared} cases, 0 divergences vs host glibc");
}
