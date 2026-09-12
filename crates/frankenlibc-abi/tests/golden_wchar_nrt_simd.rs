#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // exercises the ABI mbsnrtowcs/wcsnrtombs symbols directly
//! Golden-output gate for the SIMD ASCII fast path added to the bounded
//! restartable converters `mbsnrtowcs` / `wcsnrtombs`.
//!
//! Both previously ran a pure per-character scalar loop (the heavy ABI
//! `mbrtowc`/`wcrtomb`), unlike their non-bounded siblings `mbsrtowcs`/
//! `wcsrtombs` which already SIMD-fast-forward ASCII runs. That made them
//! thousands of x slower than glibc on ASCII-heavy text. They now widen/narrow
//! leading ASCII runs a SIMD vector at a time. Output must stay byte-for-byte
//! identical; this pins a SHA-256 over a mixed corpus and checks the round trip,
//! complementing the live-glibc `conformance_diff_wchar` and `wchar_abi_test`.

use std::ffi::c_char;

use sha2::{Digest, Sha256};

fn corpus() -> Vec<u8> {
    let mut s = String::from("café ");
    s.push_str(&"the quick brown fox jumps over the lazy dog ".repeat(30));
    for i in 0..150 {
        s.push_str("token ");
        s.push(char::from_u32(0x0410 + (i % 0x40)).unwrap()); // Cyrillic (2-byte)
        s.push_str("more ascii words ");
        s.push(char::from_u32(0x4E00 + (i % 0x100)).unwrap()); // CJK (3-byte)
        if i % 5 == 0 {
            s.push('🚀'); // 4-byte
        }
    }
    s.into_bytes()
}

fn hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn mbsnrtowcs_wcsnrtombs_simd_golden() {
    // A MULTIBYTE CORPORA NEEDS A MULTIBYTE LOCALE, and the gate must establish it
    // rather than inherit it. In the C locale every non-ASCII byte is EILSEQ — glibc
    // does exactly the same, and fl's converters mirror it — so running this corpus
    // under the worker's default locale measures the C-locale rejection path instead
    // of the SIMD widening this gate exists to pin. Measured on the 2026-09-11
    // census: `café` failed at the é, and the converter's error return was then fed
    // back as `nwc`, which aborted the process inside `slice::from_raw_parts`
    // (bd-7ilguh). Assert the locale TOOK EFFECT: a host without C.UTF-8 must fail
    // loudly here rather than silently measure the wrong path.
    let locale =
        unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C.UTF-8".as_ptr()) };
    assert!(
        !locale.is_null(),
        "C.UTF-8 must be available to exercise multibyte conversion"
    );

    let mut src = corpus();
    src.push(0);
    let nbytes = src.len() - 1;

    // UTF-8 bytes -> wide via mbsnrtowcs.
    let mut wide = vec![0i32; src.len() + 1];
    let mut p = src.as_ptr() as *const c_char;
    let nw = unsafe {
        frankenlibc_abi::wchar_abi::mbsnrtowcs(
            wide.as_mut_ptr(),
            &mut p,
            nbytes,
            wide.len(),
            std::ptr::null_mut(),
        )
    };
    // `mbsnrtowcs` returns `(size_t)-1` on error, and feeding that back as `nwc`
    // is what made this gate abort the process inside the converter rather than
    // report a result (bd-7ilguh). Assert the conversion succeeded BEFORE using
    // its return value: an unchecked error return turns a failing conversion into
    // an unreadable crash.
    assert_ne!(
        nw,
        usize::MAX,
        "mbsnrtowcs failed on the corpus (EILSEQ or tracked-source underrun), so \
         everything below would be measuring an error path"
    );
    wide.truncate(nw);
    let wide_bytes: Vec<u8> = wide.iter().flat_map(|w| w.to_le_bytes()).collect();
    let wide_hash = hex(&wide_bytes);

    // Wide -> UTF-8 via wcsnrtombs (round trip).
    let mut wide_nul = wide.clone();
    wide_nul.push(0);
    let mut back = vec![0u8; src.len() + 8];
    let mut wp = wide_nul.as_ptr();
    let nb = unsafe {
        frankenlibc_abi::wchar_abi::wcsnrtombs(
            back.as_mut_ptr() as *mut c_char,
            &mut wp,
            nw,
            back.len(),
            std::ptr::null_mut(),
        )
    };
    back.truncate(nb);

    eprintln!("mbsnrtowcs wide sha256={wide_hash} ({nw} wc)");
    eprintln!("wcsnrtombs back ({nb} B)");

    assert_eq!(
        back,
        &src[..nbytes],
        "wcsnrtombs(mbsnrtowcs(x)) must round-trip to the original UTF-8"
    );
    assert_eq!(
        wide_hash, "951d2fe3b7a882188b36bb1e47206606b86e2fa9536e107fd3ec3bca926e137f",
        "mbsnrtowcs golden drifted"
    );
}
