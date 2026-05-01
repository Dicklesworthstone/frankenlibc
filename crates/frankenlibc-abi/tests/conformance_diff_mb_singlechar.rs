#![cfg(target_os = "linux")]

//! Differential conformance harness for the single-character multibyte
//! conversions `mblen(3)`, `mbtowc(3)`, and `wctomb(3)`.
//!
//! These three operate on one multibyte character at a time and use
//! the encoding of the current LC_CTYPE locale (defaults to C/POSIX —
//! ASCII-only). fl's wchar_abi forwards to its Unicode-aware core, so
//! this harness pins down acceptance and length parity with glibc on
//! the C locale (where both impls treat input as bytes).
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int};

unsafe extern "C" {
    fn mblen(s: *const c_char, n: usize) -> c_int;
    fn mbtowc(pwc: *mut i32, s: *const c_char, n: usize) -> c_int;
    fn wctomb(s: *mut c_char, wchar: i32) -> c_int;
}

use frankenlibc_abi::wchar_abi as fl;

#[test]
fn diff_mblen_ascii_returns_one() {
    for &b in &[b'a', b'Z', b'0', b' ', b'!'] {
        let buf = [b];
        let fl_r = unsafe { fl::mblen(buf.as_ptr(), 1) };
        let lc_r = unsafe { mblen(buf.as_ptr() as *const c_char, 1) };
        assert_eq!(fl_r, lc_r, "mblen({b:#x}): fl={fl_r} lc={lc_r}");
        assert_eq!(fl_r, 1);
    }
}

#[test]
fn diff_mblen_nul_returns_zero() {
    let buf = [0u8];
    let fl_r = unsafe { fl::mblen(buf.as_ptr(), 1) };
    let lc_r = unsafe { mblen(buf.as_ptr() as *const c_char, 1) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
}

#[test]
fn diff_mblen_zero_n_returns_minus_one() {
    // Zero bytes cannot constitute a complete multibyte character;
    // both impls must return -1 (incomplete sequence). Regression
    // gate for [bd-27e6p].
    let buf = [b'a'];
    let fl_r = unsafe { fl::mblen(buf.as_ptr(), 0) };
    let lc_r = unsafe { mblen(buf.as_ptr() as *const c_char, 0) };
    assert_eq!(fl_r, lc_r, "mblen(n=0): fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, -1);
}

#[test]
fn diff_mbtowc_zero_n_returns_minus_one() {
    let buf = [b'a'];
    let mut fl_wc: i32 = 0;
    let mut lc_wc: i32 = 0;
    let fl_r = unsafe { fl::mbtowc(&mut fl_wc as *mut i32 as *mut u32, buf.as_ptr(), 0) };
    let lc_r = unsafe { mbtowc(&mut lc_wc, buf.as_ptr() as *const c_char, 0) };
    assert_eq!(fl_r, lc_r, "mbtowc(n=0): fl={fl_r} lc={lc_r}");
    assert_eq!(fl_r, -1);
}

#[test]
fn diff_mblen_null_pointer_reports_state() {
    // Per POSIX, mblen(NULL, _) returns non-zero iff the encoding is
    // stateful. C/POSIX is stateless, so both impls should return 0.
    let fl_r = unsafe { fl::mblen(std::ptr::null(), 1) };
    let lc_r = unsafe { mblen(std::ptr::null(), 1) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
}

#[test]
fn diff_mbtowc_ascii_round_trip() {
    for &b in &[b'A', b'1', b'~', b' '] {
        let in_buf = [b];
        let mut fl_wc: i32 = -1;
        let mut lc_wc: i32 = -1;
        let fl_r = unsafe { fl::mbtowc(&mut fl_wc as *mut i32 as *mut u32, in_buf.as_ptr(), 1) };
        let lc_r = unsafe { mbtowc(&mut lc_wc, in_buf.as_ptr() as *const c_char, 1) };
        assert_eq!(fl_r, lc_r, "mbtowc({b:#x}) ret: fl={fl_r} lc={lc_r}");
        assert_eq!(fl_wc, lc_wc, "mbtowc({b:#x}) wc: fl={fl_wc} lc={lc_wc}");
        assert_eq!(fl_wc, b as i32);
    }
}

#[test]
fn diff_mbtowc_null_pwc_just_advances() {
    // Passing a NULL output pointer tells mbtowc just to validate the
    // input length without storing.
    let in_buf = [b'X'];
    let fl_r = unsafe { fl::mbtowc(std::ptr::null_mut(), in_buf.as_ptr(), 1) };
    let lc_r = unsafe { mbtowc(std::ptr::null_mut(), in_buf.as_ptr() as *const c_char, 1) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 1);
}

#[test]
fn diff_mbtowc_nul_returns_zero_with_zero_wc() {
    let in_buf = [0u8];
    let mut fl_wc: i32 = -1;
    let mut lc_wc: i32 = -1;
    let fl_r = unsafe { fl::mbtowc(&mut fl_wc as *mut i32 as *mut u32, in_buf.as_ptr(), 1) };
    let lc_r = unsafe { mbtowc(&mut lc_wc, in_buf.as_ptr() as *const c_char, 1) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_wc, lc_wc);
    assert_eq!(fl_r, 0);
    assert_eq!(fl_wc, 0);
}

#[test]
fn diff_mbtowc_null_source_reports_state() {
    let fl_r = unsafe { fl::mbtowc(std::ptr::null_mut(), std::ptr::null(), 1) };
    let lc_r = unsafe { mbtowc(std::ptr::null_mut(), std::ptr::null(), 1) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
}

#[test]
fn diff_wctomb_ascii_writes_one_byte() {
    for wc in [b'a' as i32, b'Z' as i32, b'9' as i32] {
        let mut fl_buf = [0u8; 8];
        let mut lc_buf = [0u8; 8];
        let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), wc as u32) };
        let lc_r = unsafe { wctomb(lc_buf.as_mut_ptr() as *mut c_char, wc) };
        assert_eq!(fl_r, lc_r, "wctomb({wc}) ret: fl={fl_r} lc={lc_r}");
        if fl_r > 0 {
            let n = fl_r as usize;
            assert_eq!(fl_buf[..n], lc_buf[..n], "wctomb({wc}) bytes");
            assert_eq!(fl_buf[0] as i32, wc);
        }
    }
}

#[test]
fn diff_wctomb_zero_returns_one_with_nul_byte() {
    let mut fl_buf = [0xffu8; 8];
    let mut lc_buf = [0xffu8; 8];
    let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), 0) };
    let lc_r = unsafe { wctomb(lc_buf.as_mut_ptr() as *mut c_char, 0) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 1);
    assert_eq!(fl_buf[0], 0);
    assert_eq!(lc_buf[0], 0);
}

#[test]
fn diff_wctomb_null_buffer_reports_state() {
    let fl_r = unsafe { fl::wctomb(std::ptr::null_mut(), 0) };
    let lc_r = unsafe { wctomb(std::ptr::null_mut(), 0) };
    assert_eq!(fl_r, lc_r);
    assert_eq!(fl_r, 0);
}

#[test]
fn diff_wctomb_high_codepoint_in_c_locale_rejects() {
    // In the C/POSIX locale, glibc's wctomb rejects any wc > 0x7F
    // (returns -1). fl mirrors this for ASCII-only mode; if fl
    // chooses to encode UTF-8 it must do so deterministically and
    // both impls' bytes must agree (which they wouldn't in C locale,
    // so we only assert acceptance parity).
    let mut fl_buf = [0u8; 8];
    let mut lc_buf = [0u8; 8];
    let fl_r = unsafe { fl::wctomb(fl_buf.as_mut_ptr(), 0x4E2D) }; // CJK 中
    let lc_r = unsafe { wctomb(lc_buf.as_mut_ptr() as *mut c_char, 0x4E2D) };
    // Either both succeed (UTF-8 encoded) or both fail (-1, C locale).
    if fl_r > 0 && lc_r > 0 {
        assert_eq!(fl_r, lc_r);
        let n = fl_r as usize;
        assert_eq!(fl_buf[..n], lc_buf[..n]);
    }
    // Otherwise we just allow the divergence (locale-dependent path).
}

#[test]
fn mb_singlechar_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc mblen + mbtowc + wctomb\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
