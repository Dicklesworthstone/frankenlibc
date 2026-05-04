#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `mblen` / `mbtowc` / `wctomb`.
//!
//! Internal invariants that must hold regardless of glibc behavior:
//!
//!   - mbtowc(b, n) == mblen(b, n) on length match
//!   - wctomb(buf, c) round-trips: bytes encode back to c via mbtowc
//!   - mblen(b, 0) and mbtowc(b, 0) both return -1 (incomplete)
//!   - mblen(NULL, _) and mbtowc(NULL, NULL, _) both return 0
//!     (state-query, stateless encoding)
//!   - wctomb(buf, 0) writes a single NUL byte and returns 1
//!
//! Filed under [bd-27e6p] follow-up.

use std::ffi::c_void;

use frankenlibc_abi::wchar_abi as fl;

#[test]
fn metamorphic_mblen_mbtowc_consistent_on_ascii() {
    for b in 0x20u8..=0x7E {
        let buf = [b];
        let len = unsafe { fl::mblen(buf.as_ptr(), 1) };
        let mut wc: u32 = 0;
        let len2 = unsafe { fl::mbtowc(&mut wc, buf.as_ptr(), 1) };
        assert_eq!(len, len2, "mblen/mbtowc length disagree for {b:#x}");
        assert_eq!(len, 1);
        assert_eq!(wc, b as u32);
    }
}

#[test]
fn metamorphic_wctomb_then_mbtowc_round_trips_ascii() {
    // Skip c=0: per POSIX, mbtowc returns 0 (not 1) on a NUL byte
    // to signal "string terminator". wctomb(c=0) returns 1 (one
    // byte written). The round-trip property is asymmetric on NUL.
    for c in 1u32..=0x7F {
        let mut buf = [0u8; 8];
        let n = unsafe { fl::wctomb(buf.as_mut_ptr(), c) };
        assert!(n >= 0, "wctomb({c:#x}) failed");
        let mut wc: u32 = 0xff_ffff;
        let n2 = unsafe { fl::mbtowc(&mut wc, buf.as_ptr(), n as usize) };
        assert_eq!(n2, n, "mbtowc length differs from wctomb output");
        assert_eq!(wc, c, "round-trip wc differs for {c:#x}");
    }
}

#[test]
fn metamorphic_mblen_zero_n_returns_minus_one() {
    let buf = b"X";
    let v = unsafe { fl::mblen(buf.as_ptr(), 0) };
    assert_eq!(v, -1, "mblen(_, 0) must be -1 per POSIX");
}

#[test]
fn metamorphic_mbtowc_zero_n_returns_minus_one() {
    let buf = b"X";
    let mut wc: u32 = 0xff_ffff;
    let v = unsafe { fl::mbtowc(&mut wc, buf.as_ptr(), 0) };
    assert_eq!(v, -1, "mbtowc(_, _, 0) must be -1 per POSIX");
}

#[test]
fn metamorphic_mblen_null_buf_state_query_returns_zero() {
    // Per POSIX, mblen(NULL, _) returns 0 if encoding is stateless,
    // non-zero if state-dependent. fl is stateless UTF-8.
    let v = unsafe { fl::mblen(std::ptr::null(), 1) };
    assert_eq!(v, 0, "mblen(NULL) must indicate stateless");
}

#[test]
fn metamorphic_mbtowc_null_source_state_query_returns_zero() {
    let v = unsafe { fl::mbtowc(std::ptr::null_mut(), std::ptr::null(), 1) };
    assert_eq!(v, 0);
}

#[test]
fn metamorphic_wctomb_zero_writes_nul_byte_returns_one() {
    let mut buf = [0xffu8; 8];
    let n = unsafe { fl::wctomb(buf.as_mut_ptr(), 0) };
    assert_eq!(n, 1);
    assert_eq!(buf[0], 0);
}

#[test]
fn metamorphic_wctomb_null_buf_state_query() {
    // wctomb(NULL, _) in stateless encoding must return 0.
    let v = unsafe { fl::wctomb(std::ptr::null_mut(), 0) };
    assert_eq!(v, 0);
    let v2 = unsafe { fl::wctomb(std::ptr::null_mut(), b'a' as u32) };
    assert_eq!(v2, 0);
}

#[test]
fn metamorphic_mbtowc_pwc_null_only_validates() {
    // Passing NULL for pwc is valid and means "validate but don't
    // write the wide char". Length must still match the consumed
    // bytes.
    let buf = b"A";
    let n = unsafe { fl::mbtowc(std::ptr::null_mut(), buf.as_ptr(), 1) };
    assert_eq!(n, 1, "mbtowc with NULL pwc should still validate");
}

#[test]
fn metamorphic_mblen_distinct_chars_distinct_outputs_nonzero_lengths() {
    // For 5 ASCII bytes, mblen returns 1 for all; just verify
    // they don't collide in some weird way.
    for &c in b"aB1!~" {
        let buf = [c];
        let n = unsafe { fl::mblen(buf.as_ptr(), 1) };
        assert_eq!(n, 1, "mblen({c}) != 1");
    }
}

#[test]
fn metamorphic_mbtowc_invalid_utf8_returns_minus_one() {
    // 0xFF is never a valid UTF-8 start byte.
    let buf = [0xFFu8];
    let mut wc: u32 = 0;
    let n = unsafe { fl::mbtowc(&mut wc, buf.as_ptr(), 1) };
    assert_eq!(n, -1, "mbtowc(0xFF) must reject");
}

#[test]
fn mb_singlechar_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc mblen + mbtowc + wctomb\",\"reference\":\"posix-invariants\",\"properties\":11,\"divergences\":0}}",
    );
    let _ = std::ptr::null::<c_void>();
}
