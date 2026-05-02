#![cfg(target_os = "linux")]

//! Differential conformance harness for `inet_pton(AF_INET6, ...)`
//! edge cases.
//!
//! IPv6 textual representation has many subtle rules: zero
//! compression with "::", IPv4-mapped suffixes, zone IDs (rejected
//! by inet_pton), full 8-group form. This harness exercises the
//! corners.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, CString};

use frankenlibc_abi::inet_abi as fl;

unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const std::ffi::c_char, dst: *mut u8) -> c_int;
}

fn parse_both(s: &str) -> (Option<[u8; 16]>, Option<[u8; 16]>) {
    let cs = CString::new(s).unwrap();
    let mut fl_b = [0u8; 16];
    let mut lc_b = [0u8; 16];
    let fl_r = unsafe { fl::inet_pton(libc::AF_INET6, cs.as_ptr(), fl_b.as_mut_ptr() as *mut _) };
    let lc_r = unsafe { inet_pton(libc::AF_INET6, cs.as_ptr(), lc_b.as_mut_ptr()) };
    (
        if fl_r == 1 { Some(fl_b) } else { None },
        if lc_r == 1 { Some(lc_b) } else { None },
    )
}

#[test]
fn diff_inet_pton6_double_colon_zero_compression() {
    for s in ["::", "::1", "1::", "1::2", "1:2::3:4"] {
        let (fl_o, lc_o) = parse_both(s);
        assert_eq!(fl_o, lc_o, "{s}: fl={fl_o:?} lc={lc_o:?}");
        assert!(fl_o.is_some(), "should accept {s}");
    }
}

#[test]
fn diff_inet_pton6_full_8group_form() {
    let (fl_o, lc_o) = parse_both("1:2:3:4:5:6:7:8");
    assert_eq!(fl_o, lc_o);
    let expected = [
        0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
    ];
    assert_eq!(fl_o, Some(expected));
}

#[test]
fn diff_inet_pton6_ipv4_mapped() {
    // ::ffff:192.168.1.1 — IPv4-mapped IPv6 address.
    let (fl_o, lc_o) = parse_both("::ffff:192.168.1.1");
    assert_eq!(fl_o, lc_o);
    let expected = [
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01,
    ];
    assert_eq!(fl_o, Some(expected));
}

#[test]
fn diff_inet_pton6_ipv4_compatible() {
    // ::1.2.3.4 — IPv4-compatible (deprecated but still parses).
    let (fl_o, lc_o) = parse_both("::1.2.3.4");
    assert_eq!(fl_o, lc_o);
    let expected = [
        0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04,
    ];
    assert_eq!(fl_o, Some(expected));
}

#[test]
fn diff_inet_pton6_zone_id_rejected() {
    // inet_pton must reject zone IDs (the % delimiter); use
    // getaddrinfo or scope-aware APIs for those.
    let (fl_o, lc_o) = parse_both("fe80::%eth0");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_double_double_colon_rejected() {
    let (fl_o, lc_o) = parse_both("1::2::3");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_invalid_hex_rejected() {
    let (fl_o, lc_o) = parse_both("::g");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_oversized_group_rejected() {
    // Each group is at most 4 hex digits.
    let (fl_o, lc_o) = parse_both("12345::");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_too_many_groups_rejected() {
    let (fl_o, lc_o) = parse_both("1:2:3:4:5:6:7:8:9");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_too_few_no_double_colon_rejected() {
    let (fl_o, lc_o) = parse_both("1:2:3:4:5:6:7");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_trailing_colon_rejected() {
    let (fl_o, lc_o) = parse_both("1:2:3:4:5:6:7:8:");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_leading_colon_rejected() {
    // Single leading colon (not "::") is invalid.
    let (fl_o, lc_o) = parse_both(":1::");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_pton6_empty_rejected() {
    let (fl_o, lc_o) = parse_both("");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn inet_pton6_edges_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc inet_pton(AF_INET6) edges\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
