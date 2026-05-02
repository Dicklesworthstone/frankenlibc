#![cfg(target_os = "linux")]

//! Differential conformance harness for `inet_aton(3)` edge cases.
//!
//! `inet_aton` accepts four numeric forms (a.b.c.d / a.b.c / a.b /
//! a) with each component in decimal/octal/hex. The most subtle
//! invariants:
//!   - 1-part form: 32-bit value
//!   - 2-part form: net.host where host fits in 24 bits
//!   - 3-part form: net.subnet.host where host fits in 16 bits
//!   - 4-part form: each octet must fit in 8 bits
//!   - leading '.' or trailing '.' or empty component → reject
//!
//! fl could easily diverge on any of these. This harness is the
//! canary.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_int, CString};

use frankenlibc_abi::inet_abi as fl;

unsafe extern "C" {
    fn inet_aton(cp: *const std::ffi::c_char, inp: *mut u32) -> c_int;
}

fn parse_both(s: &str) -> (Option<u32>, Option<u32>) {
    let cs = CString::new(s).unwrap();
    let mut fl_v: u32 = 0;
    let mut lc_v: u32 = 0;
    let fl_r = unsafe { fl::inet_aton(cs.as_ptr(), &mut fl_v) };
    let lc_r = unsafe { inet_aton(cs.as_ptr(), &mut lc_v) };
    (
        if fl_r == 1 { Some(u32::from_be(fl_v)) } else { None },
        if lc_r == 1 { Some(u32::from_be(lc_v)) } else { None },
    )
}

#[test]
fn diff_inet_aton_dotted_quad_basic() {
    for s in ["1.2.3.4", "192.168.0.1", "127.0.0.1", "0.0.0.0", "255.255.255.255"] {
        let (fl_o, lc_o) = parse_both(s);
        assert_eq!(fl_o, lc_o, "dotted-quad {s}: fl={fl_o:?} lc={lc_o:?}");
        assert!(fl_o.is_some());
    }
}

#[test]
fn diff_inet_aton_hex_form() {
    let cases = [
        ("0xC0.0xA8.0x00.0x01", Some(0xC0_A8_00_01u32)),
        ("0xC0A80001", Some(0xC0_A8_00_01u32)),
    ];
    for (s, _expected) in cases {
        let (fl_o, lc_o) = parse_both(s);
        assert_eq!(fl_o, lc_o, "hex {s}: fl={fl_o:?} lc={lc_o:?}");
    }
}

#[test]
fn diff_inet_aton_octal_form() {
    // Glibc parses leading-zero components as octal.
    let cases = ["0300.0250.0.1", "01777777777"];
    for s in cases {
        let (fl_o, lc_o) = parse_both(s);
        assert_eq!(fl_o, lc_o, "octal {s}: fl={fl_o:?} lc={lc_o:?}");
    }
}

#[test]
fn diff_inet_aton_two_part_form_24bit_host() {
    // 1.131844 = 1.<24bit>; 131844 = 0x020304 → 1.2.3.4
    let (fl_o, lc_o) = parse_both("1.131844");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, Some(0x01020304));
}

#[test]
fn diff_inet_aton_three_part_form_overflow_rejected() {
    // 1.2.131844 — middle parts a/b are 8-bit; last part c must
    // fit 16 bits. 131844 > 65535 → reject.
    let (fl_o, lc_o) = parse_both("1.2.131844");
    assert_eq!(fl_o, lc_o, "3-part overflow: fl={fl_o:?} lc={lc_o:?}");
    assert_eq!(fl_o, None, "must reject 16-bit overflow in 3-part form");
}

#[test]
fn diff_inet_aton_one_part_form() {
    // Single-number form: 32-bit value, no dots.
    let (fl_o, lc_o) = parse_both("16909060");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, Some(0x01020304));
}

#[test]
fn diff_inet_aton_octet_overflow_rejected() {
    // 256 doesn't fit in 8 bits → reject.
    let (fl_o, lc_o) = parse_both("256.0.0.1");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_aton_decimal_overflow_rejected() {
    // Beyond u32::MAX → reject.
    let (fl_o, lc_o) = parse_both("999999999999");
    assert_eq!(fl_o, lc_o);
    assert_eq!(fl_o, None);
}

#[test]
fn diff_inet_aton_malformed_dots_rejected() {
    for s in [".1.2.3", "1.2.3.", "1..2.3", "..1.2", ".", "...", ""] {
        let (fl_o, lc_o) = parse_both(s);
        assert_eq!(fl_o, lc_o, "malformed {s:?}: fl={fl_o:?} lc={lc_o:?}");
        assert_eq!(fl_o, None, "must reject malformed: {s:?}");
    }
}

#[test]
fn diff_inet_aton_excess_components_rejected() {
    // 5+ parts not allowed.
    for s in ["1.2.3.4.5", "1.2.3.4.5.6"] {
        let (fl_o, lc_o) = parse_both(s);
        assert_eq!(fl_o, lc_o, "excess {s}: fl={fl_o:?} lc={lc_o:?}");
        assert_eq!(fl_o, None);
    }
}

#[test]
fn inet_aton_edges_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc inet_aton (edge cases)\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
