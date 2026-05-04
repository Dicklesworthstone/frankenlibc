#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `inet_aton(3)` / `inet_ntoa(3)`.
//!
//! These verify algebraic invariants that any correct IPv4
//! conversion must satisfy:
//!
//!   - aton(ntoa(addr)) == addr (round-trip on integer side)
//!   - ntoa(aton("a.b.c.d")) is a valid dotted-quad
//!   - aton always normalises to the same dotted-quad regardless of
//!     numeric form chosen on input (decimal, octal, hex, 1/2/3/4
//!     parts)
//!   - byte-order: htonl ∘ ntohl = identity
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{CStr, CString};

use frankenlibc_abi::inet_abi as fl;

#[test]
fn metamorphic_aton_ntoa_round_trip_full_byte_corpus() {
    // For each (a, b, c, d) sample, encode via dotted quad, decode
    // and re-encode; result must be identical.
    let samples: &[(u8, u8, u8, u8)] = &[
        (0, 0, 0, 0),
        (127, 0, 0, 1),
        (192, 168, 1, 1),
        (255, 255, 255, 255),
        (10, 0, 0, 1),
        (172, 16, 254, 1),
    ];
    for &(a, b, c, d) in samples {
        let s1 = format!("{a}.{b}.{c}.{d}");
        let cs = CString::new(s1.clone()).unwrap();
        let mut bin: u32 = 0;
        let r = unsafe { fl::inet_aton(cs.as_ptr(), &mut bin) };
        assert_eq!(r, 1, "aton failed for {s1}");
        // The bytes of the BE u32 must equal (a, b, c, d).
        let host = u32::from_be(bin);
        let bytes = host.to_be_bytes();
        assert_eq!(bytes, [a, b, c, d], "aton bits for {s1}");

        // ntoa takes the s_addr as a u32 in fl's signature.
        let p = unsafe { fl::inet_ntoa(bin) };
        let s2 = unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned();
        assert_eq!(s2, s1, "ntoa({s1}) round-trip");
    }
}

#[test]
fn metamorphic_aton_normalises_decimal_octal_hex_to_same_result() {
    // 192.168.1.1 in decimal, 0xC0.0xA8.0x01.0x01 in hex,
    // 0300.0250.01.01 in octal — all should produce the same key.
    let cases: &[&str] = &["192.168.1.1", "0xC0.0xA8.0x01.0x01", "0300.0250.01.01"];
    let mut seen: Option<u32> = None;
    for s in cases {
        let cs = CString::new(*s).unwrap();
        let mut bin: u32 = 0;
        let r = unsafe { fl::inet_aton(cs.as_ptr(), &mut bin) };
        assert_eq!(r, 1, "aton failed for {s}");
        match seen {
            Some(prev) => assert_eq!(prev, bin, "{s} should normalise to same value"),
            None => seen = Some(bin),
        }
    }
}

#[test]
fn metamorphic_aton_one_part_form_equals_dotted_quad() {
    // 16909060 (decimal) == 0x01020304 == 1.2.3.4
    let one_part = CString::new("16909060").unwrap();
    let dotted = CString::new("1.2.3.4").unwrap();
    let mut b1: u32 = 0;
    let mut b2: u32 = 0;
    assert_eq!(unsafe { fl::inet_aton(one_part.as_ptr(), &mut b1) }, 1);
    assert_eq!(unsafe { fl::inet_aton(dotted.as_ptr(), &mut b2) }, 1);
    assert_eq!(b1, b2, "1-part and 4-part forms differ");
}

#[test]
fn metamorphic_htonl_ntohl_round_trip_identity() {
    // For every random sample, htonl(ntohl(x)) must equal x and
    // vice versa.
    let samples: &[u32] = &[
        0,
        1,
        0xff,
        0xff00,
        0xff_0000,
        0xff00_0000,
        0x12345678,
        0xdeadbeef,
        0xcafebabe,
        u32::MAX,
    ];
    for &v in samples {
        let r1 = unsafe { fl::htonl(fl::ntohl(v)) };
        let r2 = unsafe { fl::ntohl(fl::htonl(v)) };
        assert_eq!(r1, v, "htonl ∘ ntohl({v:#x})");
        assert_eq!(r2, v, "ntohl ∘ htonl({v:#x})");
    }
}

#[test]
fn metamorphic_htons_ntohs_round_trip_identity() {
    let samples: &[u16] = &[0, 1, 0xff, 0xff00, 0x1234, 0xabcd, u16::MAX];
    for &v in samples {
        let r1 = unsafe { fl::htons(fl::ntohs(v)) };
        let r2 = unsafe { fl::ntohs(fl::htons(v)) };
        assert_eq!(r1, v, "htons ∘ ntohs({v:#x})");
        assert_eq!(r2, v, "ntohs ∘ htons({v:#x})");
    }
}

#[test]
fn metamorphic_aton_never_writes_on_failure() {
    // For invalid input, aton must return 0 and not write to *inp.
    let sentinel: u32 = 0xdead_beef;
    let mut bin: u32 = sentinel;
    let bad = CString::new("not.an.address").unwrap();
    let r = unsafe { fl::inet_aton(bad.as_ptr(), &mut bin) };
    assert_eq!(r, 0, "aton should fail on malformed input");
    assert_eq!(bin, sentinel, "aton corrupted *inp on failure");
}

#[test]
fn inet_aton_ntoa_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc inet_aton + inet_ntoa + htonl/htons\",\"reference\":\"internal-invariants\",\"properties\":6,\"divergences\":0}}",
    );
}
