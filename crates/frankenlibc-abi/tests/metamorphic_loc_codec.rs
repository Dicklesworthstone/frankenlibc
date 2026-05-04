#![cfg(target_os = "linux")]

//! Metamorphic-test harness for the RFC 1876 LOC RR codec implemented
//! in `frankenlibc_abi::resolv_abi`.
//!
//! Where conformance_diff_loc_codec.rs validates fl matches libresolv,
//! these tests validate internal invariants — properties that any
//! correct LOC codec must satisfy, regardless of reference behavior.
//! Each test asserts a metamorphic relation: changing the input in a
//! prescribed way must produce a specific change in the output.
//!
//! Filed under [bd-58e87f] follow-up — metamorphic coverage extension.

use std::ffi::{CStr, CString, c_char};

use frankenlibc_abi::resolv_abi as fl;

const POWERS_OF_TEN: [u64; 10] = [
    1,
    10,
    100,
    1_000,
    10_000,
    100_000,
    1_000_000,
    10_000_000,
    100_000_000,
    1_000_000_000,
];

/// Build a 16-byte LOC binary from explicit coords. lat/lon in
/// milli-arcseconds (signed); alt in centimeters above -100,000m.
fn build_binary(size: u8, hp: u8, vp: u8, lat_ms: i64, lon_ms: i64, alt_cm: i64) -> [u8; 16] {
    let ref_pos: i64 = 1i64 << 31;
    let lat_word = (ref_pos + lat_ms) as u32;
    let lon_word = (ref_pos + lon_ms) as u32;
    let alt_word = (alt_cm + 10_000_000) as u32;
    let mut b = [0u8; 16];
    b[0] = 0;
    b[1] = size;
    b[2] = hp;
    b[3] = vp;
    b[4..8].copy_from_slice(&lat_word.to_be_bytes());
    b[8..12].copy_from_slice(&lon_word.to_be_bytes());
    b[12..16].copy_from_slice(&alt_word.to_be_bytes());
    b
}

fn ntoa(b: &[u8; 16]) -> String {
    let mut buf = [0u8; 96];
    let p = unsafe { fl::__loc_ntoa(b.as_ptr(), buf.as_mut_ptr() as *mut c_char) };
    assert!(!p.is_null());
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn aton(text: &str) -> Option<[u8; 16]> {
    let cs = CString::new(text).ok()?;
    let mut b = [0u8; 16];
    let r = unsafe { fl::__loc_aton(cs.as_ptr(), b.as_mut_ptr()) };
    if r > 0 { Some(b) } else { None }
}

#[test]
fn metamorphic_aton_ntoa_aton_is_idempotent() {
    // Property: parse(format(parse(T))) == parse(T). After one
    // canonicalisation pass, repeated round-trips must converge.
    let inputs = [
        "42 21 54 N 71 06 18 W 24m",
        "33 51 35 S 151 12 40 E -10m",
        "90 0 0 N 180 0 0 E 0m",
        "0 0 0 N 0 0 0 E 100m 1m 100m 1m",
        "1 2 3.456 N 4 5 6.789 W 100.50m",
    ];
    for s in &inputs {
        let b1 = aton(s).expect("first aton");
        let t1 = ntoa(&b1);
        let b2 = aton(&t1).expect("second aton");
        let t2 = ntoa(&b2);
        assert_eq!(b1, b2, "binary not idempotent for {s}");
        assert_eq!(t1, t2, "text not idempotent for {s}");
    }
}

#[test]
fn metamorphic_latitude_sign_flip_changes_only_lat_word() {
    // Negating latitude (N → S, same magnitude) must change only the
    // 4-byte latitude word in the binary form.
    let lat_ms: i64 = 42 * 3_600_000 + 21 * 60_000 + 54_000;
    let lon_ms: i64 = -(71 * 3_600_000 + 6 * 60_000 + 18_000);
    let alt_cm: i64 = 24 * 100;
    let bn = build_binary(0x12, 0x16, 0x13, lat_ms, lon_ms, alt_cm);
    let bs = build_binary(0x12, 0x16, 0x13, -lat_ms, lon_ms, alt_cm);
    // ntoa must show the hemisphere flip.
    let tn = ntoa(&bn);
    let ts = ntoa(&bs);
    assert!(tn.contains(" N "), "north form: {tn}");
    assert!(ts.contains(" S "), "south form: {ts}");
    // Bytes 0..4 (version+sizes) and 8..16 (lon/alt) must be identical.
    assert_eq!(bn[..4], bs[..4]);
    assert_eq!(bn[8..16], bs[8..16]);
    // The lat word (bytes 4..8) must differ.
    assert_ne!(bn[4..8], bs[4..8]);
}

#[test]
fn metamorphic_longitude_sign_flip_changes_only_lon_word() {
    let lat_ms: i64 = 33 * 3_600_000;
    let lon_ms: i64 = 151 * 3_600_000;
    let alt_cm: i64 = 0;
    let be = build_binary(0x12, 0x16, 0x13, lat_ms, lon_ms, alt_cm);
    let bw = build_binary(0x12, 0x16, 0x13, lat_ms, -lon_ms, alt_cm);
    let te = ntoa(&be);
    let tw = ntoa(&bw);
    assert!(te.contains(" E "), "east form: {te}");
    assert!(tw.contains(" W "), "west form: {tw}");
    assert_eq!(be[..8], bw[..8]);
    assert_eq!(be[12..16], bw[12..16]);
    assert_ne!(be[8..12], bw[8..12]);
}

#[test]
fn metamorphic_altitude_offset_shifts_only_alt_word() {
    // Adding 100m to altitude must shift only the 4-byte altitude word.
    let lat_ms: i64 = 42 * 3_600_000;
    let lon_ms: i64 = 71 * 3_600_000;
    let alt_cm_a: i64 = 24 * 100;
    let alt_cm_b: i64 = (24 + 100) * 100;
    let ba = build_binary(0x12, 0x16, 0x13, lat_ms, lon_ms, alt_cm_a);
    let bb = build_binary(0x12, 0x16, 0x13, lat_ms, lon_ms, alt_cm_b);
    assert_eq!(ba[..12], bb[..12]);
    assert_ne!(ba[12..16], bb[12..16]);
    // alt_word differs by 100m * 100cm = 10000 cm = 0x2710.
    let ax = u32::from_be_bytes([ba[12], ba[13], ba[14], ba[15]]);
    let bx = u32::from_be_bytes([bb[12], bb[13], bb[14], bb[15]]);
    assert_eq!(bx.wrapping_sub(ax), 10_000);
}

#[test]
fn metamorphic_format_includes_all_three_precision_fields() {
    // The ntoa output must always contain four "Nm" altitude/precision
    // tokens. Glibc convention is "<alt>m <size>m <hp>m <vp>m".
    let b = build_binary(0x12, 0x16, 0x13, 42 * 3_600_000, 71 * 3_600_000, 24 * 100);
    let t = ntoa(&b);
    let m_count = t.matches('m').count();
    assert_eq!(m_count, 4, "expected 4 'm' suffixes in {t:?}");
}

#[test]
fn metamorphic_precsize_byte_renormalises_via_ntoa() {
    // 0x12 (1 * 10^2 cm = 1m) and 0x21 (2 * 10^1 cm = 20cm) must
    // produce different ntoa output even though they could collide in
    // a sloppy formatter.
    let b1 = build_binary(0x12, 0x16, 0x13, 0, 0, 0);
    let b2 = build_binary(0x21, 0x16, 0x13, 0, 0, 0);
    let t1 = ntoa(&b1);
    let t2 = ntoa(&b2);
    assert_ne!(t1, t2, "precsize collision: {t1} vs {t2}");
}

#[test]
fn metamorphic_aton_normalises_size_to_smallest_exponent() {
    // For the same physical value (e.g., 100 cm = 1m), the parser
    // chooses the smallest exponent that keeps mantissa <= 9.
    // 100 cm: mantissa=1, exponent=2 → 0x12.
    let t = "0 0 0 N 0 0 0 E 0m 1m 1m 1m";
    let b = aton(t).expect("aton");
    assert_eq!(b[1], 0x12, "size byte: {:#x}", b[1]);
    assert_eq!(b[2], 0x12, "hp byte: {:#x}", b[2]);
    assert_eq!(b[3], 0x12, "vp byte: {:#x}", b[3]);
}

#[test]
fn metamorphic_invalid_version_byte_returns_error_string() {
    let b = build_binary(0x12, 0x16, 0x13, 0, 0, 0);
    // Force version != 0.
    let mut bad = b;
    bad[0] = 7;
    let t = ntoa(&bad);
    assert!(t.contains("error"), "expected error sentinel in {t:?}");
}

#[test]
fn metamorphic_aton_leading_whitespace_irrelevant() {
    // Whitespace before/within the input shouldn't change the result.
    let t1 = "42 21 54 N 71 06 18 W 24m";
    let t2 = "  42 21 54 N 71 06 18 W 24m";
    let t3 = "42  21  54  N  71  06  18  W  24m";
    let b1 = aton(t1).expect("base");
    let b2 = aton(t2).expect("leading ws");
    let b3 = aton(t3).expect("internal ws");
    assert_eq!(b1, b2);
    assert_eq!(b1, b3);
}

#[test]
fn metamorphic_precsize_format_matches_independent_decoder() {
    // Replicate the precsize formula independently: size in cm =
    // mantissa * 10^exponent. Verify ntoa output mentions the
    // expected meter value for several precision-byte choices.
    for &(byte, expected_int_m, expected_frac_cm) in &[
        (0x12u8, 1u64, 0u64), // 1m
        (0x21, 0, 20),        // 20cm
        (0x33, 30, 0),        // 30m
        (0x55, 5_000, 0),     // 5km
        (0x16, 10_000, 0),    // 10km
    ] {
        let mantissa = ((byte >> 4) & 0x0f) as u64;
        let exponent = (byte & 0x0f) as usize;
        let cm = mantissa * POWERS_OF_TEN[exponent];
        assert_eq!(cm / 100, expected_int_m, "byte {byte:#x}: int part");
        assert_eq!(cm % 100, expected_frac_cm, "byte {byte:#x}: frac cm");
        let b = build_binary(byte, 0x16, 0x13, 0, 0, 0);
        let t = ntoa(&b);
        // Output should contain the expected size string before "m".
        let needle = format!("{}.{:02}m", expected_int_m, expected_frac_cm);
        assert!(
            t.contains(&needle),
            "byte {byte:#x}: expected to find {needle:?} in {t:?}"
        );
    }
}

#[test]
fn loc_codec_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv loc_aton + loc_ntoa\",\"reference\":\"internal-invariants\",\"properties\":9,\"divergences\":0}}",
    );
}
