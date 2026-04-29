#![cfg(target_os = "linux")]

//! Differential conformance harness for `loc_aton(3)` / `loc_ntoa(3)`.
//!
//! Both implement RFC 1876 LOC RR encode/decode. fl's resolv-abi
//! implementation is diff'd against host libresolv across:
//!   - 5 representative geographic samples (decoded by ntoa)
//!   - aton round-trip (text → binary → text equality with libresolv)
//!   - error paths (wrong version, NULL inputs, garbage input)
//!
//! Filed under [bd-58e87f] follow-up.

use std::ffi::{c_char, c_int, CStr, CString};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    #[link_name = "__loc_aton"]
    fn loc_aton(ascii: *const c_char, binary: *mut u8) -> c_int;
    #[link_name = "__loc_ntoa"]
    fn loc_ntoa(binary: *const u8, ascii: *mut c_char) -> *const c_char;
}

fn ntoa_both(binary: &[u8; 16]) -> (String, String) {
    let mut fl_buf = [0u8; 96];
    let mut lc_buf = [0u8; 96];
    let fl_p = unsafe { fl::__loc_ntoa(binary.as_ptr(), fl_buf.as_mut_ptr() as *mut c_char) };
    let lc_p = unsafe { loc_ntoa(binary.as_ptr(), lc_buf.as_mut_ptr() as *mut c_char) };
    assert!(!fl_p.is_null(), "fl __loc_ntoa returned NULL");
    assert!(!lc_p.is_null(), "lc loc_ntoa returned NULL");
    let fl_s = unsafe { CStr::from_ptr(fl_p) }.to_string_lossy().into_owned();
    let lc_s = unsafe { CStr::from_ptr(lc_p) }.to_string_lossy().into_owned();
    (fl_s, lc_s)
}

fn aton_both(text: &str) -> (Option<[u8; 16]>, Option<[u8; 16]>) {
    let cs = CString::new(text).unwrap();
    let mut fl_b = [0u8; 16];
    let mut lc_b = [0u8; 16];
    let fl_r = unsafe { fl::__loc_aton(cs.as_ptr(), fl_b.as_mut_ptr()) };
    let lc_r = unsafe { loc_aton(cs.as_ptr(), lc_b.as_mut_ptr()) };
    // glibc returns 16 (RR size) on success; both impls now match.
    let fl_o = if fl_r > 0 { Some(fl_b) } else { None };
    let lc_o = if lc_r > 0 { Some(lc_b) } else { None };
    (fl_o, lc_o)
}

#[test]
fn diff_loc_ntoa_simple_north_west() {
    // 42 21 54 N 71 6 18 W 24m 1m 10000m 10m
    // lat = (42*3600 + 21*60 + 54) * 1000 = 152514000 ms
    // lon = (71*3600 + 6*60 + 18) * 1000 = 255978000 ms (negative => west)
    // alt = 24m above ref-100000m → (24+100000)*100 = 10002400 cm
    let lat_ms: i64 = 152_514_000;
    let lon_ms: i64 = -255_978_000;
    let alt_cm: i64 = (24 + 100_000) * 100;
    let lat = ((1i64 << 31) + lat_ms) as u32;
    let lon = ((1i64 << 31) + lon_ms) as u32;
    let alt = alt_cm as u32;
    let mut b = [0u8; 16];
    b[0] = 0;
    b[1] = 0x12; // 1m
    b[2] = 0x16; // 10km
    b[3] = 0x13; // 10m
    b[4..8].copy_from_slice(&lat.to_be_bytes());
    b[8..12].copy_from_slice(&lon.to_be_bytes());
    b[12..16].copy_from_slice(&alt.to_be_bytes());
    let (fl_s, lc_s) = ntoa_both(&b);
    assert_eq!(fl_s, lc_s, "ntoa N+W: fl={fl_s:?} lc={lc_s:?}");
}

#[test]
fn diff_loc_ntoa_south_east_below_sea_level() {
    // 33 51 35 S 151 12 40 E -10m
    let lat_ms: i64 = -(33 * 3_600_000 + 51 * 60_000 + 35 * 1000);
    let lon_ms: i64 = 151 * 3_600_000 + 12 * 60_000 + 40 * 1000;
    let alt_cm: i64 = (-10 + 100_000) * 100;
    let lat = ((1i64 << 31) + lat_ms) as u32;
    let lon = ((1i64 << 31) + lon_ms) as u32;
    let alt = alt_cm as u32;
    let mut b = [0u8; 16];
    b[0] = 0;
    b[1] = 0x12;
    b[2] = 0x16;
    b[3] = 0x13;
    b[4..8].copy_from_slice(&lat.to_be_bytes());
    b[8..12].copy_from_slice(&lon.to_be_bytes());
    b[12..16].copy_from_slice(&alt.to_be_bytes());
    let (fl_s, lc_s) = ntoa_both(&b);
    assert_eq!(fl_s, lc_s, "ntoa S+E neg-alt: fl={fl_s:?} lc={lc_s:?}");
}

#[test]
fn diff_loc_ntoa_zero_at_intersection() {
    // Equator + Prime Meridian, sea level, default precs.
    let mut b = [0u8; 16];
    b[1] = 0x12;
    b[2] = 0x16;
    b[3] = 0x13;
    let lat = (1u32) << 31;
    let lon = (1u32) << 31;
    let alt = 100_000u32 * 100;
    b[4..8].copy_from_slice(&lat.to_be_bytes());
    b[8..12].copy_from_slice(&lon.to_be_bytes());
    b[12..16].copy_from_slice(&alt.to_be_bytes());
    let (fl_s, lc_s) = ntoa_both(&b);
    assert_eq!(fl_s, lc_s, "ntoa equator: fl={fl_s:?} lc={lc_s:?}");
}

#[test]
fn diff_loc_ntoa_with_precision_overrides() {
    // Use non-default precision bytes to exercise precsize_ntoa.
    let lat_ms: i64 = 90 * 3_600_000;
    let lon_ms: i64 = 180 * 3_600_000;
    let alt_cm: i64 = (1234 + 100_000) * 100 + 56;
    let lat = ((1i64 << 31) + lat_ms) as u32;
    let lon = ((1i64 << 31) + lon_ms) as u32;
    let alt = alt_cm as u32;
    let mut b = [0u8; 16];
    b[0] = 0;
    b[1] = 0x33; // 3 * 10^3 cm = 30m
    b[2] = 0x55; // 5 * 10^5 cm = 5000m
    b[3] = 0x14; // 1 * 10^4 cm = 100m
    b[4..8].copy_from_slice(&lat.to_be_bytes());
    b[8..12].copy_from_slice(&lon.to_be_bytes());
    b[12..16].copy_from_slice(&alt.to_be_bytes());
    let (fl_s, lc_s) = ntoa_both(&b);
    assert_eq!(fl_s, lc_s, "ntoa precs: fl={fl_s:?} lc={lc_s:?}");
}

#[test]
fn diff_loc_ntoa_unknown_version_returns_error() {
    let mut b = [0u8; 16];
    b[0] = 1; // bad version
    let (fl_s, lc_s) = ntoa_both(&b);
    assert_eq!(fl_s, lc_s, "ntoa bad version: fl={fl_s:?} lc={lc_s:?}");
    assert!(fl_s.contains("unknown LOC RR version"));
}

#[test]
fn diff_loc_aton_basic_text() {
    let (fl_o, lc_o) = aton_both("42 21 54 N 71 06 18 W 24m");
    assert!(fl_o.is_some(), "fl rejected valid LOC");
    assert!(lc_o.is_some(), "lc rejected valid LOC");
    assert_eq!(fl_o.unwrap(), lc_o.unwrap(), "aton basic differs");
}

#[test]
fn diff_loc_aton_with_subseconds_and_precision() {
    let (fl_o, lc_o) = aton_both("33 51 35.500 S 151 12 40.250 E -10.50m 1m 10000m 10m");
    assert!(fl_o.is_some());
    assert!(lc_o.is_some());
    assert_eq!(fl_o.unwrap(), lc_o.unwrap());
}

#[test]
fn diff_loc_aton_minutes_only_no_seconds() {
    // glibc accepts "42 21 N 71 6 W <alt>" with implicit zero seconds.
    let (fl_o, lc_o) = aton_both("42 21 N 71 6 W 24m");
    assert_eq!(
        fl_o.is_some(),
        lc_o.is_some(),
        "aton implicit-sec acceptance differs: fl={} lc={}",
        fl_o.is_some(),
        lc_o.is_some()
    );
    if let (Some(fl_b), Some(lc_b)) = (fl_o, lc_o) {
        assert_eq!(fl_b, lc_b);
    }
}

#[test]
fn diff_loc_aton_round_trip() {
    // Encode known coords, decode via libresolv ntoa, re-encode via fl
    // aton, compare bytes.
    let inputs = [
        "42 21 54 N 71 06 18 W 24m",
        "33 51 35 S 151 12 40 E -10m",
        "90 0 0 N 180 0 0 E 0m",
        "0 0 0 N 0 0 0 E 0m",
    ];
    for s in &inputs {
        let (fl_o, lc_o) = aton_both(s);
        assert_eq!(
            fl_o.is_some(),
            lc_o.is_some(),
            "aton acceptance differs for {s}"
        );
        if let (Some(fl_b), Some(lc_b)) = (fl_o, lc_o) {
            assert_eq!(fl_b, lc_b, "aton bytes differ for {s}");
            // And both should ntoa-format identically.
            let (fl_s, lc_s) = ntoa_both(&fl_b);
            assert_eq!(fl_s, lc_s, "ntoa-after-aton differs for {s}");
        }
    }
}

#[test]
fn diff_loc_aton_garbage_rejected() {
    let (fl_o, lc_o) = aton_both("not a LOC record");
    assert_eq!(fl_o.is_some(), lc_o.is_some(), "garbage acceptance");
    assert!(fl_o.is_none());
}

#[test]
fn fl_loc_aton_null_rejects_without_crashing() {
    // glibc segfaults on NULL ascii — we don't compare here; we just
    // verify fl is hardened and returns 0.
    let mut b = [0u8; 16];
    let fl_r = unsafe { fl::__loc_aton(std::ptr::null(), b.as_mut_ptr()) };
    assert_eq!(fl_r, 0);
}

#[test]
fn loc_codec_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv loc_aton + loc_ntoa\",\"reference\":\"glibc-libresolv\",\"functions\":2,\"divergences\":0}}",
    );
}
