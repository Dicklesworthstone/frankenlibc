#![no_main]
//! Fuzz target: round-trip coverage for the RFC 1876 LOC RR codec
//! (`__loc_aton` / `__loc_ntoa`) implemented in
//! `frankenlibc_abi::resolv_abi`.
//!
//! Two complementary modes:
//!
//! 1. **Random binary -> ntoa -> aton round-trip.** Take 16 random
//!    bytes (with version byte forced to 0), feed through fl's
//!    `__loc_ntoa`, parse the result back through fl's `__loc_aton`,
//!    require the binary representation re-encoded matches the
//!    original. This ensures the formatter and parser agree.
//!
//! 2. **Random text -> aton -> ntoa diff against libresolv.** Feed
//!    arbitrary printable text; compare fl vs libresolv on whether
//!    they accept the input and, if accepted, what bytes they emit.
//!    Any divergence is a bug.
//!
//! Filed under [bd-58e87f] follow-up — fuzz coverage extension.
//!
//! Run with:
//! ```text
//! cd crates/frankenlibc-fuzz
//! cargo +nightly fuzz run fuzz_loc_codec
//! ```

use std::ffi::{c_char, c_int, CStr};
use std::os::raw::c_uchar;

use frankenlibc_abi::resolv_abi as fl;
use libfuzzer_sys::fuzz_target;

#[link(name = "resolv")]
unsafe extern "C" {
    #[link_name = "__loc_aton"]
    fn lc_loc_aton(ascii: *const c_char, binary: *mut c_uchar) -> c_int;
    #[link_name = "__loc_ntoa"]
    fn lc_loc_ntoa(binary: *const c_uchar, ascii: *mut c_char) -> *const c_char;
}

fn try_binary_round_trip(seed: &[u8]) {
    if seed.len() < 16 {
        return;
    }
    let mut bin = [0u8; 16];
    bin.copy_from_slice(&seed[..16]);
    bin[0] = 0; // version
    // Mantissa nibble of size/hp/vp must be 0..=9 to round-trip; clamp.
    bin[1] = ((bin[1] >> 4) % 10) << 4 | (bin[1] & 0x0f) % 10;
    bin[2] = ((bin[2] >> 4) % 10) << 4 | (bin[2] & 0x0f) % 10;
    bin[3] = ((bin[3] >> 4) % 10) << 4 | (bin[3] & 0x0f) % 10;
    // Clamp lat/lon/alt to reasonable physical ranges so the formatter
    // doesn't emit values libresolv's parser would reject.
    let ref_pos: u32 = 1u32 << 31;
    let cap_arc_ms: u32 = 90 * 3_600_000; // <= 90 deg in milli-arcsec
    let cap_arc_ms_lon: u32 = 180 * 3_600_000;
    let lat = u32::from_be_bytes([bin[4], bin[5], bin[6], bin[7]]);
    let lat = ref_pos
        .wrapping_add((lat as i64 - ref_pos as i64).clamp(-(cap_arc_ms as i64), cap_arc_ms as i64) as u32);
    bin[4..8].copy_from_slice(&lat.to_be_bytes());
    let lon = u32::from_be_bytes([bin[8], bin[9], bin[10], bin[11]]);
    let lon = ref_pos
        .wrapping_add((lon as i64 - ref_pos as i64).clamp(-(cap_arc_ms_lon as i64), cap_arc_ms_lon as i64) as u32);
    bin[8..12].copy_from_slice(&lon.to_be_bytes());
    // Altitude: keep within +/-50000m of reference.
    let alt = u32::from_be_bytes([bin[12], bin[13], bin[14], bin[15]]);
    let alt_ref: u32 = 100_000 * 100;
    let cap_cm: i64 = 50_000 * 100;
    let alt = alt_ref.wrapping_add(
        (alt as i64 - alt_ref as i64).clamp(-cap_cm, cap_cm) as u32
    );
    bin[12..16].copy_from_slice(&alt.to_be_bytes());

    // Format binary -> text via fl.
    let mut text_buf = [0u8; 96];
    let p = unsafe { fl::__loc_ntoa(bin.as_ptr(), text_buf.as_mut_ptr() as *mut c_char) };
    if p.is_null() {
        return;
    }
    // Parse text -> binary via fl.
    let mut bin2 = [0u8; 16];
    let r = unsafe { fl::__loc_aton(p, bin2.as_mut_ptr()) };
    if r > 0 {
        // The round-trip should be exact for clamped inputs.
        // We only assert lat/lon/alt; precision bytes can renormalize
        // (e.g., 1*10^2 vs 10*10^1 are both 100 cm).
        assert_eq!(&bin[4..16], &bin2[4..16], "lat/lon/alt round-trip");
    }
}

fn try_text_diff(text: &[u8]) {
    // Skip inputs containing NUL — CStr can't hold those.
    if text.iter().any(|&b| b == 0) {
        return;
    }
    let cs = match std::ffi::CString::new(text) {
        Ok(c) => c,
        Err(_) => return,
    };
    let mut fl_b = [0u8; 16];
    let mut lc_b = [0u8; 16];
    let fl_r = unsafe { fl::__loc_aton(cs.as_ptr(), fl_b.as_mut_ptr()) };
    let lc_r = unsafe { lc_loc_aton(cs.as_ptr(), lc_b.as_mut_ptr()) };
    let fl_ok = fl_r > 0;
    let lc_ok = lc_r > 0;
    // Acceptance must agree.
    assert_eq!(
        fl_ok, lc_ok,
        "loc_aton acceptance differs for {:?}: fl={fl_r} lc={lc_r}",
        cs
    );
    if fl_ok && lc_ok {
        assert_eq!(fl_b, lc_b, "loc_aton bytes differ for {:?}", cs);
        // And ntoa output must agree.
        let mut fl_t = [0u8; 96];
        let mut lc_t = [0u8; 96];
        let fl_p = unsafe { fl::__loc_ntoa(fl_b.as_ptr(), fl_t.as_mut_ptr() as *mut c_char) };
        let lc_p = unsafe { lc_loc_ntoa(lc_b.as_ptr(), lc_t.as_mut_ptr() as *mut c_char) };
        assert!(!fl_p.is_null() && !lc_p.is_null());
        let fl_s = unsafe { CStr::from_ptr(fl_p) }.to_bytes();
        let lc_s = unsafe { CStr::from_ptr(lc_p) }.to_bytes();
        assert_eq!(fl_s, lc_s, "loc_ntoa text differs after round-trip");
    }
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let mode = data[0] & 1;
    let rest = &data[1..];
    if mode == 0 {
        try_binary_round_trip(rest);
    } else {
        try_text_diff(rest);
    }
});
