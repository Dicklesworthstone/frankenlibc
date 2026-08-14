#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sysconf oracle

//! Raw-integer-code differential gate for sysconf (bd-7qvvom). The existing
//! sysconf gates iterate NAMED libc::_SC_* constants, but the libc crate omits
//! some _SC_ codes — the same blind spot that once hid a wrong nl_langinfo
//! value. This walks the raw integer codes 0..=130 and asserts, vs host glibc:
//!   * availability parity — fl returns a value (>=0) exactly when glibc does
//!     (catches keys fl forgets to implement -> -1 where glibc has a value);
//!   * exact value parity for every code both support, except the handful of
//!     genuinely time-varying counters (free/online pages & CPUs).
//! No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn sysconf(name: c_int) -> std::ffi::c_long;
}

// Codes whose value legitimately fluctuates between two back-to-back reads, so
// only availability (not the exact value) is compared:
//   _SC_AVPHYS_PAGES = 86, _SC_NPROCESSORS_ONLN = 84.
const DYNAMIC: &[c_int] = &[84, 86];

// glibc selectors intentionally represented as raw numbers in the ABI match:
// the Rust libc crate does not publish this complete set on every target.
const RESTORED_GLIBC_CODES: &[c_int] = &[
    13, 20, 45, 77, 78, 79, 80, 81, 82, 88, 89, 90, 91, 93, 94, 95, 96, 98, 99, 100, 101, 102, 104,
    106, 107, 108, 109, 110, 111, 113, 115, 116, 118, 119, 120, 121, 122, 123, 124, 127, 129, 130,
];

#[test]
fn sysconf_raw_codes_match_glibc() {
    let mut value_mismatches = Vec::new();
    let mut avail_mismatches = Vec::new();
    for code in 0..=130i32 {
        let g = unsafe { sysconf(code) };
        let f = unsafe { frankenlibc_abi::unistd_abi::sysconf(code) };
        // Availability: a key is supported (>=0) or not (-1) — never fluctuates.
        if (g >= 0) != (f >= 0) {
            avail_mismatches.push(format!("code {code}: fl={f} glibc={g}"));
            continue;
        }
        if g >= 0 && f >= 0 && !DYNAMIC.contains(&code) && f != g {
            value_mismatches.push(format!("code {code}: fl={f} glibc={g}"));
        }
    }
    assert!(
        avail_mismatches.is_empty(),
        "sysconf availability divergences ({}):\n{}",
        avail_mismatches.len(),
        avail_mismatches.join("\n")
    );
    assert!(
        value_mismatches.is_empty(),
        "sysconf value divergences ({}):\n{}",
        value_mismatches.len(),
        value_mismatches.join("\n")
    );
}

#[test]
fn restored_raw_glibc_codes_match_host() {
    for &code in RESTORED_GLIBC_CODES {
        let host = unsafe { sysconf(code) };
        let implementation = unsafe { frankenlibc_abi::unistd_abi::sysconf(code) };
        assert!(
            host >= 0,
            "host glibc unexpectedly rejects raw sysconf code {code}"
        );
        assert_eq!(implementation, host, "raw sysconf code {code}");
    }
}
