#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc setlogmask oracle

//! Differential gate for setlogmask (bd-22qdtd) — no differential gate existed.
//! setlogmask(mask) sets the syslog priority mask and returns the PREVIOUS mask;
//! a 0 argument queries the current mask WITHOUT changing it. fl and glibc keep
//! independent process-global masks, so each runs its own set/query round-trip;
//! the observed (default, prev, new) sequence is compared, validating both the
//! default mask (0xFF = LOG_UPTO(DEBUG)) and the query-on-0 semantics. The
//! original mask is restored at the end. No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn setlogmask(mask: c_int) -> c_int;
}

/// [query-default, prev-when-setting-0x07, query-new]; restores at the end.
fn seq(f: unsafe extern "C" fn(c_int) -> c_int) -> [c_int; 3] {
    unsafe {
        let m0 = f(0); // query current (no change) -> default
        let prev = f(0x07); // set LOG_UPTO(ERR) -> returns old mask
        let m1 = f(0); // query -> 0x07
        f(prev); // restore original
        [m0, prev, m1]
    }
}

#[test]
fn setlogmask_round_trip_matches_glibc() {
    let g = seq(setlogmask);
    let f = seq(frankenlibc_abi::unistd_abi::setlogmask);
    assert_eq!(
        f, g,
        "setlogmask sequence [query,prev,query]: fl={f:?} glibc={g:?}"
    );
    // glibc default mask is 0xFF (all 8 priorities), and query-on-0 returns the set value.
    assert_eq!(
        g,
        [0xFF, 0xFF, 0x07],
        "glibc reference: default 0xFF, then set 0x07"
    );
}
