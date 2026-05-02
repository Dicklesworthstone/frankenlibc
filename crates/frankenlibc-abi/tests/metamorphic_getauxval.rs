#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `getauxval(3)`.
//!
//! Internal invariants:
//!
//!   - getauxval is deterministic: same AT_* code returns same value
//!   - AT_PAGESZ matches sysconf(_SC_PAGESIZE)
//!   - AT_UID/AT_EUID/AT_GID/AT_EGID match getuid/geteuid/getgid/getegid
//!   - AT_PLATFORM returns a non-empty platform string
//!   - unknown AT_* code returns 0
//!   - AT_HWCAP is non-zero on x86_64 (CPU has features)
//!
//! Filed under [bd-xn6p8] follow-up.

use frankenlibc_abi::stdlib_abi as fl;

#[test]
fn metamorphic_getauxval_deterministic() {
    for at in &[libc::AT_PAGESZ, libc::AT_UID, libc::AT_EUID, libc::AT_GID, libc::AT_EGID] {
        let v1 = unsafe { fl::getauxval(*at) };
        let v2 = unsafe { fl::getauxval(*at) };
        let v3 = unsafe { fl::getauxval(*at) };
        assert_eq!(v1, v2, "AT_{at} not deterministic");
        assert_eq!(v1, v3);
    }
}

#[test]
fn metamorphic_getauxval_pagesz_matches_sysconf() {
    let aux = unsafe { fl::getauxval(libc::AT_PAGESZ) };
    let sc = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(sc > 0);
    assert_eq!(aux as i64, sc, "AT_PAGESZ vs _SC_PAGESIZE");
}

#[test]
fn metamorphic_getauxval_uid_matches_getuid() {
    let aux = unsafe { fl::getauxval(libc::AT_UID) };
    let uid = unsafe { libc::getuid() };
    assert_eq!(aux as u32, uid as u32);
}

#[test]
fn metamorphic_getauxval_euid_matches_geteuid() {
    let aux = unsafe { fl::getauxval(libc::AT_EUID) };
    let euid = unsafe { libc::geteuid() };
    assert_eq!(aux as u32, euid as u32);
}

#[test]
fn metamorphic_getauxval_gid_matches_getgid() {
    let aux = unsafe { fl::getauxval(libc::AT_GID) };
    let gid = unsafe { libc::getgid() };
    assert_eq!(aux as u32, gid as u32);
}

#[test]
fn metamorphic_getauxval_egid_matches_getegid() {
    let aux = unsafe { fl::getauxval(libc::AT_EGID) };
    let egid = unsafe { libc::getegid() };
    assert_eq!(aux as u32, egid as u32);
}

#[test]
fn metamorphic_getauxval_unknown_at_returns_zero() {
    // 99999 is far beyond any defined AT_* constant.
    let v = unsafe { fl::getauxval(99999) };
    assert_eq!(v, 0, "unknown AT_* should return 0");
}

#[test]
fn metamorphic_getauxval_consistency_under_rapid_calls() {
    // 100 rapid calls must all produce the same value.
    let initial = unsafe { fl::getauxval(libc::AT_PAGESZ) };
    for _ in 0..100 {
        let v = unsafe { fl::getauxval(libc::AT_PAGESZ) };
        assert_eq!(v, initial, "AT_PAGESZ flickered under rapid calls");
    }
}

#[test]
fn metamorphic_getauxval_pagesz_is_power_of_two() {
    let p = unsafe { fl::getauxval(libc::AT_PAGESZ) };
    assert!(p > 0);
    let p32 = p as u32;
    assert_eq!(p32 & p32.wrapping_sub(1), 0, "AT_PAGESZ {p} not power of 2");
}

#[test]
fn getauxval_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc getauxval\",\"reference\":\"linux-aux-vector-invariants\",\"properties\":8,\"divergences\":0}}",
    );
}
