#![cfg(target_os = "linux")]

//! Differential conformance harness for `__nss_hash(3)`.
//!
//! glibc uses XXH32 with seed 0xab1aac7c since glibc 2.36; fl uses
//! FNV-1a. The symbol is GLIBC_PRIVATE so external callers can't
//! depend on the specific bits — what matters is determinism and
//! distinctness. This harness validates fl's hash without
//! requiring bit-exact parity with glibc.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::collections::BTreeSet;
use std::ffi::{c_void, CString};

unsafe extern "C" {
    fn __nss_hash(name: *const c_void, len: usize) -> u32;
}

use frankenlibc_abi::unistd_abi as fl;

#[test]
fn fl_nss_hash_is_deterministic() {
    // Same input → same output across calls.
    for s in ["hosts", "passwd", "group", "shadow", "files", "dns", "compat"] {
        let cs = CString::new(s).unwrap();
        let h1 = unsafe { fl::__nss_hash(cs.as_ptr() as *const c_void, s.len()) };
        let h2 = unsafe { fl::__nss_hash(cs.as_ptr() as *const c_void, s.len()) };
        assert_eq!(h1, h2, "fl hash not deterministic for {s:?}");
    }
}

#[test]
fn fl_nss_hash_known_inputs_distinct() {
    // The 9 NSS database/source names commonly looked up should
    // hash to 9 distinct values.
    let names = [
        "hosts", "passwd", "group", "shadow", "services",
        "files", "compat", "dns", "nis",
    ];
    let mut hashes = BTreeSet::new();
    for s in &names {
        let cs = CString::new(*s).unwrap();
        let h = unsafe { fl::__nss_hash(cs.as_ptr() as *const c_void, s.len()) };
        hashes.insert(h);
    }
    assert_eq!(
        hashes.len(),
        names.len(),
        "fl hash collisions on common NSS names"
    );
}

#[test]
fn diff_nss_hash_glibc_also_distinguishes_same_inputs() {
    // We don't compare bit-for-bit, but we verify glibc also
    // returns distinct hashes for the same set — proving both
    // impls behave as proper hash functions on this corpus.
    let names = [
        "hosts", "passwd", "group", "shadow", "services",
        "files", "compat", "dns", "nis",
    ];
    let mut fl_hashes = BTreeSet::new();
    let mut lc_hashes = BTreeSet::new();
    for s in &names {
        let cs = CString::new(*s).unwrap();
        let fl_h = unsafe { fl::__nss_hash(cs.as_ptr() as *const c_void, s.len()) };
        let lc_h = unsafe { __nss_hash(cs.as_ptr() as *const c_void, s.len()) };
        fl_hashes.insert(fl_h);
        lc_hashes.insert(lc_h);
    }
    assert_eq!(fl_hashes.len(), names.len());
    assert_eq!(lc_hashes.len(), names.len());
}

#[test]
fn fl_nss_hash_empty_returns_zero() {
    let v = unsafe { fl::__nss_hash(std::ptr::null(), 0) };
    assert_eq!(v, 0);

    // Non-NULL with length 0.
    let cs = CString::new("").unwrap();
    let v2 = unsafe { fl::__nss_hash(cs.as_ptr() as *const c_void, 0) };
    assert_eq!(v2, 0);
}

#[test]
fn fl_nss_hash_single_byte_changes_hash() {
    let h_a = unsafe { fl::__nss_hash(b"a".as_ptr() as *const c_void, 1) };
    let h_b = unsafe { fl::__nss_hash(b"b".as_ptr() as *const c_void, 1) };
    assert_ne!(h_a, h_b, "single-byte difference should change hash");
}

#[test]
fn fl_nss_hash_length_distinguishes() {
    // "abc" vs "ab" — different lengths even with shared prefix.
    let h3 = unsafe { fl::__nss_hash(b"abc".as_ptr() as *const c_void, 3) };
    let h2 = unsafe { fl::__nss_hash(b"ab".as_ptr() as *const c_void, 2) };
    assert_ne!(h2, h3);
}

#[test]
fn nss_hash_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc __nss_hash\",\"reference\":\"glibc-deterministic\",\"functions\":1,\"divergences\":\"algorithm\"}}",
    );
}
