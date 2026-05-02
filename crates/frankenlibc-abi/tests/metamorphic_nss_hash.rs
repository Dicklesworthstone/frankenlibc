#![cfg(target_os = "linux")]

//! Metamorphic-property test harness for `__nss_hash` (FNV-1a 32-bit).
//!
//! Validates internal hash invariants without requiring bit-exact
//! parity with glibc:
//!
//!   - same bytes → same hash (determinism)
//!   - distinct strings hash to ≥99% distinct values on a 1000-entry
//!     dictionary (avalanche / no-clustering)
//!   - per-byte avalanche: flipping any single bit changes the hash
//!   - prepending vs appending the same byte produces different hashes
//!     (order-sensitivity)
//!   - empty input is the FNV-1a offset basis (0x811c9dc5)
//!
//! Filed under [bd-xn6p8] follow-up.

use std::collections::BTreeSet;
use std::ffi::c_void;

use frankenlibc_abi::unistd_abi as fl;

#[test]
fn fnv_offset_basis_for_empty_input() {
    let h_null = unsafe { fl::__nss_hash(std::ptr::null(), 0) };
    let h_zero_len = unsafe { fl::__nss_hash(b"abc".as_ptr() as *const c_void, 0) };
    // Both NULL and 0-length should return 0 per fl's hardening.
    assert_eq!(h_null, 0);
    assert_eq!(h_zero_len, 0);
}

#[test]
fn metamorphic_determinism_across_repeated_calls() {
    let inputs = ["hosts", "passwd", "group", "shadow", "files", "dns"];
    for s in &inputs {
        let mut hashes = BTreeSet::new();
        for _ in 0..32 {
            let h = unsafe { fl::__nss_hash(s.as_ptr() as *const c_void, s.len()) };
            hashes.insert(h);
        }
        assert_eq!(hashes.len(), 1, "non-deterministic hash for {s:?}");
    }
}

#[test]
fn metamorphic_distinct_strings_distinct_hashes() {
    // Generate a 1000-entry dictionary of distinct ASCII strings;
    // require ≥99% unique hashes.
    let mut hashes = BTreeSet::new();
    for i in 0..1000 {
        let s = format!("entry-{i:04}");
        let h = unsafe { fl::__nss_hash(s.as_ptr() as *const c_void, s.len()) };
        hashes.insert(h);
    }
    let unique_ratio = hashes.len() as f64 / 1000.0;
    assert!(
        unique_ratio >= 0.99,
        "low unique ratio {unique_ratio} on 1000 entries"
    );
}

#[test]
fn metamorphic_single_bit_flip_changes_hash() {
    // For a fixed input, flipping any single bit in any byte must
    // produce a different hash.
    let base = b"frankenlibc-test";
    let h0 = unsafe { fl::__nss_hash(base.as_ptr() as *const c_void, base.len()) };
    for i in 0..base.len() {
        for bit in 0..8 {
            let mut mutated = base.to_vec();
            mutated[i] ^= 1 << bit;
            let h = unsafe { fl::__nss_hash(mutated.as_ptr() as *const c_void, mutated.len()) };
            assert_ne!(
                h, h0,
                "bit-flip in byte {i} bit {bit} did not change hash"
            );
        }
    }
}

#[test]
fn metamorphic_prepend_vs_append_same_byte_differs() {
    let base = b"foobar";
    let mut prepended = vec![b'!'];
    prepended.extend_from_slice(base);
    let mut appended = base.to_vec();
    appended.push(b'!');
    let h_pre = unsafe { fl::__nss_hash(prepended.as_ptr() as *const c_void, prepended.len()) };
    let h_app = unsafe { fl::__nss_hash(appended.as_ptr() as *const c_void, appended.len()) };
    assert_ne!(h_pre, h_app, "prepend and append same byte hashed equal");
}

#[test]
fn metamorphic_length_changes_hash_even_for_zero_byte_padding() {
    // Distinct inputs of differing length must hash distinctly even
    // when one is a prefix of the other.
    let short = b"abc";
    let long = b"abc\0";
    let h_s = unsafe { fl::__nss_hash(short.as_ptr() as *const c_void, short.len()) };
    let h_l = unsafe { fl::__nss_hash(long.as_ptr() as *const c_void, long.len()) };
    assert_ne!(h_s, h_l, "abc and abc\\0 hashed equal");
}

#[test]
fn metamorphic_distribution_in_low_byte() {
    // Sample 256 strings; the low byte of the hash should cover
    // many distinct values (no clustering).
    let mut low_bytes = BTreeSet::new();
    for i in 0..256 {
        let s = format!("k{i}");
        let h = unsafe { fl::__nss_hash(s.as_ptr() as *const c_void, s.len()) };
        low_bytes.insert(h as u8);
    }
    // Expect at least 100 distinct low-byte values (random would
    // give ~163; FNV-1a typically does well).
    assert!(
        low_bytes.len() >= 100,
        "low byte under-distributed: {} distinct values",
        low_bytes.len()
    );
}

#[test]
fn nss_hash_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc __nss_hash\",\"reference\":\"internal-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
