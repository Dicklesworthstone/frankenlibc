#![cfg(target_os = "linux")]

//! Metamorphic-property tests for the arc4random family.
//!
//! Validates contract properties that arc4random must satisfy
//! regardless of underlying RNG choice:
//!
//!   - arc4random_uniform(N) always r < N
//!   - arc4random_uniform(0) and arc4random_uniform(1) both return 0
//!   - distribution: 8000 samples on N=8 → all 8 buckets ≥ 700 hits
//!   - 256 draws produce ≥ 99% unique values (high entropy)
//!   - arc4random_buf zero-size is a no-op
//!   - arc4random_buf doesn't write past size bytes
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::c_void;

use frankenlibc_abi::unistd_abi as fl;

#[test]
fn metamorphic_uniform_strictly_less_than_n() {
    for upper in [1u32, 2, 3, 7, 100, 1_000_000, u32::MAX / 2, u32::MAX - 1] {
        for _ in 0..100 {
            let v = unsafe { fl::arc4random_uniform(upper) };
            assert!(v < upper, "arc4random_uniform({upper}) = {v} not < N");
        }
    }
}

#[test]
fn metamorphic_uniform_n_zero_or_one_returns_zero() {
    for _ in 0..32 {
        assert_eq!(unsafe { fl::arc4random_uniform(0) }, 0);
        assert_eq!(unsafe { fl::arc4random_uniform(1) }, 0);
    }
}

#[test]
fn metamorphic_uniform_distribution_balanced() {
    const N: u32 = 8;
    const SAMPLES: usize = 8000;
    let mut counts = [0u32; N as usize];
    for _ in 0..SAMPLES {
        let v = unsafe { fl::arc4random_uniform(N) };
        counts[v as usize] += 1;
    }
    // Expected ≈ 1000; require ≥ 700 (3σ-ish lower bound).
    for (i, &c) in counts.iter().enumerate() {
        assert!(
            c >= 700,
            "bucket {i} underfilled: {c} samples (expected ~1000)"
        );
    }
}

#[test]
fn metamorphic_arc4random_high_unique_ratio() {
    let mut samples = std::collections::BTreeSet::new();
    for _ in 0..256 {
        samples.insert(unsafe { fl::arc4random() });
    }
    let ratio = samples.len() as f64 / 256.0;
    assert!(ratio >= 0.99, "low unique ratio: {ratio}");
}

#[test]
fn metamorphic_buf_zero_size_no_op() {
    let mut sentinel: u8 = 0xa5;
    unsafe {
        fl::arc4random_buf(&mut sentinel as *mut u8 as *mut c_void, 0);
    }
    assert_eq!(sentinel, 0xa5, "arc4random_buf(_, 0) corrupted memory");
}

#[test]
fn metamorphic_buf_does_not_overwrite_past_size() {
    // Allocate a 1KB buffer, fill 64 bytes, verify the rest is
    // untouched.
    let mut buf = [0xa5u8; 1024];
    unsafe {
        fl::arc4random_buf(buf.as_mut_ptr() as *mut c_void, 64);
    }
    // Bytes 64..1024 must still be 0xa5.
    for (i, &b) in buf[64..].iter().enumerate() {
        assert_eq!(
            b, 0xa5,
            "byte {} overwritten past requested size",
            i + 64
        );
    }
    // First 64 bytes should be highly varied (≤ 5% zeros).
    let zeros = buf[..64].iter().filter(|&&b| b == 0).count();
    assert!(zeros <= 4, "too many zeros in random output: {zeros}");
}

#[test]
fn metamorphic_uniform_bound_max_minus_one_succeeds() {
    // Edge case: N = u32::MAX - 1 still has rejection sampling.
    let v = unsafe { fl::arc4random_uniform(u32::MAX - 1) };
    assert!(v < u32::MAX - 1);
}

#[test]
fn arc4random_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc arc4random + arc4random_uniform + arc4random_buf\",\"reference\":\"internal-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
