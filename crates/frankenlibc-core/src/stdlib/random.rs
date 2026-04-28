//! Pseudo-random number generation.
//!
//! Implements a simple linear congruential generator compatible with
//! glibc's `rand`/`srand` contract. Constants match glibc's TYPE_0 LCG.

use std::sync::atomic::{AtomicU32, Ordering};

/// RAND_MAX = 2^31 - 1 (matching glibc).
pub const RAND_MAX: i32 = 0x7FFF_FFFF;

static SEED: AtomicU32 = AtomicU32::new(1);

/// Returns a pseudo-random integer in [0, RAND_MAX].
pub fn rand() -> i32 {
    let mut current = SEED.load(Ordering::Relaxed);
    loop {
        let next = lcg_next(current);
        match SEED.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return (next >> 1) as i32 & RAND_MAX,
            Err(new_current) => current = new_current,
        }
    }
}

/// Seeds the random number generator.
pub fn srand(seed: u32) {
    SEED.store(seed, Ordering::Relaxed);
}

/// Reentrant variant — bit-exact port of glibc `rand_r`.
///
/// glibc `rand_r` is **not** a single LCG step. It runs three LCG
/// updates per call and combines them so the 31-bit return space is
/// actually used (a single TYPE_0 step would only produce 15 bits of
/// entropy, the historical POSIX rand_r contract). Matching glibc
/// bit-for-bit matters for any program that pre-computes expected
/// rand_r sequences for testing or that compares output across libc
/// implementations under LD_PRELOAD.
///
/// Reference: glibc `stdlib/rand_r.c`. Verified against glibc on
/// Linux/x86_64 in tests/conformance_diff_stdlib_random.rs.
pub fn rand_r(seed: &mut u32) -> i32 {
    let mut next = *seed;

    next = next.wrapping_mul(1_103_515_245).wrapping_add(12345);
    let mut result: u32 = (next / 65536) % 2048;

    next = next.wrapping_mul(1_103_515_245).wrapping_add(12345);
    result <<= 10;
    result ^= (next / 65536) % 1024;

    next = next.wrapping_mul(1_103_515_245).wrapping_add(12345);
    result <<= 10;
    result ^= (next / 65536) % 1024;

    *seed = next;
    result as i32
}

/// glibc TYPE_0 LCG step used by [`rand`]: `next = seed * 1103515245 + 12345`.
/// Note that [`rand_r`] does **not** simply wrap this — see its docs.
#[inline]
fn lcg_next(seed: u32) -> u32 {
    seed.wrapping_mul(1_103_515_245).wrapping_add(12345)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srand_then_rand_deterministic() {
        srand(42);
        let a = rand();
        srand(42);
        let b = rand();
        assert_eq!(a, b);
    }

    #[test]
    fn test_rand_in_range() {
        srand(1);
        for _ in 0..100 {
            let v = rand();
            assert!((0..=RAND_MAX).contains(&v));
        }
    }

    #[test]
    fn test_rand_r_reentrant() {
        let mut seed = 42u32;
        let a = rand_r(&mut seed);
        let saved = seed;
        let b = rand_r(&mut seed);
        assert_ne!(a, b); // different results with advancing state
        // reset and verify determinism
        seed = 42;
        let c = rand_r(&mut seed);
        assert_eq!(a, c);
        assert_eq!(saved, seed);
    }

    #[test]
    fn test_srand_default_seed() {
        // Default seed is 1, matching glibc behavior.
        srand(1);
        let v = rand();
        assert!(v >= 0);
    }

    /// Bit-exact reference values captured from host glibc `rand_r` on
    /// Linux/x86_64 (`gcc 13` + glibc 2.38). Each row is
    /// (initial_seed, three consecutive return values, final state).
    /// Pinning these here means a future refactor that breaks bit-exact
    /// glibc parity will fail the test suite immediately rather than
    /// silently drifting until a downstream consumer notices.
    #[test]
    fn rand_r_matches_glibc_reference_outputs() {
        let cases: &[(u32, [i32; 3], u32)] = &[
            (0,          [1012484, 1716955679, 1792309082], 2941955441),
            (1,          [476707713, 1186278907, 505671508], 3210001534),
            (42,         [681191333, 928546885, 1457394273], 1314989459),
            (12345,      [1036784229, 1520991917, 1373464794], 551188310),
            (0xDEADBEEF, [1075635910, 1410355045, 390111939], 2730713236),
            (0xFFFFFFFF, [1670702726, 99100226, 931463008], 2673909348),
            (100,        [393052193, 249735217, 2015305992], 3976760965),
        ];
        for &(initial, [r0, r1, r2], final_state) in cases {
            let mut seed = initial;
            assert_eq!(rand_r(&mut seed), r0, "rand_r call 0 with seed={initial}");
            assert_eq!(rand_r(&mut seed), r1, "rand_r call 1 with seed={initial}");
            assert_eq!(rand_r(&mut seed), r2, "rand_r call 2 with seed={initial}");
            assert_eq!(seed, final_state, "final state with seed={initial}");
        }
    }
}
