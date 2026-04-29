//! Pseudo-random number generation.
//!
//! `rand`/`srand` share the System V `random` state, matching glibc's
//! default TYPE_3 additive generator. `rand_r` remains the separate
//! POSIX reentrant three-step LCG.

use super::random_sv;

/// RAND_MAX = 2^31 - 1 (matching glibc).
pub const RAND_MAX: i32 = 0x7FFF_FFFF;

/// Returns a pseudo-random integer in [0, RAND_MAX].
pub fn rand() -> i32 {
    random_sv::random() as i32
}

/// Seeds the random number generator.
pub fn srand(seed: u32) {
    random_sv::srandom(seed);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srand_then_rand_deterministic() {
        let _guard = random_sv::test_global_random_lock();
        srand(42);
        let a = rand();
        srand(42);
        let b = rand();
        assert_eq!(a, b);
    }

    #[test]
    fn test_rand_in_range() {
        let _guard = random_sv::test_global_random_lock();
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
        let _guard = random_sv::test_global_random_lock();
        // Default seed is 1, matching glibc behavior.
        srand(1);
        let v = rand();
        assert!(v >= 0);
    }

    #[test]
    fn rand_matches_glibc_type3_reference_outputs() {
        let _guard = random_sv::test_global_random_lock();
        let cases: &[(u32, [i32; 6])] = &[
            (
                0,
                [
                    1_804_289_383,
                    846_930_886,
                    1_681_692_777,
                    1_714_636_915,
                    1_957_747_793,
                    424_238_335,
                ],
            ),
            (
                1,
                [
                    1_804_289_383,
                    846_930_886,
                    1_681_692_777,
                    1_714_636_915,
                    1_957_747_793,
                    424_238_335,
                ],
            ),
            (
                42,
                [
                    71_876_166,
                    708_592_740,
                    1_483_128_881,
                    907_283_241,
                    442_951_012,
                    537_146_758,
                ],
            ),
            (
                12_345,
                [
                    383_100_999,
                    858_300_821,
                    357_768_173,
                    455_528_251,
                    133_005_921,
                    116_285_904,
                ],
            ),
            (
                u32::MAX,
                [
                    254_925_627,
                    1_205_188_300,
                    366_127_624,
                    1_401_405_153,
                    76_053_476,
                    1_604_170_158,
                ],
            ),
        ];

        for &(seed, expected) in cases {
            srand(seed);
            let actual = [rand(), rand(), rand(), rand(), rand(), rand()];
            assert_eq!(actual, expected, "rand sequence for seed {seed}");
        }
    }

    #[test]
    fn srand_and_srandom_share_global_state() {
        let _guard = random_sv::test_global_random_lock();
        srand(42);
        let via_rand = rand();
        random_sv::srandom(42);
        let via_random = random_sv::random() as i32;
        assert_eq!(via_rand, via_random);

        random_sv::srandom(12_345);
        let random_first = random_sv::random() as i32;
        srand(12_345);
        let rand_first = rand();
        assert_eq!(rand_first, random_first);
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
            (0, [1012484, 1716955679, 1792309082], 2941955441),
            (1, [476707713, 1186278907, 505671508], 3210001534),
            (42, [681191333, 928546885, 1457394273], 1314989459),
            (12345, [1036784229, 1520991917, 1373464794], 551188310),
            (0xDEADBEEF, [1075635910, 1410355045, 390111939], 2730713236),
            (0xFFFFFFFF, [1670702726, 99100226, 931463008], 2673909348),
            (100, [393052193, 249735217, 2015305992], 3976760965),
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
