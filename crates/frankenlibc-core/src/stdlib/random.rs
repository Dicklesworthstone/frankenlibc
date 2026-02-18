//! Pseudo-random number generation.
//!
//! Implements a simple linear congruential generator compatible with
//! glibc's `rand`/`srand` contract. Constants match glibc's TYPE_0 LCG.

use std::cell::Cell;

/// RAND_MAX = 2^31 - 1 (matching glibc).
pub const RAND_MAX: i32 = 0x7FFF_FFFF;

thread_local! {
    static SEED: Cell<u64> = const { Cell::new(1) };
}

/// Returns a pseudo-random integer in [0, RAND_MAX].
pub fn rand() -> i32 {
    SEED.with(|s| {
        let next = lcg_next(s.get());
        s.set(next);
        (next >> 1) as i32 & RAND_MAX
    })
}

/// Seeds the random number generator.
pub fn srand(seed: u32) {
    SEED.with(|s| s.set(seed as u64));
}

/// Reentrant variant: uses `*seedp` as state.
pub fn rand_r(seed: &mut u32) -> i32 {
    let next = lcg_next(*seed as u64);
    *seed = next as u32;
    (next >> 1) as i32 & RAND_MAX
}

/// glibc TYPE_0 LCG: next = seed * 1103515245 + 12345
#[inline]
fn lcg_next(seed: u64) -> u64 {
    seed.wrapping_mul(1_103_515_245).wrapping_add(12345) & 0xFFFF_FFFF
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
}
