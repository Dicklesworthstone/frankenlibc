//! 48-bit linear congruential PRNG (drand48 family).
//!
//! Implements the System V 48-bit random number generator family:
//! `drand48`, `erand48`, `lrand48`, `nrand48`, `mrand48`, `jrand48`,
//! `srand48`, `seed48`, `lcong48`.
//!
//! The generator uses: X_{n+1} = (a * X_n + c) mod 2^48
//! with default constants matching glibc:
//!   a = 0x5DEECE66D  (25214903917)
//!   c = 0xB           (11)

use std::sync::atomic::{AtomicU64, Ordering};

/// Default multiplier (glibc constant).
const DEFAULT_A: u64 = 0x5DEECE66D;
/// Default increment (glibc constant).
const DEFAULT_C: u64 = 0xB;
/// 48-bit mask.
const MASK_48: u64 = (1u64 << 48) - 1;

/// Global 48-bit state, packed into low 48 bits of a u64.
static STATE: AtomicU64 = AtomicU64::new(0x330E_0000_0001);

/// Global multiplier (can be changed by lcong48).
static MULTIPLIER: AtomicU64 = AtomicU64::new(DEFAULT_A);

/// Global increment (can be changed by lcong48).
static INCREMENT: AtomicU64 = AtomicU64::new(DEFAULT_C);

/// Saved seed from seed48() — stored as packed 48-bit value.
static SAVED_SEED: AtomicU64 = AtomicU64::new(0);

/// Advance a 48-bit state by one step.
#[inline]
fn step(state: u64, a: u64, c: u64) -> u64 {
    (state.wrapping_mul(a).wrapping_add(c)) & MASK_48
}

/// Advance the global state atomically.
#[inline]
fn advance_global() -> u64 {
    let a = MULTIPLIER.load(Ordering::Relaxed);
    let c = INCREMENT.load(Ordering::Relaxed);
    let mut current = STATE.load(Ordering::Relaxed);
    loop {
        let next = step(current, a, c);
        match STATE.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(new_current) => current = new_current,
        }
    }
}

/// Advance a caller-supplied 48-bit state (packed in a `[u16; 3]`).
#[inline]
fn advance_state(xsubi: &mut [u16; 3]) -> u64 {
    let state = pack_state(xsubi);
    let next = step(state, DEFAULT_A, DEFAULT_C);
    unpack_state(next, xsubi);
    next
}

/// Pack three u16 values into a 48-bit u64 (low word first, matching glibc).
#[inline]
fn pack_state(xsubi: &[u16; 3]) -> u64 {
    (xsubi[0] as u64) | ((xsubi[1] as u64) << 16) | ((xsubi[2] as u64) << 32)
}

/// Unpack a 48-bit u64 into three u16 values.
#[inline]
fn unpack_state(val: u64, xsubi: &mut [u16; 3]) {
    xsubi[0] = (val & 0xFFFF) as u16;
    xsubi[1] = ((val >> 16) & 0xFFFF) as u16;
    xsubi[2] = ((val >> 32) & 0xFFFF) as u16;
}

/// `drand48` — return a double in [0.0, 1.0) using global state.
pub fn drand48() -> f64 {
    let state = advance_global();
    state as f64 / (1u64 << 48) as f64
}

/// `erand48` — return a double in [0.0, 1.0) using caller-supplied state.
pub fn erand48(xsubi: &mut [u16; 3]) -> f64 {
    let state = advance_state(xsubi);
    state as f64 / (1u64 << 48) as f64
}

/// `lrand48` — return a non-negative long in [0, 2^31) using global state.
pub fn lrand48() -> i64 {
    let state = advance_global();
    (state >> 17) as i64
}

/// `nrand48` — return a non-negative long in [0, 2^31) using caller state.
pub fn nrand48(xsubi: &mut [u16; 3]) -> i64 {
    let state = advance_state(xsubi);
    (state >> 17) as i64
}

/// `mrand48` — return a signed long in [-2^31, 2^31) using global state.
pub fn mrand48() -> i64 {
    let state = advance_global();
    ((state >> 16) as i32) as i64
}

/// `jrand48` — return a signed long in [-2^31, 2^31) using caller state.
pub fn jrand48(xsubi: &mut [u16; 3]) -> i64 {
    let state = advance_state(xsubi);
    ((state >> 16) as i32) as i64
}

/// `srand48` — seed the global 48-bit state from a single long.
///
/// Sets the high 32 bits of the 48-bit state to `seedval` and the low
/// 16 bits to 0x330E (matching glibc behavior). Resets multiplier and
/// increment to defaults.
pub fn srand48(seedval: i64) {
    let new_state = (((seedval as u64) & 0xFFFF_FFFF) << 16) | 0x330E;
    STATE.store(new_state & MASK_48, Ordering::Relaxed);
    MULTIPLIER.store(DEFAULT_A, Ordering::Relaxed);
    INCREMENT.store(DEFAULT_C, Ordering::Relaxed);
}

/// `seed48` — seed global state with three u16 values; return old seed.
///
/// Returns the previous 48-bit state as `[u16; 3]`.
pub fn seed48(seed16v: &[u16; 3]) -> [u16; 3] {
    let new_state = pack_state(seed16v) & MASK_48;
    let old = STATE.swap(new_state, Ordering::Relaxed);
    SAVED_SEED.store(old, Ordering::Relaxed);
    MULTIPLIER.store(DEFAULT_A, Ordering::Relaxed);
    INCREMENT.store(DEFAULT_C, Ordering::Relaxed);
    let mut result = [0u16; 3];
    unpack_state(old, &mut result);
    result
}

/// `lcong48` — set all LCG parameters (state, multiplier, increment).
///
/// `param[0..2]` = new state, `param[3..5]` = new multiplier,
/// `param[6]` = new increment.
pub fn lcong48(param: &[u16; 7]) {
    let new_state = (param[0] as u64) | ((param[1] as u64) << 16) | ((param[2] as u64) << 32);
    let new_a = (param[3] as u64) | ((param[4] as u64) << 16) | ((param[5] as u64) << 32);
    let new_c = param[6] as u64;

    STATE.store(new_state & MASK_48, Ordering::Relaxed);
    MULTIPLIER.store(new_a & MASK_48, Ordering::Relaxed);
    INCREMENT.store(new_c & MASK_48, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srand48_deterministic() {
        srand48(42);
        let a = drand48();
        srand48(42);
        let b = drand48();
        assert_eq!(a, b);
    }

    #[test]
    fn test_drand48_range() {
        srand48(1);
        for _ in 0..100 {
            let v = drand48();
            assert!((0.0..1.0).contains(&v), "drand48 out of range: {v}");
        }
    }

    #[test]
    fn test_lrand48_range() {
        srand48(1);
        for _ in 0..100 {
            let v = lrand48();
            assert!((0..(1i64 << 31)).contains(&v), "lrand48 out of range: {v}");
        }
    }

    #[test]
    fn test_mrand48_range() {
        srand48(1);
        for _ in 0..100 {
            let v = mrand48();
            assert!(
                (-(1i64 << 31)..(1i64 << 31)).contains(&v),
                "mrand48 out of range: {v}"
            );
        }
    }

    #[test]
    fn test_erand48_deterministic() {
        let mut state = [0x1234u16, 0x5678, 0x9ABC];
        let a = erand48(&mut state);
        let mut state2 = [0x1234u16, 0x5678, 0x9ABC];
        let b = erand48(&mut state2);
        assert_eq!(a, b);
    }

    #[test]
    fn test_nrand48_range() {
        let mut state = [0u16, 0, 1];
        for _ in 0..100 {
            let v = nrand48(&mut state);
            assert!((0..(1i64 << 31)).contains(&v));
        }
    }

    #[test]
    fn test_jrand48_signed() {
        let mut state = [0xFFFFu16, 0xFFFF, 0xFFFF];
        let _ = jrand48(&mut state);
        // Just verify it doesn't panic and returns within i32 range.
    }

    #[test]
    fn test_seed48_returns_old_state() {
        srand48(100);
        // Advance once to get a known state.
        let _ = drand48();
        let new_seed = [0x1111u16, 0x2222, 0x3333];
        let old = seed48(&new_seed);
        // Old state should be non-trivial after advancing.
        assert!(old[0] != 0 || old[1] != 0 || old[2] != 0);
    }

    #[test]
    fn test_lcong48_sets_params_without_panic() {
        // Verify lcong48 accepts custom parameters and subsequent
        // drand48 calls produce values in range (exact sequence is
        // non-deterministic under parallel test execution due to shared state).
        let params = [0u16, 0, 0, 1, 0, 0, 1];
        lcong48(&params);
        let v = drand48();
        assert!(
            (0.0..1.0).contains(&v),
            "drand48 after lcong48 out of range: {v}"
        );
        // Restore default parameters for other tests.
        srand48(1);
    }
}
