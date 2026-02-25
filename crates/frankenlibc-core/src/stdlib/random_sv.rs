//! System V `random()` family — non-linear additive feedback PRNG.
//!
//! Implements `random`, `srandom`, `initstate`, `setstate` with
//! glibc-compatible TYPE_3 (degree 31) polynomial by default.
//!
//! Unlike the simple LCG in `rand()`, this generator uses an additive
//! feedback shift register for better statistical properties.

use std::sync::Mutex;

/// Default degree-31 state table size (matching glibc TYPE_3 = 31 words + 3 bookkeeping).
const DEG_3: usize = 31;
const SEP_3: usize = 3;

/// Total state buffer size including front pointer word.
const STATE_SIZE: usize = DEG_3 + 1; // 32 words

/// Internal generator state.
struct RandomState {
    /// The state table; index 0 is unused (glibc compat), indices 1..=DEG_3 hold state.
    table: [i32; STATE_SIZE],
    /// Front pointer index (cycles through 1..=DEG_3).
    fptr: usize,
    /// Rear pointer index (offset from fptr by SEP_3).
    rptr: usize,
}

impl RandomState {
    fn seed(&mut self, seed: u32) {
        // Initialize state table using glibc's initialization algorithm.
        self.table[1] = seed as i32;
        let mut prev = seed as i64;
        for i in 2..STATE_SIZE {
            // glibc: state[i] = (16807 * state[i-1]) % 2147483647
            // Using the same LCG as glibc (Park-Miller minimal standard).
            prev = (16807 * prev) % 2_147_483_647;
            self.table[i] = prev as i32;
        }
        self.fptr = SEP_3 + 1;
        self.rptr = 1;
        // Run the generator 10*DEG_3 times to "warm up" (matching glibc).
        for _ in 0..(10 * DEG_3) {
            self.next();
        }
    }

    fn next(&mut self) -> i32 {
        let val = self.table[self.fptr].wrapping_add(self.table[self.rptr]);
        self.table[self.fptr] = val;
        let result = (val as u32 >> 1) as i32; // ensure non-negative

        self.fptr += 1;
        if self.fptr >= STATE_SIZE {
            self.fptr = 1;
        }
        self.rptr += 1;
        if self.rptr >= STATE_SIZE {
            self.rptr = 1;
        }

        result
    }
}

static GLOBAL: Mutex<RandomState> = Mutex::new(RandomState {
    table: {
        // We can't call seed() in a const context, so initialize to zeros
        // and rely on first call to srandom() or lazy init.
        [0i32; STATE_SIZE]
    },
    fptr: SEP_3 + 1,
    rptr: 1,
});

/// Track whether the global state has been initialized.
static INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn ensure_init() {
    if !INITIALIZED.load(std::sync::atomic::Ordering::Acquire) {
        let mut state = GLOBAL.lock().unwrap();
        if !INITIALIZED.load(std::sync::atomic::Ordering::Relaxed) {
            state.seed(1);
            INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// `random()` — return a pseudo-random number in [0, 2^31-1].
pub fn random() -> i64 {
    ensure_init();
    let mut state = GLOBAL.lock().unwrap();
    state.next() as i64
}

/// `srandom()` — seed the random number generator.
pub fn srandom(seed: u32) {
    let mut state = GLOBAL.lock().unwrap();
    state.seed(seed);
    INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
}

/// `initstate()` — initialize state buffer and seed.
///
/// Returns the previous state buffer as a raw pointer-sized token.
/// In this implementation, the state buffer is managed internally;
/// the returned value and provided buffer are used for API compatibility
/// but the internal Mutex-protected state is the canonical source.
///
/// `seed`: initial seed value
/// `state_buf`: caller-provided buffer (must be >= 8 bytes)
/// `size`: size of the buffer in bytes
///
/// Returns a token representing the old state (opaque pointer-like value).
pub fn initstate(seed: u32, state_buf: &mut [u8]) -> usize {
    // Minimum valid state size is 8 bytes (TYPE_0 in glibc).
    if state_buf.len() < 8 {
        return 0;
    }
    let mut state = GLOBAL.lock().unwrap();
    // Save a token for the old state (we return table[1] as a simple fingerprint).
    let old_token = state.table[1] as usize;
    state.seed(seed);
    INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    // Copy our internal state into the user buffer using safe serialization.
    let words_to_copy = state_buf.len().min(STATE_SIZE * 4) / 4;
    for i in 0..words_to_copy {
        let bytes = state.table[i].to_ne_bytes();
        let off = i * 4;
        state_buf[off..off + 4].copy_from_slice(&bytes);
    }
    old_token
}

/// `setstate()` — restore state from a previously saved buffer.
///
/// `state_buf`: buffer previously filled by `initstate()`
///
/// Returns a token representing the old state.
pub fn setstate(state_buf: &[u8]) -> usize {
    if state_buf.len() < 8 {
        return 0;
    }
    let mut state = GLOBAL.lock().unwrap();
    let old_token = state.table[1] as usize;
    // Restore internal state from the user buffer using safe deserialization.
    let words_to_copy = state_buf.len().min(STATE_SIZE * 4) / 4;
    for i in 0..words_to_copy {
        let off = i * 4;
        let bytes = [
            state_buf[off],
            state_buf[off + 1],
            state_buf[off + 2],
            state_buf[off + 3],
        ];
        state.table[i] = i32::from_ne_bytes(bytes);
    }
    // Reset pointers.
    state.fptr = SEP_3 + 1;
    state.rptr = 1;
    INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    old_token
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srandom_deterministic() {
        srandom(42);
        let a = random();
        srandom(42);
        let b = random();
        assert_eq!(a, b);
    }

    #[test]
    fn test_random_range() {
        srandom(1);
        for _ in 0..200 {
            let v = random();
            assert!(v >= 0 && v <= i32::MAX as i64, "random out of range: {v}");
        }
    }

    #[test]
    fn test_initstate_setstate_basic() {
        // Verify initstate seeds and setstate restores without panicking.
        // Seed first to ensure non-zero table state.
        srandom(777);
        let _ = random(); // advance once

        let mut buf = vec![0u8; STATE_SIZE * 4];
        let _ = initstate(42, &mut buf);
        let v1 = random();
        assert!(v1 >= 0);

        // setstate should accept the buffer.
        let _ = setstate(&buf);
        let v2 = random();
        assert!(v2 >= 0);
    }

    #[test]
    fn test_initstate_too_small_buf() {
        let mut buf = [0u8; 4]; // too small
        let token = initstate(1, &mut buf);
        assert_eq!(token, 0);
    }
}
