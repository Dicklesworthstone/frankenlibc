//! System V `random()` family — non-linear additive feedback PRNG.
//!
//! Implements `random`, `srandom`, `initstate`, `setstate` with
//! glibc-compatible TYPE_3 (degree 31) polynomial by default.
//!
//! The public `rand()`/`srand()` wrappers share this state, matching glibc.
//! This generator uses an additive feedback shift register for better
//! statistical properties than the historical one-word LCG.

use std::sync::Mutex;
#[cfg(test)]
use std::sync::MutexGuard;

/// Default degree-31 state (glibc TYPE_3). Kept for the test buffers that size
/// themselves as `STATE_SIZE * 4` and for the default global generator.
const DEG_3: usize = 31;
const SEP_3: usize = 3;

/// Total default (TYPE_3) state buffer size in 32-bit words (test buffers).
#[cfg(test)]
const STATE_SIZE: usize = DEG_3 + 1; // 32 words

/// Maximum polynomial degree across all glibc generator types (TYPE_4).
const MAX_DEG: usize = 63;

/// Per-type polynomial degree and separation, indexed by `rand_type` 0..=4.
/// These are glibc's exact additive-feedback parameters:
///   TYPE_0  x**0          (a pure linear congruential generator)
///   TYPE_1  x**7 + x**3 + 1
///   TYPE_2  x**15 + x + 1
///   TYPE_3  x**31 + x**3 + 1   (the default)
///   TYPE_4  x**63 + x + 1
const DEG: [usize; 5] = [0, 7, 15, 31, 63];
const SEP: [usize; 5] = [0, 3, 1, 3, 1];

/// glibc state-size breakpoints (in bytes): `initstate(seed, buf, n)` selects
/// the largest type whose state fits in `n`.
const BREAK_0: usize = 8; // minimum valid buffer
const BREAK_1: usize = 32;
const BREAK_2: usize = 64;
const BREAK_3: usize = 128;
const BREAK_4: usize = 256;

/// Map a state-buffer byte length to a glibc generator type, or `None` if the
/// buffer is too small (`< 8` bytes), exactly mirroring glibc's `__initstate_r`.
fn rand_type_for_size(n: usize) -> Option<u8> {
    if n < BREAK_0 {
        None
    } else if n < BREAK_1 {
        Some(0)
    } else if n < BREAK_2 {
        Some(1)
    } else if n < BREAK_3 {
        Some(2)
    } else if n < BREAK_4 {
        Some(3)
    } else {
        Some(4)
    }
}

/// Internal generator state. Mirrors glibc's `random_data`: a 0-based state
/// table of `deg` words plus front/rear cursors. For TYPE_0 only `table[0]`
/// is live (the LCG accumulator).
struct RandomState {
    /// glibc generator type 0..=4.
    rand_type: u8,
    /// Polynomial degree (number of live state words).
    deg: usize,
    /// Front/rear cursor separation.
    sep: usize,
    /// State words; indices `[0, deg)` are live.
    table: [i32; MAX_DEG],
    /// Front cursor (index into `table`).
    fptr: usize,
    /// Rear cursor (index into `table`).
    rptr: usize,
}

impl RandomState {
    /// Switch this generator to `rand_type`, setting the matching degree/sep.
    fn set_type(&mut self, rand_type: u8) {
        self.rand_type = rand_type;
        self.deg = DEG[rand_type as usize];
        self.sep = SEP[rand_type as usize];
    }

    /// Seed the generator, exactly matching glibc `__srandom_r`.
    ///
    /// A zero seed is replaced by 1 (glibc quirk). For TYPE_0 the seed is the
    /// sole LCG accumulator. For higher types the table is filled by the
    /// Park-Miller minimal-standard generator via Schrage's overflow-free
    /// decomposition (this is bit-exact with glibc for *all* seeds, including
    /// those with the high bit set — a plain `(16807*x) % m` over `i64`/
    /// `rem_euclid` diverges from glibc on negative intermediate words).
    fn seed(&mut self, seed: u32) {
        let (fptr, rptr) = seed_table(self.rand_type, self.deg, seed, &mut self.table);
        self.fptr = fptr;
        self.rptr = rptr;
    }

    fn next(&mut self) -> i32 {
        next_draw(
            self.rand_type,
            self.deg,
            &mut self.table,
            &mut self.fptr,
            &mut self.rptr,
        )
    }
}

/// Seed a `deg`-word state `table` exactly as glibc `__srandom_r`, returning the
/// post-warmup `(fptr, rptr)` cursor indices. Shared by the process-global
/// generator and the reentrant `random_r` family.
///
/// A zero seed is replaced by 1 (glibc quirk). For TYPE_0 the seed is the sole
/// LCG accumulator. For higher types the table is filled by the Park-Miller
/// minimal-standard generator via Schrage's overflow-free decomposition (bit-
/// exact with glibc for *all* seeds, including high-bit-set ones, where a plain
/// `(16807*x) % m` / `rem_euclid` diverges on negative intermediate words).
fn seed_table(rand_type: u8, deg: usize, seed: u32, table: &mut [i32]) -> (usize, usize) {
    let seed = if seed == 0 { 1 } else { seed };
    table[0] = seed as i32;
    if rand_type == 0 {
        return (0, 0);
    }
    let mut word = seed as i32;
    for slot in table.iter_mut().take(deg).skip(1) {
        // Schrage: word = 16807 * word (mod 2147483647), kept in i32 range.
        // hi/lo use C/Rust truncating division, identical for negatives.
        let hi = word / 127_773;
        let lo = word % 127_773;
        // The product stays within i32 for every reachable word, but compute in
        // i64 to make that explicit and panic-proof under overflow checks.
        word = (16807_i64 * lo as i64 - 2836_i64 * hi as i64) as i32;
        if word < 0 {
            word += 2_147_483_647;
        }
        *slot = word;
    }
    let mut fptr = SEP[rand_type as usize];
    let mut rptr = 0usize;
    // Warm up 10*deg draws. Because that is a whole number of cursor cycles
    // (the cursors have period `deg`), they return to (sep, 0).
    for _ in 0..(10 * deg) {
        next_draw(rand_type, deg, table, &mut fptr, &mut rptr);
    }
    (fptr, rptr)
}

/// One draw from a `deg`-word state `table`, advancing the cursors (and, for
/// TYPE_0, `table[0]`). Mirrors glibc `__random_r`. Shared by the global and
/// reentrant generators.
fn next_draw(
    rand_type: u8,
    deg: usize,
    table: &mut [i32],
    fptr: &mut usize,
    rptr: &mut usize,
) -> i32 {
    if rand_type == 0 {
        // TYPE_0: a single-word linear congruential generator.
        let val = table[0].wrapping_mul(1_103_515_245).wrapping_add(12_345) & 0x7fff_ffff;
        table[0] = val;
        return val;
    }
    // TYPE_>0: additive feedback. `*fptr += *rptr` (unsigned, wrapping), stored
    // back; the result drops the low (least random) bit.
    let val = (table[*fptr] as u32).wrapping_add(table[*rptr] as u32);
    table[*fptr] = val as i32;
    let result = ((val >> 1) & 0x7fff_ffff) as i32;

    // glibc cursor advance: bump fptr; on wrap reset it and bump rptr (which
    // cannot also wrap in that step), else bump rptr with its own wrap check.
    *fptr += 1;
    if *fptr >= deg {
        *fptr = 0;
        *rptr += 1;
    } else {
        *rptr += 1;
        if *rptr >= deg {
            *rptr = 0;
        }
    }

    result
}

static GLOBAL: Mutex<RandomState> = Mutex::new(RandomState {
    // Default generator is TYPE_3 (degree 31), matching glibc's unseeded
    // `random()`. The table is zeroed; first use lazily seeds with 1.
    rand_type: 3,
    deg: DEG_3,
    sep: SEP_3,
    table: [0i32; MAX_DEG],
    fptr: SEP_3,
    rptr: 0,
});

/// Track whether the global state has been initialized.
static INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
static TEST_RANDOM_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn test_global_random_lock() -> MutexGuard<'static, ()> {
    TEST_RANDOM_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ensure_init() {
    if !INITIALIZED.load(std::sync::atomic::Ordering::Acquire) {
        let mut state = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
        if !INITIALIZED.load(std::sync::atomic::Ordering::Relaxed) {
            state.seed(1);
            INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// `random()` — return a pseudo-random number in [0, 2^31-1].
pub fn random() -> i64 {
    ensure_init();
    let mut state = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    state.next() as i64
}

/// `srandom()` — seed the random number generator.
pub fn srandom(seed: u32) {
    let mut state = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
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
    // glibc selects the generator type from the buffer size; < 8 bytes is
    // invalid (EINVAL at the ABI boundary).
    let Some(rand_type) = rand_type_for_size(state_buf.len()) else {
        return 0;
    };
    let mut state = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    // Token for the old state (a simple fingerprint of the live accumulator).
    let old_token = state.table[0] as usize;
    state.set_type(rand_type);
    state.seed(seed);
    INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    // Snapshot the live state words into the caller buffer so a later
    // setstate() on the same buffer (which re-derives the type from its size)
    // can restore them.
    let words_to_copy = (state_buf.len() / 4).min(state.deg.max(1));
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
    // Re-derive the generator type from the buffer size, exactly as the
    // initstate() that produced it did (the ABI layer hands us a slice whose
    // length is the remembered statelen).
    let Some(rand_type) = rand_type_for_size(state_buf.len()) else {
        return 0;
    };
    let mut state = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
    let old_token = state.table[0] as usize;
    state.set_type(rand_type);
    // Restore the live state words from the buffer.
    let words_to_copy = (state_buf.len() / 4).min(state.deg.max(1));
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
    // Restore the cursors to their post-seed position. The warmup advances the
    // cursors a whole number of periods, so (sep, 0) is exactly where they sat
    // when initstate() snapshotted the table.
    state.fptr = state.sep;
    state.rptr = 0;
    INITIALIZED.store(true, std::sync::atomic::Ordering::Release);
    old_token
}

// ===========================================================================
// Reentrant `random_r` family (POSIX `random_r`/`srandom_r`/`initstate_r`/
// `setstate_r`).
//
// glibc keeps the live state in the caller's `statebuf` (a 32-bit-word array)
// and a small cursor/type record in the caller's `struct random_data`. The
// statebuf word layout matches glibc exactly so `setstate_r` round-trips:
//   word[0]            = encoding `MAX_TYPES * rear + type` (TYPE_0 => 0)
//   word[1 ..= deg]    = the `deg` live state words
// `rear` is the rear-cursor offset; the front cursor is `rear + sep (mod deg)`.
//
// These pure functions operate on the caller's word slice plus a `RandomRState`
// cursor record. The ABI layer owns the raw pointers and stores `RandomRState`
// (plus a pointer back to `statebuf`) inside the opaque `random_data` blob.
// ===========================================================================

/// Number of generator types; the multiplier in the statebuf[0] encoding.
const MAX_TYPES: i32 = 5;

/// Cursor + type record for a reentrant generator, stored by the ABI inside the
/// caller's opaque `random_data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomRState {
    pub rand_type: u8,
    pub deg: u32,
    pub sep: u32,
    pub fptr: u32,
    pub rptr: u32,
}

/// glibc generator type for a `statelen`-byte buffer, or `None` if too small.
pub fn random_r_type_for_len(statelen: usize) -> Option<u8> {
    rand_type_for_size(statelen)
}

/// Encode the current cursor/type into `words[0]`, exactly as glibc flushes a
/// generator's info before switching away from its statebuf.
fn encode_info(words: &mut [i32], st: &RandomRState) {
    words[0] = if st.rand_type == 0 {
        0
    } else {
        MAX_TYPES * st.rptr as i32 + st.rand_type as i32
    };
}

/// `initstate_r`: select the type from `words.len()` (= statelen/4), seed the
/// `deg` state words, write the encoding into `words[0]`, and return the cursor.
/// Returns `None` (EINVAL) if the buffer is too small.
pub fn random_r_initstate(seed: u32, words: &mut [i32]) -> Option<RandomRState> {
    let rand_type = rand_type_for_size(words.len().saturating_mul(4))?;
    let deg = DEG[rand_type as usize];
    let sep = SEP[rand_type as usize];
    // State table lives in words[1..=deg]; word[0] holds the encoding.
    let (fptr, rptr) = seed_table(rand_type, deg, seed, &mut words[1..]);
    let st = RandomRState {
        rand_type,
        deg: deg as u32,
        sep: sep as u32,
        fptr: fptr as u32,
        rptr: rptr as u32,
    };
    encode_info(words, &st);
    Some(st)
}

/// `srandom_r`: re-seed the existing generator (type unchanged) and update the
/// cursor in place. `words` is the same statebuf bound at initstate time.
pub fn random_r_srandom(seed: u32, words: &mut [i32], st: &mut RandomRState) {
    let (fptr, rptr) = seed_table(st.rand_type, st.deg as usize, seed, &mut words[1..]);
    st.fptr = fptr as u32;
    st.rptr = rptr as u32;
}

/// One reentrant draw: advance the generator in `words[1..]` and the cursor.
pub fn random_r_step(words: &mut [i32], st: &mut RandomRState) -> i32 {
    let mut fptr = st.fptr as usize;
    let mut rptr = st.rptr as usize;
    let val = next_draw(
        st.rand_type,
        st.deg as usize,
        &mut words[1..],
        &mut fptr,
        &mut rptr,
    );
    st.fptr = fptr as u32;
    st.rptr = rptr as u32;
    val
}

/// `setstate_r`: recover the type and rear cursor from `words[0]`, returning a
/// fresh cursor. Returns `None` (EINVAL) if the encoded type is invalid.
pub fn random_r_setstate(words: &[i32]) -> Option<RandomRState> {
    let encoded = words[0];
    let rand_type = encoded.rem_euclid(MAX_TYPES) as u8;
    let rear = encoded.div_euclid(MAX_TYPES);
    if rand_type > 4 || rear < 0 {
        return None;
    }
    let deg = DEG[rand_type as usize];
    let sep = SEP[rand_type as usize];
    let (fptr, rptr) = if rand_type == 0 {
        (0, 0)
    } else {
        let rptr = rear as usize % deg;
        ((rptr + sep) % deg, rptr)
    };
    Some(RandomRState {
        rand_type,
        deg: deg as u32,
        sep: sep as u32,
        fptr: fptr as u32,
        rptr: rptr as u32,
    })
}

/// Flush a generator's live cursor back into its statebuf encoding word. The ABI
/// calls this on the *old* statebuf before `initstate_r`/`setstate_r` rebind the
/// `random_data` to a new buffer, matching glibc's save-old-state behavior.
pub fn random_r_flush(words: &mut [i32], st: &RandomRState) {
    encode_info(words, st);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srandom_deterministic() {
        let _guard = test_global_random_lock();
        srandom(42);
        let a = random();
        srandom(42);
        let b = random();
        assert_eq!(a, b);
    }

    #[test]
    fn test_random_range() {
        let _guard = test_global_random_lock();
        srandom(1);
        for _ in 0..200 {
            let v = random();
            assert!(v >= 0 && v <= i32::MAX as i64, "random out of range: {v}");
        }
    }

    #[test]
    fn test_initstate_setstate_basic() {
        let _guard = test_global_random_lock();
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
    fn initstate_same_seed_serializes_same_state() {
        let _guard = test_global_random_lock();
        let mut first = vec![0u8; STATE_SIZE * 4];
        let mut second = vec![0u8; STATE_SIZE * 4];

        let _ = initstate(12345, &mut first);
        let _ = initstate(12345, &mut second);

        assert_eq!(first, second);
    }

    #[test]
    fn setstate_replays_saved_seed_sequence_after_intervening_state() {
        let _guard = test_global_random_lock();
        let mut saved = vec![0u8; STATE_SIZE * 4];
        let _ = initstate(2026, &mut saved);
        let expected: Vec<i64> = (0..8).map(|_| random()).collect();

        srandom(99);
        let _: Vec<i64> = (0..8).map(|_| random()).collect();

        let _ = setstate(&saved);
        let replayed: Vec<i64> = (0..8).map(|_| random()).collect();
        assert_eq!(replayed, expected);
    }

    #[test]
    fn test_initstate_too_small_buf() {
        let _guard = test_global_random_lock();
        let mut buf = [0u8; 4]; // too small
        let token = initstate(1, &mut buf);
        assert_eq!(token, 0);
    }

    #[test]
    fn setstate_too_small_buffer_preserves_current_state() {
        let _guard = test_global_random_lock();
        srandom(321);
        let expected = random();

        srandom(321);
        let tiny = [0u8; 4];
        let token = setstate(&tiny);
        assert_eq!(token, 0);
        assert_eq!(random(), expected);
    }

    #[test]
    fn srandom_zero_matches_seed_one() {
        let _guard = test_global_random_lock();
        srandom(0);
        let zero_seeded: Vec<i64> = (0..6).map(|_| random()).collect();
        srandom(1);
        let one_seeded: Vec<i64> = (0..6).map(|_| random()).collect();
        assert_eq!(zero_seeded, one_seeded);
    }

    #[test]
    fn glibc_random_sequence_parity() {
        // Verify exact glibc random() sequence with default seed (1).
        // These values were captured from glibc 2.38 on x86_64-linux.
        let _guard = test_global_random_lock();
        srandom(1);
        let expected = [1804289383i64, 846930886, 1681692777, 1714636915, 1957747793];
        for (i, &exp) in expected.iter().enumerate() {
            let got = random();
            assert_eq!(
                got, exp,
                "random()[{i}] mismatch: expected {exp}, got {got}"
            );
        }
    }

    #[test]
    fn glibc_srandom_42_sequence_parity() {
        // Verify glibc random() sequence with seed 42.
        // These values were captured from glibc 2.38 on x86_64-linux using srandom(42)/random().
        // Note: srand/rand use a different algorithm than srandom/random.
        let _guard = test_global_random_lock();
        srandom(42);
        let expected = [71876166i64, 708592740, 1483128881, 907283241, 442951012];
        for (i, &exp) in expected.iter().enumerate() {
            let got = random();
            assert_eq!(
                got, exp,
                "random()[{i}] with seed 42 mismatch: expected {exp}, got {got}"
            );
        }
    }
}
