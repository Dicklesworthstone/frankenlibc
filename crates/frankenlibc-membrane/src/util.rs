//! Shared utilities for the membrane crate.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::{
    RwLock as StdRwLock, RwLockReadGuard as StdRwLockReadGuard,
    RwLockWriteGuard as StdRwLockWriteGuard, TryLockError,
};

// Controller math must not resolve through the C ABI that this library
// interposes: std's f64 transcendentals can call math_abi and change errno.
// These are the same pure-Rust algorithms used by frankenlibc-core, with no
// libc calls or errno writes. RuntimeMathKernel's floating-environment guard
// separately preserves the caller's rounding mode and sticky exception flags.
pub(crate) use libm::{
    acos as acos_f64, exp as exp_f64, log as ln_f64, log1p as ln_1p_f64, log2 as log2_f64,
    pow as pow_f64,
};

/// Deterministic, integer-fast hasher for the crate's internal maps.
///
/// Was `#[cfg(feature = "owned-tls-cache")]`, so the DEPLOYED build (which does not enable
/// that feature) fell back to `RandomState`/SipHash. Attribution of hardened `strlen` put
/// `RandomState::hash_one::<&usize>` at 84 Ir plus `Sip13Rounds::write` at 56 and the map
/// access at 81 — ~221 of 2,178 Ir, about 10% of the entry — to hash a page number. SipHash
/// buys HashDoS resistance against attacker-chosen keys; the only hot user is
/// `PageOracle::l2_maps`, whose keys are internally derived page addresses, so that
/// resistance is not doing anything here. The crate already sanctioned this hasher behind a
/// feature flag; making it unconditional also makes the maps' iteration order deterministic,
/// which is what the `Artifact`/`Deterministic` naming was after in the first place.
#[derive(Clone)]
pub(crate) struct DeterministicHasher {
    state: u64,
}

impl Default for DeterministicHasher {
    fn default() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

impl Hasher for DeterministicHasher {
    /// Integer keys take a closed-form mix instead of the byte loop below. `usize`'s `Hash`
    /// calls `write_usize`, which by default forwards to `write(&i.to_ne_bytes())` — eight
    /// iterations of xor-multiply to hash one word. This is the splitmix64 finalizer: two
    /// multiplies and three xor-shifts, no loop.
    #[inline]
    fn write_usize(&mut self, i: usize) {
        self.write_u64(i as u64);
    }

    #[inline]
    fn write_u64(&mut self, i: u64) {
        let mut z = i ^ self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        self.state = z ^ (z >> 31);
    }

    #[inline]
    fn write_u32(&mut self, i: u32) {
        self.write_u64(u64::from(i));
    }

    /// Byte path, retained unchanged for the `String`-keyed evidence-ledger map.
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        const PRIME: u64 = 0x0000_0100_0000_01b3;
        for byte in bytes {
            self.state ^= u64::from(*byte);
            self.state = self.state.wrapping_mul(PRIME);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

type ArtifactBuildHasher = BuildHasherDefault<DeterministicHasher>;

pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V, ArtifactBuildHasher>;

#[inline]
pub(crate) fn artifact_hash_map<K, V>() -> ArtifactHashMap<K, V> {
    ArtifactHashMap::default()
}

/// Kernel thread identity, without allocation, errno writes or compiler TLS.
///
/// Native clones may share a host TLS pointer, and evidence can be recorded
/// after Rust has destroyed its thread handle. Neither a Rust `ThreadId` nor a
/// stack address identifies those callers correctly. Zero denotes an
/// unavailable identity if a syscall filter rejects `gettid`.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[inline]
#[allow(unsafe_code)]
pub(crate) fn current_thread_id_u64() -> u64 {
    let tid: usize;
    // SAFETY: gettid takes no arguments and accesses no user memory. Calling
    // the kernel directly cannot reenter an interposed ABI or touch host TLS.
    unsafe {
        #[cfg(target_arch = "x86_64")]
        std::arch::asm!(
            "syscall",
            inlateout("rax") 186usize => tid,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
        #[cfg(target_arch = "aarch64")]
        std::arch::asm!(
            "svc 0",
            in("x8") 178usize,
            lateout("x0") tid,
            options(nostack),
        );
    }
    u64::try_from(tid as isize).unwrap_or(0)
}

/// Stable Rust thread identity on targets without the native Linux boundary.
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[inline]
pub(crate) fn current_thread_id_u64() -> u64 {
    use std::hash::Hash;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::thread::current().id().hash(&mut hasher);
    hasher.finish()
}

/// Back off under contention without linking Rust thread TLS in owned-TLS artifacts.
#[inline]
pub(crate) fn contention_backoff() {
    #[cfg(feature = "owned-tls-cache")]
    {
        std::hint::spin_loop();
    }

    #[cfg(not(feature = "owned-tls-cache"))]
    {
        std::thread::yield_now();
    }
}

/// Incremented in a forked child (see [`note_fork_child`]). A mutex whose
/// holder stamped an older generation is held by a thread of the parent
/// process, which does not exist in the child.
static FORK_GENERATION: AtomicU32 = AtomicU32::new(0);

/// Called by the fork path in the child, immediately after the clone and
/// before anything else runs (bd-rc0923-epic-eeuy4f.5).
///
/// Every membrane lock another thread held at the instant of the clone stays
/// held in the child, whose single thread would then block forever on its
/// first validation. With the generation bumped, such orphaned locks are
/// taken over by the next locker instead.
pub fn note_fork_child() {
    FORK_GENERATION.fetch_add(1, Ordering::AcqRel);
}

mod fork_mutex;
pub(crate) use fork_mutex::{NoPoisonMutex, NoPoisonMutexGuard};

/// Private FUTEX_WAIT on `word` while it equals `expected`. The membrane has
/// no libc or core dependency, so the syscall is issued directly.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
fn futex_wait(word: &AtomicU32, expected: u32) {
    const FUTEX_WAIT_PRIVATE: usize = 128;
    // SAFETY: futex on a live, aligned u32 with a null timeout; the kernel
    // only reads the word.
    unsafe {
        futex_syscall(
            word.as_ptr() as usize,
            FUTEX_WAIT_PRIVATE,
            expected as usize,
        )
    };
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
fn futex_wake_one(word: &AtomicU32) {
    const FUTEX_WAKE_PRIVATE: usize = 129;
    // SAFETY: futex wake on a live, aligned u32.
    unsafe { futex_syscall(word.as_ptr() as usize, FUTEX_WAKE_PRIVATE, 1) };
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
unsafe fn futex_syscall(uaddr: usize, op: usize, val: usize) {
    const SYS_FUTEX: usize = 202;
    // SAFETY: raw futex syscall; arguments are validated by the callers.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") SYS_FUTEX => _,
            in("rdi") uaddr,
            in("rsi") op,
            in("rdx") val,
            in("r10") 0usize,
            in("r8") 0usize,
            in("r9") 0usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[allow(unsafe_code)]
unsafe fn futex_syscall(uaddr: usize, op: usize, val: usize) {
    const SYS_FUTEX: usize = 98;
    // SAFETY: raw futex syscall; arguments are validated by the callers.
    unsafe {
        std::arch::asm!(
            "svc 0",
            in("x8") SYS_FUTEX,
            inlateout("x0") uaddr => _,
            in("x1") op,
            in("x2") val,
            in("x3") 0usize,
            in("x4") 0usize,
            in("x5") 0usize,
            options(nostack),
        );
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn futex_wait(_word: &AtomicU32, _expected: u32) {
    std::thread::yield_now();
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn futex_wake_one(_word: &AtomicU32) {}

/// RwLock wrapper that recovers poisoned locks instead of panicking.
#[derive(Debug)]
pub(crate) struct NoPoisonRwLock<T>(StdRwLock<T>);

pub(crate) type NoPoisonRwLockReadGuard<'a, T> = StdRwLockReadGuard<'a, T>;
pub(crate) type NoPoisonRwLockWriteGuard<'a, T> = StdRwLockWriteGuard<'a, T>;

impl<T> NoPoisonRwLock<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(StdRwLock::new(value))
    }

    pub(crate) fn read(&self) -> NoPoisonRwLockReadGuard<'_, T> {
        match self.0.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn write(&self) -> NoPoisonRwLockWriteGuard<'_, T> {
        match self.0.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn try_write(&self) -> Option<NoPoisonRwLockWriteGuard<'_, T>> {
        match self.0.try_write() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

/// Heap value built on first use, without ever blocking.
///
/// Racing initializers each build a value; one installs its pointer and the
/// others drop theirs. `OnceLock` instead parks losers on a futex, and a fork
/// taken while its initializer runs leaves the child's cell stuck "running"
/// forever (the hazard `NoPoisonMutex` is fork-aware against).
pub struct LazyBox<T> {
    ptr: AtomicPtr<T>,
}

// SAFETY: the pointee is shared by reference across threads once installed,
// and moved with the box: the usual `Box<T>` + `&T` sharing bounds.
#[allow(unsafe_code)]
unsafe impl<T: Send + Sync> Sync for LazyBox<T> {}
// SAFETY: as above.
#[allow(unsafe_code)]
unsafe impl<T: Send> Send for LazyBox<T> {}

impl<T> LazyBox<T> {
    pub const fn new() -> Self {
        Self {
            ptr: AtomicPtr::new(std::ptr::null_mut()),
        }
    }

    /// Already initialized with `value`.
    pub fn new_with(value: T) -> Self {
        Self {
            ptr: AtomicPtr::new(Box::into_raw(Box::new(value))),
        }
    }

    /// Exclusive access to the value, if initialized.
    #[allow(unsafe_code)]
    pub fn get_mut(&mut self) -> Option<&mut T> {
        let ptr = *self.ptr.get_mut();
        // SAFETY: `&mut self` excludes every other reference to the pointee;
        // the pointer came from `Box::into_raw`.
        (!ptr.is_null()).then(|| unsafe { &mut *ptr })
    }

    #[allow(unsafe_code)]
    pub fn get(&self) -> Option<&T> {
        let ptr = self.ptr.load(Ordering::Acquire);
        // SAFETY: a non-null pointer came from `Box::into_raw` in
        // `get_or_init`; normal execution keeps it installed until `drop`.
        // The child-only replacement contract separately excludes live refs.
        (!ptr.is_null()).then(|| unsafe { &*ptr })
    }

    #[allow(unsafe_code)]
    pub fn get_or_init(&self, init: impl FnOnce() -> T) -> &T {
        if let Some(value) = self.get() {
            return value;
        }
        let fresh = Box::into_raw(Box::new(init()));
        match self.ptr.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            // SAFETY: `fresh` is now installed and remains live during normal
            // execution; the child-only replacement contract excludes refs.
            Ok(_) => unsafe { &*fresh },
            Err(installed) => {
                // SAFETY: `fresh` lost the race and was never shared.
                drop(unsafe { Box::from_raw(fresh) });
                // SAFETY: as in `get`.
                unsafe { &*installed }
            }
        }
    }

    /// Initialize without aborting if either construction or the owning box
    /// cannot allocate. A failed attempt leaves the cell available for retry.
    ///
    /// As with `get_or_init`, initializers never wait for one another. A
    /// concurrent or reentrant initializer can still install a usable value
    /// while this attempt fails, so check for that winner before returning.
    #[allow(unsafe_code)]
    pub fn get_or_try_init(&self, init: impl FnOnce() -> Option<T>) -> Option<&T> {
        if let Some(value) = self.get() {
            return Some(value);
        }
        let Some(value) = init() else {
            return self.get();
        };
        let Ok(value) = Box::try_new(value) else {
            return self.get();
        };
        let fresh = Box::into_raw(value);
        let installed = match self.ptr.compare_exchange(
            std::ptr::null_mut(),
            fresh,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => fresh,
            Err(installed) => {
                // SAFETY: `fresh` lost the race and was never shared.
                drop(unsafe { Box::from_raw(fresh) });
                installed
            }
        };
        // SAFETY: the winning pointer came from `Box::into_raw` and remains
        // installed until drop; child-only replacement excludes live refs.
        Some(unsafe { &*installed })
    }

    /// Replace an initialized value in the single-threaded child immediately
    /// after `fork`.
    ///
    /// # Safety
    ///
    /// The caller must be executing in the freshly forked child before it has
    /// created any threads, and the surviving thread must not hold a reference
    /// returned by this `LazyBox`. References held by vanished parent threads
    /// do not exist in the child's address space execution state. These
    /// conditions make it safe to reclaim the inherited value after the atomic
    /// replacement.
    #[allow(unsafe_code)]
    pub unsafe fn replace_in_fork_child(&self, value: T) {
        let fresh = Box::into_raw(Box::new(value));
        let inherited = self.ptr.swap(fresh, Ordering::AcqRel);
        if !inherited.is_null() {
            // SAFETY: the child-only contract above excludes live references
            // in the surviving thread; `inherited` came from `Box::into_raw`.
            drop(unsafe { Box::from_raw(inherited) });
        }
    }
}

impl<T> Default for LazyBox<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Drop for LazyBox<T> {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        let ptr = *self.ptr.get_mut();
        if !ptr.is_null() {
            // SAFETY: exclusive access; the pointer came from `Box::into_raw`.
            drop(unsafe { Box::from_raw(ptr) });
        }
    }
}

/// Convert a Unix timestamp (days since 1970-01-01) to a civil date (year, month, day).
///
/// Uses Howard Hinnant's algorithm for efficient conversion without loops.
#[must_use]
pub fn civil_date_from_unix_days(days_since_unix_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_unix_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    let year = year + if month <= 2 { 1 } else { 0 };
    (year, month as u32, day as u32)
}

/// Returns the current UTC time in a standard ISO-like format: `YYYY-MM-DDTHH:MM:SS.mmmZ`.
///
/// This implementation is zero-dependency and safe for use in reentrant contexts.
#[must_use]
pub fn now_utc_iso_like() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let millis = duration.subsec_millis();
    let days = (secs / 86_400) as i64;
    let seconds_of_day = secs % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60,
        millis,
    )
}

/// Bitwise IEEE-754 truncation toward zero without emitting a `trunc@PLT` call
/// on baseline x86-64 (which lacks SSE4.1 `roundsd`; bd-rc0923-epic-eeuy4f.29).
#[inline]
#[must_use]
pub fn trunc_f64(x: f64) -> f64 {
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7ff) as i32 - 1023;
    if exp < 0 {
        return f64::from_bits(bits & (1u64 << 63));
    }
    if exp >= 52 {
        return x;
    }
    let mask = (1u64 << (52 - exp)) - 1;
    f64::from_bits(bits & !mask)
}

/// Bitwise IEEE-754 floor toward `-inf` without emitting a `floor@PLT` call on
/// baseline x86-64 (bd-rc0923-epic-eeuy4f.29).
#[inline]
#[must_use]
pub fn floor_f64(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let t = trunc_f64(x);
    if x < t { t - 1.0 } else { t }
}

/// Bitwise IEEE-754 ceil toward `+inf` without emitting a `ceil@PLT` call on
/// baseline x86-64 (bd-rc0923-epic-eeuy4f.29).
#[inline]
#[must_use]
pub fn ceil_f64(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let t = trunc_f64(x);
    if x > t { t + 1.0 } else { t }
}

/// Bitwise IEEE-754 round-half-away-from-zero without emitting a `round@PLT`
/// call on baseline x86-64 (bd-rc0923-epic-eeuy4f.29).
#[inline]
#[must_use]
pub fn round_f64(x: f64) -> f64 {
    if !x.is_finite() {
        return x;
    }
    let t = trunc_f64(x);
    let rem = (x - t).abs();
    if rem >= 0.5 {
        if x.is_sign_negative() {
            t - 1.0
        } else {
            t + 1.0
        }
    } else {
        t
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LazyBox, acos_f64, ceil_f64, exp_f64, floor_f64, ln_1p_f64, ln_f64, log2_f64, pow_f64,
        round_f64, trunc_f64,
    };
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counted(Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn assert_math_close(actual: f64, expected: f64, operation: &str, input: f64) {
        if expected.is_nan() {
            assert!(actual.is_nan(), "{operation}({input}) must be NaN");
            return;
        }
        if actual.to_bits() == expected.to_bits() {
            return;
        }
        assert!(
            actual.is_finite() && expected.is_finite(),
            "{operation}({input})"
        );
        let ordered = |value: f64| {
            let bits = value.to_bits();
            if value.is_sign_negative() {
                !bits
            } else {
                bits | (1 << 63)
            }
        };
        let ulps = ordered(actual).abs_diff(ordered(expected));
        assert!(
            ulps <= 4,
            "{operation}({input}): {actual} vs {expected} differ by {ulps} ULP",
        );
    }

    #[test]
    fn policy_math_matches_host_reference_across_dynamic_range() {
        let boundary = [
            f64::from_bits(1),
            f64::from_bits((1 << 52) - 1),
            f64::MIN_POSITIVE,
            1.0 - f64::EPSILON,
            1.0,
            1.0 + f64::EPSILON,
            f64::MAX,
            0.0,
            -0.0,
            -1.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ];
        for x in boundary {
            let x = std::hint::black_box(x);
            assert_math_close(ln_f64(x), x.ln(), "ln", x);
            assert_math_close(log2_f64(x), x.log2(), "log2", x);
            assert_math_close(ln_1p_f64(x), x.ln_1p(), "ln_1p", x);
            assert_math_close(exp_f64(x), x.exp(), "exp", x);
            assert_math_close(acos_f64(x), x.acos(), "acos", x);
        }

        // Deterministic mantissas throughout the positive binary exponent range
        // and controller-sized exp/acos/pow domains, against the host libm.
        let mut state = 0xa496_379c_4d20_a12bu64;
        for exponent in 1..2047u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let positive = f64::from_bits((exponent << 52) | (state & ((1 << 52) - 1)));
            assert_math_close(ln_f64(positive), positive.ln(), "ln", positive);
            assert_math_close(log2_f64(positive), positive.log2(), "log2", positive);
            let fraction = (state >> 11) as f64 / ((1u64 << 53) as f64);
            let signed = 2.0 * fraction - 1.0;
            let exp_input = fraction * 1440.0 - 740.0;
            assert_math_close(exp_f64(exp_input), exp_input.exp(), "exp", exp_input);
            assert_math_close(ln_1p_f64(signed), signed.ln_1p(), "ln_1p", signed);
            assert_math_close(acos_f64(signed), signed.acos(), "acos", signed);
            let base = 0.01 + 100.0 * fraction;
            assert_math_close(pow_f64(base, 4.0 / 3.0), base.powf(4.0 / 3.0), "pow", base);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn policy_math_preserves_errno_at_underflow_and_domain_boundaries() {
        struct RestoreErrno(*mut i32, i32);
        impl Drop for RestoreErrno {
            fn drop(&mut self) {
                // SAFETY: this pointer is the current test thread's errno slot.
                unsafe { self.0.write(self.1) };
            }
        }
        // SAFETY: libc supplies the calling thread's valid errno cell.
        let errno = unsafe { libc::__errno_location() };
        let _restore = RestoreErrno(errno, unsafe { errno.read() });
        let cases: [(fn(f64) -> f64, f64); 7] = [
            (exp_f64, -1000.0),
            (exp_f64, 1000.0),
            (ln_f64, 0.0),
            (ln_f64, -1.0),
            (log2_f64, -1.0),
            (ln_1p_f64, -1.0),
            (acos_f64, 2.0),
        ];
        for sentinel in [0, libc::EACCES] {
            for (operation, input) in cases {
                // SAFETY: the errno cell belongs to this thread.
                unsafe { errno.write(sentinel) };
                std::hint::black_box(operation(std::hint::black_box(input)));
                assert_eq!(unsafe { errno.read() }, sentinel);
            }
            unsafe { errno.write(sentinel) };
            std::hint::black_box(pow_f64(std::hint::black_box(-1.0), 0.5));
            assert_eq!(unsafe { errno.read() }, sentinel);
        }
    }

    #[test]
    fn lazy_box_builds_once_and_racers_drop_their_losing_values() {
        let drops = Arc::new(AtomicUsize::new(0));
        let builds = Arc::new(AtomicUsize::new(0));
        let lazy = Arc::new(LazyBox::<Counted>::new());
        assert!(lazy.get().is_none());

        let barrier = Arc::new(std::sync::Barrier::new(8));
        let winners: Vec<usize> = (0..8)
            .map(|_| {
                let (lazy, drops, builds, barrier) =
                    (lazy.clone(), drops.clone(), builds.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    let value = lazy.get_or_init(|| {
                        builds.fetch_add(1, Ordering::SeqCst);
                        Counted(drops)
                    });
                    value as *const Counted as usize
                })
            })
            // Spawn ALL eight before joining any: chained lazily, the first
            // thread was joined before the second existed and waited at the
            // 8-party barrier forever.
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        assert!(winners.iter().all(|ptr| *ptr == winners[0]));
        assert_eq!(
            lazy.get().map(|v| v as *const Counted as usize),
            Some(winners[0])
        );
        let built = builds.load(Ordering::SeqCst);
        assert!(built >= 1);
        assert_eq!(
            drops.load(Ordering::SeqCst),
            built - 1,
            "every loser dropped"
        );

        drop(Arc::try_unwrap(lazy).ok().expect("sole owner"));
        assert_eq!(drops.load(Ordering::SeqCst), built, "winner freed on drop");
    }

    #[test]
    fn fallible_lazy_box_retries_and_accepts_a_reentrant_winner() {
        let lazy = LazyBox::<usize>::new();
        assert!(lazy.get_or_try_init(|| None).is_none());
        assert!(lazy.get().is_none());
        let value = lazy.get_or_try_init(|| {
            assert_eq!(lazy.get_or_try_init(|| Some(17)), Some(&17));
            // An outer initializer can fail after reentry installed a value.
            None
        });
        assert_eq!(value, Some(&17));
        assert_eq!(
            lazy.get_or_try_init(|| panic!("initialized cell must not rebuild")),
            Some(&17)
        );
    }

    #[test]
    fn fallible_lazy_box_racers_drop_all_losing_values() {
        let drops = Arc::new(AtomicUsize::new(0));
        let lazy = Arc::new(LazyBox::<Counted>::new());
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8)
            .map(|_| {
                let (lazy, drops, barrier) = (lazy.clone(), drops.clone(), barrier.clone());
                std::thread::spawn(move || {
                    let value = lazy
                        .get_or_try_init(|| {
                            // All eight initializers have entered before any
                            // can publish, so every losing value must be freed.
                            barrier.wait();
                            Some(Counted(drops))
                        })
                        .expect("ordinary allocation");
                    value as *const Counted as usize
                })
            })
            .collect();
        let winners: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(winners.iter().all(|ptr| *ptr == winners[0]));
        assert_eq!(drops.load(Ordering::SeqCst), 7);
        drop(Arc::try_unwrap(lazy).ok().expect("sole owner"));
        assert_eq!(drops.load(Ordering::SeqCst), 8);
    }

    #[test]
    #[allow(unsafe_code)]
    fn lazy_box_fork_child_replacement_drops_inherited_value() {
        let drops = Arc::new(AtomicUsize::new(0));
        let lazy = LazyBox::new_with(Counted(drops.clone()));

        // SAFETY: this single-threaded test models the freshly forked child;
        // it holds no reference returned by `lazy` across the replacement.
        unsafe { lazy.replace_in_fork_child(Counted(drops.clone())) };
        assert_eq!(drops.load(Ordering::SeqCst), 1, "inherited value dropped");

        drop(lazy);
        assert_eq!(drops.load(Ordering::SeqCst), 2, "replacement dropped");
    }

    #[test]
    fn bitwise_f64_rounding_helpers_match_ieee754() {
        let samples = [
            0.0,
            -0.0,
            0.25,
            -0.25,
            0.5,
            -0.5,
            0.499_999_999_999_999_94,
            -0.499_999_999_999_999_94,
            1.0,
            -1.0,
            1.5,
            -1.5,
            2.5,
            -2.5,
            12.8,
            -12.8,
            4_503_599_627_370_495.5,
            -4_503_599_627_370_495.5,
            4_503_599_627_370_496.0,
            f64::INFINITY,
            f64::NEG_INFINITY,
        ];
        for x in samples {
            assert_eq!(trunc_f64(x).to_bits(), x.trunc().to_bits(), "trunc({x})");
            assert_eq!(floor_f64(x).to_bits(), x.floor().to_bits(), "floor({x})");
            assert_eq!(ceil_f64(x).to_bits(), x.ceil().to_bits(), "ceil({x})");
            assert_eq!(round_f64(x).to_bits(), x.round().to_bits(), "round({x})");
        }
        assert!(trunc_f64(f64::NAN).is_nan());
        assert!(floor_f64(f64::NAN).is_nan());
        assert!(ceil_f64(f64::NAN).is_nan());
        assert!(round_f64(f64::NAN).is_nan());
    }
}
