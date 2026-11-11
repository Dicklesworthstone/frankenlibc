//! Shared utilities for the membrane crate.

use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use std::sync::{
    RwLock as StdRwLock, RwLockReadGuard as StdRwLockReadGuard,
    RwLockWriteGuard as StdRwLockWriteGuard, TryLockError,
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

    pub(crate) fn try_read(&self) -> Option<NoPoisonRwLockReadGuard<'_, T>> {
        match self.0.try_read() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
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

const LN2_HI: f64 = f64::from_bits(0x3fe6_2e42_fee0_0000);
const LN2_LO: f64 = f64::from_bits(0x3dea_39ef_3579_3c76);
const INV_LN2: f64 = f64::from_bits(0x3ff7_1547_652b_82fe);
const INV_LN2_HI: f64 = f64::from_bits(0x3ff7_1547_6500_0000);
const INV_LN2_LO: f64 = f64::from_bits(0x3e05_c17f_0bbb_e880);
const SQRT2: f64 = f64::from_bits(0x3ff6_a09e_667f_3bcd);

const LG1: f64 = f64::from_bits(0x3fe5_5555_5555_5593);
const LG2: f64 = f64::from_bits(0x3fd9_9999_9997_fa04);
const LG3: f64 = f64::from_bits(0x3fd2_4924_9422_9359);
const LG4: f64 = f64::from_bits(0x3fcc_71c5_1d8e_78af);
const LG5: f64 = f64::from_bits(0x3fc7_4664_96cb_03de);
const LG6: f64 = f64::from_bits(0x3fc3_9a09_d078_c69f);
const LG7: f64 = f64::from_bits(0x3fc2_f112_df3e_5244);

#[inline]
fn ln_poly_tail(f: f64) -> (f64, f64, f64) {
    let s = f / (2.0 + f);
    let hfsq = 0.5 * f * f;
    let z = s * s;
    let w = z * z;
    let t1 = w * (LG2 + w * (LG4 + w * LG6));
    let t2 = z * (LG1 + w * (LG3 + w * (LG5 + w * LG7)));
    (s, hfsq, t2 + t1)
}

#[inline]
fn ln_decompose_positive(x: f64) -> (i32, f64, f64, f64, f64) {
    let mut bits = x.to_bits();
    let mut k = 0i32;
    if (bits & 0x7ff0_0000_0000_0000) == 0 {
        // Normalize positive subnormal by multiplying by 2^54.
        bits = (x * f64::from_bits(0x4350_0000_0000_0000)).to_bits();
        k -= 54;
    }
    k += ((bits >> 52) & 0x7ff) as i32 - 1023;
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    if m > SQRT2 {
        m *= 0.5;
        k += 1;
    }
    let f = m - 1.0;
    let (s, hfsq, r) = ln_poly_tail(f);
    (k, f, s, hfsq, r)
}

/// Pure-Rust IEEE-754 `exp(x)` (~0.9 ULP) with zero C `libm` relocations and zero
/// `errno` side effects under overflow/underflow (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn exp_f64(x: f64) -> f64 {
    const P1: f64 = f64::from_bits(0x3fc5_5555_5555_553e);
    const P2: f64 = f64::from_bits(0xbf66_c16c_16be_bd93);
    const P3: f64 = f64::from_bits(0x3f11_566a_af25_de2c);
    const P4: f64 = f64::from_bits(0xbebb_bd41_c5d2_6bf1);
    const P5: f64 = f64::from_bits(0x3e66_3769_72be_a4d0);

    if x.is_nan() {
        return f64::NAN;
    }
    if x > f64::from_bits(0x4086_2e42_fefa_39ef) {
        return f64::INFINITY;
    }
    if x <= f64::from_bits(0xc087_4910_d52d_3052) {
        return 0.0;
    }
    if x.abs() < f64::from_bits(0x3e30_0000_0000_0000) {
        return 1.0 + x;
    }

    let kf = round_f64(x * INV_LN2);
    let k = kf as i32;
    let hi = x - kf * LN2_HI;
    let lo = kf * LN2_LO;
    let r = hi - lo;
    let t = r * r;
    let c = r - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    let y = 1.0 - ((lo - (r * c) / (2.0 - c)) - hi);

    if k == 1024 {
        return (y * 2.0) * f64::from_bits(0x7fe0_0000_0000_0000);
    }
    if k >= -1021 {
        return y * f64::from_bits(((k + 1023) as u64) << 52);
    }
    (y * f64::from_bits(((k + 1023 + 54) as u64) << 52)) * f64::from_bits(0x3c90_0000_0000_0000)
}

/// Pure-Rust IEEE-754 `ln(x)` (~0.9 ULP) with zero C `libm` relocations and zero
/// `errno` side effects (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn ln_f64(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    if x == 1.0 {
        return 0.0;
    }
    let (k, f, s, hfsq, r) = ln_decompose_positive(x);
    if k == 0 {
        f - (hfsq - s * (hfsq + r))
    } else {
        let dk = f64::from(k);
        dk * LN2_HI - ((hfsq - (s * (hfsq + r) + dk * LN2_LO)) - f)
    }
}

/// Pure-Rust IEEE-754 `log2(x)` (~0.9 ULP) with zero C `libm` relocations and zero
/// `errno` side effects (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn log2_f64(x: f64) -> f64 {
    if x.is_nan() || x < 0.0 {
        return f64::NAN;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    if x == 1.0 {
        return 0.0;
    }
    let (k, f, s, hfsq, r) = ln_decompose_positive(x);
    let f_hi = f64::from_bits(f.to_bits() & 0xffff_ffff_f000_0000);
    let f_lo = (f - f_hi) + (s * (hfsq + r) - hfsq);
    let log2_1pf_hi = f_hi * INV_LN2_HI;
    let log2_1pf_lo = f_lo * INV_LN2 + f_hi * INV_LN2_LO;
    f64::from(k) + (log2_1pf_hi + log2_1pf_lo)
}

/// Pure-Rust IEEE-754 `ln(1 + x)` (~1.0 ULP) with zero C `libm` relocations and
/// zero `errno` side effects (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn ln_1p_f64(x: f64) -> f64 {
    if x.is_nan() || x < -1.0 {
        return f64::NAN;
    }
    if x == -1.0 {
        return f64::NEG_INFINITY;
    }
    if x == f64::INFINITY {
        return f64::INFINITY;
    }
    if x == 0.0 {
        return x;
    }
    let ax = x.abs();
    if ax < f64::from_bits(0x3c90_0000_0000_0000) {
        return x;
    }
    if ax < f64::from_bits(0x3e20_0000_0000_0000) {
        return x - 0.5 * x * x;
    }
    if x > -0.292_893_218_813_452_5 && x < 0.414_213_562_373_095_03 {
        let (s, hfsq, r) = ln_poly_tail(x);
        return x - (hfsq - s * (hfsq + r));
    }
    if x >= f64::from_bits(0x4340_0000_0000_0000) {
        return ln_f64(x);
    }

    let u = 1.0 + x;
    let corr = if x >= 1.0 {
        1.0 - (u - x)
    } else {
        x - (u - 1.0)
    };
    let bits = u.to_bits();
    let mut k = ((bits >> 52) & 0x7ff) as i32 - 1023;
    let mut m = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);
    let mut scale_exp = k;
    if m > SQRT2 {
        m *= 0.5;
        k += 1;
        scale_exp = k;
    }
    let c = if scale_exp >= -1021 && scale_exp <= 1023 {
        corr * f64::from_bits(((1023 - scale_exp) as u64) << 52) / m
    } else {
        corr / u
    };
    let f = m - 1.0;
    let (s, hfsq, r) = ln_poly_tail(f);
    if k == 0 {
        f - (hfsq - (s * (hfsq + r) + c))
    } else {
        let dk = f64::from(k);
        dk * LN2_HI - ((hfsq - (s * (hfsq + r) + (dk * LN2_LO + c))) - f)
    }
}

/// Pure-Rust IEEE-754 `acos(x)` (~0.9 ULP) using SSE2 `sqrtsd` and fdlibm rational
/// minimax, emitting zero C `libm` relocations and zero `errno` writes
/// (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn acos_f64(x: f64) -> f64 {
    const PIO2_HI: f64 = f64::from_bits(0x3ff9_21fb_5444_2d18);
    const PIO2_LO: f64 = f64::from_bits(0x3c91_a626_3314_5c07);
    const PI_HI: f64 = f64::from_bits(0x4009_21fb_5444_2d18);
    const PS0: f64 = f64::from_bits(0x3fc5_5555_5555_5555);
    const PS1: f64 = f64::from_bits(0xbfd4_d612_03eb_6f7d);
    const PS2: f64 = f64::from_bits(0x3fc9_c155_0e88_4455);
    const PS3: f64 = f64::from_bits(0xbfa4_8228_b568_8f3b);
    const PS4: f64 = f64::from_bits(0x3f49_efe0_7501_b288);
    const PS5: f64 = f64::from_bits(0x3f02_3de1_0dfd_f709);
    const QS1: f64 = f64::from_bits(0xc003_3a27_1c8a_2d4b);
    const QS2: f64 = f64::from_bits(0x4000_2ae5_9c59_8ac8);
    const QS3: f64 = f64::from_bits(0xbfe6_066c_1b8d_0159);
    const QS4: f64 = f64::from_bits(0x3fb3_b8c5_b12e_9282);

    if x.is_nan() || !(-1.0..=1.0).contains(&x) {
        return f64::NAN;
    }
    if x == 1.0 {
        return 0.0;
    }
    if x == -1.0 {
        return core::f64::consts::PI;
    }

    let ax = x.abs();
    if ax < 0.5 {
        if ax < f64::from_bits(0x3c60_0000_0000_0000) {
            return PIO2_HI + PIO2_LO;
        }
        let z = x * x;
        let p = z * (PS0 + z * (PS1 + z * (PS2 + z * (PS3 + z * (PS4 + z * PS5)))));
        let q = 1.0 + z * (QS1 + z * (QS2 + z * (QS3 + z * QS4)));
        let r = p / q;
        return PIO2_HI - (x - (PIO2_LO - x * r));
    }

    if x < 0.0 {
        let z = (1.0 + x) * 0.5;
        let p = z * (PS0 + z * (PS1 + z * (PS2 + z * (PS3 + z * (PS4 + z * PS5)))));
        let q = 1.0 + z * (QS1 + z * (QS2 + z * (QS3 + z * QS4)));
        let s = z.sqrt();
        let r = p / q;
        let w = r * s - PIO2_LO;
        PI_HI - 2.0 * (s + w)
    } else {
        let z = (1.0 - x) * 0.5;
        let s = z.sqrt();
        let df = f64::from_bits(s.to_bits() & 0xffff_ffff_0000_0000);
        let c = (z - df * df) / (s + df);
        let p = z * (PS0 + z * (PS1 + z * (PS2 + z * (PS3 + z * (PS4 + z * PS5)))));
        let q = 1.0 + z * (QS1 + z * (QS2 + z * (QS3 + z * QS4)));
        let r = p / q;
        let w = r * s + c;
        2.0 * (df + w)
    }
}

/// Pure-Rust integer exponentiation `base^exp` without `pow` / `llvm.powi` symbol
/// calls (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn powi_f64(base: f64, exp: i32) -> f64 {
    if exp == 0 {
        return 1.0;
    }
    if base.is_nan() {
        return f64::NAN;
    }
    let mut n = exp.unsigned_abs();
    let invert_after = exp < 0 && base.abs() < 1.0;
    let mut b = if exp < 0 && !invert_after {
        1.0 / base
    } else {
        base
    };
    let mut acc = 1.0_f64;
    while n != 0 {
        if (n & 1) != 0 {
            acc *= b;
        }
        n >>= 1;
        if n != 0 {
            b *= b;
        }
    }
    if invert_after { 1.0 / acc } else { acc }
}

/// Pure-Rust floating-point exponentiation `base^exp` (~1.0 ULP) using extended
/// `(hi, lo)` `exp(exp * ln(base))` decomposition with zero C `libm` calls and
/// zero `errno` writes (bd-reality-202609-lx578q.4.1).
#[inline]
#[must_use]
pub fn powf_f64(base: f64, exp: f64) -> f64 {
    if exp == 0.0 || base == 1.0 {
        return 1.0;
    }
    if base.is_nan() || exp.is_nan() {
        return f64::NAN;
    }
    if base == 0.0 {
        let odd_int = exp.is_finite()
            && trunc_f64(exp) == exp
            && trunc_f64(exp * 0.5) * 2.0 != exp;
        let sign = if base.is_sign_negative() && odd_int {
            -1.0
        } else {
            1.0
        };
        return if exp > 0.0 {
            0.0_f64.copysign(sign)
        } else {
            f64::INFINITY.copysign(sign)
        };
    }
    if !exp.is_finite() {
        let ab = base.abs();
        if ab == 1.0 {
            return 1.0;
        }
        return if (ab > 1.0) == exp.is_sign_positive() {
            f64::INFINITY
        } else {
            0.0
        };
    }
    if !base.is_finite() {
        if base.is_sign_positive() {
            return if exp > 0.0 { f64::INFINITY } else { 0.0 };
        }
        if trunc_f64(exp) != exp {
            return f64::NAN;
        }
        let odd_int = trunc_f64(exp * 0.5) * 2.0 != exp;
        let mag = if exp > 0.0 { f64::INFINITY } else { 0.0 };
        return if odd_int { -mag } else { mag };
    }

    let mut sign = 1.0_f64;
    let x = if base < 0.0 {
        if trunc_f64(exp) != exp {
            return f64::NAN;
        }
        if trunc_f64(exp * 0.5) * 2.0 != exp {
            sign = -1.0;
        }
        -base
    } else {
        base
    };

    if exp == 0.5 {
        return sign * x.sqrt();
    }
    if exp == 0.25 {
        return sign * x.sqrt().sqrt();
    }

    let (k, f, s, hfsq, r) = ln_decompose_positive(x);
    let dk = f64::from(k);
    let f_hi = f64::from_bits(f.to_bits() & 0xffff_ffff_f000_0000);
    let f_lo = (f - f_hi) + (s * (hfsq + r) - hfsq);
    let ln_hi_raw = dk * LN2_HI + f_hi;
    let ln_lo_raw = (dk * LN2_HI - ln_hi_raw + f_hi) + (dk * LN2_LO + f_lo);
    let ln_sum = ln_hi_raw + ln_lo_raw;
    let ln_hi = f64::from_bits(ln_sum.to_bits() & 0xffff_ffff_f000_0000);
    let ln_lo = (ln_hi_raw - ln_hi) + ln_lo_raw;

    let exp_hi = f64::from_bits(exp.to_bits() & 0xffff_ffff_f000_0000);
    let exp_lo = exp - exp_hi;
    let prod_hi = exp_hi * ln_hi;
    let prod_lo = exp_lo * ln_hi + exp * ln_lo;
    let z = prod_hi + prod_lo;

    if z > f64::from_bits(0x4086_2e42_fefa_39ef) {
        return sign * f64::INFINITY;
    }
    if z <= f64::from_bits(0xc087_4910_d52d_3052) {
        return 0.0_f64.copysign(sign);
    }

    // Apply prod_hi + prod_lo reduction directly so intermediate multiplication
    // rounding does not inflate ULP error at large exponents.
    let kf = round_f64(z * INV_LN2);
    let k_out = kf as i32;
    let hi = (prod_hi - kf * LN2_HI) + prod_lo;
    let lo = kf * LN2_LO;
    let rem = hi - lo;

    const P1: f64 = f64::from_bits(0x3fc5_5555_5555_553e);
    const P2: f64 = f64::from_bits(0xbf66_c16c_16be_bd93);
    const P3: f64 = f64::from_bits(0x3f11_566a_af25_de2c);
    const P4: f64 = f64::from_bits(0xbebb_bd41_c5d2_6bf1);
    const P5: f64 = f64::from_bits(0x3e66_3769_72be_a4d0);

    let t = rem * rem;
    let c = rem - t * (P1 + t * (P2 + t * (P3 + t * (P4 + t * P5))));
    let y = 1.0 - ((lo - (rem * c) / (2.0 - c)) - hi);
    let mag = if k_out == 1024 {
        (y * 2.0) * f64::from_bits(0x7fe0_0000_0000_0000)
    } else if k_out >= -1021 {
        y * f64::from_bits(((k_out + 1023) as u64) << 52)
    } else {
        (y * f64::from_bits(((k_out + 1023 + 54) as u64) << 52))
            * f64::from_bits(0x3c90_0000_0000_0000)
    };
    sign * mag
}

#[cfg(test)]
mod tests {
    use super::{LazyBox, ceil_f64, floor_f64, round_f64, trunc_f64};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counted(Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
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

    fn ulp_distance(a: f64, b: f64) -> u64 {
        if a == 0.0 && b == 0.0 {
            return 0;
        }
        let to_ordered = |x: f64| -> i64 {
            let bits = x.to_bits() as i64;
            if bits < 0 {
                i64::MIN - bits
            } else {
                bits
            }
        };
        to_ordered(a).abs_diff(to_ordered(b))
    }

    #[test]
    fn pure_rust_transcendentals_match_ieee754_within_two_ulp() {
        use super::{acos_f64, exp_f64, ln_1p_f64, ln_f64, log2_f64, powf_f64, powi_f64};

        let exp_inputs = [
            -800.0,
            -745.133_219_101_941_2,
            -744.44,
            -708.396_4,
            -100.0,
            -1.0,
            -1e-12,
            0.0,
            1e-12,
            0.693_147_180_559_945_3,
            1.0,
            10.5,
            709.78,
            709.782_712_893_384,
            800.0,
        ];
        for x in exp_inputs {
            let got = exp_f64(x);
            let want = x.exp();
            if want.is_infinite() {
                assert!(got.is_infinite() && got.is_sign_positive(), "exp({x})");
            } else {
                assert!(
                    ulp_distance(got, want) <= 2,
                    "exp({x}): got={got:e} want={want:e} ulp={}",
                    ulp_distance(got, want)
                );
            }
        }
        assert!(exp_f64(f64::NAN).is_nan());
        assert_eq!(exp_f64(f64::NEG_INFINITY), 0.0);
        assert_eq!(exp_f64(f64::INFINITY), f64::INFINITY);

        let pos_inputs = [
            f64::from_bits(1),
            1e-315,
            f64::MIN_POSITIVE,
            1e-100,
            1e-10,
            0.5,
            0.75,
            0.999_999_9,
            1.0,
            1.000_000_1,
            core::f64::consts::E,
            2.0,
            8.0,
            256.0,
            1e50,
            f64::MAX,
        ];
        for x in pos_inputs {
            let got_ln = ln_f64(x);
            let want_ln = x.ln();
            assert!(
                ulp_distance(got_ln, want_ln) <= 2,
                "ln({x:e}): got={got_ln} want={want_ln} ulp={}",
                ulp_distance(got_ln, want_ln)
            );
            let got_log2 = log2_f64(x);
            let want_log2 = x.log2();
            assert!(
                ulp_distance(got_log2, want_log2) <= 2,
                "log2({x:e}): got={got_log2} want={want_log2} ulp={}",
                ulp_distance(got_log2, want_log2)
            );
        }
        assert_eq!(ln_f64(0.0), f64::NEG_INFINITY);
        assert_eq!(log2_f64(0.0), f64::NEG_INFINITY);
        assert!(ln_f64(-1.0).is_nan());
        assert!(log2_f64(-1.0).is_nan());
        assert_eq!(ln_f64(f64::INFINITY), f64::INFINITY);
        assert_eq!(log2_f64(f64::INFINITY), f64::INFINITY);

        let ln1p_inputs = [
            -0.999_999_9,
            -0.5,
            -0.25,
            -1e-15,
            -0.0,
            0.0,
            1e-16,
            1e-8,
            0.125,
            0.5,
            1.0,
            100.0,
            1e20,
        ];
        for x in ln1p_inputs {
            let got = ln_1p_f64(x);
            let want = x.ln_1p();
            assert!(
                ulp_distance(got, want) <= 2,
                "ln_1p({x:e}): got={got:e} want={want:e} ulp={}",
                ulp_distance(got, want)
            );
        }
        assert_eq!(ln_1p_f64(-1.0), f64::NEG_INFINITY);
        assert!(ln_1p_f64(-1.5).is_nan());

        for i in -100..=100 {
            let x = f64::from(i) / 100.0;
            let got = acos_f64(x);
            let want = x.acos();
            assert!(
                ulp_distance(got, want) <= 2,
                "acos({x}): got={got} want={want} ulp={}",
                ulp_distance(got, want)
            );
        }
        assert!(acos_f64(1.000_001).is_nan());
        assert!(acos_f64(-1.000_001).is_nan());

        for k in [-1050, -63, -12, -1, 0, 1, 2, 16, 100] {
            let got = powi_f64(2.0, k);
            let want = 2.0_f64.powf(f64::from(k));
            assert!(
                ulp_distance(got, want) <= 1,
                "2.0.powi({k}): got={got:e} want={want:e}"
            );
        }

        let powf_cases = [
            (0.125, 0.25),
            (1.5, 4.0 / 3.0),
            (64.0, -2.0 / 3.0),
            (3.75, 2.25),
            (0.01, 0.5),
            (-2.0, 3.0),
            (-2.0, 4.0),
        ];
        for (b, e) in powf_cases {
            let got = powf_f64(b, e);
            let want = b.powf(e);
            assert!(
                ulp_distance(got, want) <= 2,
                "powf({b}, {e}): got={got} want={want} ulp={}",
                ulp_distance(got, want)
            );
        }
        assert!(powf_f64(-2.0, 0.5).is_nan());
    }
}
