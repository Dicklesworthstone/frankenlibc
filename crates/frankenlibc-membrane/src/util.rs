//! Shared utilities for the membrane crate.

use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::atomic::{AtomicU32, Ordering};
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

/// The membrane's mutex: never poisons, and survives `fork` from a
/// multithreaded parent (a lock held by a parent thread at the clone is taken
/// over in the child rather than waited on forever). A futex word: 0 free,
/// 1 held, 2 held with waiters; `holder_generation` is the fork generation the
/// current holder locked it in.
pub(crate) struct NoPoisonMutex<T> {
    state: AtomicU32,
    holder_generation: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: access to `value` is serialized by `state` (a guard exists only
// while the lock is held), exactly as for `std::sync::Mutex`.
#[allow(unsafe_code)]
unsafe impl<T: Send> Sync for NoPoisonMutex<T> {}
// SAFETY: as above.
#[allow(unsafe_code)]
unsafe impl<T: Send> Send for NoPoisonMutex<T> {}

impl<T> std::fmt::Debug for NoPoisonMutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoPoisonMutex").finish_non_exhaustive()
    }
}

/// Guard of a [`NoPoisonMutex`]; unlocks on drop.
pub(crate) struct NoPoisonMutexGuard<'a, T> {
    lock: &'a NoPoisonMutex<T>,
    /// Guards are not `Send`, like `std::sync::MutexGuard`.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl<T> NoPoisonMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            state: AtomicU32::new(0),
            holder_generation: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    fn guard(&self) -> NoPoisonMutexGuard<'_, T> {
        self.holder_generation
            .store(FORK_GENERATION.load(Ordering::Acquire), Ordering::Release);
        NoPoisonMutexGuard {
            lock: self,
            _not_send: std::marker::PhantomData,
        }
    }

    /// Take over a lock whose holder belongs to an earlier fork generation.
    fn try_take_orphan(&self) -> bool {
        let generation = FORK_GENERATION.load(Ordering::Acquire);
        let holder = self.holder_generation.load(Ordering::Acquire);
        holder != generation
            && self.state.load(Ordering::Acquire) != 0
            && self
                .holder_generation
                .compare_exchange(holder, generation, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
    }

    pub(crate) fn lock(&self) -> NoPoisonMutexGuard<'_, T> {
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return self.guard();
        }
        loop {
            if self.try_take_orphan() {
                return self.guard();
            }
            if self.state.swap(2, Ordering::Acquire) == 0 {
                return self.guard();
            }
            futex_wait(&self.state, 2);
        }
    }

    pub(crate) fn try_lock(&self) -> Option<NoPoisonMutexGuard<'_, T>> {
        if self
            .state
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
            || self.try_take_orphan()
        {
            Some(self.guard())
        } else {
            None
        }
    }
}

impl<T> std::ops::Deref for NoPoisonMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard proves the lock is held by this thread.
        #[allow(unsafe_code)]
        unsafe {
            &*self.lock.value.get()
        }
    }
}

impl<T> std::ops::DerefMut for NoPoisonMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the guard proves exclusive access.
        #[allow(unsafe_code)]
        unsafe {
            &mut *self.lock.value.get()
        }
    }
}

impl<T> Drop for NoPoisonMutexGuard<'_, T> {
    fn drop(&mut self) {
        if self.lock.state.swap(0, Ordering::Release) == 2 {
            futex_wake_one(&self.lock.state);
        }
    }
}

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
