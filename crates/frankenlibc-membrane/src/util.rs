//! Shared utilities for the membrane crate.

use std::collections::HashMap;
#[cfg(feature = "owned-tls-cache")]
use std::hash::{BuildHasherDefault, Hasher};
use std::sync::{
    Mutex as StdMutex, MutexGuard as StdMutexGuard, RwLock as StdRwLock,
    RwLockReadGuard as StdRwLockReadGuard, RwLockWriteGuard as StdRwLockWriteGuard, TryLockError,
};

#[cfg(feature = "owned-tls-cache")]
#[derive(Clone)]
pub(crate) struct DeterministicHasher {
    state: u64,
}

#[cfg(feature = "owned-tls-cache")]
impl Default for DeterministicHasher {
    fn default() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }
}

#[cfg(feature = "owned-tls-cache")]
impl Hasher for DeterministicHasher {
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

#[cfg(feature = "owned-tls-cache")]
type ArtifactBuildHasher = BuildHasherDefault<DeterministicHasher>;

#[cfg(feature = "owned-tls-cache")]
pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V, ArtifactBuildHasher>;
#[cfg(not(feature = "owned-tls-cache"))]
pub(crate) type ArtifactHashMap<K, V> = HashMap<K, V>;

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

/// Mutex wrapper that recovers poisoned locks instead of panicking.
#[derive(Debug)]
pub(crate) struct NoPoisonMutex<T>(StdMutex<T>);

pub(crate) type NoPoisonMutexGuard<'a, T> = StdMutexGuard<'a, T>;

impl<T> NoPoisonMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(StdMutex::new(value))
    }

    pub(crate) fn lock(&self) -> NoPoisonMutexGuard<'_, T> {
        match self.0.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn try_lock(&self) -> Option<NoPoisonMutexGuard<'_, T>> {
        match self.0.try_lock() {
            Ok(guard) => Some(guard),
            Err(TryLockError::Poisoned(poisoned)) => Some(poisoned.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }
}

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
