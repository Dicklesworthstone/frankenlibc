//! Packed semaphore state shared by the C ABI and native runtime.
//!
//! One atomic word contains the token count (low 32 bits) and registered
//! waiters (high 32 bits). Publishing a token also observes whether a wake is
//! necessary. A successful slow acquisition removes its registration in that
//! same transition: neither side needs to touch storage after handing it off.
use core::sync::atomic::{AtomicU64, Ordering};

pub const MAX_VALUE: u32 = i32::MAX as u32;
const WAITER: u64 = 1 << 32;

#[repr(transparent)]
pub struct SemaphoreState(AtomicU64);

impl SemaphoreState {
    pub const fn new(value: u32) -> Option<Self> {
        if value <= MAX_VALUE {
            Some(Self(AtomicU64::new(value as u64)))
        } else {
            None
        }
    }

    #[inline]
    pub fn value(&self) -> u32 {
        self.0.load(Ordering::Relaxed) as u32
    }

    #[inline]
    pub fn waiter_count(&self) -> u32 {
        (self.0.load(Ordering::Relaxed) >> 32) as u32
    }

    /// None means overflow, with no state change. Some(true) carries the
    /// wake decision made before another thread can consume the last token.
    #[inline]
    pub fn post(&self) -> Option<bool> {
        let mut old = self.0.load(Ordering::Relaxed);
        loop {
            if old as u32 >= MAX_VALUE {
                return None;
            }
            match self
                .0
                .compare_exchange_weak(old, old + 1, Ordering::Release, Ordering::Relaxed)
            {
                Ok(_) => return Some(old >> 32 != 0),
                Err(current) => old = current,
            }
        }
    }

    #[inline]
    fn take(&self, registered: bool) -> bool {
        let mut old = self.0.load(Ordering::Relaxed);
        loop {
            if old as u32 == 0 {
                return false;
            }
            let new = old - 1 - if registered { WAITER } else { 0 };
            match self
                .0
                .compare_exchange_weak(old, new, Ordering::Acquire, Ordering::Relaxed)
            {
                Ok(_) => return true,
                Err(current) => old = current,
            }
        }
    }

    #[inline]
    pub fn try_acquire(&self) -> bool {
        self.take(false)
    }

    /// Register before retrying acquisition. All token publications and
    /// registrations modify the same atomic word, eliminating split-counter
    /// missed wakes without imposing SeqCst on the uncontended fast path.
    #[inline]
    pub fn register(&self) -> Option<SemaphoreWaiter<'_>> {
        self.0
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
                old.checked_add(WAITER)
            })
            .ok()?;
        Some(SemaphoreWaiter {
            state: self,
            active: true,
        })
    }
}

pub struct SemaphoreWaiter<'a> {
    state: &'a SemaphoreState,
    active: bool,
}

impl SemaphoreWaiter<'_> {
    #[inline]
    pub fn try_acquire(&mut self) -> bool {
        if self.active && self.state.take(true) {
            self.active = false;
            true
        } else {
            false
        }
    }
}

impl Drop for SemaphoreWaiter<'_> {
    #[inline]
    fn drop(&mut self) {
        if self.active {
            self.state.0.fetch_sub(WAITER, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn packed_layout_and_initial_bounds() {
        assert_eq!(core::mem::size_of::<SemaphoreState>(), 8);
        assert_eq!(
            core::mem::align_of::<SemaphoreState>(),
            core::mem::align_of::<AtomicU64>()
        );
        assert!(SemaphoreState::new(u32::MAX).is_none());
        let state = SemaphoreState::new(MAX_VALUE).unwrap();
        assert_eq!(state.value(), MAX_VALUE);
        assert_eq!(state.waiter_count(), 0);
        assert_eq!(state.post(), None);
        assert!(state.try_acquire());
        assert_eq!(state.post(), Some(false));
        assert_eq!(state.value(), MAX_VALUE);
    }

    #[test]
    fn wake_witness_and_acquisition_are_single_transitions() {
        let state = SemaphoreState::new(0).unwrap();
        let mut first = state.register().unwrap();
        let second = state.register().unwrap();
        assert!(!first.try_acquire());
        assert_eq!(state.waiter_count(), 2);
        assert_eq!(state.post(), Some(true));
        assert!(first.try_acquire());
        assert_eq!(state.0.load(Ordering::Relaxed), WAITER);
        assert!(!first.try_acquire());
        drop(first);
        assert_eq!(state.waiter_count(), 1);
        drop(second);
        assert_eq!(state.0.load(Ordering::Relaxed), 0);
        assert_eq!(state.post(), Some(false));
    }

    #[test]
    fn cancellation_and_timeout_cleanup_preserve_tokens() {
        let state = SemaphoreState::new(0).unwrap();
        let waiter = state.register().unwrap();
        assert_eq!(state.post(), Some(true));
        drop(waiter);
        assert_eq!(state.0.load(Ordering::Relaxed), 1);
        assert!(state.try_acquire());
        assert!(!state.try_acquire());
    }

    #[test]
    fn registration_exhaustion_cannot_wrap_tokens() {
        let state = SemaphoreState(AtomicU64::new((u32::MAX as u64) << 32 | 7));
        assert!(state.register().is_none());
        assert_eq!(state.value(), 7);
        assert_eq!(state.waiter_count(), u32::MAX);
    }

    #[test]
    fn overflowing_posters_never_publish_an_invalid_value() {
        let state = Arc::new(SemaphoreState::new(MAX_VALUE).unwrap());
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let state = state.clone();
                scope.spawn(move || {
                    for _ in 0..50_000 {
                        assert_eq!(state.post(), None);
                    }
                });
            }
            for _ in 0..50_000 {
                assert_eq!(state.value(), MAX_VALUE);
            }
        });
        assert_eq!(state.waiter_count(), 0);
    }

    #[test]
    fn contended_token_conservation_and_registration_cleanup() {
        let state = SemaphoreState::new(0).unwrap();
        let gate = Barrier::new(8);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    gate.wait();
                    for _ in 0..10_000 {
                        assert!(state.post().is_some());
                    }
                });
                scope.spawn(|| {
                    gate.wait();
                    for _ in 0..10_000 {
                        if !state.try_acquire() {
                            let mut waiter = state.register().unwrap();
                            while !waiter.try_acquire() {
                                std::thread::yield_now();
                            }
                        }
                    }
                });
            }
        });
        assert_eq!(state.value(), 0);
        assert_eq!(state.waiter_count(), 0);
    }
}
