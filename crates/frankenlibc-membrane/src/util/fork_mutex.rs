//! Fork-aware mutex ownership is published in one atomic transition.
//!
//! Keeping the held bit and its fork generation in separate atomics allowed
//! a second child thread to steal a newly acquired lock before the first
//! owner stamped its generation. A guard also retains its generation so an
//! inherited guard cannot unlock a lock already taken over in the child.

use super::{FORK_GENERATION, futex_wait, futex_wake_one};
use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const UNLOCKED: u32 = 0;
const LOCKED: u32 = 1;
const CONTENDED: u32 = 2;

fn tagged(generation: u32, state: u32) -> u64 {
    (u64::from(generation) << 32) | u64::from(state)
}

fn generation_of(state: u64) -> u32 {
    (state >> 32) as u32
}

/// Never poisons; an inherited parent owner can be replaced in the child.
///
/// Fork notification must precede child membrane use and thread creation.
/// The surviving thread must not access an inherited guard's value after
/// takeover. This retains the existing child-only fork-recovery contract.
pub(crate) struct NoPoisonMutex<T> {
    /// Upper 32 bits: fork generation; lower 32 bits: ownership state.
    state: AtomicU64,
    /// A separate, genuinely 32-bit futex word. Do not overlay an AtomicU32
    /// on the AtomicU64: Rust accesses of different atomic sizes must not race.
    wake_sequence: AtomicU32,
    value: UnsafeCell<T>,
}

// SAFETY: each acquisition atomically claims both state and generation.
// Same-generation contenders cannot take over a live owner. Fork recovery
// is confined to a child with no surviving users of the inherited value.
#[allow(unsafe_code)]
unsafe impl<T: Send> Sync for NoPoisonMutex<T> {}
// SAFETY: moving the mutex transfers its exclusively owned value.
#[allow(unsafe_code)]
unsafe impl<T: Send> Send for NoPoisonMutex<T> {}

impl<T> std::fmt::Debug for NoPoisonMutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoPoisonMutex").finish_non_exhaustive()
    }
}

pub(crate) struct NoPoisonMutexGuard<'a, T> {
    lock: &'a NoPoisonMutex<T>,
    generation: u32,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl<T> NoPoisonMutex<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self {
            state: AtomicU64::new(0),
            wake_sequence: AtomicU32::new(0),
            value: UnsafeCell::new(value),
        }
    }

    fn guard(&self, generation: u32) -> NoPoisonMutexGuard<'_, T> {
        // No publication here: the CAS already made generation and ownership
        // visible together, including the very first lock after fork.
        NoPoisonMutexGuard {
            lock: self,
            generation,
            _not_send: std::marker::PhantomData,
        }
    }

    fn try_lock_in_generation(&self, generation: u32) -> Option<NoPoisonMutexGuard<'_, T>> {
        let current = self.state.load(Ordering::Relaxed);
        if generation_of(current) == generation && current as u32 != UNLOCKED {
            return None;
        }
        // A free word, or any word copied from a previous fork generation,
        // is claimed atomically. A raced ownership change rejects the claim.
        self.state
            .compare_exchange(
                current,
                tagged(generation, LOCKED),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .ok()
            .map(|_| self.guard(generation))
    }

    pub(crate) fn try_lock(&self) -> Option<NoPoisonMutexGuard<'_, T>> {
        self.try_lock_in_generation(FORK_GENERATION.load(Ordering::Acquire))
    }

    pub(crate) fn lock(&self) -> NoPoisonMutexGuard<'_, T> {
        self.lock_in_generation(FORK_GENERATION.load(Ordering::Acquire))
    }

    fn lock_in_generation(&self, generation: u32) -> NoPoisonMutexGuard<'_, T> {
        if let Some(guard) = self.try_lock_in_generation(generation) {
            return guard;
        }
        self.lock_contended(generation)
    }

    #[cold]
    fn lock_contended(&self, generation: u32) -> NoPoisonMutexGuard<'_, T> {
        loop {
            // Snapshot before checking ownership and advertising a waiter.
            // An intervening unlock changes this word, so FUTEX_WAIT fails
            // with EAGAIN rather than sleeping past the wakeup.
            let sequence = self.wake_sequence.load(Ordering::Acquire);
            let current = self.state.load(Ordering::Relaxed);
            if generation_of(current) != generation || current as u32 == UNLOCKED {
                if self
                    .state
                    .compare_exchange(
                        current,
                        tagged(generation, CONTENDED),
                        Ordering::Acquire,
                        Ordering::Relaxed,
                    )
                    .is_ok()
                {
                    // Carry the waiter bit through handoff: other sleepers
                    // may still need the next owner's unlock to wake them.
                    return self.guard(generation);
                }
                continue;
            }
            if current as u32 != CONTENDED
                && self
                    .state
                    .compare_exchange(
                        current,
                        tagged(generation, CONTENDED),
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                    )
                    .is_err()
            {
                continue;
            }
            futex_wait(&self.wake_sequence, sequence);
        }
    }

    fn unlock(&self, generation: u32) {
        let mut current = self.state.load(Ordering::Relaxed);
        loop {
            // A pre-fork guard can be dropped after child takeover. It no
            // longer owns this lock and must not release its new owner.
            if generation_of(current) != generation || current as u32 == UNLOCKED {
                return;
            }
            match self.state.compare_exchange_weak(
                current,
                tagged(generation, UNLOCKED),
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(previous) => {
                    if previous as u32 == CONTENDED {
                        self.wake_sequence.fetch_add(1, Ordering::Release);
                        futex_wake_one(&self.wake_sequence);
                    }
                    return;
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl<T> std::ops::Deref for NoPoisonMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the guard owns this generation's lock; the child contract
        // excludes dereferencing an inherited guard after takeover.
        #[allow(unsafe_code)]
        unsafe {
            &*self.lock.value.get()
        }
    }
}

impl<T> std::ops::DerefMut for NoPoisonMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: the same ownership invariant gives exclusive access.
        #[allow(unsafe_code)]
        unsafe {
            &mut *self.lock.value.get()
        }
    }
}

impl<T> Drop for NoPoisonMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.unlock(self.generation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier, mpsc};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn claim_publishes_generation_and_ownership_together() {
        let lock = NoPoisonMutex::new(17);
        // Exercise a nonzero child generation without changing the process
        // generation under unrelated parallel tests.
        let guard = lock.try_lock_in_generation(7).expect("first owner");
        assert_eq!(lock.state.load(Ordering::Acquire), tagged(7, LOCKED));
        assert!(lock.try_lock_in_generation(7).is_none());
        assert_eq!(*guard, 17);
        drop(guard);
        assert_eq!(lock.state.load(Ordering::Acquire), tagged(7, UNLOCKED));
    }

    #[test]
    fn inherited_guard_cannot_unlock_the_child_owner() {
        let lock = NoPoisonMutex::new(0);
        let inherited = lock.try_lock_in_generation(1).expect("parent owner");
        // Model child takeover. No reference to the inherited value escapes,
        // and the inherited guard is only dropped, never dereferenced again.
        let mut child = lock.try_lock_in_generation(2).expect("child owner");
        *child = 23;
        drop(inherited);
        assert!(lock.try_lock_in_generation(2).is_none());
        assert_eq!(*child, 23);
        drop(child);
        assert_eq!(*lock.try_lock_in_generation(2).expect("released"), 23);
    }

    #[test]
    fn inherited_guard_releases_an_untaken_parent_word() {
        let lock = NoPoisonMutex::new(0);
        let inherited = lock.try_lock_in_generation(8).expect("parent owner");
        drop(inherited);
        assert_eq!(lock.state.load(Ordering::Acquire), tagged(8, UNLOCKED));
        assert!(lock.try_lock_in_generation(9).is_some());
    }

    #[test]
    fn a_panicking_owner_does_not_poison_the_mutex() {
        let lock = NoPoisonMutex::new(0);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = lock.lock();
            *guard = 41;
            panic!("injected owner panic");
        }));
        assert!(result.is_err());
        assert_eq!(*lock.lock(), 41);
    }

    #[test]
    fn nonzero_generation_contention_preserves_exclusion_and_wakes_all_waiters() {
        const THREADS: usize = 8;
        const ITERATIONS: usize = 2_000;
        let lock = Arc::new(NoPoisonMutex::new(0usize));
        let start = Arc::new(Barrier::new(THREADS));
        let (done_tx, done_rx) = mpsc::channel();
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let lock = Arc::clone(&lock);
                let start = Arc::clone(&start);
                let done_tx = done_tx.clone();
                thread::spawn(move || {
                    start.wait();
                    for i in 0..ITERATIONS {
                        let mut guard = lock.lock_in_generation(19);
                        let previous = *guard;
                        if i % 31 == 0 {
                            thread::yield_now();
                        }
                        assert!(lock.try_lock_in_generation(19).is_none());
                        *guard = previous + 1;
                    }
                    done_tx.send(()).expect("completion receiver");
                })
            })
            .collect();
        for _ in 0..THREADS {
            done_rx
                .recv_timeout(Duration::from_secs(20))
                .expect("mutex waiter stopped making progress");
        }
        for worker in workers {
            worker.join().expect("mutex worker");
        }
        assert_eq!(*lock.lock_in_generation(19), THREADS * ITERATIONS);
    }

    #[test]
    fn unlock_advances_notification_before_a_late_wait() {
        let lock = NoPoisonMutex::new(0);
        let guard = lock.lock_in_generation(3);
        let sequence = lock.wake_sequence.load(Ordering::Acquire);
        assert!(
            lock.state
                .compare_exchange(
                    tagged(3, LOCKED),
                    tagged(3, CONTENDED),
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                )
                .is_ok()
        );
        drop(guard);
        assert_ne!(lock.wake_sequence.load(Ordering::Acquire), sequence);
        // The existing syscall wrapper must return EAGAIN on the stale
        // notification; do it on a bounded worker to expose a lost wakeup.
        let lock = Arc::new(lock);
        let waiter = Arc::clone(&lock);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            futex_wait(&waiter.wake_sequence, sequence);
            done_tx.send(()).expect("completion receiver");
        });
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("late futex wait lost the notification");
        worker.join().expect("late waiter");
    }

    #[test]
    fn contended_acquisition_keeps_the_wakeup_obligation() {
        let lock = NoPoisonMutex::new(0);
        let guard = lock.lock_contended(31);
        assert_eq!(lock.state.load(Ordering::Acquire), tagged(31, CONTENDED));
        let sequence = lock.wake_sequence.load(Ordering::Acquire);
        drop(guard);
        assert_eq!(
            lock.wake_sequence.load(Ordering::Acquire),
            sequence.wrapping_add(1)
        );
    }

    #[test]
    fn full_width_generation_is_preserved() {
        let lock = NoPoisonMutex::new(5);
        let guard = lock.lock_in_generation(u32::MAX);
        assert_eq!(lock.state.load(Ordering::Acquire), tagged(u32::MAX, LOCKED));
        assert!(lock.try_lock_in_generation(u32::MAX).is_none());
        drop(guard);
        assert_eq!(*lock.lock_in_generation(0), 5);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(unsafe_code)]
    fn real_fork_child_takes_over_a_vanished_threads_lock() {
        let lock = Arc::new(NoPoisonMutex::new(73));
        let parent_lock = Arc::clone(&lock);
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let owner = thread::spawn(move || {
            let guard = parent_lock.lock();
            ready_tx.send(()).expect("parent receiver");
            release_rx.recv().expect("release parent owner");
            assert_eq!(*guard, 73);
        });
        ready_rx.recv().expect("parent owner ready");
        // SAFETY: child uses only atomics, a stack-local mutex, raw owned
        // memory and _exit; it neither allocates nor uses inherited std locks.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            super::super::note_fork_child();
            let good = match lock.try_lock() {
                Some(mut guard) => {
                    let preserved = *guard == 73;
                    *guard = 99;
                    preserved && lock.try_lock().is_none()
                }
                None => false,
            };
            let fresh = NoPoisonMutex::new(11);
            let fresh_good = match fresh.try_lock() {
                Some(guard) => *guard == 11 && fresh.try_lock().is_none(),
                None => false,
            };
            unsafe { libc::_exit(if good && fresh_good { 0 } else { 2 }) };
        }
        release_tx.send(()).expect("release parent");
        owner.join().expect("parent owner");
        assert!(pid > 0, "fork failed");
        let mut status = 0;
        // Child uses try_lock only, so it cannot block on a mutex regression.
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(
            *lock.lock(),
            73,
            "child mutations must stay in child memory"
        );
    }
}
