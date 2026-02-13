//! POSIX condition variable operations.
//!
//! Implements pthread condition variable constants, validators, the
//! clean-room semantics contract, and the futex-based core implementation
//! for `pthread_cond_*` operations.
//! The clean-room contract narrative is documented in `cond_contract.md`.

use crate::errno;
use crate::syscall;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Condition variable clock constants
// ---------------------------------------------------------------------------

/// Use CLOCK_REALTIME for condition variable timed waits (default).
pub const PTHREAD_COND_CLOCK_REALTIME: i32 = 0;
/// Use CLOCK_MONOTONIC for condition variable timed waits.
pub const PTHREAD_COND_CLOCK_MONOTONIC: i32 = 1;

// ---------------------------------------------------------------------------
// Futex operation constants (Linux x86_64)
// ---------------------------------------------------------------------------

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_PRIVATE_FLAG: i32 = 0x80;
const FUTEX_WAIT_BITSET: i32 = 9;
const FUTEX_CLOCK_REALTIME: i32 = 256;
const FUTEX_BITSET_MATCH_ANY: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// Condvar internal data structure (bd-gcy)
// ---------------------------------------------------------------------------

/// Internal condvar representation overlaid on `pthread_cond_t` memory.
///
/// Layout (20 bytes, fits within 48-byte `pthread_cond_t` on Linux x86_64):
/// - `seq`: sequence counter, incremented on signal/broadcast
/// - `nwaiters`: count of threads blocked in wait/timedwait
/// - `assoc_mutex`: address of the associated mutex (0 if unset)
/// - `clock_id`: clock for timedwait (0=REALTIME, 1=MONOTONIC)
#[repr(C)]
pub struct CondvarData {
    pub seq: AtomicU32,
    pub nwaiters: AtomicU32,
    pub assoc_mutex: AtomicUsize,
    pub clock_id: AtomicU32,
}

impl CondvarData {
    /// Initialize condvar data to default state.
    pub fn init(&self, clock_id: i32) {
        self.seq.store(0, Ordering::Relaxed);
        self.nwaiters.store(0, Ordering::Relaxed);
        self.assoc_mutex.store(0, Ordering::Relaxed);
        self.clock_id
            .store(sanitize_cond_clock(clock_id) as u32, Ordering::Relaxed);
    }

    /// Check if any threads are currently waiting.
    pub fn has_waiters(&self) -> bool {
        self.nwaiters.load(Ordering::Acquire) > 0
    }
}

// ---------------------------------------------------------------------------
// Core condvar operations (bd-gcy)
// ---------------------------------------------------------------------------

/// Initialize condvar at the given pointer.
///
/// # Safety
///
/// `condvar_ptr` must point to valid, aligned memory of at least
/// `size_of::<CondvarData>()` bytes (satisfied by `pthread_cond_t`).
#[allow(unsafe_code)]
pub unsafe fn condvar_init(condvar_ptr: *mut CondvarData, clock_id: i32) -> i32 {
    if condvar_ptr.is_null() {
        return errno::EINVAL;
    }
    // SAFETY: caller guarantees pointer validity.
    let cv = unsafe { &*condvar_ptr };
    cv.init(clock_id);
    0
}

/// Destroy condvar. Returns EBUSY if waiters exist.
///
/// # Safety
///
/// `condvar_ptr` must point to a valid initialized `CondvarData`.
#[allow(unsafe_code)]
pub unsafe fn condvar_destroy(condvar_ptr: *mut CondvarData) -> i32 {
    if condvar_ptr.is_null() {
        return errno::EINVAL;
    }
    let cv = unsafe { &*condvar_ptr };
    if cv.has_waiters() {
        return errno::EBUSY;
    }
    // Reset to uninit state.
    cv.seq.store(0, Ordering::Relaxed);
    cv.assoc_mutex.store(0, Ordering::Relaxed);
    cv.clock_id.store(0, Ordering::Relaxed);
    0
}

/// Signal one waiter on the condvar.
///
/// # Safety
///
/// `condvar_ptr` must point to a valid initialized `CondvarData`.
#[allow(unsafe_code)]
pub unsafe fn condvar_signal(condvar_ptr: *mut CondvarData) -> i32 {
    if condvar_ptr.is_null() {
        return errno::EINVAL;
    }
    let cv = unsafe { &*condvar_ptr };
    // Increment sequence counter to unblock a waiter.
    cv.seq.fetch_add(1, Ordering::Release);
    if cv.has_waiters() {
        let seq_ptr = &cv.seq as *const AtomicU32 as *const u32;
        // SAFETY: seq_ptr is valid and aligned.
        let _ = unsafe { syscall::sys_futex(seq_ptr, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, 0, 0, 0) };
    }
    0
}

/// Broadcast to all waiters on the condvar.
///
/// # Safety
///
/// `condvar_ptr` must point to a valid initialized `CondvarData`.
#[allow(unsafe_code)]
pub unsafe fn condvar_broadcast(condvar_ptr: *mut CondvarData) -> i32 {
    if condvar_ptr.is_null() {
        return errno::EINVAL;
    }
    let cv = unsafe { &*condvar_ptr };
    cv.seq.fetch_add(1, Ordering::Release);
    if cv.has_waiters() {
        let seq_ptr = &cv.seq as *const AtomicU32 as *const u32;
        // SAFETY: seq_ptr is valid and aligned.
        let _ = unsafe {
            syscall::sys_futex(
                seq_ptr,
                FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
                i32::MAX as u32,
                0,
                0,
                0,
            )
        };
    }
    0
}

/// Wait on condvar, atomically releasing and reacquiring the mutex.
///
/// The `mutex_futex_word` points to the first word of the mutex (the lock state).
/// This function implements the wait choreography:
/// 1. Read current sequence
/// 2. Validate/store associated mutex
/// 3. Increment waiter count
/// 4. Unlock mutex (futex wake)
/// 5. futex_wait on sequence counter
/// 6. Decrement waiter count
/// 7. Relock mutex (futex wait loop)
///
/// # Safety
///
/// - `condvar_ptr` must point to a valid initialized `CondvarData`.
/// - `mutex_futex_word` must point to a valid aligned `u32` (the mutex lock word).
#[allow(unsafe_code)]
pub unsafe fn condvar_wait(condvar_ptr: *mut CondvarData, mutex_futex_word: *const u32) -> i32 {
    if condvar_ptr.is_null() || mutex_futex_word.is_null() {
        return errno::EINVAL;
    }
    let cv = unsafe { &*condvar_ptr };
    let mutex_word = unsafe { &*(mutex_futex_word as *const AtomicU32) };

    // Validate mutex association invariant.
    let mutex_addr = mutex_futex_word as usize;
    let stored = cv.assoc_mutex.load(Ordering::Acquire);
    if stored == 0 {
        cv.assoc_mutex.store(mutex_addr, Ordering::Release);
    } else if stored != mutex_addr {
        return errno::EINVAL;
    }

    // Capture seq before releasing mutex.
    let expected_seq = cv.seq.load(Ordering::Acquire);
    cv.nwaiters.fetch_add(1, Ordering::AcqRel);

    // Release mutex: set lock word to 0 and wake one waiter.
    mutex_word.store(0, Ordering::Release);
    let _ = unsafe {
        syscall::sys_futex(
            mutex_futex_word,
            FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
            1,
            0,
            0,
            0,
        )
    };

    // Block until seq changes (signal/broadcast).
    let seq_ptr = &cv.seq as *const AtomicU32 as *const u32;
    loop {
        // SAFETY: seq_ptr is valid and aligned.
        let result = unsafe {
            syscall::sys_futex(
                seq_ptr,
                FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
                expected_seq,
                0,
                0,
                0,
            )
        };
        // Break on wakeup (seq changed or spurious).
        match result {
            Ok(_) => break,
            Err(e) if e == errno::EAGAIN => break, // seq already changed
            Err(e) if e == errno::EINTR => continue, // interrupted, retry
            Err(_) => break,                       // other error, don't loop forever
        }
    }

    cv.nwaiters.fetch_sub(1, Ordering::AcqRel);

    // Clear mutex association if we're the last waiter.
    if cv.nwaiters.load(Ordering::Acquire) == 0 {
        cv.assoc_mutex.store(0, Ordering::Release);
    }

    // Reacquire mutex via futex CAS loop.
    relock_mutex(mutex_word, mutex_futex_word);
    0
}

/// Timed wait on condvar with absolute deadline.
///
/// Uses `FUTEX_WAIT_BITSET` with the condvar's clock for absolute timeout.
/// Returns `ETIMEDOUT` if the deadline expires before signal/broadcast.
///
/// # Safety
///
/// - `condvar_ptr` must point to a valid initialized `CondvarData`.
/// - `mutex_futex_word` must point to a valid aligned `u32`.
/// - `abstime` must point to a valid `Timespec`.
#[allow(unsafe_code)]
pub unsafe fn condvar_timedwait(
    condvar_ptr: *mut CondvarData,
    mutex_futex_word: *const u32,
    tv_sec: i64,
    tv_nsec: i64,
) -> i32 {
    if condvar_ptr.is_null() || mutex_futex_word.is_null() {
        return errno::EINVAL;
    }
    if !valid_timespec_nsec(tv_nsec) {
        return errno::EINVAL;
    }

    let cv = unsafe { &*condvar_ptr };
    let mutex_word = unsafe { &*(mutex_futex_word as *const AtomicU32) };

    // Validate mutex association invariant.
    let mutex_addr = mutex_futex_word as usize;
    let stored = cv.assoc_mutex.load(Ordering::Acquire);
    if stored == 0 {
        cv.assoc_mutex.store(mutex_addr, Ordering::Release);
    } else if stored != mutex_addr {
        return errno::EINVAL;
    }

    let expected_seq = cv.seq.load(Ordering::Acquire);
    cv.nwaiters.fetch_add(1, Ordering::AcqRel);

    // Release mutex.
    mutex_word.store(0, Ordering::Release);
    let _ = unsafe {
        syscall::sys_futex(
            mutex_futex_word,
            FUTEX_WAKE | FUTEX_PRIVATE_FLAG,
            1,
            0,
            0,
            0,
        )
    };

    // Build the absolute timeout as a kernel timespec.
    // Layout: [tv_sec: i64, tv_nsec: i64] = 16 bytes.
    let ts: [i64; 2] = [tv_sec, tv_nsec];
    let ts_ptr = ts.as_ptr() as usize;

    // Choose futex op based on clock.
    // FUTEX_WAIT_BITSET supports absolute timeout natively.
    // FUTEX_CLOCK_REALTIME flag selects CLOCK_REALTIME; without it, CLOCK_MONOTONIC.
    let clock = cv.clock_id.load(Ordering::Relaxed) as i32;
    let futex_op = FUTEX_WAIT_BITSET
        | FUTEX_PRIVATE_FLAG
        | if clock == PTHREAD_COND_CLOCK_REALTIME {
            FUTEX_CLOCK_REALTIME
        } else {
            0
        };

    let seq_ptr = &cv.seq as *const AtomicU32 as *const u32;
    let mut timed_out = false;

    loop {
        // SAFETY: seq_ptr and ts_ptr are valid.
        let result = unsafe {
            syscall::sys_futex(
                seq_ptr,
                futex_op,
                expected_seq,
                ts_ptr,
                0,
                FUTEX_BITSET_MATCH_ANY,
            )
        };
        match result {
            Ok(_) => break,
            Err(e) if e == errno::EAGAIN => break,
            Err(e) if e == errno::EINTR => continue,
            Err(e) if e == errno::ETIMEDOUT => {
                timed_out = true;
                break;
            }
            Err(_) => break,
        }
    }

    cv.nwaiters.fetch_sub(1, Ordering::AcqRel);
    if cv.nwaiters.load(Ordering::Acquire) == 0 {
        cv.assoc_mutex.store(0, Ordering::Release);
    }

    // Reacquire mutex even on timeout (per POSIX).
    relock_mutex(mutex_word, mutex_futex_word);

    if timed_out { errno::ETIMEDOUT } else { 0 }
}

/// Relock a futex-based mutex after condvar wait.
///
/// Simple CAS loop with futex parking. No spin optimization needed
/// since we just woke from a condvar and expect contention to be brief.
#[allow(unsafe_code)]
fn relock_mutex(mutex_word: &AtomicU32, mutex_futex_ptr: *const u32) {
    loop {
        // Try uncontended acquire.
        if mutex_word
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            return;
        }
        // Mark as contended and park.
        let _ = mutex_word.compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed);
        // SAFETY: mutex_futex_ptr is valid and aligned.
        let _ = unsafe {
            syscall::sys_futex(mutex_futex_ptr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 2, 0, 0, 0)
        };
    }
}

// ---------------------------------------------------------------------------
// Clean-room semantics contract (bd-blg)
// ---------------------------------------------------------------------------

/// Phase-scoped condvar state abstraction used for clean-room transition contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondvarContractState {
    /// Memory has not been initialized as a condvar object.
    Uninitialized,
    /// Condvar is initialized and has zero waiters.
    Idle,
    /// Condvar is initialized and has one or more threads blocked in wait/timedwait.
    Waiting,
    /// Condvar has been destroyed and must be reinitialized before reuse.
    Destroyed,
}

/// Contract-level operation set for condvar transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondvarContractOp {
    Init,
    Destroy,
    Wait,
    TimedWait,
    Signal,
    Broadcast,
}

/// Deterministic transition result for a condvar contract operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CondvarContractOutcome {
    /// Next abstract state after applying the operation.
    pub next: CondvarContractState,
    /// POSIX errno-style result (0 on success).
    pub errno: i32,
    /// Whether the operation blocks the calling thread.
    pub blocks: bool,
}

/// Deferred attribute classes in the current condvar phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CondvarAttributeContract {
    /// `PTHREAD_PROCESS_SHARED`.
    pub process_shared: bool,
}

/// Returns true when the current phase supports the provided attribute profile.
#[must_use]
pub const fn condvar_attr_is_supported(attrs: CondvarAttributeContract) -> bool {
    !attrs.process_shared
}

/// Deterministic errno mapping for unsupported attribute combinations.
#[must_use]
pub const fn condvar_attr_support_errno(attrs: CondvarAttributeContract) -> i32 {
    if condvar_attr_is_supported(attrs) {
        0
    } else {
        errno::EINVAL
    }
}

/// Contention/futex notes for the condvar wait/signal/broadcast path.
#[must_use]
pub const fn futex_condvar_contention_note() -> &'static str {
    "Condvar uses a sequence counter for signal/broadcast ordering. \
wait path: unlock mutex -> futex_wait(seq) -> relock mutex. \
Signal wakes one via futex_wake(1). Broadcast wakes all via futex_wake(INT_MAX) \
or futex_cmp_requeue to move waiters to mutex futex. \
Wake ordering is kernel-scheduled (not strict FIFO). \
All concurrent waiters must use the same mutex (enforced; EINVAL on mismatch)."
}

/// Spurious wakeup policy documentation.
#[must_use]
pub const fn spurious_wakeup_policy() -> &'static str {
    "Per POSIX.1-2017: spurious wakeups may occur from pthread_cond_wait \
and pthread_cond_timedwait. Callers MUST use a predicate loop: \
while (!predicate) { pthread_cond_wait(&cond, &mutex); }. \
FrankenLibC does not suppress spurious wakeups in either mode."
}

/// Clean-room transition contract for condvar operations.
///
/// Models the abstract state machine per POSIX.1-2017. The `has_waiters`
/// parameter disambiguates Waiting->Idle vs Waiting->Waiting for signal.
#[must_use]
pub const fn condvar_contract_transition(
    state: CondvarContractState,
    op: CondvarContractOp,
    has_waiters: bool,
) -> CondvarContractOutcome {
    match state {
        CondvarContractState::Uninitialized => match op {
            CondvarContractOp::Init => CondvarContractOutcome {
                next: CondvarContractState::Idle,
                errno: 0,
                blocks: false,
            },
            _ => CondvarContractOutcome {
                next: CondvarContractState::Uninitialized,
                errno: errno::EINVAL,
                blocks: false,
            },
        },
        CondvarContractState::Destroyed => match op {
            CondvarContractOp::Init => CondvarContractOutcome {
                next: CondvarContractState::Idle,
                errno: 0,
                blocks: false,
            },
            _ => CondvarContractOutcome {
                next: CondvarContractState::Destroyed,
                errno: errno::EINVAL,
                blocks: false,
            },
        },
        CondvarContractState::Idle => match op {
            CondvarContractOp::Init => CondvarContractOutcome {
                next: CondvarContractState::Idle,
                errno: errno::EBUSY,
                blocks: false,
            },
            CondvarContractOp::Destroy => CondvarContractOutcome {
                next: CondvarContractState::Destroyed,
                errno: 0,
                blocks: false,
            },
            CondvarContractOp::Wait | CondvarContractOp::TimedWait => CondvarContractOutcome {
                next: CondvarContractState::Waiting,
                errno: 0,
                blocks: true,
            },
            CondvarContractOp::Signal | CondvarContractOp::Broadcast => CondvarContractOutcome {
                next: CondvarContractState::Idle,
                errno: 0,
                blocks: false,
            },
        },
        CondvarContractState::Waiting => match op {
            CondvarContractOp::Init => CondvarContractOutcome {
                next: CondvarContractState::Waiting,
                errno: errno::EBUSY,
                blocks: false,
            },
            CondvarContractOp::Destroy => CondvarContractOutcome {
                next: CondvarContractState::Waiting,
                errno: errno::EBUSY,
                blocks: false,
            },
            CondvarContractOp::Wait | CondvarContractOp::TimedWait => CondvarContractOutcome {
                next: CondvarContractState::Waiting,
                errno: 0,
                blocks: true,
            },
            CondvarContractOp::Signal => {
                // Signal wakes one waiter. If this was the last waiter, -> Idle.
                if has_waiters {
                    CondvarContractOutcome {
                        next: CondvarContractState::Waiting,
                        errno: 0,
                        blocks: false,
                    }
                } else {
                    CondvarContractOutcome {
                        next: CondvarContractState::Idle,
                        errno: 0,
                        blocks: false,
                    }
                }
            }
            CondvarContractOp::Broadcast => CondvarContractOutcome {
                next: CondvarContractState::Idle,
                errno: 0,
                blocks: false,
            },
        },
    }
}

/// Validate a timespec for timedwait: tv_nsec must be in [0, 999_999_999].
#[must_use]
pub const fn valid_timespec_nsec(tv_nsec: i64) -> bool {
    tv_nsec >= 0 && tv_nsec < 1_000_000_000
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `clock_id` is a recognized condition variable clock.
#[must_use]
pub const fn valid_cond_clock(clock_id: i32) -> bool {
    matches!(
        clock_id,
        PTHREAD_COND_CLOCK_REALTIME | PTHREAD_COND_CLOCK_MONOTONIC
    )
}

/// Sanitize clock id: if unknown, default to REALTIME.
#[must_use]
pub const fn sanitize_cond_clock(clock_id: i32) -> i32 {
    if valid_cond_clock(clock_id) {
        clock_id
    } else {
        PTHREAD_COND_CLOCK_REALTIME
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use super::*;

    // ---- Clock constant and validator tests (existing) ----

    #[test]
    fn cond_clock_constants() {
        assert_eq!(PTHREAD_COND_CLOCK_REALTIME, 0);
        assert_eq!(PTHREAD_COND_CLOCK_MONOTONIC, 1);
    }

    #[test]
    fn valid_cond_clock_check() {
        assert!(valid_cond_clock(PTHREAD_COND_CLOCK_REALTIME));
        assert!(valid_cond_clock(PTHREAD_COND_CLOCK_MONOTONIC));
        assert!(!valid_cond_clock(2));
        assert!(!valid_cond_clock(-1));
    }

    #[test]
    fn sanitize_cond_clock_check() {
        assert_eq!(
            sanitize_cond_clock(PTHREAD_COND_CLOCK_MONOTONIC),
            PTHREAD_COND_CLOCK_MONOTONIC
        );
        assert_eq!(sanitize_cond_clock(99), PTHREAD_COND_CLOCK_REALTIME);
    }

    #[test]
    fn sanitize_cond_clock_extremes_default_to_realtime() {
        assert_eq!(sanitize_cond_clock(i32::MIN), PTHREAD_COND_CLOCK_REALTIME);
        assert_eq!(sanitize_cond_clock(i32::MAX), PTHREAD_COND_CLOCK_REALTIME);
    }

    // ---- Contract transition tests ----

    #[test]
    fn contract_init_from_uninitialized() {
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Init,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_init_from_destroyed() {
        let o = condvar_contract_transition(
            CondvarContractState::Destroyed,
            CondvarContractOp::Init,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_reinit_idle_is_ebusy() {
        let o =
            condvar_contract_transition(CondvarContractState::Idle, CondvarContractOp::Init, false);
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, errno::EBUSY);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_reinit_waiting_is_ebusy() {
        let o = condvar_contract_transition(
            CondvarContractState::Waiting,
            CondvarContractOp::Init,
            true,
        );
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert_eq!(o.errno, errno::EBUSY);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_destroy_idle_succeeds() {
        let o = condvar_contract_transition(
            CondvarContractState::Idle,
            CondvarContractOp::Destroy,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_destroy_waiting_is_ebusy() {
        let o = condvar_contract_transition(
            CondvarContractState::Waiting,
            CondvarContractOp::Destroy,
            true,
        );
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert_eq!(o.errno, errno::EBUSY);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_destroy_uninitialized_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Destroy,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Uninitialized);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_destroy_destroyed_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Destroyed,
            CondvarContractOp::Destroy,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_wait_from_idle_blocks_and_transitions_to_waiting() {
        let o =
            condvar_contract_transition(CondvarContractState::Idle, CondvarContractOp::Wait, false);
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert_eq!(o.errno, 0);
        assert!(o.blocks);
    }

    #[test]
    fn contract_wait_from_waiting_adds_waiter() {
        let o = condvar_contract_transition(
            CondvarContractState::Waiting,
            CondvarContractOp::Wait,
            true,
        );
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert_eq!(o.errno, 0);
        assert!(o.blocks);
    }

    #[test]
    fn contract_wait_from_uninitialized_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Wait,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Uninitialized);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_wait_from_destroyed_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Destroyed,
            CondvarContractOp::Wait,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_timedwait_from_idle_blocks() {
        let o = condvar_contract_transition(
            CondvarContractState::Idle,
            CondvarContractOp::TimedWait,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert_eq!(o.errno, 0);
        assert!(o.blocks);
    }

    #[test]
    fn contract_timedwait_from_destroyed_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Destroyed,
            CondvarContractOp::TimedWait,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_signal_idle_is_noop() {
        let o = condvar_contract_transition(
            CondvarContractState::Idle,
            CondvarContractOp::Signal,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_signal_waiting_with_remaining_waiters() {
        // has_waiters=true means waiters remain after this signal
        let o = condvar_contract_transition(
            CondvarContractState::Waiting,
            CondvarContractOp::Signal,
            true,
        );
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_signal_waiting_last_waiter_transitions_to_idle() {
        // has_waiters=false means this was the last waiter
        let o = condvar_contract_transition(
            CondvarContractState::Waiting,
            CondvarContractOp::Signal,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_signal_uninitialized_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Signal,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Uninitialized);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_signal_destroyed_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Destroyed,
            CondvarContractOp::Signal,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_broadcast_idle_is_noop() {
        let o = condvar_contract_transition(
            CondvarContractState::Idle,
            CondvarContractOp::Broadcast,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_broadcast_waiting_wakes_all_to_idle() {
        let o = condvar_contract_transition(
            CondvarContractState::Waiting,
            CondvarContractOp::Broadcast,
            true,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_broadcast_uninitialized_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Broadcast,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Uninitialized);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    #[test]
    fn contract_broadcast_destroyed_is_einval() {
        let o = condvar_contract_transition(
            CondvarContractState::Destroyed,
            CondvarContractOp::Broadcast,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, errno::EINVAL);
        assert!(!o.blocks);
    }

    // ---- Attribute contract tests ----

    #[test]
    fn attr_default_is_supported() {
        let a = CondvarAttributeContract::default();
        assert!(condvar_attr_is_supported(a));
        assert_eq!(condvar_attr_support_errno(a), 0);
    }

    #[test]
    fn attr_process_shared_is_deferred() {
        let a = CondvarAttributeContract {
            process_shared: true,
        };
        assert!(!condvar_attr_is_supported(a));
        assert_eq!(condvar_attr_support_errno(a), errno::EINVAL);
    }

    // ---- Timespec validation tests ----

    #[test]
    fn timespec_nsec_valid_range() {
        assert!(valid_timespec_nsec(0));
        assert!(valid_timespec_nsec(500_000_000));
        assert!(valid_timespec_nsec(999_999_999));
    }

    #[test]
    fn timespec_nsec_invalid_negative() {
        assert!(!valid_timespec_nsec(-1));
        assert!(!valid_timespec_nsec(i64::MIN));
    }

    #[test]
    fn timespec_nsec_invalid_too_large() {
        assert!(!valid_timespec_nsec(1_000_000_000));
        assert!(!valid_timespec_nsec(i64::MAX));
    }

    // ---- Documentation / policy tests ----

    #[test]
    fn contention_note_mentions_requeue() {
        let note = futex_condvar_contention_note();
        assert!(note.contains("requeue"));
        assert!(note.contains("mutex"));
    }

    #[test]
    fn spurious_wakeup_policy_mentions_predicate_loop() {
        let policy = spurious_wakeup_policy();
        assert!(policy.contains("predicate"));
        assert!(policy.contains("spurious"));
    }

    // ---- Full lifecycle scenario tests ----

    #[test]
    fn lifecycle_init_wait_signal_destroy() {
        // Init
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Init,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);

        // Wait (first waiter)
        let o = condvar_contract_transition(o.next, CondvarContractOp::Wait, false);
        assert_eq!(o.next, CondvarContractState::Waiting);
        assert!(o.blocks);

        // Signal (last waiter woken)
        let o = condvar_contract_transition(o.next, CondvarContractOp::Signal, false);
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);

        // Destroy
        let o = condvar_contract_transition(o.next, CondvarContractOp::Destroy, false);
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, 0);
    }

    #[test]
    fn lifecycle_init_multiple_waiters_broadcast_destroy() {
        // Init
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Init,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);

        // First waiter
        let o = condvar_contract_transition(o.next, CondvarContractOp::Wait, false);
        assert_eq!(o.next, CondvarContractState::Waiting);

        // Second waiter
        let o = condvar_contract_transition(o.next, CondvarContractOp::Wait, true);
        assert_eq!(o.next, CondvarContractState::Waiting);

        // Broadcast wakes all
        let o = condvar_contract_transition(o.next, CondvarContractOp::Broadcast, true);
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);

        // Destroy
        let o = condvar_contract_transition(o.next, CondvarContractOp::Destroy, false);
        assert_eq!(o.next, CondvarContractState::Destroyed);
        assert_eq!(o.errno, 0);
    }

    #[test]
    fn lifecycle_destroy_and_reinit() {
        let o = condvar_contract_transition(
            CondvarContractState::Uninitialized,
            CondvarContractOp::Init,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);

        let o = condvar_contract_transition(o.next, CondvarContractOp::Destroy, false);
        assert_eq!(o.next, CondvarContractState::Destroyed);

        let o = condvar_contract_transition(o.next, CondvarContractOp::Init, false);
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
    }

    #[test]
    fn signal_on_idle_is_harmless_noop() {
        let o = condvar_contract_transition(
            CondvarContractState::Idle,
            CondvarContractOp::Signal,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn broadcast_on_idle_is_harmless_noop() {
        let o = condvar_contract_transition(
            CondvarContractState::Idle,
            CondvarContractOp::Broadcast,
            false,
        );
        assert_eq!(o.next, CondvarContractState::Idle);
        assert_eq!(o.errno, 0);
        assert!(!o.blocks);
    }

    #[test]
    fn all_ops_on_uninitialized_are_einval_except_init() {
        for op in [
            CondvarContractOp::Destroy,
            CondvarContractOp::Wait,
            CondvarContractOp::TimedWait,
            CondvarContractOp::Signal,
            CondvarContractOp::Broadcast,
        ] {
            let o = condvar_contract_transition(CondvarContractState::Uninitialized, op, false);
            assert_eq!(
                o.errno,
                errno::EINVAL,
                "expected EINVAL for {op:?} on Uninitialized"
            );
            assert_eq!(o.next, CondvarContractState::Uninitialized);
            assert!(!o.blocks);
        }
    }

    #[test]
    fn all_ops_on_destroyed_are_einval_except_init() {
        for op in [
            CondvarContractOp::Destroy,
            CondvarContractOp::Wait,
            CondvarContractOp::TimedWait,
            CondvarContractOp::Signal,
            CondvarContractOp::Broadcast,
        ] {
            let o = condvar_contract_transition(CondvarContractState::Destroyed, op, false);
            assert_eq!(
                o.errno,
                errno::EINVAL,
                "expected EINVAL for {op:?} on Destroyed"
            );
            assert_eq!(o.next, CondvarContractState::Destroyed);
            assert!(!o.blocks);
        }
    }

    // ---- Core implementation unit tests (bd-gcy) ----

    #[test]
    fn core_init_sets_clock_and_zeros_fields() {
        let cv = CondvarData {
            seq: AtomicU32::new(0xFF),
            nwaiters: AtomicU32::new(0xFF),
            assoc_mutex: AtomicUsize::new(0xDEAD),
            clock_id: AtomicU32::new(0xFF),
        };
        cv.init(PTHREAD_COND_CLOCK_MONOTONIC);
        assert_eq!(cv.seq.load(Ordering::Relaxed), 0);
        assert_eq!(cv.nwaiters.load(Ordering::Relaxed), 0);
        assert_eq!(cv.assoc_mutex.load(Ordering::Relaxed), 0);
        assert_eq!(cv.clock_id.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn core_init_default_clock_is_realtime() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0xFF),
        };
        cv.init(PTHREAD_COND_CLOCK_REALTIME);
        assert_eq!(cv.clock_id.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn core_init_invalid_clock_defaults_to_realtime() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0xFF),
        };
        cv.init(99);
        assert_eq!(cv.clock_id.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn core_has_waiters_false_when_zero() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        assert!(!cv.has_waiters());
    }

    #[test]
    fn core_has_waiters_true_when_nonzero() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(3),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        assert!(cv.has_waiters());
    }

    #[test]
    fn core_condvar_init_null_returns_einval() {
        let ret = unsafe { condvar_init(core::ptr::null_mut(), 0) };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_destroy_null_returns_einval() {
        let ret = unsafe { condvar_destroy(core::ptr::null_mut()) };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_signal_null_returns_einval() {
        let ret = unsafe { condvar_signal(core::ptr::null_mut()) };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_broadcast_null_returns_einval() {
        let ret = unsafe { condvar_broadcast(core::ptr::null_mut()) };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_wait_null_condvar_returns_einval() {
        let mutex_word = AtomicU32::new(1);
        let ret = unsafe {
            condvar_wait(
                core::ptr::null_mut(),
                &mutex_word as *const AtomicU32 as *const u32,
            )
        };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_wait_null_mutex_returns_einval() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let ret = unsafe {
            condvar_wait(
                &cv as *const CondvarData as *mut CondvarData,
                core::ptr::null(),
            )
        };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_timedwait_null_returns_einval() {
        let ret = unsafe { condvar_timedwait(core::ptr::null_mut(), core::ptr::null(), 0, 0) };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_timedwait_invalid_nsec_returns_einval() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let mutex_word = AtomicU32::new(1);
        let ret = unsafe {
            condvar_timedwait(
                &cv as *const CondvarData as *mut CondvarData,
                &mutex_word as *const AtomicU32 as *const u32,
                100,
                -1, // invalid nsec
            )
        };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_timedwait_nsec_billion_returns_einval() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let mutex_word = AtomicU32::new(1);
        let ret = unsafe {
            condvar_timedwait(
                &cv as *const CondvarData as *mut CondvarData,
                &mutex_word as *const AtomicU32 as *const u32,
                100,
                1_000_000_000, // >= 1e9
            )
        };
        assert_eq!(ret, errno::EINVAL);
    }

    #[test]
    fn core_condvar_init_and_destroy_lifecycle() {
        let cv = CondvarData {
            seq: AtomicU32::new(0xFF),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0xFF),
        };
        let cv_ptr = &cv as *const CondvarData as *mut CondvarData;
        assert_eq!(unsafe { condvar_init(cv_ptr, 0) }, 0);
        assert_eq!(cv.seq.load(Ordering::Relaxed), 0);
        assert_eq!(unsafe { condvar_destroy(cv_ptr) }, 0);
    }

    #[test]
    fn core_condvar_destroy_with_waiters_returns_ebusy() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(2),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let cv_ptr = &cv as *const CondvarData as *mut CondvarData;
        assert_eq!(unsafe { condvar_destroy(cv_ptr) }, errno::EBUSY);
    }

    #[test]
    fn core_condvar_signal_on_empty_is_noop() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let cv_ptr = &cv as *const CondvarData as *mut CondvarData;
        assert_eq!(unsafe { condvar_signal(cv_ptr) }, 0);
        // Seq incremented even with no waiters (cheap and consistent).
        assert_eq!(cv.seq.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn core_condvar_broadcast_on_empty_is_noop() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let cv_ptr = &cv as *const CondvarData as *mut CondvarData;
        assert_eq!(unsafe { condvar_broadcast(cv_ptr) }, 0);
        assert_eq!(cv.seq.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn core_condvar_signal_increments_seq() {
        let cv = CondvarData {
            seq: AtomicU32::new(42),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let cv_ptr = &cv as *const CondvarData as *mut CondvarData;
        unsafe { condvar_signal(cv_ptr) };
        assert_eq!(cv.seq.load(Ordering::Relaxed), 43);
        unsafe { condvar_signal(cv_ptr) };
        assert_eq!(cv.seq.load(Ordering::Relaxed), 44);
    }

    // ---- Threaded integration tests (bd-gcy) ----

    #[test]
    fn core_condvar_wait_signal_roundtrip() {
        use std::sync::Arc;
        use std::thread;

        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        });
        // Mutex simulated as AtomicU32: 0=unlocked, 1=locked, 2=contended.
        let mutex = Arc::new(AtomicU32::new(0));
        let done = Arc::new(AtomicU32::new(0));

        let cv2 = cv.clone();
        let mutex2 = mutex.clone();
        let done2 = done.clone();

        // Waiter thread.
        let waiter = thread::spawn(move || {
            // Acquire mutex.
            while mutex2
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }

            let cv_ptr = &*cv2 as *const CondvarData as *mut CondvarData;
            let mutex_ptr = &*mutex2 as *const AtomicU32 as *const u32;

            // Wait for signal.
            let ret = unsafe { condvar_wait(cv_ptr, mutex_ptr) };
            assert_eq!(ret, 0);

            // Mutex should be reacquired (value 1).
            assert_ne!(mutex2.load(Ordering::Relaxed), 0);

            done2.store(1, Ordering::Release);

            // Release mutex.
            mutex2.store(0, Ordering::Release);
        });

        // Give waiter time to block.
        thread::sleep(std::time::Duration::from_millis(50));

        // Verify waiter is blocked.
        assert!(cv.nwaiters.load(Ordering::Acquire) > 0 || done.load(Ordering::Acquire) == 1);

        // Signal.
        let cv_ptr = &*cv as *const CondvarData as *mut CondvarData;
        assert_eq!(unsafe { condvar_signal(cv_ptr) }, 0);

        waiter.join().unwrap();
        assert_eq!(done.load(Ordering::Acquire), 1);
        assert_eq!(cv.nwaiters.load(Ordering::Acquire), 0);
    }

    #[test]
    fn core_condvar_broadcast_wakes_all() {
        use std::sync::Arc;
        use std::thread;

        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        });
        let mutex = Arc::new(AtomicU32::new(0));
        let woke_count = Arc::new(AtomicU32::new(0));

        let num_waiters = 4;
        let mut handles = Vec::new();

        for _ in 0..num_waiters {
            let cv2 = cv.clone();
            let mutex2 = mutex.clone();
            let woke2 = woke_count.clone();

            handles.push(thread::spawn(move || {
                // Acquire mutex.
                loop {
                    if mutex2
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                    // Simple spin + futex wait for contention.
                    let _ = mutex2.compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed);
                    let mutex_ptr = &*mutex2 as *const AtomicU32 as *const u32;
                    let _ = unsafe { syscall::sys_futex(mutex_ptr, 0x80, 2, 0, 0, 0) };
                }

                let cv_ptr = &*cv2 as *const CondvarData as *mut CondvarData;
                let mutex_ptr = &*mutex2 as *const AtomicU32 as *const u32;

                let ret = unsafe { condvar_wait(cv_ptr, mutex_ptr) };
                assert_eq!(ret, 0);
                woke2.fetch_add(1, Ordering::AcqRel);

                // Release mutex.
                mutex2.store(0, Ordering::Release);
                let _ = unsafe { syscall::sys_futex(mutex_ptr, 0x01 | 0x80, 1, 0, 0, 0) };
            }));
        }

        // Give all waiters time to block.
        thread::sleep(std::time::Duration::from_millis(100));

        // Broadcast.
        let cv_ptr = &*cv as *const CondvarData as *mut CondvarData;
        assert_eq!(unsafe { condvar_broadcast(cv_ptr) }, 0);

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(woke_count.load(Ordering::Acquire), num_waiters);
        assert_eq!(cv.nwaiters.load(Ordering::Acquire), 0);
    }

    #[test]
    fn core_condvar_timedwait_expires() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Instant;

        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(PTHREAD_COND_CLOCK_MONOTONIC as u32),
        });
        let mutex = Arc::new(AtomicU32::new(0));

        let cv2 = cv.clone();
        let mutex2 = mutex.clone();

        let waiter = thread::spawn(move || {
            // Acquire mutex.
            while mutex2
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }

            // Use a deadline that's already in the past (epoch 0).
            let cv_ptr = &*cv2 as *const CondvarData as *mut CondvarData;
            let mutex_ptr = &*mutex2 as *const AtomicU32 as *const u32;

            let start = Instant::now();
            let ret = unsafe { condvar_timedwait(cv_ptr, mutex_ptr, 0, 0) };
            let elapsed = start.elapsed();

            // Should return ETIMEDOUT quickly.
            assert_eq!(ret, errno::ETIMEDOUT);
            // Should not take more than 1 second (the deadline was in the past).
            assert!(
                elapsed.as_secs() < 2,
                "timedwait took too long: {elapsed:?}"
            );

            // Mutex should be reacquired.
            assert_ne!(mutex2.load(Ordering::Relaxed), 0);
            mutex2.store(0, Ordering::Release);
        });

        waiter.join().unwrap();
        assert_eq!(cv.nwaiters.load(Ordering::Acquire), 0);
    }

    #[test]
    fn core_condvar_mutex_association_mismatch() {
        let cv = CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        };
        let mutex_a = AtomicU32::new(1);
        let mutex_b = AtomicU32::new(1);

        // Set association to mutex_a.
        cv.assoc_mutex
            .store(&mutex_a as *const AtomicU32 as usize, Ordering::Release);

        // Try wait with mutex_b — should get EINVAL.
        let cv_ptr = &cv as *const CondvarData as *mut CondvarData;
        let ret = unsafe { condvar_wait(cv_ptr, &mutex_b as *const AtomicU32 as *const u32) };
        assert_eq!(ret, errno::EINVAL);
    }

    // ---- Deterministic integration scenarios (bd-21k) ----

    /// Producer/consumer bounded queue using condvar for synchronization.
    #[test]
    fn scenario_producer_consumer_bounded_queue() {
        use std::sync::Arc;
        use std::thread;

        const QUEUE_CAPACITY: usize = 4;
        const NUM_ITEMS: u32 = 20;

        struct SharedQueue {
            cv_not_empty: CondvarData,
            cv_not_full: CondvarData,
            mutex: AtomicU32,
            items: std::cell::UnsafeCell<Vec<u32>>,
            done: AtomicU32,
        }
        // SAFETY: All access to items is protected by the mutex.
        unsafe impl Sync for SharedQueue {}

        let q = Arc::new(SharedQueue {
            cv_not_empty: CondvarData {
                seq: AtomicU32::new(0),
                nwaiters: AtomicU32::new(0),
                assoc_mutex: AtomicUsize::new(0),
                clock_id: AtomicU32::new(0),
            },
            cv_not_full: CondvarData {
                seq: AtomicU32::new(0),
                nwaiters: AtomicU32::new(0),
                assoc_mutex: AtomicUsize::new(0),
                clock_id: AtomicU32::new(0),
            },
            mutex: AtomicU32::new(0),
            items: std::cell::UnsafeCell::new(Vec::new()),
            done: AtomicU32::new(0),
        });

        fn mutex_ptr(q: &SharedQueue) -> *const u32 {
            &q.mutex as *const AtomicU32 as *const u32
        }

        let lock = |q: &SharedQueue| {
            loop {
                if q.mutex
                    .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
                let _ = q
                    .mutex
                    .compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed);
                let _ = unsafe { syscall::sys_futex(mutex_ptr(q), 0x80, 2, 0, 0, 0) };
            }
        };

        let unlock = |q: &SharedQueue| {
            q.mutex.store(0, Ordering::Release);
            let _ = unsafe { syscall::sys_futex(mutex_ptr(q), 0x01 | 0x80, 1, 0, 0, 0) };
        };

        // Producer
        let q2 = q.clone();
        let producer = thread::spawn(move || {
            for i in 0..NUM_ITEMS {
                lock(&q2);
                while unsafe { &*q2.items.get() }.len() >= QUEUE_CAPACITY {
                    let cv_ptr = &q2.cv_not_full as *const CondvarData as *mut CondvarData;
                    unsafe { condvar_wait(cv_ptr, mutex_ptr(&q2)) };
                }
                unsafe { &mut *q2.items.get() }.push(i);
                let cv_ptr = &q2.cv_not_empty as *const CondvarData as *mut CondvarData;
                unsafe { condvar_signal(cv_ptr) };
                unlock(&q2);
            }
            lock(&q2);
            q2.done.store(1, Ordering::Release);
            let cv_ptr = &q2.cv_not_empty as *const CondvarData as *mut CondvarData;
            unsafe { condvar_broadcast(cv_ptr) };
            unlock(&q2);
        });

        // Consumer
        let q3 = q.clone();
        let consumer = thread::spawn(move || {
            let mut received = Vec::new();
            loop {
                lock(&q3);
                while unsafe { &*q3.items.get() }.is_empty() {
                    if q3.done.load(Ordering::Acquire) == 1 {
                        unlock(&q3);
                        return received;
                    }
                    let cv_ptr = &q3.cv_not_empty as *const CondvarData as *mut CondvarData;
                    unsafe { condvar_wait(cv_ptr, mutex_ptr(&q3)) };
                }
                let item = unsafe { &mut *q3.items.get() }.remove(0);
                received.push(item);
                let cv_ptr = &q3.cv_not_full as *const CondvarData as *mut CondvarData;
                unsafe { condvar_signal(cv_ptr) };
                unlock(&q3);
            }
        });

        producer.join().unwrap();
        let received = consumer.join().unwrap();
        assert_eq!(received.len(), NUM_ITEMS as usize);
        for (i, &val) in received.iter().enumerate() {
            assert_eq!(val, i as u32);
        }
    }

    /// Stress test: many waiters with mixed signal/broadcast patterns.
    #[test]
    fn scenario_stress_many_waiters_mixed_wake() {
        use std::sync::Arc;
        use std::thread;

        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(0),
        });
        let mutex = Arc::new(AtomicU32::new(0));
        let counter = Arc::new(AtomicU32::new(0));
        let go = Arc::new(AtomicU32::new(0));

        let num_waiters: u32 = 8;
        let mut handles = Vec::new();

        for _ in 0..num_waiters {
            let cv2 = cv.clone();
            let mutex2 = mutex.clone();
            let counter2 = counter.clone();
            let go2 = go.clone();

            handles.push(thread::spawn(move || {
                loop {
                    if mutex2
                        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                        .is_ok()
                    {
                        break;
                    }
                    let _ = mutex2.compare_exchange(1, 2, Ordering::Acquire, Ordering::Relaxed);
                    let mp = &*mutex2 as *const AtomicU32 as *const u32;
                    let _ = unsafe { syscall::sys_futex(mp, 0x80, 2, 0, 0, 0) };
                }

                while go2.load(Ordering::Acquire) == 0 {
                    let cv_ptr = &*cv2 as *const CondvarData as *mut CondvarData;
                    let mp = &*mutex2 as *const AtomicU32 as *const u32;
                    unsafe { condvar_wait(cv_ptr, mp) };
                }

                counter2.fetch_add(1, Ordering::AcqRel);

                mutex2.store(0, Ordering::Release);
                let mp = &*mutex2 as *const AtomicU32 as *const u32;
                let _ = unsafe { syscall::sys_futex(mp, 0x01 | 0x80, 1, 0, 0, 0) };
            }));
        }

        thread::sleep(std::time::Duration::from_millis(100));

        // Signal a couple individually first.
        let cv_ptr = &*cv as *const CondvarData as *mut CondvarData;
        unsafe { condvar_signal(cv_ptr) };
        thread::sleep(std::time::Duration::from_millis(10));
        unsafe { condvar_signal(cv_ptr) };
        thread::sleep(std::time::Duration::from_millis(10));

        // Set go flag and broadcast remaining.
        go.store(1, Ordering::Release);
        unsafe { condvar_broadcast(cv_ptr) };

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.load(Ordering::Acquire), num_waiters);
    }

    /// Timedwait with CLOCK_MONOTONIC past deadline: verifies quick timeout.
    #[test]
    fn scenario_timedwait_monotonic_past_deadline() {
        use std::sync::Arc;
        use std::thread;
        use std::time::Instant;

        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(PTHREAD_COND_CLOCK_MONOTONIC as u32),
        });
        let mutex = Arc::new(AtomicU32::new(0));

        let cv2 = cv.clone();
        let mutex2 = mutex.clone();

        let waiter = thread::spawn(move || {
            while mutex2
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }

            let cv_ptr = &*cv2 as *const CondvarData as *mut CondvarData;
            let mp = &*mutex2 as *const AtomicU32 as *const u32;

            // Deadline of 1 second from epoch = far in the past for CLOCK_MONOTONIC.
            let start = Instant::now();
            let ret = unsafe { condvar_timedwait(cv_ptr, mp, 1, 0) };
            let elapsed = start.elapsed();

            assert_eq!(ret, errno::ETIMEDOUT);
            assert!(elapsed.as_secs() < 2);
            mutex2.store(0, Ordering::Release);
        });

        waiter.join().unwrap();
    }

    /// Signal-before-wait: signals are not queued per POSIX.
    #[test]
    fn scenario_signal_before_wait_not_queued() {
        use std::sync::Arc;
        use std::thread;

        let cv = Arc::new(CondvarData {
            seq: AtomicU32::new(0),
            nwaiters: AtomicU32::new(0),
            assoc_mutex: AtomicUsize::new(0),
            clock_id: AtomicU32::new(PTHREAD_COND_CLOCK_MONOTONIC as u32),
        });
        let mutex = Arc::new(AtomicU32::new(0));

        // Signal 3 times with no waiters — not queued.
        let cv_ptr = &*cv as *const CondvarData as *mut CondvarData;
        unsafe { condvar_signal(cv_ptr) };
        unsafe { condvar_signal(cv_ptr) };
        unsafe { condvar_signal(cv_ptr) };

        assert_eq!(cv.seq.load(Ordering::Relaxed), 3);

        let cv2 = cv.clone();
        let mutex2 = mutex.clone();

        let waiter = thread::spawn(move || {
            while mutex2
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_err()
            {
                core::hint::spin_loop();
            }

            let cv_ptr = &*cv2 as *const CondvarData as *mut CondvarData;
            let mp = &*mutex2 as *const AtomicU32 as *const u32;

            // Use timedwait with past deadline to avoid blocking forever.
            let ret = unsafe { condvar_timedwait(cv_ptr, mp, 0, 0) };
            assert_eq!(
                ret,
                errno::ETIMEDOUT,
                "signal-before-wait should not unblock"
            );
            mutex2.store(0, Ordering::Release);
        });

        waiter.join().unwrap();
    }
}
