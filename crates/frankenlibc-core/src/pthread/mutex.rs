//! POSIX mutex operations.
//!
//! Implements pthread mutex constants, validators, and type definitions.
//! Actual locking is performed via libc syscalls at the ABI layer;
//! this module provides the safe-Rust validation logic.
//! The clean-room contract narrative is documented in `mutex_contract.md`.

use crate::errno;

// ---------------------------------------------------------------------------
// Mutex type constants
// ---------------------------------------------------------------------------

/// Normal (default) mutex — no error checking, no recursive locking.
pub const PTHREAD_MUTEX_NORMAL: i32 = 0;
/// Recursive mutex — the owning thread can re-lock without deadlock.
pub const PTHREAD_MUTEX_RECURSIVE: i32 = 1;
/// Error-checking mutex — returns EDEADLK on recursive lock.
pub const PTHREAD_MUTEX_ERRORCHECK: i32 = 2;
/// Default mutex type (alias for NORMAL on Linux).
pub const PTHREAD_MUTEX_DEFAULT: i32 = PTHREAD_MUTEX_NORMAL;

// ---------------------------------------------------------------------------
// Clean-room semantics contract (bd-327)
// ---------------------------------------------------------------------------

/// Phase-scoped mutex state abstraction used for clean-room transition contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutexContractState {
    /// Memory has not been initialized as a mutex object.
    Uninitialized,
    /// Mutex is initialized and currently unlocked.
    Unlocked,
    /// Mutex is locked by the calling thread.
    LockedBySelf,
    /// Mutex is locked by a different thread.
    LockedByOther,
    /// Mutex has been destroyed and must be reinitialized before reuse.
    Destroyed,
}

/// Contract-level operation set for mutex transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutexContractOp {
    Init,
    Lock,
    TryLock,
    Unlock,
    Destroy,
}

/// Deterministic transition result for a contract operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MutexContractOutcome {
    /// Next abstract state after applying the operation.
    pub next: MutexContractState,
    /// POSIX errno-style result (0 on success).
    pub errno: i32,
    /// Whether the operation may block awaiting progress by another thread.
    pub blocks: bool,
}

/// Deferred attribute classes in the current mutex phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MutexAttributeContract {
    /// `PTHREAD_PROCESS_SHARED`.
    pub process_shared: bool,
    /// Robust mutex mode.
    pub robust: bool,
    /// Priority inheritance protocol.
    pub priority_inherit: bool,
    /// Priority protection protocol.
    pub priority_protect: bool,
}

/// Returns true when the current phase supports the provided attribute profile.
#[must_use]
pub const fn mutex_attr_is_supported(attrs: MutexAttributeContract) -> bool {
    !(attrs.process_shared || attrs.robust || attrs.priority_inherit || attrs.priority_protect)
}

/// Deterministic errno mapping for unsupported attribute combinations.
#[must_use]
pub const fn mutex_attr_support_errno(attrs: MutexAttributeContract) -> i32 {
    if mutex_attr_is_supported(attrs) {
        0
    } else {
        errno::EINVAL
    }
}

/// Contention/fairness contract note for futex-backed NORMAL mutex path.
#[must_use]
pub const fn futex_contention_fairness_note() -> &'static str {
    "Deterministic adaptive path: uncontended CAS fast path, bounded spin classification, \
futex wait/wake parking. Wake ordering is kernel-scheduled (not strict FIFO), but starvation \
is mitigated by mandatory wake on contended unlock."
}

/// Clean-room transition contract for NORMAL/ERRORCHECK/RECURSIVE mutexes.
#[must_use]
pub const fn mutex_contract_transition(
    kind: i32,
    state: MutexContractState,
    op: MutexContractOp,
) -> MutexContractOutcome {
    if !valid_mutex_type(kind) {
        return MutexContractOutcome {
            next: state,
            errno: errno::EINVAL,
            blocks: false,
        };
    }

    match state {
        MutexContractState::Uninitialized => match op {
            MutexContractOp::Init => MutexContractOutcome {
                next: MutexContractState::Unlocked,
                errno: 0,
                blocks: false,
            },
            _ => MutexContractOutcome {
                next: MutexContractState::Uninitialized,
                errno: errno::EINVAL,
                blocks: false,
            },
        },
        MutexContractState::Destroyed => match op {
            MutexContractOp::Init => MutexContractOutcome {
                next: MutexContractState::Unlocked,
                errno: 0,
                blocks: false,
            },
            _ => MutexContractOutcome {
                next: MutexContractState::Destroyed,
                errno: errno::EINVAL,
                blocks: false,
            },
        },
        MutexContractState::Unlocked => match op {
            MutexContractOp::Init => MutexContractOutcome {
                next: MutexContractState::Unlocked,
                errno: errno::EBUSY,
                blocks: false,
            },
            MutexContractOp::Lock | MutexContractOp::TryLock => MutexContractOutcome {
                next: MutexContractState::LockedBySelf,
                errno: 0,
                blocks: false,
            },
            MutexContractOp::Unlock => MutexContractOutcome {
                next: MutexContractState::Unlocked,
                errno: errno::EPERM,
                blocks: false,
            },
            MutexContractOp::Destroy => MutexContractOutcome {
                next: MutexContractState::Destroyed,
                errno: 0,
                blocks: false,
            },
        },
        MutexContractState::LockedByOther => match op {
            MutexContractOp::Init => MutexContractOutcome {
                next: MutexContractState::LockedByOther,
                errno: errno::EBUSY,
                blocks: false,
            },
            MutexContractOp::Lock => MutexContractOutcome {
                next: MutexContractState::LockedByOther,
                errno: 0,
                blocks: true,
            },
            MutexContractOp::TryLock => MutexContractOutcome {
                next: MutexContractState::LockedByOther,
                errno: errno::EBUSY,
                blocks: false,
            },
            MutexContractOp::Unlock => MutexContractOutcome {
                next: MutexContractState::LockedByOther,
                errno: errno::EPERM,
                blocks: false,
            },
            MutexContractOp::Destroy => MutexContractOutcome {
                next: MutexContractState::LockedByOther,
                errno: errno::EBUSY,
                blocks: false,
            },
        },
        MutexContractState::LockedBySelf => match op {
            MutexContractOp::Init => MutexContractOutcome {
                next: MutexContractState::LockedBySelf,
                errno: errno::EBUSY,
                blocks: false,
            },
            MutexContractOp::Destroy => MutexContractOutcome {
                next: MutexContractState::LockedBySelf,
                errno: errno::EBUSY,
                blocks: false,
            },
            MutexContractOp::Unlock => MutexContractOutcome {
                next: MutexContractState::Unlocked,
                errno: 0,
                blocks: false,
            },
            MutexContractOp::TryLock => {
                if kind == PTHREAD_MUTEX_RECURSIVE {
                    MutexContractOutcome {
                        next: MutexContractState::LockedBySelf,
                        errno: 0,
                        blocks: false,
                    }
                } else {
                    MutexContractOutcome {
                        next: MutexContractState::LockedBySelf,
                        errno: errno::EBUSY,
                        blocks: false,
                    }
                }
            }
            MutexContractOp::Lock => {
                if kind == PTHREAD_MUTEX_RECURSIVE {
                    MutexContractOutcome {
                        next: MutexContractState::LockedBySelf,
                        errno: 0,
                        blocks: false,
                    }
                } else if kind == PTHREAD_MUTEX_ERRORCHECK {
                    MutexContractOutcome {
                        next: MutexContractState::LockedBySelf,
                        errno: errno::EDEADLK,
                        blocks: false,
                    }
                } else {
                    MutexContractOutcome {
                        next: MutexContractState::LockedBySelf,
                        errno: 0,
                        blocks: true,
                    }
                }
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `kind` is a recognized mutex type.
#[must_use]
pub const fn valid_mutex_type(kind: i32) -> bool {
    matches!(
        kind,
        PTHREAD_MUTEX_NORMAL | PTHREAD_MUTEX_RECURSIVE | PTHREAD_MUTEX_ERRORCHECK
    )
}

/// Sanitize mutex type: if unknown, default to NORMAL.
#[must_use]
pub const fn sanitize_mutex_type(kind: i32) -> i32 {
    if valid_mutex_type(kind) {
        kind
    } else {
        PTHREAD_MUTEX_NORMAL
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn mutex_type_constants() {
        assert_eq!(PTHREAD_MUTEX_NORMAL, 0);
        assert_eq!(PTHREAD_MUTEX_RECURSIVE, 1);
        assert_eq!(PTHREAD_MUTEX_ERRORCHECK, 2);
        assert_eq!(PTHREAD_MUTEX_DEFAULT, PTHREAD_MUTEX_NORMAL);
    }

    #[test]
    fn valid_mutex_type_check() {
        assert!(valid_mutex_type(PTHREAD_MUTEX_NORMAL));
        assert!(valid_mutex_type(PTHREAD_MUTEX_RECURSIVE));
        assert!(valid_mutex_type(PTHREAD_MUTEX_ERRORCHECK));
        assert!(!valid_mutex_type(3));
        assert!(!valid_mutex_type(-1));
    }

    #[test]
    fn sanitize_mutex_type_check() {
        assert_eq!(
            sanitize_mutex_type(PTHREAD_MUTEX_RECURSIVE),
            PTHREAD_MUTEX_RECURSIVE
        );
        assert_eq!(sanitize_mutex_type(99), PTHREAD_MUTEX_NORMAL);
        assert_eq!(sanitize_mutex_type(-1), PTHREAD_MUTEX_NORMAL);
    }

    #[test]
    fn sanitize_mutex_type_extremes_default_to_normal() {
        assert_eq!(sanitize_mutex_type(i32::MIN), PTHREAD_MUTEX_NORMAL);
        assert_eq!(sanitize_mutex_type(i32::MAX), PTHREAD_MUTEX_NORMAL);
    }

    #[test]
    fn contract_normal_relock_blocks() {
        let outcome = mutex_contract_transition(
            PTHREAD_MUTEX_NORMAL,
            MutexContractState::LockedBySelf,
            MutexContractOp::Lock,
        );
        assert_eq!(outcome.next, MutexContractState::LockedBySelf);
        assert_eq!(outcome.errno, 0);
        assert!(outcome.blocks);
    }

    #[test]
    fn contract_errorcheck_relock_is_ededlk() {
        let outcome = mutex_contract_transition(
            PTHREAD_MUTEX_ERRORCHECK,
            MutexContractState::LockedBySelf,
            MutexContractOp::Lock,
        );
        assert_eq!(outcome.next, MutexContractState::LockedBySelf);
        assert_eq!(outcome.errno, errno::EDEADLK);
        assert!(!outcome.blocks);
    }

    #[test]
    fn contract_recursive_relock_succeeds_nonblocking() {
        let outcome = mutex_contract_transition(
            PTHREAD_MUTEX_RECURSIVE,
            MutexContractState::LockedBySelf,
            MutexContractOp::Lock,
        );
        assert_eq!(outcome.next, MutexContractState::LockedBySelf);
        assert_eq!(outcome.errno, 0);
        assert!(!outcome.blocks);
    }

    #[test]
    fn contract_unlock_locked_by_other_is_eperm() {
        let outcome = mutex_contract_transition(
            PTHREAD_MUTEX_NORMAL,
            MutexContractState::LockedByOther,
            MutexContractOp::Unlock,
        );
        assert_eq!(outcome.next, MutexContractState::LockedByOther);
        assert_eq!(outcome.errno, errno::EPERM);
        assert!(!outcome.blocks);
    }

    #[test]
    fn contract_destroy_while_locked_is_ebusy() {
        let outcome = mutex_contract_transition(
            PTHREAD_MUTEX_NORMAL,
            MutexContractState::LockedByOther,
            MutexContractOp::Destroy,
        );
        assert_eq!(outcome.next, MutexContractState::LockedByOther);
        assert_eq!(outcome.errno, errno::EBUSY);
        assert!(!outcome.blocks);
    }

    #[test]
    fn contract_uninitialized_lock_is_einval() {
        let outcome = mutex_contract_transition(
            PTHREAD_MUTEX_NORMAL,
            MutexContractState::Uninitialized,
            MutexContractOp::Lock,
        );
        assert_eq!(outcome.next, MutexContractState::Uninitialized);
        assert_eq!(outcome.errno, errno::EINVAL);
        assert!(!outcome.blocks);
    }

    #[test]
    fn attr_matrix_marks_deferred_features_unsupported() {
        let supported = MutexAttributeContract::default();
        assert!(mutex_attr_is_supported(supported));
        assert_eq!(mutex_attr_support_errno(supported), 0);

        let robust = MutexAttributeContract {
            robust: true,
            ..MutexAttributeContract::default()
        };
        assert!(!mutex_attr_is_supported(robust));
        assert_eq!(mutex_attr_support_errno(robust), errno::EINVAL);

        let pshared = MutexAttributeContract {
            process_shared: true,
            ..MutexAttributeContract::default()
        };
        assert!(!mutex_attr_is_supported(pshared));
        assert_eq!(mutex_attr_support_errno(pshared), errno::EINVAL);
    }

    #[test]
    fn fairness_note_mentions_wait_wake_policy() {
        let note = futex_contention_fairness_note();
        assert!(note.contains("wait/wake"));
        assert!(note.contains("starvation"));
    }

    proptest! {
        #[test]
        fn prop_sanitize_always_returns_supported_kind(kind in any::<i32>()) {
            prop_assert!(valid_mutex_type(sanitize_mutex_type(kind)));
        }

        #[test]
        fn prop_invalid_kind_transitions_fail_with_einval(
            kind in any::<i32>(),
            state in prop_oneof![
                Just(MutexContractState::Uninitialized),
                Just(MutexContractState::Unlocked),
                Just(MutexContractState::LockedBySelf),
                Just(MutexContractState::LockedByOther),
                Just(MutexContractState::Destroyed),
            ],
            op in prop_oneof![
                Just(MutexContractOp::Init),
                Just(MutexContractOp::Lock),
                Just(MutexContractOp::TryLock),
                Just(MutexContractOp::Unlock),
                Just(MutexContractOp::Destroy),
            ],
        ) {
            prop_assume!(!valid_mutex_type(kind));
            let outcome = mutex_contract_transition(kind, state, op);
            prop_assert_eq!(outcome.next, state);
            prop_assert_eq!(outcome.errno, errno::EINVAL);
            prop_assert!(!outcome.blocks);
        }

        #[test]
        fn prop_relock_semantics_from_locked_by_self(kind in prop_oneof![
            Just(PTHREAD_MUTEX_NORMAL),
            Just(PTHREAD_MUTEX_RECURSIVE),
            Just(PTHREAD_MUTEX_ERRORCHECK),
        ]) {
            let outcome =
                mutex_contract_transition(kind, MutexContractState::LockedBySelf, MutexContractOp::Lock);

            prop_assert_eq!(outcome.next, MutexContractState::LockedBySelf);
            match kind {
                PTHREAD_MUTEX_RECURSIVE => {
                    prop_assert_eq!(outcome.errno, 0);
                    prop_assert!(!outcome.blocks);
                }
                PTHREAD_MUTEX_ERRORCHECK => {
                    prop_assert_eq!(outcome.errno, errno::EDEADLK);
                    prop_assert!(!outcome.blocks);
                }
                _ => {
                    prop_assert_eq!(outcome.errno, 0);
                    prop_assert!(outcome.blocks);
                }
            }
        }
    }
}
