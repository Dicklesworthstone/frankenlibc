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
    use proptest::test_runner::Config as ProptestConfig;

    fn property_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(default_cases);

        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

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
        #![proptest_config(property_proptest_config(256))]

        #[test]
        fn prop_sanitize_always_returns_supported_kind(kind in any::<i32>()) {
            prop_assert!(valid_mutex_type(sanitize_mutex_type(kind)));
        }

        #[test]
        fn prop_init_from_reinit_states_transitions_to_unlocked(
            kind in prop_oneof![
                Just(PTHREAD_MUTEX_NORMAL),
                Just(PTHREAD_MUTEX_RECURSIVE),
                Just(PTHREAD_MUTEX_ERRORCHECK),
            ],
            state in prop_oneof![
                Just(MutexContractState::Uninitialized),
                Just(MutexContractState::Destroyed),
            ],
        ) {
            let outcome = mutex_contract_transition(kind, state, MutexContractOp::Init);
            prop_assert_eq!(outcome.next, MutexContractState::Unlocked);
            prop_assert_eq!(outcome.errno, 0);
            prop_assert!(!outcome.blocks);
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

        /// Metamorphic (absorbing state): Destroyed traps every op except Init.
        ///
        /// POSIX requires the destroyed memory be uninitialized before reuse:
        /// only a fresh Init re-enters the usable state machine. This MR
        /// fences the state graph against any refactor that would accidentally
        /// allow Lock/TryLock/Unlock/Destroy to escape the Destroyed sink
        /// (e.g. via "recover on Unlock" heuristics in the ABI wrapper).
        #[test]
        fn prop_destroyed_absorbs_non_init_ops(
            kind in prop_oneof![
                Just(PTHREAD_MUTEX_NORMAL),
                Just(PTHREAD_MUTEX_RECURSIVE),
                Just(PTHREAD_MUTEX_ERRORCHECK),
            ],
            op in prop_oneof![
                Just(MutexContractOp::Lock),
                Just(MutexContractOp::TryLock),
                Just(MutexContractOp::Unlock),
                Just(MutexContractOp::Destroy),
            ],
        ) {
            let outcome = mutex_contract_transition(
                kind,
                MutexContractState::Destroyed,
                op,
            );
            prop_assert_eq!(outcome.next, MutexContractState::Destroyed);
            prop_assert_eq!(outcome.errno, errno::EINVAL);
            prop_assert!(!outcome.blocks, "Destroyed state never blocks");
        }

        /// Metamorphic (absorbing state): Uninitialized traps every op except Init.
        ///
        /// Symmetric to prop_destroyed_absorbs_non_init_ops. Independent because
        /// Uninitialized and Destroyed use separate match arms in the contract
        /// function; a bug could regress one arm without affecting the other.
        #[test]
        fn prop_uninitialized_absorbs_non_init_ops(
            kind in prop_oneof![
                Just(PTHREAD_MUTEX_NORMAL),
                Just(PTHREAD_MUTEX_RECURSIVE),
                Just(PTHREAD_MUTEX_ERRORCHECK),
            ],
            op in prop_oneof![
                Just(MutexContractOp::Lock),
                Just(MutexContractOp::TryLock),
                Just(MutexContractOp::Unlock),
                Just(MutexContractOp::Destroy),
            ],
        ) {
            let outcome = mutex_contract_transition(
                kind,
                MutexContractState::Uninitialized,
                op,
            );
            prop_assert_eq!(outcome.next, MutexContractState::Uninitialized);
            prop_assert_eq!(outcome.errno, errno::EINVAL);
            prop_assert!(!outcome.blocks, "Uninitialized state never blocks");
        }

        /// Metamorphic structural invariant: `blocks ⇒ errno == 0`.
        ///
        /// A blocking outcome reports that the calling thread will wait for
        /// forward progress. Waiting with an error is nonsensical: the caller
        /// either acquired the mutex (success) or the call failed immediately.
        /// Sweeps the full (kind × state × op) cube including invalid kinds.
        #[test]
        fn prop_blocks_implies_success(
            kind in prop_oneof![
                Just(PTHREAD_MUTEX_NORMAL),
                Just(PTHREAD_MUTEX_RECURSIVE),
                Just(PTHREAD_MUTEX_ERRORCHECK),
                any::<i32>(),
            ],
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
            let outcome = mutex_contract_transition(kind, state, op);
            if outcome.blocks {
                prop_assert_eq!(
                    outcome.errno, 0,
                    "blocking outcome must report success (kind={}, state={:?}, op={:?}, errno={})",
                    kind, state, op, outcome.errno
                );
            }
        }

        /// Metamorphic (invertive): Lock→Unlock roundtrip from Unlocked
        /// returns to Unlocked, errno=0, non-blocking — for every valid kind.
        ///
        /// Catches: state-mutation bugs that leave the contract machine in
        /// LockedByOther or Destroyed, spurious EPERM/EBUSY on clean unlock,
        /// and lost-kind regressions in the LockedBySelf→Unlocked arrow.
        #[test]
        fn prop_lock_unlock_roundtrip_is_identity(kind in prop_oneof![
            Just(PTHREAD_MUTEX_NORMAL),
            Just(PTHREAD_MUTEX_RECURSIVE),
            Just(PTHREAD_MUTEX_ERRORCHECK),
        ]) {
            let lock = mutex_contract_transition(
                kind,
                MutexContractState::Unlocked,
                MutexContractOp::Lock,
            );
            prop_assert_eq!(lock.next, MutexContractState::LockedBySelf);
            prop_assert_eq!(lock.errno, 0);
            prop_assert!(!lock.blocks, "Lock on Unlocked must not block");

            let unlock = mutex_contract_transition(
                kind,
                lock.next,
                MutexContractOp::Unlock,
            );
            prop_assert_eq!(unlock.next, MutexContractState::Unlocked);
            prop_assert_eq!(unlock.errno, 0);
            prop_assert!(!unlock.blocks);
        }

        /// Metamorphic (invertive): TryLock→Unlock roundtrip mirrors Lock→Unlock.
        ///
        /// Independent of prop_lock_unlock_roundtrip_is_identity because TryLock
        /// and Lock reach LockedBySelf via different arms of the state machine
        /// and a refactor could silently diverge the two acquisition paths.
        #[test]
        fn prop_trylock_unlock_roundtrip_is_identity(kind in prop_oneof![
            Just(PTHREAD_MUTEX_NORMAL),
            Just(PTHREAD_MUTEX_RECURSIVE),
            Just(PTHREAD_MUTEX_ERRORCHECK),
        ]) {
            let try_ = mutex_contract_transition(
                kind,
                MutexContractState::Unlocked,
                MutexContractOp::TryLock,
            );
            prop_assert_eq!(try_.next, MutexContractState::LockedBySelf);
            prop_assert_eq!(try_.errno, 0);
            prop_assert!(!try_.blocks);

            let unlock = mutex_contract_transition(
                kind,
                try_.next,
                MutexContractOp::Unlock,
            );
            prop_assert_eq!(unlock.next, MutexContractState::Unlocked);
            prop_assert_eq!(unlock.errno, 0);
            prop_assert!(!unlock.blocks);
        }

        /// Metamorphic: TryLock must never block, for any (kind, state).
        ///
        /// POSIX contract: pthread_mutex_trylock returns immediately with either
        /// 0 (acquired) or an error (EBUSY/EDEADLK/EINVAL). It never waits.
        /// This MR rejects any future refactor that conflates Lock/TryLock paths.
        #[test]
        fn prop_trylock_never_blocks(
            kind in prop_oneof![
                Just(PTHREAD_MUTEX_NORMAL),
                Just(PTHREAD_MUTEX_RECURSIVE),
                Just(PTHREAD_MUTEX_ERRORCHECK),
                any::<i32>(),
            ],
            state in prop_oneof![
                Just(MutexContractState::Uninitialized),
                Just(MutexContractState::Unlocked),
                Just(MutexContractState::LockedBySelf),
                Just(MutexContractState::LockedByOther),
                Just(MutexContractState::Destroyed),
            ],
        ) {
            let outcome = mutex_contract_transition(kind, state, MutexContractOp::TryLock);
            prop_assert!(
                !outcome.blocks,
                "TryLock must never block (kind={}, state={:?}, errno={})",
                kind, state, outcome.errno
            );
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

    // -----------------------------------------------------------------
    // POSIX.1-2017 conformance table: pthread_mutex_unlock (bd-u8qy)
    // -----------------------------------------------------------------
    //
    // Spec source: IEEE Std 1003.1-2017, System Interfaces, pthread_mutex_unlock.
    //
    // Each entry cites the section/paragraph of POSIX that mandates the
    // expected outcome. Reviewers can audit conformance by diffing the
    // cited clause against the contract transition it exercises.

    struct UnlockConformanceCase {
        id: &'static str,
        posix_ref: &'static str,
        kind: i32,
        state: MutexContractState,
        expected_next: MutexContractState,
        expected_errno: i32,
    }

    const UNLOCK_CONFORMANCE_TABLE: &[UnlockConformanceCase] = &[
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-001",
            // "If there are threads blocked on the mutex object ... the scheduling policy shall
            //  determine which thread shall acquire the mutex." — a successful unlock releases it.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Description",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::LockedBySelf,
            expected_next: MutexContractState::Unlocked,
            expected_errno: 0,
        },
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-002",
            // Error-checking mutexes: "If the mutex is not currently locked by the calling
            //  thread ... an error shall be returned." EPERM is the mandated errno.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Errors/EPERM",
            kind: PTHREAD_MUTEX_ERRORCHECK,
            state: MutexContractState::LockedByOther,
            expected_next: MutexContractState::LockedByOther,
            expected_errno: errno::EPERM,
        },
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-003",
            // Normal mutexes: Linux glibc returns EPERM for unlock-by-non-owner to avoid
            //  silent corruption; POSIX permits implementation-defined behavior here and
            //  FrankenLibC mirrors the glibc choice.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Errors/EPERM + glibc extension",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::LockedByOther,
            expected_next: MutexContractState::LockedByOther,
            expected_errno: errno::EPERM,
        },
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-004",
            // Unlock of a never-locked Unlocked mutex: EPERM (the calling thread is not
            //  the owner, matching the LockedByOther arm's semantics).
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Errors/EPERM",
            kind: PTHREAD_MUTEX_ERRORCHECK,
            state: MutexContractState::Unlocked,
            expected_next: MutexContractState::Unlocked,
            expected_errno: errno::EPERM,
        },
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-005",
            // Operations on an uninitialized or destroyed mutex "shall return an error".
            //  POSIX allows either EINVAL or undefined behavior; FrankenLibC chooses EINVAL
            //  as the safest mechanical fallback.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Errors/EINVAL",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::Uninitialized,
            expected_next: MutexContractState::Uninitialized,
            expected_errno: errno::EINVAL,
        },
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-006",
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Errors/EINVAL",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::Destroyed,
            expected_next: MutexContractState::Destroyed,
            expected_errno: errno::EINVAL,
        },
        UnlockConformanceCase {
            id: "POSIX-MUTEX-UNLOCK-007",
            // Recursive mutex: unlock by owner returns 0 regardless of recursion depth;
            //  the contract abstracts depth into the LockedBySelf state.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_unlock ¶Description (recursive)",
            kind: PTHREAD_MUTEX_RECURSIVE,
            state: MutexContractState::LockedBySelf,
            expected_next: MutexContractState::Unlocked,
            expected_errno: 0,
        },
    ];

    // -----------------------------------------------------------------
    // POSIX.1-2017 conformance table: pthread_mutex_destroy (bd-u8qy)
    // -----------------------------------------------------------------
    //
    // Spec source: IEEE Std 1003.1-2017 §pthread_mutex_destroy.
    // Key clauses:
    //   • "It shall be safe to destroy an initialized mutex that is
    //      unlocked." — destroy of Unlocked succeeds.
    //   • "Attempting to destroy a locked mutex ... results in
    //      undefined behavior." — FrankenLibC returns EBUSY as a safe
    //      mechanical fallback (aligned with glibc PTHREAD_MUTEX_ROBUST).
    //   • "The results ... are undefined if ... the mutex is not
    //      initialized." — EINVAL on Uninitialized/Destroyed.

    struct DestroyConformanceCase {
        id: &'static str,
        posix_ref: &'static str,
        kind: i32,
        state: MutexContractState,
        expected_next: MutexContractState,
        expected_errno: i32,
    }

    const DESTROY_CONFORMANCE_TABLE: &[DestroyConformanceCase] = &[
        DestroyConformanceCase {
            id: "POSIX-MUTEX-DESTROY-001",
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_destroy ¶Description",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::Unlocked,
            expected_next: MutexContractState::Destroyed,
            expected_errno: 0,
        },
        DestroyConformanceCase {
            id: "POSIX-MUTEX-DESTROY-002",
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_destroy ¶Description (RECURSIVE)",
            kind: PTHREAD_MUTEX_RECURSIVE,
            state: MutexContractState::Unlocked,
            expected_next: MutexContractState::Destroyed,
            expected_errno: 0,
        },
        DestroyConformanceCase {
            id: "POSIX-MUTEX-DESTROY-003",
            // Destroy of mutex locked by another thread: UB by POSIX,
            //  EBUSY as FrankenLibC's deterministic safe fallback.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_destroy ¶Errors/EBUSY (mechanical fallback)",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::LockedByOther,
            expected_next: MutexContractState::LockedByOther,
            expected_errno: errno::EBUSY,
        },
        DestroyConformanceCase {
            id: "POSIX-MUTEX-DESTROY-004",
            // Destroy of self-locked mutex: also EBUSY — the caller holds
            //  the lock and must unlock before destroy.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_destroy ¶Errors/EBUSY (mechanical fallback)",
            kind: PTHREAD_MUTEX_ERRORCHECK,
            state: MutexContractState::LockedBySelf,
            expected_next: MutexContractState::LockedBySelf,
            expected_errno: errno::EBUSY,
        },
        DestroyConformanceCase {
            id: "POSIX-MUTEX-DESTROY-005",
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_destroy ¶Errors/EINVAL",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::Uninitialized,
            expected_next: MutexContractState::Uninitialized,
            expected_errno: errno::EINVAL,
        },
        DestroyConformanceCase {
            id: "POSIX-MUTEX-DESTROY-006",
            // Double-destroy: POSIX leaves behavior undefined; FrankenLibC
            //  mechanically rejects with EINVAL so the caller cannot
            //  reference freed kernel state.
            posix_ref: "IEEE 1003.1-2017 §pthread_mutex_destroy ¶Errors/EINVAL (double-destroy)",
            kind: PTHREAD_MUTEX_NORMAL,
            state: MutexContractState::Destroyed,
            expected_next: MutexContractState::Destroyed,
            expected_errno: errno::EINVAL,
        },
    ];

    #[test]
    fn posix_mutex_destroy_conformance_table() {
        let mut fails = Vec::new();
        for case in DESTROY_CONFORMANCE_TABLE {
            let outcome =
                mutex_contract_transition(case.kind, case.state, MutexContractOp::Destroy);
            if outcome.next != case.expected_next || outcome.errno != case.expected_errno {
                fails.push(format!(
                    "{} [{}]: expected next={:?}/errno={} got next={:?}/errno={}",
                    case.id,
                    case.posix_ref,
                    case.expected_next,
                    case.expected_errno,
                    outcome.next,
                    outcome.errno,
                ));
            }
            assert!(
                !outcome.blocks,
                "{}: destroy must never block (POSIX §pthread_mutex_destroy)",
                case.id
            );
        }
        assert!(
            fails.is_empty(),
            "POSIX mutex-destroy conformance failures:\n  {}",
            fails.join("\n  ")
        );
    }

    #[test]
    fn posix_mutex_unlock_conformance_table() {
        let mut fails = Vec::new();
        for case in UNLOCK_CONFORMANCE_TABLE {
            let outcome = mutex_contract_transition(case.kind, case.state, MutexContractOp::Unlock);
            if outcome.next != case.expected_next || outcome.errno != case.expected_errno {
                fails.push(format!(
                    "{} [{}]: expected next={:?}/errno={} got next={:?}/errno={}",
                    case.id,
                    case.posix_ref,
                    case.expected_next,
                    case.expected_errno,
                    outcome.next,
                    outcome.errno,
                ));
            }
            // Unlock is never a blocking operation regardless of outcome.
            assert!(
                !outcome.blocks,
                "{}: unlock must never block (POSIX §pthread_mutex_unlock)",
                case.id
            );
        }
        assert!(
            fails.is_empty(),
            "POSIX mutex-unlock conformance failures:\n  {}",
            fails.join("\n  ")
        );
    }
}
