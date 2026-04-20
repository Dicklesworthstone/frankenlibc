//! Signal handling — validators and types.
//!
//! Implements `<signal.h>` pure-logic helpers. Actual syscall invocations
//! (`kill`, `sigaction`, etc.) live in the ABI crate.

/// Signal numbers.
pub const SIGHUP: i32 = 1;
pub const SIGINT: i32 = 2;
pub const SIGQUIT: i32 = 3;
pub const SIGILL: i32 = 4;
pub const SIGABRT: i32 = 6;
pub const SIGFPE: i32 = 8;
pub const SIGKILL: i32 = 9;
pub const SIGUSR1: i32 = 10;
pub const SIGSEGV: i32 = 11;
pub const SIGUSR2: i32 = 12;
pub const SIGPIPE: i32 = 13;
pub const SIGALRM: i32 = 14;
pub const SIGTERM: i32 = 15;
pub const SIGCHLD: i32 = 17;
pub const SIGCONT: i32 = 18;
pub const SIGSTOP: i32 = 19;
pub const SIGTSTP: i32 = 20;

/// Maximum signal number on Linux (NSIG - 1).
const MAX_SIGNAL: i32 = 64;

/// Returns `true` if `signum` is within the valid signal range (1..=64).
#[inline]
pub fn valid_signal(signum: i32) -> bool {
    (1..=MAX_SIGNAL).contains(&signum)
}

/// Returns `true` if `signum` can have a user-defined handler installed.
///
/// SIGKILL and SIGSTOP cannot be caught, blocked, or ignored.
#[inline]
pub fn catchable_signal(signum: i32) -> bool {
    valid_signal(signum) && signum != SIGKILL && signum != SIGSTOP
}

/// Signal set — a bitmask of up to 64 signals.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigSet {
    bits: u64,
}

impl SigSet {
    /// Creates an empty signal set.
    #[inline]
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a full signal set (all signals 1..=64).
    #[inline]
    pub const fn full() -> Self {
        Self { bits: u64::MAX }
    }

    /// Adds a signal to the set.
    #[inline]
    pub fn add(&mut self, signum: i32) -> bool {
        if !valid_signal(signum) {
            return false;
        }
        self.bits |= 1u64 << (signum - 1);
        true
    }

    /// Removes a signal from the set.
    #[inline]
    pub fn del(&mut self, signum: i32) -> bool {
        if !valid_signal(signum) {
            return false;
        }
        self.bits &= !(1u64 << (signum - 1));
        true
    }

    /// Returns `true` if the signal is in the set.
    #[inline]
    pub fn is_member(&self, signum: i32) -> bool {
        if !valid_signal(signum) {
            return false;
        }
        (self.bits & (1u64 << (signum - 1))) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signal() {
        assert!(!valid_signal(0));
        assert!(valid_signal(1));
        assert!(valid_signal(64));
        assert!(!valid_signal(65));
        assert!(!valid_signal(-1));
    }

    #[test]
    fn test_catchable_signal() {
        assert!(catchable_signal(SIGINT));
        assert!(catchable_signal(SIGTERM));
        assert!(catchable_signal(SIGUSR1));
        assert!(!catchable_signal(SIGKILL));
        assert!(!catchable_signal(SIGSTOP));
        assert!(!catchable_signal(0));
    }

    #[test]
    fn test_sigset_empty_full() {
        let empty = SigSet::empty();
        assert!(!empty.is_member(SIGINT));
        assert!(!empty.is_member(SIGKILL));

        let full = SigSet::full();
        assert!(full.is_member(SIGINT));
        assert!(full.is_member(SIGKILL));
        assert!(full.is_member(1));
        assert!(full.is_member(64));
    }

    #[test]
    fn test_sigset_add_del() {
        let mut set = SigSet::empty();
        assert!(set.add(SIGINT));
        assert!(set.is_member(SIGINT));
        assert!(!set.is_member(SIGTERM));

        assert!(set.add(SIGTERM));
        assert!(set.is_member(SIGTERM));

        assert!(set.del(SIGINT));
        assert!(!set.is_member(SIGINT));
        assert!(set.is_member(SIGTERM));

        // invalid signal
        assert!(!set.add(0));
        assert!(!set.add(65));
        assert!(!set.del(0));
        assert!(!set.is_member(0));
    }

    // -----------------------------------------------------------------
    // Metamorphic proptests for SigSet bitset algebra (bd-0udd)
    // -----------------------------------------------------------------

    use proptest::prelude::*;
    use proptest::test_runner::Config as ProptestConfig;

    fn mr_proptest_config(default_cases: u32) -> ProptestConfig {
        let cases = std::env::var("FRANKENLIBC_PROPTEST_CASES")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(default_cases);
        ProptestConfig {
            cases,
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    fn any_valid_signal() -> impl Strategy<Value = i32> {
        1i32..=MAX_SIGNAL
    }

    proptest! {
        #![proptest_config(mr_proptest_config(256))]

        /// MR (invertive + identity): for any valid sig, starting from
        /// empty, add(sig) then is_member(sig) must be true; and
        /// add(sig) → del(sig) returns is_member(sig) to false.
        #[test]
        fn prop_sigset_add_then_is_member(sig in any_valid_signal()) {
            let mut set = SigSet::empty();
            prop_assert!(set.add(sig));
            prop_assert!(set.is_member(sig));
            prop_assert!(set.del(sig));
            prop_assert!(!set.is_member(sig));
        }

        /// MR (idempotent): adding the same signal twice leaves the
        /// underlying bit in the same state — the second add is a
        /// no-op because OR of a bit with itself is the bit.
        #[test]
        fn prop_sigset_add_is_idempotent(sig in any_valid_signal()) {
            let mut once = SigSet::empty();
            once.add(sig);
            let mut twice = SigSet::empty();
            twice.add(sig);
            twice.add(sig);
            prop_assert_eq!(once, twice);
        }

        /// MR (commutative): order of add operations must not change
        /// the final set — bitmask OR is commutative.
        #[test]
        fn prop_sigset_add_order_is_commutative(
            a in any_valid_signal(),
            b in any_valid_signal(),
        ) {
            let mut ab = SigSet::empty();
            ab.add(a);
            ab.add(b);
            let mut ba = SigSet::empty();
            ba.add(b);
            ba.add(a);
            prop_assert_eq!(ab, ba);
        }

        /// MR: invalid signals must be rejected without mutating
        /// state. A regression that silently truncated large sig to
        /// `sig % 64` would flip a valid bit and fail here.
        #[test]
        fn prop_sigset_invalid_signal_preserves_state(
            sig in prop_oneof![
                Just(0i32),
                Just(-1i32),
                Just(65i32),
                Just(127i32),
                Just(i32::MIN),
                Just(i32::MAX),
            ],
            pre_populate in proptest::collection::vec(any_valid_signal(), 0..8),
        ) {
            let mut set = SigSet::empty();
            for s in &pre_populate {
                set.add(*s);
            }
            let before = set;
            prop_assert!(!set.add(sig), "add of invalid sig={sig} must return false");
            prop_assert_eq!(
                set, before,
                "invalid add must not mutate set"
            );
            prop_assert!(!set.del(sig), "del of invalid sig={sig} must return false");
            prop_assert_eq!(
                set, before,
                "invalid del must not mutate set"
            );
            prop_assert!(!set.is_member(sig), "invalid sig={sig} is never a member");
        }

        /// MR (equivalence): full().is_member(sig) ⇔ valid_signal(sig).
        /// The full set must expose exactly the same signals that
        /// valid_signal admits — any drift between the two functions
        /// means the "full set" is inconsistent.
        #[test]
        fn prop_sigset_full_membership_iff_valid_signal(sig in -2..=66i32) {
            let full = SigSet::full();
            prop_assert_eq!(full.is_member(sig), valid_signal(sig));
        }

        /// MR (invertive, bulk): add every valid signal in random
        /// order ⇒ the resulting set has is_member(s) = true for all
        /// valid s; del every valid signal ⇒ set is empty.
        #[test]
        fn prop_sigset_bulk_add_then_bulk_del_is_empty(
            sigs in proptest::collection::vec(any_valid_signal(), 1..=MAX_SIGNAL as usize),
        ) {
            let mut set = SigSet::empty();
            for s in &sigs {
                set.add(*s);
            }
            for s in 1..=MAX_SIGNAL {
                set.del(s);
            }
            prop_assert_eq!(set, SigSet::empty(),
                "bulk add followed by bulk del-all must return to empty");
        }

        /// MR (absorbing): del of an already-absent signal is a no-op.
        /// A regression that XOR'd instead of AND'd would flip the bit
        /// on every stray del and fail here.
        #[test]
        fn prop_sigset_del_absent_signal_is_noop(sig in any_valid_signal()) {
            let set_before = SigSet::empty();
            let mut set_after = SigSet::empty();
            prop_assert!(set_after.del(sig), "del returns true for valid sig");
            prop_assert_eq!(set_after, set_before,
                "del of absent sig must not mutate state");
            prop_assert!(!set_after.is_member(sig));
        }
    }
}
