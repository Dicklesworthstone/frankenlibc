//! Decision contract for strict/hardened state transitions.
//!
//! The contract models TSM lifecycle states:
//! - `Safe`: no active anomaly.
//! - `Suspicious`: soft anomalies observed; monitoring is elevated.
//! - `Unsafe`: hard violation observed; explicit repair required to clear.
//!
//! Transition coverage is exhaustive over `3 x 5 = 15` state/event pairs.
//! Compile-time checks enforce:
//! - no unhandled state/event tuples,
//! - no silent `Unsafe -> Safe` transition without `RepairComplete`,
//! - path-to-safe reachability from all states.

use crate::config::SafetyLevel;

/// Number of contract states.
pub const STATE_COUNT: usize = 3;
/// Number of contract events.
pub const EVENT_COUNT: usize = 5;
/// Default suspicious-state consecutive-pass threshold.
pub const DEFAULT_CLEAR_THRESHOLD: u16 = 3;

/// TSM decision state.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TsmState {
    /// No active anomaly.
    #[default]
    Safe = 0,
    /// Soft anomaly observed; monitor until confidence is restored.
    Suspicious = 1,
    /// Hard violation observed; explicit repair is required.
    Unsafe = 2,
}

/// Events driving the decision contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DecisionEvent {
    /// Soft anomaly (e.g., suspicious but not definitive violation).
    SoftAnomaly = 0,
    /// Hard violation (UAF, double-free, bounds fault, etc.).
    HardViolation = 1,
    /// Validation succeeded with no adverse signal.
    CheckPass = 2,
    /// Explicit repair completed.
    RepairComplete = 3,
    /// Suspicious window timed out without sufficient clears.
    Timeout = 4,
}

/// Action emitted by the contract transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DecisionAction {
    /// Emit explainability/log evidence only.
    Log = 0,
    /// Increase monitoring intensity.
    IncrMonitor = 1,
    /// Quarantine or isolate risky path.
    Quarantine = 2,
    /// Trigger a repair path.
    Repair = 3,
    /// Escalate to stronger safety handling.
    Escalate = 4,
    /// Clear suspicion and return to steady state.
    ClearSuspicion = 5,
}

/// One transition-table cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DecisionTransition {
    pub from: TsmState,
    pub event: DecisionEvent,
    pub to: TsmState,
    pub action: DecisionAction,
}

impl DecisionTransition {
    #[must_use]
    pub const fn new(
        from: TsmState,
        event: DecisionEvent,
        to: TsmState,
        action: DecisionAction,
    ) -> Self {
        Self {
            from,
            event,
            to,
            action,
        }
    }

    #[must_use]
    pub const fn with_action(self, action: DecisionAction) -> Self {
        Self { action, ..self }
    }
}

/// Exhaustive decision contract table, indexed as `[state][event]`.
pub const DECISION_CONTRACT: [[DecisionTransition; EVENT_COUNT]; STATE_COUNT] = [
    // Safe
    [
        DecisionTransition::new(
            TsmState::Safe,
            DecisionEvent::SoftAnomaly,
            TsmState::Suspicious,
            DecisionAction::IncrMonitor,
        ),
        DecisionTransition::new(
            TsmState::Safe,
            DecisionEvent::HardViolation,
            TsmState::Unsafe,
            DecisionAction::Quarantine,
        ),
        DecisionTransition::new(
            TsmState::Safe,
            DecisionEvent::CheckPass,
            TsmState::Safe,
            DecisionAction::Log,
        ),
        DecisionTransition::new(
            TsmState::Safe,
            DecisionEvent::RepairComplete,
            TsmState::Safe,
            DecisionAction::Log,
        ),
        DecisionTransition::new(
            TsmState::Safe,
            DecisionEvent::Timeout,
            TsmState::Safe,
            DecisionAction::Log,
        ),
    ],
    // Suspicious
    [
        DecisionTransition::new(
            TsmState::Suspicious,
            DecisionEvent::SoftAnomaly,
            TsmState::Suspicious,
            DecisionAction::IncrMonitor,
        ),
        DecisionTransition::new(
            TsmState::Suspicious,
            DecisionEvent::HardViolation,
            TsmState::Unsafe,
            DecisionAction::Quarantine,
        ),
        DecisionTransition::new(
            TsmState::Suspicious,
            DecisionEvent::CheckPass,
            TsmState::Suspicious,
            DecisionAction::IncrMonitor,
        ),
        DecisionTransition::new(
            TsmState::Suspicious,
            DecisionEvent::RepairComplete,
            TsmState::Safe,
            DecisionAction::ClearSuspicion,
        ),
        DecisionTransition::new(
            TsmState::Suspicious,
            DecisionEvent::Timeout,
            TsmState::Unsafe,
            DecisionAction::Escalate,
        ),
    ],
    // Unsafe
    [
        DecisionTransition::new(
            TsmState::Unsafe,
            DecisionEvent::SoftAnomaly,
            TsmState::Unsafe,
            DecisionAction::Escalate,
        ),
        DecisionTransition::new(
            TsmState::Unsafe,
            DecisionEvent::HardViolation,
            TsmState::Unsafe,
            DecisionAction::Escalate,
        ),
        DecisionTransition::new(
            TsmState::Unsafe,
            DecisionEvent::CheckPass,
            TsmState::Unsafe,
            DecisionAction::Repair,
        ),
        DecisionTransition::new(
            TsmState::Unsafe,
            DecisionEvent::RepairComplete,
            TsmState::Safe,
            DecisionAction::ClearSuspicion,
        ),
        DecisionTransition::new(
            TsmState::Unsafe,
            DecisionEvent::Timeout,
            TsmState::Unsafe,
            DecisionAction::Escalate,
        ),
    ],
];

/// Lookup one transition table cell.
#[must_use]
pub const fn transition(state: TsmState, event: DecisionEvent) -> DecisionTransition {
    DECISION_CONTRACT[state as usize][event as usize]
}

/// Mode-aware action projection.
///
/// Strict/off modes keep transition tracking but project active actions to log-only.
#[must_use]
pub const fn effective_action_for_mode(
    action: DecisionAction,
    mode: SafetyLevel,
) -> DecisionAction {
    match mode {
        SafetyLevel::Hardened => action,
        SafetyLevel::Strict | SafetyLevel::Off => DecisionAction::Log,
    }
}

const fn verify_no_unhandled_events() -> bool {
    let mut state_idx = 0;
    while state_idx < STATE_COUNT {
        let mut event_idx = 0;
        while event_idx < EVENT_COUNT {
            let t = DECISION_CONTRACT[state_idx][event_idx];
            if t.from as usize != state_idx || t.event as usize != event_idx {
                return false;
            }
            event_idx += 1;
        }
        state_idx += 1;
    }
    true
}

const fn verify_monotonic_unsafe_gate() -> bool {
    let mut event_idx = 0;
    while event_idx < EVENT_COUNT {
        let event = match event_idx {
            0 => DecisionEvent::SoftAnomaly,
            1 => DecisionEvent::HardViolation,
            2 => DecisionEvent::CheckPass,
            3 => DecisionEvent::RepairComplete,
            _ => DecisionEvent::Timeout,
        };
        let t = DECISION_CONTRACT[TsmState::Unsafe as usize][event_idx];
        if !matches!(event, DecisionEvent::RepairComplete) && !matches!(t.to, TsmState::Unsafe) {
            return false;
        }
        event_idx += 1;
    }
    true
}

const fn verify_path_to_safe_from(start: TsmState) -> bool {
    let mut reachable = [false; STATE_COUNT];
    reachable[start as usize] = true;

    let mut rounds = 0;
    while rounds < STATE_COUNT {
        let mut state_idx = 0;
        while state_idx < STATE_COUNT {
            if reachable[state_idx] {
                let mut event_idx = 0;
                while event_idx < EVENT_COUNT {
                    let to = DECISION_CONTRACT[state_idx][event_idx].to as usize;
                    reachable[to] = true;
                    event_idx += 1;
                }
            }
            state_idx += 1;
        }
        rounds += 1;
    }

    reachable[TsmState::Safe as usize]
}

/// Compile-time contract invariant verification.
#[must_use]
pub const fn verify_contract() -> bool {
    verify_no_unhandled_events()
        && verify_monotonic_unsafe_gate()
        && verify_path_to_safe_from(TsmState::Safe)
        && verify_path_to_safe_from(TsmState::Suspicious)
        && verify_path_to_safe_from(TsmState::Unsafe)
}

const _: () = {
    assert!(verify_contract());
};

/// Runtime tracker for decision-contract state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionContractMachine {
    state: TsmState,
    suspicious_pass_streak: u16,
    suspicious_clear_threshold: u16,
}

impl Default for DecisionContractMachine {
    fn default() -> Self {
        Self::new(DEFAULT_CLEAR_THRESHOLD)
    }
}

impl DecisionContractMachine {
    #[must_use]
    pub const fn new(suspicious_clear_threshold: u16) -> Self {
        Self {
            state: TsmState::Safe,
            suspicious_pass_streak: 0,
            suspicious_clear_threshold: if suspicious_clear_threshold == 0 {
                1
            } else {
                suspicious_clear_threshold
            },
        }
    }

    #[must_use]
    pub const fn state(self) -> TsmState {
        self.state
    }

    #[must_use]
    pub const fn suspicious_pass_streak(self) -> u16 {
        self.suspicious_pass_streak
    }

    #[must_use]
    pub const fn suspicious_clear_threshold(self) -> u16 {
        self.suspicious_clear_threshold
    }

    /// Observe an event and apply one contract transition.
    ///
    /// Suspicious-state clearing requires N consecutive `CheckPass` events where
    /// N is `suspicious_clear_threshold`.
    #[must_use]
    pub fn observe(&mut self, event: DecisionEvent, mode: SafetyLevel) -> DecisionTransition {
        let mut next = transition(self.state, event);

        if matches!(self.state, TsmState::Suspicious) && matches!(event, DecisionEvent::CheckPass) {
            self.suspicious_pass_streak = self.suspicious_pass_streak.saturating_add(1);
            if self.suspicious_pass_streak >= self.suspicious_clear_threshold {
                self.suspicious_pass_streak = 0;
                next = DecisionTransition::new(
                    TsmState::Suspicious,
                    DecisionEvent::CheckPass,
                    TsmState::Safe,
                    DecisionAction::ClearSuspicion,
                );
            }
        } else {
            self.suspicious_pass_streak = 0;
        }

        self.state = next.to;
        next.with_action(effective_action_for_mode(next.action, mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_exhaustive_for_all_state_event_pairs() {
        for (state_idx, row) in DECISION_CONTRACT.iter().enumerate() {
            for (event_idx, t) in row.iter().copied().enumerate() {
                assert_eq!(t.from as usize, state_idx);
                assert_eq!(t.event as usize, event_idx);
            }
        }
    }

    #[test]
    fn contract_invariants_hold() {
        assert!(verify_contract());
    }

    #[test]
    fn unsafe_requires_repaircomplete_for_safe_transition() {
        for t in DECISION_CONTRACT[TsmState::Unsafe as usize].iter().copied() {
            let event = t.event;
            if matches!(event, DecisionEvent::RepairComplete) {
                assert_eq!(t.to, TsmState::Safe);
            } else {
                assert_eq!(t.to, TsmState::Unsafe);
            }
        }
    }

    #[test]
    fn suspicious_requires_n_check_passes_to_clear() {
        let mut machine = DecisionContractMachine::new(3);
        assert_eq!(
            machine
                .observe(DecisionEvent::SoftAnomaly, SafetyLevel::Hardened)
                .to,
            TsmState::Suspicious
        );

        assert_eq!(
            machine
                .observe(DecisionEvent::CheckPass, SafetyLevel::Hardened)
                .to,
            TsmState::Suspicious
        );
        assert_eq!(
            machine
                .observe(DecisionEvent::CheckPass, SafetyLevel::Hardened)
                .to,
            TsmState::Suspicious
        );
        let last = machine.observe(DecisionEvent::CheckPass, SafetyLevel::Hardened);
        assert_eq!(last.to, TsmState::Safe);
        assert_eq!(last.action, DecisionAction::ClearSuspicion);
    }

    #[test]
    fn strict_mode_projects_to_log_actions() {
        let mut machine = DecisionContractMachine::new(1);
        let t = machine.observe(DecisionEvent::SoftAnomaly, SafetyLevel::Strict);
        assert_eq!(t.action, DecisionAction::Log);
        assert_eq!(t.to, TsmState::Suspicious);
    }

    #[test]
    fn hardened_mode_keeps_contract_actions() {
        let mut machine = DecisionContractMachine::new(1);
        let t = machine.observe(DecisionEvent::SoftAnomaly, SafetyLevel::Hardened);
        assert_eq!(t.action, DecisionAction::IncrMonitor);
    }

    #[test]
    fn timeout_escalates_suspicious_to_unsafe() {
        let mut machine = DecisionContractMachine::new(3);
        let _ = machine.observe(DecisionEvent::SoftAnomaly, SafetyLevel::Hardened);
        let t = machine.observe(DecisionEvent::Timeout, SafetyLevel::Hardened);
        assert_eq!(t.to, TsmState::Unsafe);
        assert_eq!(t.action, DecisionAction::Escalate);
    }

    #[test]
    fn repair_complete_clears_unsafe_state() {
        let mut machine = DecisionContractMachine::new(2);
        let _ = machine.observe(DecisionEvent::HardViolation, SafetyLevel::Hardened);
        assert_eq!(machine.state(), TsmState::Unsafe);
        let t = machine.observe(DecisionEvent::RepairComplete, SafetyLevel::Hardened);
        assert_eq!(t.to, TsmState::Safe);
        assert_eq!(t.action, DecisionAction::ClearSuspicion);
    }
}
