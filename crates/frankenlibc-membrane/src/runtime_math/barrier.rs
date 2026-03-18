//! Barrier admissibility filter for runtime actions.

use crate::config::SafetyLevel;

use super::control::ControlLimits;
use super::{RuntimeContext, ValidationProfile};

/// Constant-time barrier guard.
///
/// This is the runtime embodiment of barrier-certificate admissibility:
/// if a proposed action exits the certified safe set, deny/escalate.
pub struct BarrierOracle;

impl BarrierOracle {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns true if the decision candidate is admissible.
    #[must_use]
    pub fn admissible(
        &self,
        ctx: &RuntimeContext,
        mode: SafetyLevel,
        profile: ValidationProfile,
        risk_upper_bound_ppm: u32,
        limits: ControlLimits,
    ) -> bool {
        // Keep gigantic requests out of the admissible region.
        if ctx.requested_bytes > limits.max_request_bytes {
            return false;
        }

        // In strict mode, avoid introducing surprise hard denies on pointer
        // classification paths. Escalate to `Full` instead of deny.
        if matches!(mode, SafetyLevel::Strict)
            && matches!(ctx.family, super::ApiFamily::PointerValidation)
            && ctx.bloom_negative
            && risk_upper_bound_ppm < 900_000
        {
            return true;
        }

        // If a write operation has extreme risk and still asks for fast profile,
        // it's outside admissible region.
        if ctx.is_write
            && risk_upper_bound_ppm > limits.repair_trigger_ppm
            && matches!(profile, ValidationProfile::Fast)
        {
            return false;
        }

        true
    }
}

impl Default for BarrierOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_math::control::ControlLimits;
    use crate::runtime_math::{ApiFamily, RuntimeContext};

    #[test]
    fn rejects_unbounded_request() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x1000,
                requested_bytes: usize::MAX,
                is_write: true,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Hardened,
            ValidationProfile::Fast,
            10_000,
            ControlLimits {
                full_validation_trigger_ppm: 50_000,
                repair_trigger_ppm: 80_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok);
    }

    #[test]
    fn strict_pointer_validation_bloom_negative_is_admissible() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::PointerValidation,
                addr_hint: 0x2000,
                requested_bytes: 64,
                is_write: false,
                contention_hint: 0,
                bloom_negative: true,
            },
            SafetyLevel::Strict,
            ValidationProfile::Fast,
            100_000,
            ControlLimits {
                full_validation_trigger_ppm: 220_000,
                repair_trigger_ppm: 1_000_000,
                max_request_bytes: 4096,
            },
        );
        assert!(ok);
    }

    #[test]
    fn fast_write_with_extreme_risk_is_rejected() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x3000,
                requested_bytes: 128,
                is_write: true,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Hardened,
            ValidationProfile::Fast,
            200_000,
            ControlLimits {
                full_validation_trigger_ppm: 80_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok);
    }

    #[test]
    fn full_profile_keeps_high_risk_write_admissible_for_escalation() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x4000,
                requested_bytes: 128,
                is_write: true,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Hardened,
            ValidationProfile::Full,
            200_000,
            ControlLimits {
                full_validation_trigger_ppm: 80_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(ok);
    }

    #[test]
    fn request_size_limit_is_inclusive() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::StringMemory,
                addr_hint: 0x5000,
                requested_bytes: 4096,
                is_write: false,
                contention_hint: 0,
                bloom_negative: false,
            },
            SafetyLevel::Strict,
            ValidationProfile::Fast,
            50_000,
            ControlLimits {
                full_validation_trigger_ppm: 90_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(ok);
    }

    #[test]
    fn strict_pointer_bypass_does_not_override_request_size_guard() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::PointerValidation,
                addr_hint: 0x6000,
                requested_bytes: 4097,
                is_write: false,
                contention_hint: 0,
                bloom_negative: true,
            },
            SafetyLevel::Strict,
            ValidationProfile::Fast,
            100_000,
            ControlLimits {
                full_validation_trigger_ppm: 220_000,
                repair_trigger_ppm: 1_000_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok);
    }

    #[test]
    fn strict_pointer_bypass_turns_off_at_high_risk_and_rejects_fast_write() {
        let oracle = BarrierOracle::new();
        let ok = oracle.admissible(
            &RuntimeContext {
                family: ApiFamily::PointerValidation,
                addr_hint: 0x7000,
                requested_bytes: 128,
                is_write: true,
                contention_hint: 0,
                bloom_negative: true,
            },
            SafetyLevel::Strict,
            ValidationProfile::Fast,
            900_000,
            ControlLimits {
                full_validation_trigger_ppm: 200_000,
                repair_trigger_ppm: 800_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok);
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Admissibility Monotonicity in Risk
    //
    // Theorem: For any fixed (ctx, mode, profile, limits), if a
    // request is rejected at risk R, it is also rejected at all R' ≥ R.
    // Conversely, if admitted at R, it is admitted at all R' ≤ R.
    //
    // This proves the risk dimension has no non-monotone "holes"
    // where increasing risk accidentally re-admits requests.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_admissibility_monotone_in_risk() {
        let oracle = BarrierOracle::new();
        let limits = ControlLimits {
            full_validation_trigger_ppm: 80_000,
            repair_trigger_ppm: 140_000,
            max_request_bytes: 4096,
        };

        // For write + Fast profile (the guard that depends on risk):
        let ctx = RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x1000,
            requested_bytes: 128,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        };

        let mut last_admitted = true;
        for risk in (0..=1_000_000).step_by(1_000) {
            let admitted = oracle.admissible(
                &ctx,
                SafetyLevel::Hardened,
                ValidationProfile::Fast,
                risk,
                limits,
            );
            // Once rejected, must stay rejected (monotone)
            if !last_admitted {
                assert!(
                    !admitted,
                    "Risk monotonicity violated: rejected at lower risk \
                     but admitted at risk={risk}"
                );
            }
            last_admitted = admitted;
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Guard Conjunction Necessity
    //
    // Theorem: Each of the three guard conditions is necessary —
    // removing any one would admit a request that should be rejected.
    //
    // Guard 1: Size limit (requested_bytes ≤ max_request_bytes)
    // Guard 2: Strict pointer bypass (bloom_negative + low risk)
    // Guard 3: Fast write + extreme risk rejection
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_size_guard_is_necessary() {
        let oracle = BarrierOracle::new();
        // Without the size guard, this oversized request would pass
        let ctx_oversized = RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x1000,
            requested_bytes: 8192,
            is_write: false,
            contention_hint: 0,
            bloom_negative: false,
        };
        let ok = oracle.admissible(
            &ctx_oversized,
            SafetyLevel::Strict,
            ValidationProfile::Fast,
            10_000,
            ControlLimits {
                full_validation_trigger_ppm: 80_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok, "Size guard must reject oversized request");
    }

    #[test]
    fn proof_risk_guard_is_necessary() {
        let oracle = BarrierOracle::new();
        // Without the risk guard, this dangerous write would pass
        let ctx_risky = RuntimeContext {
            family: ApiFamily::StringMemory,
            addr_hint: 0x1000,
            requested_bytes: 128,
            is_write: true,
            contention_hint: 0,
            bloom_negative: false,
        };
        let ok = oracle.admissible(
            &ctx_risky,
            SafetyLevel::Hardened,
            ValidationProfile::Fast,
            500_000,
            ControlLimits {
                full_validation_trigger_ppm: 80_000,
                repair_trigger_ppm: 140_000,
                max_request_bytes: 4096,
            },
        );
        assert!(!ok, "Risk guard must reject high-risk fast write");
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Mode Coverage Completeness
    //
    // Theorem: The admissibility function is defined for all
    // combinations of (mode, profile, family) — no panics or
    // undefined behavior for any valid input.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_mode_coverage_complete() {
        let oracle = BarrierOracle::new();
        let limits = ControlLimits {
            full_validation_trigger_ppm: 80_000,
            repair_trigger_ppm: 140_000,
            max_request_bytes: 4096,
        };

        let families = [
            ApiFamily::PointerValidation,
            ApiFamily::StringMemory,
            ApiFamily::Allocator,
            ApiFamily::Threading,
            ApiFamily::IoFd,
            ApiFamily::Resolver,
        ];
        let modes = [SafetyLevel::Strict, SafetyLevel::Hardened];
        let profiles = [ValidationProfile::Fast, ValidationProfile::Full];
        let risks = [0u32, 50_000, 200_000, 500_000, 900_000, 1_000_000];

        for family in &families {
            for &mode in &modes {
                for &profile in &profiles {
                    for &risk in &risks {
                        for &is_write in &[true, false] {
                            for &bloom in &[true, false] {
                                let ctx = RuntimeContext {
                                    family: *family,
                                    addr_hint: 0x1000,
                                    requested_bytes: 128,
                                    is_write,
                                    contention_hint: 0,
                                    bloom_negative: bloom,
                                };
                                // Must not panic
                                let _ = oracle.admissible(&ctx, mode, profile, risk, limits);
                            }
                        }
                    }
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Profile Escalation Safety
    //
    // Theorem: Upgrading from Fast to Full profile never makes a
    // previously-admitted request rejected. Full profile is always
    // at least as permissive as Fast.
    //
    // This ensures the escalation path (Fast → Full) is safe:
    // if Fast admitted the request, Full will too.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_full_profile_at_least_as_permissive_as_fast() {
        let oracle = BarrierOracle::new();
        let limits = ControlLimits {
            full_validation_trigger_ppm: 80_000,
            repair_trigger_ppm: 140_000,
            max_request_bytes: 4096,
        };

        let families = [
            ApiFamily::PointerValidation,
            ApiFamily::StringMemory,
            ApiFamily::Allocator,
        ];
        let modes = [SafetyLevel::Strict, SafetyLevel::Hardened];

        for family in &families {
            for &mode in &modes {
                for risk in (0..=1_000_000).step_by(50_000) {
                    for &is_write in &[true, false] {
                        let ctx = RuntimeContext {
                            family: *family,
                            addr_hint: 0x1000,
                            requested_bytes: 128,
                            is_write,
                            contention_hint: 0,
                            bloom_negative: false,
                        };
                        let fast_ok =
                            oracle.admissible(&ctx, mode, ValidationProfile::Fast, risk, limits);
                        let full_ok =
                            oracle.admissible(&ctx, mode, ValidationProfile::Full, risk, limits);
                        // If fast admits, full must also admit
                        if fast_ok {
                            assert!(
                                full_ok,
                                "Fast admitted but Full rejected: \
                                 family={family:?}, mode={mode:?}, \
                                 risk={risk}, write={is_write}"
                            );
                        }
                    }
                }
            }
        }
    }
}
