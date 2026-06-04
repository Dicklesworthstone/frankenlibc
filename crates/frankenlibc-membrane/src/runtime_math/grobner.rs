//! Table-driven normal-form reduction (Grobner-style).
//!
//! This module is intentionally runtime-light:
//! - No Grobner basis computation at runtime.
//! - Only applies an oriented reduction table (rewrite rules).
//! - Deterministic, bounded-time, and allocation-free.
//!
//! v1 implementation treats a signature as a boolean monomial represented by a bitset:
//! each variable is a bit, and a monomial is the bitwise OR of its variables.
//!
//! Reduction rule semantics:
//! - `lhs` matches when all bits in `lhs` are present in the current mask.
//! - applying a rule replaces `lhs` bits with `rhs` bits:
//!   `mask := (mask & ~lhs) | rhs`
//!
//! Termination and confluence are policy responsibilities:
//! - When rules are extracted from a Grobner basis with a fixed term order, the reduction
//!   is confluent and terminates.
//! - We still enforce a hard step budget to bound time in the face of malformed policies.

/// Bitset type used for monomial/signature representation (up to 128 variables).
pub type MonomialMask = u128;

/// One oriented reduction rule: `lhs -> rhs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReductionRule {
    pub lhs: MonomialMask,
    pub rhs: MonomialMask,
}

impl ReductionRule {
    #[inline]
    #[must_use]
    pub const fn matches(&self, mask: MonomialMask) -> bool {
        self.lhs != 0 && (mask & self.lhs) == self.lhs
    }

    #[inline]
    #[must_use]
    pub const fn apply(&self, mask: MonomialMask) -> MonomialMask {
        (mask & !self.lhs) | self.rhs
    }
}

/// Reduction statistics (useful for tests/telemetry).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReduceStats {
    /// How many successful rewrites were applied.
    pub steps: u32,
    /// Whether reduction reached a fixed point within the step limit.
    pub reached_fixpoint: bool,
}

/// Reduction errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReduceError {
    /// The rule set did not converge within the configured step budget.
    StepLimitExceeded { steps: u32 },
}

/// Default maximum number of successful rewrites permitted per reduction.
///
/// This is a safety belt, not a claim about required iterations for well-formed policies.
pub const DEFAULT_STEP_LIMIT: u32 = 1024;

/// Reduce a monomial/signature mask to normal form using the provided rule table.
///
/// Returns the reduced mask and reduction stats.
pub fn reduce_mask_with_limit(
    mut mask: MonomialMask,
    rules: &[ReductionRule],
    step_limit: u32,
) -> Result<(MonomialMask, ReduceStats), ReduceError> {
    let mut steps = 0_u32;

    loop {
        let mut changed = false;

        for rule in rules {
            if !rule.matches(mask) {
                continue;
            }

            let next = rule.apply(mask);
            if next == mask {
                continue;
            }

            mask = next;
            changed = true;
            steps = steps.saturating_add(1);

            if steps >= step_limit {
                return Err(ReduceError::StepLimitExceeded { steps });
            }
        }

        if !changed {
            break;
        }
    }

    Ok((
        mask,
        ReduceStats {
            steps,
            reached_fixpoint: true,
        },
    ))
}

/// Reduce using the default step limit.
#[inline]
pub fn reduce_mask(
    mask: MonomialMask,
    rules: &[ReductionRule],
) -> Result<MonomialMask, ReduceError> {
    Ok(reduce_mask_with_limit(mask, rules, DEFAULT_STEP_LIMIT)?.0)
}

// ── Canonical root-cause classification ──────────────────────────────────
//
// The 6 latent causes from sparse recovery map to monomial bits:
//   bit 0 (C0): temporal/provenance
//   bit 1 (C1): tail-latency/congestion
//   bit 2 (C2): topological/path-complexity
//   bit 3 (C3): transition/regime-shift
//   bit 4 (C4): numeric/floating exceptional
//   bit 5 (C5): resource-admissibility
//
// The reduction rules below form a confluent, terminating rewrite system
// (a Gröbner basis under degree-lex order over 6 boolean variables) that
// collapses co-occurring causes to their canonical root:
//
//   c0 ∧ c3 → c3   (temporal subsumed by regime-shift)
//   c1 ∧ c4 → c1   (numeric subsumed by congestion)
//   c2 ∧ c5 → c5   (topology subsumed by admissibility)

/// Bit for latent cause 0: temporal/provenance.
pub const C0_TEMPORAL: MonomialMask = 1 << 0;
/// Bit for latent cause 1: tail-latency/congestion.
pub const C1_CONGESTION: MonomialMask = 1 << 1;
/// Bit for latent cause 2: topological/path-complexity.
pub const C2_TOPOLOGICAL: MonomialMask = 1 << 2;
/// Bit for latent cause 3: transition/regime-shift.
pub const C3_REGIME: MonomialMask = 1 << 3;
/// Bit for latent cause 4: numeric/floating exceptional.
pub const C4_NUMERIC: MonomialMask = 1 << 4;
/// Bit for latent cause 5: resource-admissibility.
pub const C5_ADMISSIBILITY: MonomialMask = 1 << 5;

/// Number of latent causes tracked by sparse recovery.
pub const NUM_LATENT_CAUSES: usize = 6;

/// Oriented reduction rules for canonical root-cause classification.
///
/// These are confluent and terminating (each rule strictly decreases the
/// degree under lex order since `rhs` is a proper subset of `lhs`).
#[cfg(test)]
const CANONICAL_RULES: [ReductionRule; 3] = [
    // temporal + regime-shift → regime-shift
    ReductionRule {
        lhs: C0_TEMPORAL | C3_REGIME,
        rhs: C3_REGIME,
    },
    // congestion + numeric → congestion
    ReductionRule {
        lhs: C1_CONGESTION | C4_NUMERIC,
        rhs: C1_CONGESTION,
    },
    // topological + admissibility → admissibility
    ReductionRule {
        lhs: C2_TOPOLOGICAL | C5_ADMISSIBILITY,
        rhs: C5_ADMISSIBILITY,
    },
];

/// Canonical class IDs (compact u8 for telemetry).
pub const CANONICAL_CLASS_NONE: u8 = 0;
pub const CANONICAL_CLASS_TEMPORAL: u8 = 1;
pub const CANONICAL_CLASS_CONGESTION: u8 = 2;
pub const CANONICAL_CLASS_TOPOLOGICAL: u8 = 3;
pub const CANONICAL_CLASS_REGIME: u8 = 4;
pub const CANONICAL_CLASS_NUMERIC: u8 = 5;
pub const CANONICAL_CLASS_ADMISSIBILITY: u8 = 6;
pub const CANONICAL_CLASS_COMPOUND: u8 = 7;

/// Number of canonical class bins (for per-class counting).
pub const NUM_CANONICAL_CLASSES: usize = 8;

/// Convert a sparse-recovery support vector to a canonical class ID.
///
/// Takes a boolean array indicating which latent causes are active
/// (above the support threshold), reduces the corresponding monomial
/// mask via the Gröbner reduction table, and returns a compact class ID.
#[must_use]
pub fn canonical_class_from_support(active: &[bool; NUM_LATENT_CAUSES]) -> u8 {
    let mask = support_mask(active);
    if mask == 0 {
        return CANONICAL_CLASS_NONE;
    }

    canonical_id_from_reduced(canonical_reduce_mask(mask))
}

#[inline]
#[must_use]
fn support_mask(active: &[bool; NUM_LATENT_CAUSES]) -> MonomialMask {
    let mut mask: MonomialMask = 0;
    if active[0] {
        mask |= C0_TEMPORAL;
    }
    if active[1] {
        mask |= C1_CONGESTION;
    }
    if active[2] {
        mask |= C2_TOPOLOGICAL;
    }
    if active[3] {
        mask |= C3_REGIME;
    }
    if active[4] {
        mask |= C4_NUMERIC;
    }
    if active[5] {
        mask |= C5_ADMISSIBILITY;
    }
    mask
}

#[inline]
#[must_use]
fn canonical_reduce_mask(mut mask: MonomialMask) -> MonomialMask {
    if (mask & (C0_TEMPORAL | C3_REGIME)) == (C0_TEMPORAL | C3_REGIME) {
        mask = (mask & !(C0_TEMPORAL | C3_REGIME)) | C3_REGIME;
    }
    if (mask & (C1_CONGESTION | C4_NUMERIC)) == (C1_CONGESTION | C4_NUMERIC) {
        mask = (mask & !(C1_CONGESTION | C4_NUMERIC)) | C1_CONGESTION;
    }
    if (mask & (C2_TOPOLOGICAL | C5_ADMISSIBILITY)) == (C2_TOPOLOGICAL | C5_ADMISSIBILITY) {
        mask = (mask & !(C2_TOPOLOGICAL | C5_ADMISSIBILITY)) | C5_ADMISSIBILITY;
    }
    mask
}

/// Map a reduced monomial mask to a compact canonical class ID.
#[must_use]
fn canonical_id_from_reduced(mask: MonomialMask) -> u8 {
    match mask {
        0 => CANONICAL_CLASS_NONE,
        m if m == C0_TEMPORAL => CANONICAL_CLASS_TEMPORAL,
        m if m == C1_CONGESTION => CANONICAL_CLASS_CONGESTION,
        m if m == C2_TOPOLOGICAL => CANONICAL_CLASS_TOPOLOGICAL,
        m if m == C3_REGIME => CANONICAL_CLASS_REGIME,
        m if m == C4_NUMERIC => CANONICAL_CLASS_NUMERIC,
        m if m == C5_ADMISSIBILITY => CANONICAL_CLASS_ADMISSIBILITY,
        _ => CANONICAL_CLASS_COMPOUND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: MonomialMask = 1u128 << 0;
    const B: MonomialMask = 1u128 << 1;
    const C: MonomialMask = 1u128 << 2;
    const D: MonomialMask = 1u128 << 3;

    #[test]
    fn drops_redundant_atom() {
        // a*b -> a
        let rules = [ReductionRule { lhs: A | B, rhs: A }];
        let (out, stats) = reduce_mask_with_limit(A | B, &rules, 16).unwrap();
        assert_eq!(out, A);
        assert!(stats.steps >= 1);
    }

    #[test]
    fn supports_chained_rewrites() {
        // a*b -> a, a -> c
        let rules = [
            ReductionRule { lhs: A | B, rhs: A },
            ReductionRule { lhs: A, rhs: C },
        ];
        let out = reduce_mask(A | B, &rules).unwrap();
        assert_eq!(out, C);
    }

    #[test]
    fn preserves_unrelated_bits() {
        // a -> c, but d remains.
        let rules = [ReductionRule { lhs: A, rhs: C }];
        let out = reduce_mask(A | D, &rules).unwrap();
        assert_eq!(out, C | D);
    }

    #[test]
    fn ignores_zero_lhs_rule() {
        // lhs=0 is invalid; it must not match everything.
        let rules = [
            ReductionRule { lhs: 0, rhs: C },
            ReductionRule { lhs: A, rhs: B },
        ];
        let out = reduce_mask(A, &rules).unwrap();
        assert_eq!(out, B);
    }

    #[test]
    fn detects_non_converging_rules_via_step_limit() {
        // a <-> b ping-pong. With a strict step budget, this should error.
        let rules = [
            ReductionRule { lhs: A, rhs: B },
            ReductionRule { lhs: B, rhs: A },
        ];

        let err = reduce_mask_with_limit(A, &rules, 8).unwrap_err();
        assert_eq!(err, ReduceError::StepLimitExceeded { steps: 8 });
    }

    // ── Canonical root-cause classification tests ──

    #[test]
    fn no_active_causes_yields_none() {
        let active = [false; NUM_LATENT_CAUSES];
        assert_eq!(canonical_class_from_support(&active), CANONICAL_CLASS_NONE);
    }

    #[test]
    fn single_cause_maps_to_itself() {
        for (i, expected) in [
            CANONICAL_CLASS_TEMPORAL,
            CANONICAL_CLASS_CONGESTION,
            CANONICAL_CLASS_TOPOLOGICAL,
            CANONICAL_CLASS_REGIME,
            CANONICAL_CLASS_NUMERIC,
            CANONICAL_CLASS_ADMISSIBILITY,
        ]
        .iter()
        .enumerate()
        {
            let mut active = [false; NUM_LATENT_CAUSES];
            active[i] = true;
            assert_eq!(
                canonical_class_from_support(&active),
                *expected,
                "single cause {} should yield class {}",
                i,
                expected
            );
        }
    }

    #[test]
    fn temporal_plus_regime_reduces_to_regime() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[0] = true; // c0 temporal
        active[3] = true; // c3 regime
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_REGIME
        );
    }

    #[test]
    fn congestion_plus_numeric_reduces_to_congestion() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[1] = true; // c1 congestion
        active[4] = true; // c4 numeric
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_CONGESTION
        );
    }

    #[test]
    fn topological_plus_admissibility_reduces_to_admissibility() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[2] = true; // c2 topological
        active[5] = true; // c5 admissibility
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_ADMISSIBILITY
        );
    }

    #[test]
    fn unrelated_pair_yields_compound() {
        let mut active = [false; NUM_LATENT_CAUSES];
        active[0] = true; // c0 temporal
        active[1] = true; // c1 congestion
        // No rule reduces c0+c1, so it stays compound.
        assert_eq!(
            canonical_class_from_support(&active),
            CANONICAL_CLASS_COMPOUND
        );
    }

    #[test]
    fn all_active_reduces_via_chained_rules() {
        let active = [true; NUM_LATENT_CAUSES];
        let cls = canonical_class_from_support(&active);
        // After reduction: c0|c3 → c3, c1|c4 → c1, c2|c5 → c5
        // Remaining: c1|c3|c5 → compound (3 irreducible causes).
        assert_eq!(cls, CANONICAL_CLASS_COMPOUND);
    }

    // ── bd-3ld: Canonicalization stability and cost proofs ──

    #[test]
    fn equivalent_signatures_reduce_to_same_normal_form() {
        // Signatures that differ only in ordering of cause activation
        // must produce identical canonical classes.
        // Both {c0,c3} and {c3,c0} (same set) should yield REGIME.
        let mut a1 = [false; NUM_LATENT_CAUSES];
        a1[0] = true;
        a1[3] = true;
        let mut a2 = [false; NUM_LATENT_CAUSES];
        a2[3] = true;
        a2[0] = true;
        assert_eq!(
            canonical_class_from_support(&a1),
            canonical_class_from_support(&a2)
        );

        // {c1,c4} and {c4,c1} → CONGESTION.
        let mut b1 = [false; NUM_LATENT_CAUSES];
        b1[1] = true;
        b1[4] = true;
        let mut b2 = [false; NUM_LATENT_CAUSES];
        b2[4] = true;
        b2[1] = true;
        assert_eq!(
            canonical_class_from_support(&b1),
            canonical_class_from_support(&b2)
        );
    }

    #[test]
    fn reduction_is_idempotent() {
        // Applying reduce_mask to an already-reduced mask yields the same result.
        // Exhaustively test all 2^6 = 64 possible support combinations.
        for bits in 0u8..64 {
            let mut active = [false; NUM_LATENT_CAUSES];
            for (j, a) in active.iter_mut().enumerate() {
                *a = (bits >> j) & 1 == 1;
            }
            let cls1 = canonical_class_from_support(&active);
            // Construct the support vector that the canonical class implies,
            // then reduce again — must be the same class.
            let mut mask1: MonomialMask = 0;
            for (i, &a) in active.iter().enumerate() {
                if a {
                    mask1 |= 1u128 << i;
                }
            }
            let reduced1 = reduce_mask_with_limit(mask1, &CANONICAL_RULES, 16)
                .map(|(m, _)| m)
                .unwrap_or(mask1);
            let reduced2 = reduce_mask_with_limit(reduced1, &CANONICAL_RULES, 16)
                .map(|(m, _)| m)
                .unwrap_or(reduced1);
            assert_eq!(
                reduced1, reduced2,
                "Idempotency failed for bits={:#08b}: first={:#b}, second={:#b}",
                bits, reduced1, reduced2
            );
            // Also verify the class ID is the same.
            assert_eq!(
                cls1,
                canonical_id_from_reduced(reduced2),
                "Class mismatch after double reduction for bits={:#08b}",
                bits
            );
        }
    }

    #[test]
    fn confluence_all_64_support_patterns() {
        // Every support pattern must converge (no StepLimitExceeded).
        for bits in 0u8..64 {
            let mut mask: MonomialMask = 0;
            for j in 0..NUM_LATENT_CAUSES {
                if (bits >> j) & 1 == 1 {
                    mask |= 1u128 << j;
                }
            }
            let result = reduce_mask_with_limit(mask, &CANONICAL_RULES, 16);
            assert!(
                result.is_ok(),
                "Reduction did not converge for bits={:#08b}",
                bits
            );
            let (_, stats) = result.unwrap();
            assert!(
                stats.reached_fixpoint,
                "Did not reach fixpoint for bits={:#08b}",
                bits
            );
            // Each rule fires at most once (3 rules, each strictly reduces degree).
            assert!(
                stats.steps <= 3,
                "Took {} steps for bits={:#08b}, expected ≤3",
                stats.steps,
                bits
            );
        }
    }

    #[test]
    fn canonical_fast_path_matches_reducer_all_64_patterns() {
        for bits in 0u8..64 {
            let mut active = [false; NUM_LATENT_CAUSES];
            for (j, a) in active.iter_mut().enumerate() {
                *a = (bits >> j) & 1 == 1;
            }

            let mut mask: MonomialMask = 0;
            for j in 0..NUM_LATENT_CAUSES {
                if (bits >> j) & 1 == 1 {
                    mask |= 1u128 << j;
                }
            }

            let generic = reduce_mask_with_limit(mask, &CANONICAL_RULES, 16)
                .map(|(m, _)| canonical_id_from_reduced(m))
                .unwrap_or_else(|_| canonical_id_from_reduced(mask));
            assert_eq!(canonical_class_from_support(&active), generic);
        }
    }

    #[test]
    fn bounded_runtime_canonical_classification() {
        // 100k classifications must complete in bounded time (< 50ms).
        let start = std::time::Instant::now();
        let mut checksum = 0u64;
        for i in 0u32..100_000 {
            let bits = (i % 64) as u8;
            let mut active = [false; NUM_LATENT_CAUSES];
            for (j, a) in active.iter_mut().enumerate() {
                *a = (bits >> j) & 1 == 1;
            }
            checksum += u64::from(canonical_class_from_support(&active));
        }
        let elapsed = start.elapsed();
        // Prevent optimizer from eliding the loop.
        assert!(checksum > 0);
        assert!(
            elapsed.as_millis() < 200,
            "100k canonical classifications took {}ms (expected <200ms in debug)",
            elapsed.as_millis()
        );
    }

    #[test]
    fn reducer_is_o1_with_canonical_table() {
        // Since there are only 3 rules and each fires at most once,
        // reduction is O(1) regardless of mask value. Verify that the
        // maximum steps across all 64 patterns is ≤3.
        let mut max_steps = 0u32;
        for bits in 0u8..64 {
            let mut mask: MonomialMask = 0;
            for j in 0..NUM_LATENT_CAUSES {
                if (bits >> j) & 1 == 1 {
                    mask |= 1u128 << j;
                }
            }
            if let Ok((_, stats)) = reduce_mask_with_limit(mask, &CANONICAL_RULES, 16) {
                max_steps = max_steps.max(stats.steps);
            }
        }
        assert!(
            max_steps <= 3,
            "Max steps across all 64 patterns was {}, expected ≤3",
            max_steps
        );
    }

    #[test]
    fn perf_no_degradation_at_large_masks() {
        // Verify that reduction cost is independent of mask magnitude.
        // Even with high bits set (bits 64..127), the canonical rules
        // only touch bits 0..5 and ignore the rest.
        let big_mask: MonomialMask = (1u128 << 120) | (1u128 << 100) | C0_TEMPORAL | C3_REGIME;
        let (reduced, stats) = reduce_mask_with_limit(big_mask, &CANONICAL_RULES, 16).unwrap();
        // c0|c3 → c3, but bits 100 and 120 are preserved.
        assert_eq!(reduced, (1u128 << 120) | (1u128 << 100) | C3_REGIME);
        assert!(stats.steps <= 3);
    }

    #[test]
    fn canonical_class_covers_all_ids() {
        // Ensure all 8 canonical class IDs are reachable.
        let mut seen = [false; NUM_CANONICAL_CLASSES];
        for bits in 0u8..64 {
            let mut active = [false; NUM_LATENT_CAUSES];
            for (j, a) in active.iter_mut().enumerate() {
                *a = (bits >> j) & 1 == 1;
            }
            let cls = canonical_class_from_support(&active);
            seen[usize::from(cls)] = true;
        }
        for (id, &was_seen) in seen.iter().enumerate() {
            assert!(was_seen, "Canonical class {} was never produced", id);
        }
    }
}
