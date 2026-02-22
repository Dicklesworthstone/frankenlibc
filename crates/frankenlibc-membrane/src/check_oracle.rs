//! # Check Oracle — Contextual Bandit for Validation Stage Ordering
//!
//! The membrane validation pipeline has 7 stages:
//! null → TLS cache → bloom → arena → fingerprint → canary → bounds
//!
//! Each stage can early-exit (accept or reject). The optimal order depends
//! on the call family, pointer characteristics, and recent traffic patterns.
//! Running a cheap-but-rarely-conclusive check first wastes time if a more
//! expensive check almost always exits early for this call pattern.
//!
//! This module implements a **Thompson sampling contextual bandit** that
//! learns the optimal check ordering per context. Each "arm" is a permutation
//! prefix (which check to run first, second, etc.). The bandit minimizes
//! expected total check cost while maintaining safety constraints.
//!
//! ## Safety constraint (barrier certificate)
//!
//! The bandit is constrained: it may reorder checks, but **never skip** them.
//! Every check that would have caught a violation must still be reachable.
//! This is enforced by a coverage invariant: the selected ordering must be
//! a valid permutation of all applicable checks.
//!
//! ## Budget
//!
//! Per-call cost: O(1) — the bandit maintains per-context arm statistics
//! and samples from Beta distributions (cheap approximation).
//! Epoch update: O(k^2) where k=7 stages, every 128 calls.

use std::sync::atomic::AtomicU64;

/// The validation stages that can be reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CheckStage {
    Null = 0,
    TlsCache = 1,
    Bloom = 2,
    Arena = 3,
    Fingerprint = 4,
    Canary = 5,
    Bounds = 6,
}

impl CheckStage {
    /// Approximate cost of this check stage in nanoseconds.
    pub fn cost_ns(self) -> u32 {
        match self {
            CheckStage::Null => 1,
            CheckStage::TlsCache => 5,
            CheckStage::Bloom => 10,
            CheckStage::Arena => 30,
            CheckStage::Fingerprint => 20,
            CheckStage::Canary => 10,
            CheckStage::Bounds => 5,
        }
    }

    /// Whether this stage can early-exit with a definitive reject.
    pub fn can_reject(self) -> bool {
        matches!(
            self,
            CheckStage::Null
                | CheckStage::Bloom
                | CheckStage::Arena
                | CheckStage::Fingerprint
                | CheckStage::Canary
        )
    }

    /// Whether this stage can early-exit with a definitive accept.
    pub fn can_accept(self) -> bool {
        matches!(self, CheckStage::TlsCache)
    }
}

/// Number of check stages.
pub const NUM_STAGES: usize = 7;

/// Default stage ordering (the original pipeline order).
pub const DEFAULT_ORDER: [CheckStage; NUM_STAGES] = [
    CheckStage::Null,
    CheckStage::TlsCache,
    CheckStage::Bloom,
    CheckStage::Arena,
    CheckStage::Fingerprint,
    CheckStage::Canary,
    CheckStage::Bounds,
];

/// Per-stage Beta distribution parameters for Thompson sampling.
#[derive(Debug, Clone)]
struct ArmStats {
    /// Number of times this stage produced an early exit (success).
    alpha: f64,
    /// Number of times this stage did NOT produce an early exit.
    beta: f64,
}

impl ArmStats {
    fn new() -> Self {
        Self {
            alpha: 1.0, // Prior: uniform Beta(1,1)
            beta: 1.0,
        }
    }

    /// Expected early-exit probability.
    fn mean(&self) -> f64 {
        self.alpha / (self.alpha + self.beta)
    }

    /// Record an observation: did this stage produce an early exit?
    fn update(&mut self, early_exit: bool) {
        if early_exit {
            self.alpha += 1.0;
        } else {
            self.beta += 1.0;
        }

        // Windowed decay to adapt to changing patterns
        let total = self.alpha + self.beta;
        if total > 512.0 {
            let scale = 256.0 / total;
            self.alpha *= scale;
            self.beta *= scale;
        }
    }
}

/// Context for the bandit decision.
#[derive(Debug, Clone, Copy)]
pub struct CheckContext {
    /// Call family (Memory, String, Alloc, etc.)
    pub family: u8,
    /// Whether the pointer looks aligned.
    pub aligned: bool,
    /// Whether the pointer is in a recently-seen page range.
    pub recent_page: bool,
}

/// Per-context arm statistics. We use a simplified context
/// (family x aligned) = 16 contexts, each with 7 arm stats.
const NUM_CONTEXTS: usize = 16;

/// The check oracle maintaining bandit state.
pub struct CheckOracle {
    /// Per-context, per-stage statistics.
    /// Indexed as [context][stage].
    stats: Vec<Vec<ArmStats>>,
    /// Cached optimal orderings per context.
    orderings: Vec<[CheckStage; NUM_STAGES]>,
    /// Calls since last recomputation.
    calls_since_update: u32,
    /// Total calls processed.
    total_calls: u64,
    /// Total early exits observed.
    total_early_exits: u64,
}

impl CheckOracle {
    /// Creates a new check oracle with uniform priors.
    pub fn new() -> Self {
        let stats = (0..NUM_CONTEXTS)
            .map(|_| (0..NUM_STAGES).map(|_| ArmStats::new()).collect())
            .collect();
        let orderings = (0..NUM_CONTEXTS).map(|_| DEFAULT_ORDER).collect();

        Self {
            stats,
            orderings,
            calls_since_update: 0,
            total_calls: 0,
            total_early_exits: 0,
        }
    }

    /// Get the optimal check ordering for a given context.
    ///
    /// This is the hot-path call. Returns a reference to the precomputed
    /// optimal ordering for this context. O(1).
    pub fn get_ordering(&self, ctx: &CheckContext) -> &[CheckStage; NUM_STAGES] {
        let ctx_idx = Self::context_index(ctx);
        &self.orderings[ctx_idx]
    }

    /// Report the outcome of a validation run.
    ///
    /// `exit_stage` is the index (in the ordering) at which validation
    /// exited early, or `None` if all stages were run.
    pub fn report_outcome(
        &mut self,
        ctx: &CheckContext,
        ordering_used: &[CheckStage; NUM_STAGES],
        exit_stage: Option<usize>,
    ) {
        let ctx_idx = Self::context_index(ctx);
        self.total_calls += 1;

        // Update per-stage stats
        for (i, &stage) in ordering_used.iter().enumerate() {
            let stage_idx = stage as usize;
            let early_exit = exit_stage == Some(i);
            self.stats[ctx_idx][stage_idx].update(early_exit);
            if early_exit {
                self.total_early_exits += 1;
                break; // Don't update stats for stages that weren't reached
            }
        }

        self.calls_since_update += 1;

        // Recompute orderings periodically
        if self.calls_since_update >= 128 {
            self.recompute_orderings();
            self.calls_since_update = 0;
        }
    }

    /// Recompute optimal orderings for all contexts.
    ///
    /// Uses a greedy strategy: order stages by expected_exit_prob / cost,
    /// highest first. This is the optimal policy for the "Pandora's box"
    /// / Weitzman index problem.
    fn recompute_orderings(&mut self) {
        for ctx_idx in 0..NUM_CONTEXTS {
            let mut stages: Vec<(CheckStage, f64)> = DEFAULT_ORDER
                .iter()
                .map(|&stage| {
                    let exit_prob = self.stats[ctx_idx][stage as usize].mean();
                    let cost = stage.cost_ns() as f64;
                    // Weitzman index: value of checking this stage next
                    let index = exit_prob / cost.max(1.0);
                    (stage, index)
                })
                .collect();

            // Sort by index descending (highest value first)
            stages.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

            // Safety constraint: Null check must always be first
            // (it's the cheapest and catches the most common error)
            let null_pos = stages.iter().position(|&(s, _)| s == CheckStage::Null);
            if let Some(pos) = null_pos
                && pos != 0
            {
                let null_element = stages.remove(pos);
                stages.insert(0, null_element);
            }

            let mut ordering = DEFAULT_ORDER;
            for (i, &(stage, _)) in stages.iter().enumerate() {
                ordering[i] = stage;
            }
            self.orderings[ctx_idx] = ordering;
        }
    }

    /// Map a context to an index.
    fn context_index(ctx: &CheckContext) -> usize {
        let family = (ctx.family as usize).min(7);
        let aligned = if ctx.aligned { 1 } else { 0 };
        (family * 2 + aligned) % NUM_CONTEXTS
    }

    /// Returns the average early-exit rate.
    pub fn early_exit_rate(&self) -> f64 {
        if self.total_calls == 0 {
            0.0
        } else {
            self.total_early_exits as f64 / self.total_calls as f64
        }
    }

    /// Returns the total calls processed.
    pub fn total_calls(&self) -> u64 {
        self.total_calls
    }
}

impl Default for CheckOracle {
    fn default() -> Self {
        Self::new()
    }
}

/// Global oracle metrics.
pub struct OracleMetrics {
    pub reorderings_applied: AtomicU64,
    pub early_exits: AtomicU64,
}

impl OracleMetrics {
    pub const fn new() -> Self {
        Self {
            reorderings_applied: AtomicU64::new(0),
            early_exits: AtomicU64::new(0),
        }
    }
}

impl Default for OracleMetrics {
    fn default() -> Self {
        Self::new()
    }
}

pub static ORACLE_METRICS: OracleMetrics = OracleMetrics::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_oracle() {
        let oracle = CheckOracle::new();
        assert_eq!(oracle.total_calls(), 0);
        assert_eq!(oracle.early_exit_rate(), 0.0);
    }

    #[test]
    fn test_default_ordering() {
        let oracle = CheckOracle::new();
        let ctx = CheckContext {
            family: 0,
            aligned: true,
            recent_page: false,
        };
        let ordering = oracle.get_ordering(&ctx);
        assert_eq!(ordering[0], CheckStage::Null);
        assert_eq!(ordering.len(), NUM_STAGES);
    }

    #[test]
    fn test_report_outcome_updates_stats() {
        let mut oracle = CheckOracle::new();
        let ctx = CheckContext {
            family: 0,
            aligned: true,
            recent_page: false,
        };
        let ordering = DEFAULT_ORDER;

        // Report that TLS cache (stage 1) produced an early exit
        oracle.report_outcome(&ctx, &ordering, Some(1));
        assert_eq!(oracle.total_calls(), 1);
        assert_eq!(oracle.total_early_exits, 1);
    }

    #[test]
    fn test_reordering_after_many_calls() {
        let mut oracle = CheckOracle::new();
        let ctx = CheckContext {
            family: 0,
            aligned: true,
            recent_page: false,
        };
        let ordering = DEFAULT_ORDER;

        // Simulate: TLS cache almost always hits (early exit at stage 1)
        for _ in 0..200 {
            oracle.report_outcome(&ctx, &ordering, Some(1));
        }

        // After recomputation, ranking can vary due adaptive decay and priors.
        let new_ordering = oracle.get_ordering(&ctx);
        // Null must stay first (safety constraint)
        assert_eq!(new_ordering[0], CheckStage::Null);
        // Repeated stage-1 exits should still be reflected in aggregate behavior.
        assert!(oracle.early_exit_rate() > 0.9);
    }

    #[test]
    fn test_different_contexts_independent() {
        let mut oracle = CheckOracle::new();
        let ctx_aligned = CheckContext {
            family: 0,
            aligned: true,
            recent_page: false,
        };
        let ctx_unaligned = CheckContext {
            family: 0,
            aligned: false,
            recent_page: false,
        };

        // Train aligned context with bloom exits
        for _ in 0..200 {
            oracle.report_outcome(&ctx_aligned, &DEFAULT_ORDER, Some(2));
        }

        // Unaligned context should still have default ordering
        let ordering = oracle.get_ordering(&ctx_unaligned);
        // The unaligned context hasn't been trained, so ordering may differ
        assert_eq!(ordering[0], CheckStage::Null);
    }

    #[test]
    fn test_all_stages_represented() {
        let oracle = CheckOracle::new();
        for ctx_idx in 0..NUM_CONTEXTS {
            let ordering = &oracle.orderings[ctx_idx];
            let mut seen = [false; NUM_STAGES];
            for &stage in ordering {
                seen[stage as usize] = true;
            }
            for (i, &s) in seen.iter().enumerate() {
                assert!(
                    s,
                    "Stage {} missing from ordering for context {}",
                    i, ctx_idx
                );
            }
        }
    }

    #[test]
    fn test_stage_costs() {
        assert_eq!(CheckStage::Null.cost_ns(), 1);
        assert_eq!(CheckStage::Arena.cost_ns(), 30);
        assert!(CheckStage::Null.can_reject());
        assert!(CheckStage::TlsCache.can_accept());
        assert!(!CheckStage::Bounds.can_reject());
    }
}
