//! Self-healing policy engine.
//!
//! When the membrane detects an invalid operation, instead of crashing or
//! invoking undefined behavior, it applies a deterministic healing action.
//! Every libc function has defined healing for every class of invalid input.

use std::sync::atomic::{AtomicU64, Ordering};

/// Actions the membrane can take to heal an unsafe operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealingAction {
    /// Clamp a size/length parameter to fit within known bounds.
    ClampSize { requested: usize, clamped: usize },
    /// Truncate output and ensure null termination for string ops.
    TruncateWithNull { requested: usize, truncated: usize },
    /// Silently ignore a double-free (already freed pointer).
    IgnoreDoubleFree,
    /// Silently ignore a free of a pointer we don't own.
    IgnoreForeignFree,
    /// Treat realloc of a freed/unknown pointer as malloc.
    ReallocAsMalloc { size: usize },
    /// Return a safe default value instead of performing the operation.
    ReturnSafeDefault,
    /// Upgrade a known-unsafe function call to its safe variant.
    /// e.g., strcpy -> strncpy with bounds.
    UpgradeToSafeVariant,
    /// No healing needed — operation is valid.
    None,
}

impl HealingAction {
    /// Returns true if this action represents an actual healing (not None).
    #[must_use]
    pub const fn is_heal(&self) -> bool {
        !matches!(self, Self::None)
    }
}

/// Policy engine that decides which healing action to apply.
pub struct HealingPolicy {
    /// Total heals applied.
    pub total_heals: AtomicU64,
    /// Size clamps applied.
    pub size_clamps: AtomicU64,
    /// Null truncations applied.
    pub null_truncations: AtomicU64,
    /// Double frees ignored.
    pub double_frees: AtomicU64,
    /// Foreign frees ignored.
    pub foreign_frees: AtomicU64,
    /// Reallocs treated as malloc.
    pub realloc_as_mallocs: AtomicU64,
    /// Safe defaults returned.
    pub safe_defaults: AtomicU64,
    /// Safe variant upgrades.
    pub variant_upgrades: AtomicU64,
}

impl HealingPolicy {
    /// Create a new policy with zeroed counters.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            total_heals: AtomicU64::new(0),
            size_clamps: AtomicU64::new(0),
            null_truncations: AtomicU64::new(0),
            double_frees: AtomicU64::new(0),
            foreign_frees: AtomicU64::new(0),
            realloc_as_mallocs: AtomicU64::new(0),
            safe_defaults: AtomicU64::new(0),
            variant_upgrades: AtomicU64::new(0),
        }
    }

    /// Record a healing action.
    ///
    /// @separation-pre: `Owns(HealingCounters) * Action(action)` with frame `F`.
    /// @separation-post: `Owns(HealingCounters')` where only relevant counters advance;
    /// frame `F` is preserved.
    /// @separation-frame: `F` (non-counter memory is untouched).
    /// @separation-alias: `repair_apply`.
    pub fn record(&self, action: &HealingAction) {
        if action.is_heal() {
            self.total_heals.fetch_add(1, Ordering::Relaxed);
        }

        match action {
            HealingAction::ClampSize { .. } => {
                self.size_clamps.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::TruncateWithNull { .. } => {
                self.null_truncations.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::IgnoreDoubleFree => {
                self.double_frees.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::IgnoreForeignFree => {
                self.foreign_frees.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::ReallocAsMalloc { .. } => {
                self.realloc_as_mallocs.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::ReturnSafeDefault => {
                self.safe_defaults.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::UpgradeToSafeVariant => {
                self.variant_upgrades.fetch_add(1, Ordering::Relaxed);
            }
            HealingAction::None => {}
        }
    }

    /// Decide healing for a copy/memory operation with bounds.
    #[must_use]
    pub fn heal_copy_bounds(
        &self,
        requested: usize,
        src_remaining: Option<usize>,
        dst_remaining: Option<usize>,
    ) -> HealingAction {
        let available = match (src_remaining, dst_remaining) {
            (Some(s), Some(d)) => s.min(d),
            (Some(s), None) => s,
            (None, Some(d)) => d,
            (None, None) => return HealingAction::None,
        };

        if requested > available {
            HealingAction::ClampSize {
                requested,
                clamped: available,
            }
        } else {
            HealingAction::None
        }
    }

    /// Decide healing for a string operation with destination bounds.
    #[must_use]
    pub fn heal_string_bounds(
        &self,
        src_len: usize,
        dst_remaining: Option<usize>,
    ) -> HealingAction {
        match dst_remaining {
            Some(0) => HealingAction::ClampSize {
                requested: src_len,
                clamped: 0,
            },
            Some(remaining) if src_len >= remaining => HealingAction::TruncateWithNull {
                requested: src_len,
                truncated: remaining.saturating_sub(1), // leave room for null
            },
            _ => HealingAction::None,
        }
    }
}

impl Default for HealingPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Recommended default healing action for a Gröbner canonical root-cause class.
///
/// This maps the reduced root-cause classification from sparse recovery into
/// a deterministic healing suggestion. The mapping is advisory — callers may
/// override based on mode/context. No unsafe semantic changes are made.
#[must_use]
pub fn recommended_healing_for_canonical_class(class_id: u8) -> HealingAction {
    use crate::grobner;

    match class_id {
        grobner::CANONICAL_CLASS_NONE => HealingAction::None,
        // Temporal/provenance faults: stale data → safe defaults.
        grobner::CANONICAL_CLASS_TEMPORAL => HealingAction::ReturnSafeDefault,
        // Congestion: resource pressure → clamp sizes to relieve load.
        grobner::CANONICAL_CLASS_CONGESTION => HealingAction::ClampSize {
            requested: 0,
            clamped: 0,
        },
        // Topological complexity: complex paths → upgrade to safe variant.
        grobner::CANONICAL_CLASS_TOPOLOGICAL => HealingAction::UpgradeToSafeVariant,
        // Regime shift: transitional state → safe defaults until stable.
        grobner::CANONICAL_CLASS_REGIME => HealingAction::ReturnSafeDefault,
        // Numeric exceptional: floating-point edge cases → clamp values.
        grobner::CANONICAL_CLASS_NUMERIC => HealingAction::ClampSize {
            requested: 0,
            clamped: 0,
        },
        // Resource admissibility: constraints → upgrade to safe variant.
        grobner::CANONICAL_CLASS_ADMISSIBILITY => HealingAction::UpgradeToSafeVariant,
        // Compound (multiple irreducible causes): conservative safe default.
        _ => HealingAction::ReturnSafeDefault,
    }
}

/// Global healing policy instance.
static GLOBAL_POLICY: HealingPolicy = HealingPolicy::new();

/// Access the global healing policy.
#[must_use]
pub fn global_healing_policy() -> &'static HealingPolicy {
    &GLOBAL_POLICY
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clamp_size_when_exceeding_bounds() {
        let policy = HealingPolicy::new();
        let action = policy.heal_copy_bounds(1000, Some(500), Some(800));
        assert_eq!(
            action,
            HealingAction::ClampSize {
                requested: 1000,
                clamped: 500
            }
        );
    }

    #[test]
    fn no_heal_when_within_bounds() {
        let policy = HealingPolicy::new();
        let action = policy.heal_copy_bounds(100, Some(500), Some(800));
        assert_eq!(action, HealingAction::None);
    }

    #[test]
    fn no_heal_when_no_bounds_known() {
        let policy = HealingPolicy::new();
        let action = policy.heal_copy_bounds(1000, None, None);
        assert_eq!(action, HealingAction::None);
    }

    #[test]
    fn truncate_string_when_exceeding_dst() {
        let policy = HealingPolicy::new();
        let action = policy.heal_string_bounds(100, Some(50));
        assert_eq!(
            action,
            HealingAction::TruncateWithNull {
                requested: 100,
                truncated: 49
            }
        );
    }

    #[test]
    fn record_increments_counters() {
        let policy = HealingPolicy::new();
        policy.record(&HealingAction::IgnoreDoubleFree);
        policy.record(&HealingAction::IgnoreDoubleFree);
        policy.record(&HealingAction::ClampSize {
            requested: 10,
            clamped: 5,
        });

        assert_eq!(policy.total_heals.load(Ordering::Relaxed), 3);
        assert_eq!(policy.double_frees.load(Ordering::Relaxed), 2);
        assert_eq!(policy.size_clamps.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn none_is_not_a_heal() {
        assert!(!HealingAction::None.is_heal());
        assert!(HealingAction::IgnoreDoubleFree.is_heal());
        assert!(HealingAction::ReturnSafeDefault.is_heal());
    }

    #[test]
    fn canonical_class_none_yields_no_healing() {
        use crate::grobner::CANONICAL_CLASS_NONE;
        let action = recommended_healing_for_canonical_class(CANONICAL_CLASS_NONE);
        assert_eq!(action, HealingAction::None);
    }

    #[test]
    fn canonical_class_mapping_covers_all_classes() {
        use crate::grobner;
        for class_id in 0..grobner::NUM_CANONICAL_CLASSES as u8 {
            let action = recommended_healing_for_canonical_class(class_id);
            if class_id == grobner::CANONICAL_CLASS_NONE {
                assert!(!action.is_heal());
            } else {
                assert!(
                    action.is_heal(),
                    "Class {} should produce a healing action",
                    class_id
                );
            }
        }
    }

    #[test]
    fn canonical_class_out_of_range_returns_safe_default() {
        let action = recommended_healing_for_canonical_class(255);
        assert_eq!(action, HealingAction::ReturnSafeDefault);
    }
}
