//! Self-healing policy engine.
//!
//! When the membrane detects an invalid operation, instead of crashing or
//! invoking undefined behavior, it applies a deterministic healing action.
//! Every libc function has defined healing for every class of invalid input.

use crate::ids::{DecisionId, MEMBRANE_SCHEMA_VERSION};
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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

const HEALING_LOG_CAPACITY: usize = 1024;
const HEALING_BEAD_ID: &str = "bd-32e.4";

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
    /// Whether structured healing logging is enabled.
    healing_logging_enabled: AtomicBool,
    /// Monotone decision id for healing evidence rows.
    healing_log_decision_seq: AtomicU64,
    /// Bounded JSONL healing evidence ring buffer.
    healing_logs: Mutex<VecDeque<String>>,
}

impl HealingPolicy {
    /// Create a new policy with zeroed counters.
    #[must_use]
    pub fn new() -> Self {
        let logging_enabled = heal_logging_enabled_by_default();
        Self {
            total_heals: AtomicU64::new(0),
            size_clamps: AtomicU64::new(0),
            null_truncations: AtomicU64::new(0),
            double_frees: AtomicU64::new(0),
            foreign_frees: AtomicU64::new(0),
            realloc_as_mallocs: AtomicU64::new(0),
            safe_defaults: AtomicU64::new(0),
            variant_upgrades: AtomicU64::new(0),
            healing_logging_enabled: AtomicBool::new(logging_enabled),
            healing_log_decision_seq: AtomicU64::new(0),
            healing_logs: Mutex::new(VecDeque::with_capacity(HEALING_LOG_CAPACITY)),
        }
    }

    /// Enable or disable structured healing evidence logging.
    pub fn set_healing_logging_enabled(&self, enabled: bool) {
        self.healing_logging_enabled
            .store(enabled, Ordering::Relaxed);
    }

    /// Clear buffered healing evidence rows.
    pub fn clear_healing_logs(&self) {
        self.healing_logs.lock().clear();
    }

    /// Export buffered healing evidence as deterministic JSONL.
    #[must_use]
    pub fn export_healing_log_jsonl(&self) -> String {
        self.healing_logs
            .lock()
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n")
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

        self.emit_healing_log(action);
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

    fn emit_healing_log(&self, action: &HealingAction) {
        if !action.is_heal() || !self.healing_logging_enabled.load(Ordering::Relaxed) {
            return;
        }

        let decision_id = DecisionId::from_raw(
            self.healing_log_decision_seq
                .fetch_add(1, Ordering::Relaxed)
                + 1,
        );
        let level = healing_log_level(action);
        let escalated = healing_action_escalated(action);
        let trace_id = decision_id.scoped_trace_id("membrane::heal");

        // Emit to unified evidence ledger for cross-stream correlation.
        crate::evidence_ledger::global_evidence_ledger().record_healing(
            action,
            trace_id.clone(),
            decision_id,
            "membrane-heal",
            "",
        );

        let line = format!(
            "{{\"trace_id\":\"{trace_id}\",\"decision_id\":{},\"schema_version\":\"{}\",\
\"bead_id\":\"{HEALING_BEAD_ID}\",\"runtime_mode\":\"{}\",\"level\":\"{level}\",\
\"api_family\":\"membrane-heal\",\"decision_path\":\"record\",\"outcome\":\"repair\",\
\"healing_action\":\"{}\",\"escalated\":{escalated},\"details\":{}}}",
            decision_id.as_u64(),
            MEMBRANE_SCHEMA_VERSION,
            runtime_mode_label(),
            healing_action_name(action),
            healing_action_details_json(action)
        );
        self.push_healing_log_line(line);
    }

    fn push_healing_log_line(&self, line: String) {
        let mut logs = self.healing_logs.lock();
        while logs.len() >= HEALING_LOG_CAPACITY {
            let _ = logs.pop_front();
        }
        logs.push_back(line);
    }
}

impl Default for HealingPolicy {
    fn default() -> Self {
        Self::new()
    }
}

fn heal_logging_enabled_by_default() -> bool {
    match std::env::var("FRANKENLIBC_HEAL_LOG") {
        Ok(value) => !matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "off" | "no"
        ),
        Err(_) => true,
    }
}

fn healing_log_level(action: &HealingAction) -> &'static str {
    if healing_action_escalated(action) {
        "warn"
    } else {
        "info"
    }
}

fn healing_action_escalated(action: &HealingAction) -> bool {
    matches!(
        action,
        HealingAction::ReturnSafeDefault | HealingAction::UpgradeToSafeVariant
    )
}

fn runtime_mode_label() -> &'static str {
    match crate::config::safety_level() {
        crate::config::SafetyLevel::Strict => "strict",
        crate::config::SafetyLevel::Hardened => "hardened",
        crate::config::SafetyLevel::Off => "off",
    }
}

fn healing_action_name(action: &HealingAction) -> &'static str {
    match action {
        HealingAction::ClampSize { .. } => "ClampSize",
        HealingAction::TruncateWithNull { .. } => "TruncateWithNull",
        HealingAction::IgnoreDoubleFree => "IgnoreDoubleFree",
        HealingAction::IgnoreForeignFree => "IgnoreForeignFree",
        HealingAction::ReallocAsMalloc { .. } => "ReallocAsMalloc",
        HealingAction::ReturnSafeDefault => "ReturnSafeDefault",
        HealingAction::UpgradeToSafeVariant => "UpgradeToSafeVariant",
        HealingAction::None => "None",
    }
}

fn healing_action_details_json(action: &HealingAction) -> String {
    match action {
        HealingAction::ClampSize { requested, clamped } => {
            format!("{{\"requested\":{requested},\"clamped\":{clamped}}}")
        }
        HealingAction::TruncateWithNull {
            requested,
            truncated,
        } => {
            format!("{{\"requested\":{requested},\"truncated\":{truncated}}}")
        }
        HealingAction::ReallocAsMalloc { size } => format!("{{\"size\":{size}}}"),
        HealingAction::IgnoreDoubleFree
        | HealingAction::IgnoreForeignFree
        | HealingAction::ReturnSafeDefault
        | HealingAction::UpgradeToSafeVariant
        | HealingAction::None => "{}".to_string(),
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
static GLOBAL_POLICY: LazyLock<HealingPolicy> = LazyLock::new(HealingPolicy::new);

/// Access the global healing policy.
#[must_use]
pub fn global_healing_policy() -> &'static HealingPolicy {
    &GLOBAL_POLICY
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

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

    #[test]
    fn healing_log_export_contains_required_fields() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        policy.record(&HealingAction::ClampSize {
            requested: 32,
            clamped: 8,
        });

        let jsonl = policy.export_healing_log_jsonl();
        let row: Value = serde_json::from_str(jsonl.trim()).expect("row must be valid JSON");
        assert_eq!(row["bead_id"], HEALING_BEAD_ID);
        assert_eq!(row["api_family"], "membrane-heal");
        assert_eq!(row["decision_path"], "record");
        assert_eq!(row["outcome"], "repair");
        assert_eq!(row["healing_action"], "ClampSize");
        assert_eq!(row["level"], "info");
        assert_eq!(row["details"]["requested"], 32);
        assert_eq!(row["details"]["clamped"], 8);
        assert!(
            row["trace_id"]
                .as_str()
                .is_some_and(|id| id.starts_with("membrane::heal::"))
        );
        assert!(row["decision_id"].as_u64().is_some_and(|id| id > 0));
        assert_eq!(row["schema_version"].as_str(), Some("1.0"));
    }

    #[test]
    fn escalated_healing_actions_emit_warn_level() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        policy.record(&HealingAction::ReturnSafeDefault);

        let jsonl = policy.export_healing_log_jsonl();
        let row: Value = serde_json::from_str(jsonl.trim()).expect("row must be valid JSON");
        assert_eq!(row["healing_action"], "ReturnSafeDefault");
        assert_eq!(row["level"], "warn");
        assert_eq!(row["escalated"], true);
    }

    #[test]
    fn none_action_does_not_emit_healing_log_row() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        policy.record(&HealingAction::None);

        assert!(
            policy.export_healing_log_jsonl().trim().is_empty(),
            "HealingAction::None should not produce evidence rows"
        );
    }

    #[test]
    fn healing_log_capacity_is_bounded() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        for i in 0..(HEALING_LOG_CAPACITY + 32) {
            policy.record(&HealingAction::ReallocAsMalloc { size: i });
        }

        let row_count = policy
            .export_healing_log_jsonl()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        assert_eq!(row_count, HEALING_LOG_CAPACITY);
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Healing Never Produces UB
    //
    // Theorem: Every healing action's output satisfies the
    // invariant that the effective parameters are SAFE —
    // clamped sizes never exceed bounds, truncated strings have
    // null termination room, and no action can widen a buffer.
    //
    // This is the core hardened-mode safety property: healing
    // prevents UB propagation by construction.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_healing_never_widens_bounds() {
        let policy = HealingPolicy::new();

        // For any requested > available, ClampSize.clamped <= available
        let test_pairs = [
            (100usize, Some(50usize), Some(80usize)), // min(50,80) = 50
            (100, Some(200), Some(30)),               // min(200,30) = 30
            (100, Some(50), None),                    // 50
            (100, None, Some(30)),                    // 30
            (usize::MAX, Some(0), Some(0)),           // 0
            (0, Some(100), Some(100)),                // no clamp needed
        ];

        for &(requested, src_rem, dst_rem) in &test_pairs {
            let action = policy.heal_copy_bounds(requested, src_rem, dst_rem);
            match action {
                HealingAction::ClampSize { clamped, .. } => {
                    let available = match (src_rem, dst_rem) {
                        (Some(s), Some(d)) => s.min(d),
                        (Some(s), None) => s,
                        (None, Some(d)) => d,
                        (None, None) => unreachable!(),
                    };
                    assert!(
                        clamped <= available,
                        "Clamp widened: clamped={clamped}, available={available}"
                    );
                }
                HealingAction::None => {
                    // No healing needed means requested <= available
                }
                _ => panic!("Unexpected healing action: {action:?}"),
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: String Truncation Preserves Null-Termination Room
    //
    // Theorem: heal_string_bounds() always truncates to at most
    // remaining-1 bytes, leaving room for the null terminator.
    // This prevents buffer overflow in string operations.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_string_truncation_leaves_null_room() {
        let policy = HealingPolicy::new();

        for remaining in 0..=100usize {
            for src_len in [0, 1, remaining, remaining + 1, remaining + 100, usize::MAX] {
                let action = policy.heal_string_bounds(src_len, Some(remaining));
                match action {
                    HealingAction::TruncateWithNull { truncated, .. } => {
                        if remaining > 0 {
                            assert!(
                                truncated < remaining,
                                "Truncated ({truncated}) must be < remaining ({remaining}) \
                                 for null terminator room"
                            );
                        }
                    }
                    HealingAction::ClampSize { clamped, .. } => {
                        assert_eq!(remaining, 0, "ClampSize should only occur for remaining=0");
                        assert_eq!(clamped, 0);
                    }
                    HealingAction::None => {
                        // No healing means src_len < remaining
                        assert!(
                            src_len < remaining,
                            "None healing but src_len={src_len} >= remaining={remaining}"
                        );
                    }
                    _ => panic!("Unexpected action: {action:?}"),
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Healing Action Exhaustiveness
    //
    // Theorem: Every HealingAction variant has a corresponding
    // counter in HealingPolicy, and record() increments exactly
    // the right counter. No action goes untracked.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_healing_counter_exhaustiveness() {
        let actions = [
            HealingAction::ClampSize {
                requested: 10,
                clamped: 5,
            },
            HealingAction::TruncateWithNull {
                requested: 20,
                truncated: 15,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::IgnoreForeignFree,
            HealingAction::ReallocAsMalloc { size: 64 },
            HealingAction::ReturnSafeDefault,
            HealingAction::UpgradeToSafeVariant,
        ];

        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(false); // avoid log noise

        for action in &actions {
            policy.record(action);
        }

        // Each counter should be exactly 1
        assert_eq!(policy.size_clamps.load(Ordering::Relaxed), 1);
        assert_eq!(policy.null_truncations.load(Ordering::Relaxed), 1);
        assert_eq!(policy.double_frees.load(Ordering::Relaxed), 1);
        assert_eq!(policy.foreign_frees.load(Ordering::Relaxed), 1);
        assert_eq!(policy.realloc_as_mallocs.load(Ordering::Relaxed), 1);
        assert_eq!(policy.safe_defaults.load(Ordering::Relaxed), 1);
        assert_eq!(policy.variant_upgrades.load(Ordering::Relaxed), 1);

        // total_heals should be 7 (all actions are heals)
        assert_eq!(policy.total_heals.load(Ordering::Relaxed), 7);

        // HealingAction::None should NOT increment any counter
        let before_total = policy.total_heals.load(Ordering::Relaxed);
        policy.record(&HealingAction::None);
        assert_eq!(
            policy.total_heals.load(Ordering::Relaxed),
            before_total,
            "None should not increment total_heals"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // FORMAL PROOF: Healing Evidence Monotone Decision IDs
    //
    // Theorem: Each healing evidence row has a strictly increasing
    // decision_id. This ensures deterministic replay: the evidence
    // log can be replayed in order to reconstruct the exact
    // sequence of healing decisions.
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn proof_healing_evidence_monotone_decision_ids() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        let actions = [
            HealingAction::ClampSize {
                requested: 10,
                clamped: 5,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::ReturnSafeDefault,
            HealingAction::TruncateWithNull {
                requested: 20,
                truncated: 15,
            },
            HealingAction::ReallocAsMalloc { size: 128 },
        ];

        for action in &actions {
            policy.record(action);
        }

        let jsonl = policy.export_healing_log_jsonl();
        let mut prev_id = 0u64;
        for (i, line) in jsonl.lines().filter(|l| !l.trim().is_empty()).enumerate() {
            let row: Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("Invalid JSON at row {i}: {e}"));
            let decision_id = row["decision_id"]
                .as_u64()
                .unwrap_or_else(|| panic!("Missing decision_id at row {i}"));
            assert!(
                decision_id > prev_id,
                "Decision IDs not monotone: row {i} has id={decision_id}, prev={prev_id}"
            );
            prev_id = decision_id;
        }
        assert_eq!(
            prev_id as usize,
            actions.len(),
            "Should have all decision IDs"
        );
    }

    #[test]
    fn every_healing_action_variant_emits_dispatch_evidence() {
        let policy = HealingPolicy::new();
        policy.set_healing_logging_enabled(true);
        policy.clear_healing_logs();

        let actions = [
            HealingAction::ClampSize {
                requested: 7,
                clamped: 3,
            },
            HealingAction::TruncateWithNull {
                requested: 16,
                truncated: 15,
            },
            HealingAction::IgnoreDoubleFree,
            HealingAction::IgnoreForeignFree,
            HealingAction::ReallocAsMalloc { size: 64 },
            HealingAction::ReturnSafeDefault,
            HealingAction::UpgradeToSafeVariant,
        ];

        for action in &actions {
            policy.record(action);
        }

        let rows = policy
            .export_healing_log_jsonl()
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str::<Value>(line).expect("row must be valid JSON"))
            .collect::<Vec<_>>();
        assert_eq!(rows.len(), actions.len());
        for row in rows {
            assert_eq!(row["outcome"], "repair");
            assert_eq!(row["api_family"], "membrane-heal");
            assert!(
                row["healing_action"]
                    .as_str()
                    .is_some_and(|name| !name.is_empty())
            );
            assert!(matches!(row["level"].as_str(), Some("info" | "warn")));
        }
    }
}
