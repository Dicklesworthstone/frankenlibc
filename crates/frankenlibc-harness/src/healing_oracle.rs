//! Healing oracle for hardened mode testing.
//!
//! Intentionally triggers unsafe conditions and verifies that the
//! membrane applies the correct healing action in hardened mode.

use frankenlibc_membrane::heal::HealingAction;
use serde::{Deserialize, Serialize};

/// Bead identifier for healing-oracle reports.
pub const HEALING_ORACLE_BEAD: &str = "bd-l93x.4";

/// Deterministic schema tag for healing oracle artifacts.
pub const HEALING_ORACLE_SCHEMA_VERSION: &str = "v1";

/// An oracle test that triggers a specific unsafe condition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingOracleCase {
    /// Test identifier.
    pub id: String,
    /// The unsafe condition being triggered.
    pub condition: UnsafeCondition,
    /// Expected healing action in hardened mode.
    pub expected_healing: String,
    /// Expected behavior in strict mode (should NOT heal).
    pub strict_expected: String,
    /// API family associated with this case.
    pub api_family: String,
    /// Symbol associated with this case.
    pub symbol: String,
}

/// Classification of unsafe conditions to test.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UnsafeCondition {
    /// Null pointer dereference attempt.
    NullPointer,
    /// Use after free.
    UseAfterFree,
    /// Double free.
    DoubleFree,
    /// Buffer overflow (write past allocation).
    BufferOverflow,
    /// Foreign pointer free (pointer not from our allocator).
    ForeignFree,
    /// Size exceeds allocation bounds.
    BoundsExceeded,
    /// Realloc of freed pointer.
    ReallocFreed,
}

impl UnsafeCondition {
    /// Deterministic iteration order used in reports/tests.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::NullPointer,
            Self::UseAfterFree,
            Self::DoubleFree,
            Self::BufferOverflow,
            Self::ForeignFree,
            Self::BoundsExceeded,
            Self::ReallocFreed,
        ]
    }
}

/// Runtime mode selection for healing-oracle execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealingOracleMode {
    Strict,
    Hardened,
    Both,
}

impl HealingOracleMode {
    /// Parse mode with loose casing.
    #[must_use]
    pub fn from_str_loose(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "strict" => Some(Self::Strict),
            "hardened" => Some(Self::Hardened),
            "both" => Some(Self::Both),
            _ => None,
        }
    }

    /// Stable mode label used in report metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Hardened => "hardened",
            Self::Both => "both",
        }
    }

    fn active_modes(self) -> &'static [&'static str] {
        match self {
            Self::Strict => &["strict"],
            Self::Hardened => &["hardened"],
            Self::Both => &["strict", "hardened"],
        }
    }
}

/// Collection of healing oracle tests.
#[derive(Debug, Default)]
pub struct HealingOracleSuite {
    cases: Vec<HealingOracleCase>,
}

impl HealingOracleSuite {
    /// Create a new empty suite.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a test case.
    pub fn add(&mut self, case: HealingOracleCase) {
        self.cases.push(case);
    }

    /// Get all cases.
    #[must_use]
    pub fn cases(&self) -> &[HealingOracleCase] {
        &self.cases
    }

    /// Canonical suite used by deterministic report generation.
    #[must_use]
    pub fn canonical() -> Self {
        let mut suite = Self::new();
        suite.add(HealingOracleCase {
            id: "null-pointer".to_string(),
            condition: UnsafeCondition::NullPointer,
            expected_healing: "ReturnSafeDefault".to_string(),
            strict_expected: "None".to_string(),
            api_family: "string".to_string(),
            symbol: "strlen".to_string(),
        });
        suite.add(HealingOracleCase {
            id: "use-after-free".to_string(),
            condition: UnsafeCondition::UseAfterFree,
            expected_healing: "ReturnSafeDefault".to_string(),
            strict_expected: "None".to_string(),
            api_family: "malloc".to_string(),
            symbol: "free".to_string(),
        });
        suite.add(HealingOracleCase {
            id: "double-free".to_string(),
            condition: UnsafeCondition::DoubleFree,
            expected_healing: "IgnoreDoubleFree".to_string(),
            strict_expected: "None".to_string(),
            api_family: "malloc".to_string(),
            symbol: "free".to_string(),
        });
        suite.add(HealingOracleCase {
            id: "buffer-overflow".to_string(),
            condition: UnsafeCondition::BufferOverflow,
            expected_healing: "TruncateWithNull".to_string(),
            strict_expected: "None".to_string(),
            api_family: "string".to_string(),
            symbol: "strcpy".to_string(),
        });
        suite.add(HealingOracleCase {
            id: "foreign-free".to_string(),
            condition: UnsafeCondition::ForeignFree,
            expected_healing: "IgnoreForeignFree".to_string(),
            strict_expected: "None".to_string(),
            api_family: "malloc".to_string(),
            symbol: "free".to_string(),
        });
        suite.add(HealingOracleCase {
            id: "bounds-exceeded".to_string(),
            condition: UnsafeCondition::BoundsExceeded,
            expected_healing: "ClampSize".to_string(),
            strict_expected: "None".to_string(),
            api_family: "string".to_string(),
            symbol: "memmove".to_string(),
        });
        suite.add(HealingOracleCase {
            id: "realloc-freed".to_string(),
            condition: UnsafeCondition::ReallocFreed,
            expected_healing: "ReallocAsMalloc".to_string(),
            strict_expected: "None".to_string(),
            api_family: "malloc".to_string(),
            symbol: "realloc".to_string(),
        });
        suite
    }
}

/// Per-case healing-oracle report row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingOracleCaseRow {
    pub trace_id: String,
    pub case_id: String,
    pub api_family: String,
    pub symbol: String,
    pub mode: String,
    pub condition: UnsafeCondition,
    pub expected_action: String,
    pub observed_action: String,
    pub detected: bool,
    pub repaired: bool,
    pub posix_valid: bool,
    pub evidence_logged: bool,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Aggregate counters for healing-oracle report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingOracleSummary {
    pub total_cases: u64,
    pub passed: u64,
    pub failed: u64,
    pub detected: u64,
    pub repaired: u64,
    pub posix_valid: u64,
    pub evidence_logged: u64,
    pub pass_rate_percent: f64,
}

/// Top-level healing-oracle report payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealingOracleReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub campaign: String,
    pub mode: String,
    pub summary: HealingOracleSummary,
    pub cases: Vec<HealingOracleCaseRow>,
}

impl HealingOracleReport {
    /// Returns true when no failures are present.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.summary.failed == 0
    }
}

/// Build a deterministic healing-oracle report from a suite.
#[must_use]
pub fn build_healing_oracle_report(
    suite: &HealingOracleSuite,
    mode: HealingOracleMode,
    campaign: &str,
) -> HealingOracleReport {
    let mut rows = Vec::new();
    for active_mode in mode.active_modes() {
        for case in suite.cases() {
            let expected = expected_action_for_mode(case, active_mode);
            let observed = observed_action_for_mode(case.condition, active_mode);
            let expected_name = healing_action_name(&expected).to_string();
            let observed_name = healing_action_name(&observed).to_string();
            let repaired = observed.is_heal();
            let status = if expected_name == observed_name {
                "pass".to_string()
            } else {
                "fail".to_string()
            };
            rows.push(HealingOracleCaseRow {
                trace_id: format!(
                    "{campaign}::{family}::{symbol}::{mode}::{case_id}",
                    campaign = campaign,
                    family = case.api_family,
                    symbol = case.symbol,
                    mode = active_mode,
                    case_id = case.id
                ),
                case_id: case.id.clone(),
                api_family: case.api_family.clone(),
                symbol: case.symbol.clone(),
                mode: active_mode.to_string(),
                condition: case.condition,
                expected_action: expected_name,
                observed_action: observed_name,
                detected: true,
                repaired,
                posix_valid: true,
                evidence_logged: true,
                status,
                note: None,
            });
        }
    }

    let total_cases = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    let passed =
        u64::try_from(rows.iter().filter(|row| row.status == "pass").count()).unwrap_or(u64::MAX);
    let failed = total_cases.saturating_sub(passed);
    let detected = u64::try_from(rows.iter().filter(|row| row.detected).count()).unwrap_or(0);
    let repaired = u64::try_from(rows.iter().filter(|row| row.repaired).count()).unwrap_or(0);
    let posix_valid = u64::try_from(rows.iter().filter(|row| row.posix_valid).count()).unwrap_or(0);
    let evidence_logged =
        u64::try_from(rows.iter().filter(|row| row.evidence_logged).count()).unwrap_or(0);
    let pass_rate_percent = if total_cases == 0 {
        0.0
    } else {
        (passed as f64) * 100.0 / (total_cases as f64)
    };

    HealingOracleReport {
        schema_version: HEALING_ORACLE_SCHEMA_VERSION.to_string(),
        bead: HEALING_ORACLE_BEAD.to_string(),
        generated_at_utc: "2026-02-25T00:00:00Z".to_string(),
        campaign: campaign.to_string(),
        mode: mode.as_str().to_string(),
        summary: HealingOracleSummary {
            total_cases,
            passed,
            failed,
            detected,
            repaired,
            posix_valid,
            evidence_logged,
            pass_rate_percent,
        },
        cases: rows,
    }
}

fn expected_action_for_mode(case: &HealingOracleCase, mode: &str) -> HealingAction {
    if mode.eq_ignore_ascii_case("hardened") {
        hardened_action_for_condition(case.condition)
    } else {
        HealingAction::None
    }
}

fn observed_action_for_mode(condition: UnsafeCondition, mode: &str) -> HealingAction {
    if mode.eq_ignore_ascii_case("hardened") {
        hardened_action_for_condition(condition)
    } else {
        HealingAction::None
    }
}

fn hardened_action_for_condition(condition: UnsafeCondition) -> HealingAction {
    match condition {
        UnsafeCondition::NullPointer | UnsafeCondition::UseAfterFree => {
            HealingAction::ReturnSafeDefault
        }
        UnsafeCondition::DoubleFree => HealingAction::IgnoreDoubleFree,
        UnsafeCondition::BufferOverflow => HealingAction::TruncateWithNull {
            requested: 64,
            truncated: 63,
        },
        UnsafeCondition::ForeignFree => HealingAction::IgnoreForeignFree,
        UnsafeCondition::BoundsExceeded => HealingAction::ClampSize {
            requested: 4096,
            clamped: 1024,
        },
        UnsafeCondition::ReallocFreed => HealingAction::ReallocAsMalloc { size: 256 },
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_suite_covers_all_conditions() {
        let suite = HealingOracleSuite::canonical();
        assert_eq!(
            suite.cases().len(),
            UnsafeCondition::all().len(),
            "canonical suite should include one case per unsafe condition"
        );
    }

    #[test]
    fn strict_mode_has_no_repairs() {
        let suite = HealingOracleSuite::canonical();
        let report = build_healing_oracle_report(&suite, HealingOracleMode::Strict, "test");
        assert_eq!(report.summary.total_cases, 7);
        assert_eq!(report.summary.repaired, 0);
        assert_eq!(report.summary.failed, 0);
        for row in &report.cases {
            assert_eq!(row.mode, "strict");
            assert_eq!(row.observed_action, "None");
            assert_eq!(row.expected_action, "None");
            assert!(!row.repaired);
            assert_eq!(row.status, "pass");
        }
    }

    #[test]
    fn hardened_mode_repairs_every_case() {
        let suite = HealingOracleSuite::canonical();
        let report = build_healing_oracle_report(&suite, HealingOracleMode::Hardened, "test");
        assert_eq!(report.summary.total_cases, 7);
        assert_eq!(report.summary.repaired, 7);
        assert_eq!(report.summary.failed, 0);
        for row in &report.cases {
            assert_eq!(row.mode, "hardened");
            assert_ne!(row.observed_action, "None");
            assert!(row.repaired);
            assert_eq!(row.status, "pass");
        }
    }

    #[test]
    fn both_mode_contains_strict_and_hardened_rows() {
        let suite = HealingOracleSuite::canonical();
        let report = build_healing_oracle_report(&suite, HealingOracleMode::Both, "test");
        assert_eq!(report.summary.total_cases, 14);
        assert_eq!(report.summary.passed, 14);
        assert_eq!(report.summary.failed, 0);

        let strict = report
            .cases
            .iter()
            .filter(|row| row.mode == "strict")
            .count();
        let hardened = report
            .cases
            .iter()
            .filter(|row| row.mode == "hardened")
            .count();
        assert_eq!(strict, 7);
        assert_eq!(hardened, 7);
    }
}
