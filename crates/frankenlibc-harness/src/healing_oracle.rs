//! Healing oracle for hardened mode testing.
//!
//! Intentionally triggers unsafe conditions and verifies that the
//! membrane applies the correct healing action in hardened mode.

use frankenlibc_membrane::heal::HealingAction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

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
    /// Expected behavior of the valid strict-mode counterpart (no repair).
    pub strict_expected: String,
    /// API family associated with this case.
    pub api_family: String,
    /// Symbol associated with this case.
    pub symbol: String,
}

/// Classification of unsafe conditions to test.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
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
        let canonical_matrix = [
            (
                "null-pointer-strlen",
                UnsafeCondition::NullPointer,
                "string",
                "strlen",
            ),
            (
                "null-pointer-strcmp",
                UnsafeCondition::NullPointer,
                "string",
                "strcmp",
            ),
            (
                "use-after-free-free",
                UnsafeCondition::UseAfterFree,
                "malloc",
                "free",
            ),
            (
                "use-after-free-realloc",
                UnsafeCondition::UseAfterFree,
                "malloc",
                "realloc",
            ),
            (
                "double-free-free",
                UnsafeCondition::DoubleFree,
                "malloc",
                "free",
            ),
            (
                "double-free-cfree",
                UnsafeCondition::DoubleFree,
                "malloc",
                "cfree",
            ),
            (
                "buffer-overflow-strcpy",
                UnsafeCondition::BufferOverflow,
                "string",
                "strcpy",
            ),
            (
                "buffer-overflow-strncpy",
                UnsafeCondition::BufferOverflow,
                "string",
                "strncpy",
            ),
            (
                "foreign-free-free",
                UnsafeCondition::ForeignFree,
                "malloc",
                "free",
            ),
            (
                "foreign-free-cfree",
                UnsafeCondition::ForeignFree,
                "malloc",
                "cfree",
            ),
            (
                "bounds-exceeded-memmove",
                UnsafeCondition::BoundsExceeded,
                "string",
                "memmove",
            ),
            (
                "bounds-exceeded-memcpy",
                UnsafeCondition::BoundsExceeded,
                "string",
                "memcpy",
            ),
            (
                "realloc-freed-realloc",
                UnsafeCondition::ReallocFreed,
                "malloc",
                "realloc",
            ),
            (
                "realloc-freed-reallocarray",
                UnsafeCondition::ReallocFreed,
                "stdlib",
                "reallocarray",
            ),
        ];

        for (id, condition, api_family, symbol) in canonical_matrix {
            suite.add(HealingOracleCase {
                id: id.to_string(),
                condition,
                expected_healing: healing_action_name(&hardened_action_for_symbol(
                    condition, symbol,
                ))
                .to_string(),
                strict_expected: "None".to_string(),
                api_family: api_family.to_string(),
                symbol: symbol.to_string(),
            });
        }
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
    /// Valid control outcome or specified hardened repair outcome; undefined
    /// fault inputs do not establish POSIX conformance.
    pub contract_valid: bool,
    pub evidence_logged: bool,
    pub evidence_kind: String,
    pub status: String,
    /// Strict runs exercise valid counterparts, not undefined invalid C calls.
    pub input_kind: String,
    pub observation: Option<HealingObservation>,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Raw measurements emitted by the provider-checked C subprocess, not a policy
/// model. Counter deltas and memory effects are evaluated independently below.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealingObservation {
    pub case_id: String,
    pub mode: String,
    pub action: u32,
    pub value: i64,
    pub errno: i32,
    pub prefix: u32,
    pub nul: i32,
    pub same_pointer: bool,
    pub counter_before: u64,
    pub counter_after: u64,
    pub guard_before: [u8; 8],
    pub guard_after: [u8; 8],
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
    pub library: String,
    pub library_sha256: String,
    pub probe_sha256: String,
    pub summary: HealingOracleSummary,
    pub cases: Vec<HealingOracleCaseRow>,
}

impl HealingOracleReport {
    /// Returns true when no failures are present.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.summary.total_cases > 0 && self.summary.failed == 0
    }
}

/// Execute each case in a fresh process against an explicit release artifact.
/// Requires coreutils timeout/env and a compiled fixture_malloc.c probe.
/// Missing providers, timeouts, crashes and malformed observations are failures.
pub fn build_healing_oracle_report(
    suite: &HealingOracleSuite,
    mode: HealingOracleMode,
    campaign: &str,
    probe: &Path,
    library: &Path,
) -> Result<HealingOracleReport, String> {
    let supported = HealingOracleSuite::canonical();
    let mut seen = std::collections::BTreeSet::new();
    for case in suite.cases() {
        if !seen.insert(&case.id)
            || !supported.cases().iter().any(|known| {
                known.id == case.id
                    && known.symbol == case.symbol
                    && known.condition == case.condition
            })
        {
            return Err(format!(
                "unsupported or duplicate live healing case: {}",
                case.id
            ));
        }
    }
    let probe = probe
        .canonicalize()
        .map_err(|e| format!("probe path: {e}"))?;
    let library = library
        .canonicalize()
        .map_err(|e| format!("library path: {e}"))?;
    let digest = |path: &Path| -> Result<String, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        if bytes.is_empty() {
            return Err(format!("empty artifact: {}", path.display()));
        }
        Ok(Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    };
    let library_sha256 = digest(&library)?;
    let probe_sha256 = digest(&probe)?;
    let mut rows = Vec::new();
    for &active_mode in mode.active_modes() {
        for case in suite.cases() {
            let expected = expected_action_for_mode(case, active_mode);
            let expected_name = healing_action_name(&expected).to_string();
            // Only the probe, not timeout itself, is preloaded. Keep the timeout
            // supervisor independent of the potentially broken library.
            let command = vec![
                "timeout".to_string(),
                "--signal=KILL".to_string(),
                "10s".to_string(),
                "env".to_string(),
                format!("LD_PRELOAD={}", library.display()),
                format!("FRANKENLIBC_MODE={active_mode}"),
                probe.display().to_string(),
                "--healing-case".to_string(),
                case.id.clone(),
                library.display().to_string(),
            ];
            let (observation, exit_code, mut note) = observe_probe(&command);
            let (behavior_ok, counter_ok, detected) = observation
                .as_ref()
                .map(|raw| evaluate_observation(case, active_mode, raw))
                .unwrap_or((false, false, false));
            let passed = behavior_ok && counter_ok;
            let observed_name = if detected {
                expected_name.clone()
            } else if observation.is_some() {
                "None".to_string()
            } else {
                "Unobserved".to_string()
            };
            let repaired = active_mode == "hardened" && passed;
            if !passed && note.is_none() {
                note = Some(format!(
                    "independent outcome check={behavior_ok}, action-counter check={counter_ok}"
                ));
            }
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
                detected,
                repaired,
                posix_valid: active_mode == "strict" && behavior_ok,
                contract_valid: behavior_ok,
                evidence_logged: counter_ok && observation.is_some(),
                evidence_kind: "isolated_action_counter_delta".to_string(),
                status: if passed { "pass" } else { "fail" }.to_string(),
                input_kind: if active_mode == "strict" {
                    "valid_control"
                } else {
                    "injected_fault"
                }
                .to_string(),
                observation,
                command,
                exit_code,
                note,
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

    // Refuse a receipt if the named artifacts changed during execution.
    if digest(&library)? != library_sha256 || digest(&probe)? != probe_sha256 {
        return Err("artifact changed during healing verification".to_string());
    }
    Ok(HealingOracleReport {
        schema_version: HEALING_ORACLE_SCHEMA_VERSION.to_string(),
        bead: HEALING_ORACLE_BEAD.to_string(),
        generated_at_utc: crate::capture::format_utc_from_unix_seconds(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| format!("system clock: {e}"))?
                .as_secs(),
        ),
        campaign: campaign.to_string(),
        mode: mode.as_str().to_string(),
        library: library.display().to_string(),
        library_sha256,
        probe_sha256,
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
    })
}

fn observe_probe(command: &[String]) -> (Option<HealingObservation>, Option<i32>, Option<String>) {
    let output = Command::new(&command[0])
        .args(&command[1..])
        .env_remove("LD_PRELOAD")
        .env_remove("LD_AUDIT")
        .output();
    match output {
        Ok(output) => {
            let code = output.status.code();
            if !output.status.success() {
                return (
                    None,
                    code,
                    Some(format!(
                        "probe {}: stdout={} stderr={}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )),
                );
            }
            match serde_json::from_slice::<HealingObservation>(&output.stdout) {
                Ok(raw) => (Some(raw), code, None),
                Err(error) => (
                    None,
                    code,
                    Some(format!(
                        "invalid observation: {error}; stdout={}; stderr={}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    )),
                ),
            }
        }
        Err(error) => (
            None,
            None,
            Some(format!("could not execute probe: {error}")),
        ),
    }
}

fn expected_action_for_mode(case: &HealingOracleCase, mode: &str) -> HealingAction {
    if mode.eq_ignore_ascii_case("hardened") {
        hardened_action_for_symbol(case.condition, &case.symbol)
    } else {
        HealingAction::None
    }
}

fn hardened_action_for_symbol(condition: UnsafeCondition, symbol: &str) -> HealingAction {
    match condition {
        UnsafeCondition::NullPointer => HealingAction::ReturnSafeDefault,
        UnsafeCondition::UseAfterFree if symbol == "free" => HealingAction::IgnoreDoubleFree,
        UnsafeCondition::UseAfterFree => HealingAction::ReallocAsMalloc { size: 32 },
        UnsafeCondition::DoubleFree => HealingAction::IgnoreDoubleFree,
        UnsafeCondition::BufferOverflow if symbol == "strncpy" => HealingAction::ClampSize {
            requested: 32,
            clamped: 8,
        },
        UnsafeCondition::BufferOverflow => HealingAction::TruncateWithNull {
            requested: 31,
            truncated: 7,
        },
        UnsafeCondition::ForeignFree => HealingAction::IgnoreForeignFree,
        UnsafeCondition::BoundsExceeded => HealingAction::ClampSize {
            requested: 32,
            clamped: 8,
        },
        UnsafeCondition::ReallocFreed => HealingAction::ReallocAsMalloc { size: 32 },
    }
}

fn evaluate_observation(
    case: &HealingOracleCase,
    mode: &str,
    raw: &HealingObservation,
) -> (bool, bool, bool) {
    let action = hardened_action_for_symbol(case.condition, &case.symbol);
    let action_id = match action {
        HealingAction::ClampSize { .. } => 1,
        HealingAction::TruncateWithNull { .. } => 2,
        HealingAction::IgnoreDoubleFree => 3,
        HealingAction::IgnoreForeignFree => 4,
        HealingAction::ReallocAsMalloc { .. } => 5,
        HealingAction::ReturnSafeDefault => 6,
        _ => return (false, false, false),
    };
    if raw.case_id != case.id || raw.mode != mode || raw.action != action_id {
        return (false, false, false);
    }
    let hardened = mode == "hardened";
    let delta = raw.counter_after.checked_sub(raw.counter_before);
    let detected = matches!(delta, Some(1..)) && raw.counter_after != u64::MAX;
    let counter_ok = raw.counter_before != u64::MAX
        && raw.counter_after != u64::MAX
        && if hardened {
            delta == Some(1)
        } else {
            delta == Some(0)
        };
    let behavior_ok = match action_id {
        1 | 2 => {
            raw.value == 1
                && raw.prefix == if hardened && action_id == 2 { 7 } else { 8 }
                && raw.nul == if hardened && action_id == 2 { 7 } else { -1 }
                && if hardened {
                    raw.guard_before == raw.guard_after
                } else {
                    raw.guard_after == *b"IJKLMNOP"
                }
        }
        3 => raw.value == 0,
        4 => raw.value == 0 && (!hardened || raw.prefix == 8),
        5 => {
            raw.value == 1
                && if hardened {
                    !raw.same_pointer
                } else {
                    raw.prefix == 8
                }
        }
        6 => {
            raw.value
                == if !hardened && case.symbol == "strlen" {
                    1
                } else {
                    0
                }
        }
        _ => false,
    };
    (behavior_ok && raw.errno == 0, counter_ok, detected)
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
    use std::collections::BTreeSet;

    #[test]
    fn canonical_suite_covers_all_conditions() {
        let suite = HealingOracleSuite::canonical();
        let observed: BTreeSet<_> = suite.cases().iter().map(|case| case.condition).collect();
        let expected: BTreeSet<_> = UnsafeCondition::all().iter().copied().collect();
        assert_eq!(
            observed, expected,
            "canonical suite should cover all conditions"
        );
        assert!(
            suite.cases().len() >= UnsafeCondition::all().len() * 2,
            "canonical suite should include multiple symbols per condition"
        );
    }

    #[test]
    fn strict_mode_has_no_repairs() {
        let suite = HealingOracleSuite::canonical();
        for case in suite.cases() {
            assert_eq!(
                expected_action_for_mode(case, "strict"),
                HealingAction::None
            );
        }
    }

    // These are parser/evaluator unit fixtures, never deployed ABI evidence.
    fn copy_observation() -> HealingObservation {
        HealingObservation {
            case_id: "bounds-exceeded-memcpy".to_string(),
            mode: "hardened".to_string(),
            action: 1,
            value: 1,
            errno: 0,
            prefix: 8,
            nul: -1,
            same_pointer: false,
            counter_before: 12,
            counter_after: 13,
            guard_before: [0x57; 8],
            guard_after: [0x57; 8],
        }
    }

    #[test]
    fn observed_repair_requires_independent_bounds_and_counter_evidence() {
        let suite = HealingOracleSuite::canonical();
        let case = suite
            .cases()
            .iter()
            .find(|c| c.id == "bounds-exceeded-memcpy")
            .unwrap();
        let mut raw = copy_observation();
        assert_eq!(
            evaluate_observation(case, "hardened", &raw),
            (true, true, true)
        );
        raw.guard_after[0] ^= 1;
        assert_eq!(
            evaluate_observation(case, "hardened", &raw),
            (false, true, true)
        );
        raw = copy_observation();
        raw.counter_after = raw.counter_before;
        assert_eq!(
            evaluate_observation(case, "hardened", &raw),
            (true, false, false)
        );
        raw.counter_after = raw.counter_before - 1;
        assert!(!evaluate_observation(case, "hardened", &raw).1);
        raw.counter_before = u64::MAX;
        raw.counter_after = u64::MAX;
        assert!(!evaluate_observation(case, "hardened", &raw).1);
        raw = copy_observation();
        raw.mode = "strict".to_string();
        assert_eq!(
            evaluate_observation(case, "hardened", &raw),
            (false, false, false)
        );
    }

    #[test]
    fn zero_exit_without_observations_fails_both_modes() {
        let suite = HealingOracleSuite::canonical();
        let report = build_healing_oracle_report(
            &suite,
            HealingOracleMode::Both,
            "test",
            Path::new("/bin/true"),
            Path::new("/bin/true"),
        )
        .unwrap();
        let base = suite.cases().len();
        assert_eq!(
            report.summary.total_cases,
            u64::try_from(base * 2).unwrap_or(u64::MAX)
        );
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.failed as usize, base * 2);
        assert!(!report.all_passed());
        assert!(
            report
                .cases
                .iter()
                .all(|row| row.observation.is_none() && !row.evidence_logged)
        );

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
        assert_eq!(strict, base);
        assert_eq!(hardened, base);
    }

    #[test]
    fn empty_suite_is_not_a_green_run() {
        let report = build_healing_oracle_report(
            &HealingOracleSuite::new(),
            HealingOracleMode::Both,
            "empty",
            Path::new("/bin/true"),
            Path::new("/bin/true"),
        )
        .unwrap();
        assert_eq!(report.summary.total_cases, 0);
        assert!(!report.all_passed());
    }

    #[test]
    fn missing_artifact_is_an_error_not_a_model_fallback() {
        let absent =
            std::env::temp_dir().join(format!("missing-healing-probe-{}", std::process::id()));
        assert!(
            build_healing_oracle_report(
                &HealingOracleSuite::canonical(),
                HealingOracleMode::Both,
                "missing",
                &absent,
                Path::new("/bin/true")
            )
            .is_err()
        );
    }

    #[test]
    fn expected_repairs_are_symbol_specific() {
        assert!(matches!(
            hardened_action_for_symbol(UnsafeCondition::BufferOverflow, "strncpy"),
            HealingAction::ClampSize { .. }
        ));
        assert_eq!(
            hardened_action_for_symbol(UnsafeCondition::UseAfterFree, "free"),
            HealingAction::IgnoreDoubleFree
        );
        assert!(matches!(
            hardened_action_for_symbol(UnsafeCondition::UseAfterFree, "realloc"),
            HealingAction::ReallocAsMalloc { .. }
        ));
    }

    #[test]
    fn a_counter_increment_cannot_legitimize_a_retired_realloc_pointer() {
        let suite = HealingOracleSuite::canonical();
        let case = suite
            .cases()
            .iter()
            .find(|case| case.id == "realloc-freed-realloc")
            .unwrap();
        let mut raw = copy_observation();
        raw.case_id = case.id.clone();
        raw.action = 5;
        raw.same_pointer = true;
        assert_eq!(
            evaluate_observation(case, "hardened", &raw),
            (false, true, true)
        );
        raw.same_pointer = false;
        assert_eq!(
            evaluate_observation(case, "hardened", &raw),
            (true, true, true)
        );
    }

    #[test]
    fn unsupported_and_duplicate_cases_are_rejected_not_inferred() {
        let mut suite = HealingOracleSuite::canonical();
        suite.add(suite.cases()[0].clone());
        assert!(
            build_healing_oracle_report(
                &suite,
                HealingOracleMode::Both,
                "duplicate",
                Path::new("/bin/true"),
                Path::new("/bin/true")
            )
            .is_err()
        );
        let mut case = suite.cases()[0].clone();
        case.symbol = "not_implemented".to_string();
        let mut unsupported = HealingOracleSuite::new();
        unsupported.add(case);
        assert!(
            build_healing_oracle_report(
                &unsupported,
                HealingOracleMode::Both,
                "unsupported",
                Path::new("/bin/true"),
                Path::new("/bin/true")
            )
            .is_err()
        );
    }

    #[test]
    fn child_failures_timeouts_signals_and_missing_commands_never_produce_observations() {
        // These exercise runner failure handling, not libc behavior.
        for args in [
            vec!["/bin/false"],
            vec!["/bin/sh", "-c", "kill -TERM $$"],
            vec!["timeout", "--signal=KILL", "0.05s", "sleep", "10"],
            vec!["/definitely-absent-frankenlibc-probe"],
        ] {
            let command: Vec<String> = args.into_iter().map(str::to_string).collect();
            let (observation, exit, note) = observe_probe(&command);
            assert!(observation.is_none(), "{command:?}");
            assert_ne!(exit, Some(0), "{command:?}");
            assert!(note.is_some(), "{command:?}");
        }
    }
}
