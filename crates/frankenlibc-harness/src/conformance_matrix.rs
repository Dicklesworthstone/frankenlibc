//! Differential conformance matrix generation (bd-l93x.2).
//!
//! This module executes fixture cases against host-vs-implementation paths and
//! emits a machine-readable matrix with symbol-level aggregation.

use std::collections::BTreeMap;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::verify::{ExpectedOutputMatch, expected_output_match};
use crate::{FixtureCase, FixtureSet};
use frankenlibc_fixture_exec::{DifferentialExecution, execute_fixture_case};

/// Runtime mode selection for matrix generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatrixMode {
    Strict,
    Hardened,
    Both,
}

impl MatrixMode {
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

/// One execution row in the differential conformance matrix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceCaseRow {
    pub trace_id: String,
    pub family: String,
    pub symbol: String,
    pub mode: String,
    pub case_name: String,
    pub spec_section: String,
    pub input_hex: String,
    pub expected_output: String,
    pub actual_output: String,
    pub host_output: Option<String>,
    pub host_parity: Option<bool>,
    pub note: Option<String>,
    pub status: String,
    pub passed: bool,
    pub error: Option<String>,
    pub diff_offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// Symbol-level aggregate row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolMatrixRow {
    pub symbol: String,
    pub mode: String,
    pub total: u64,
    pub passed: u64,
    pub failed: u64,
    pub errors: u64,
    pub pass_rate_percent: f64,
}

/// Matrix summary counters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceMatrixSummary {
    pub total_cases: u64,
    pub passed: u64,
    pub failed: u64,
    pub errors: u64,
    pub pass_rate_percent: f64,
}

/// Top-level matrix report payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConformanceMatrixReport {
    pub schema_version: String,
    pub bead: String,
    pub generated_at_utc: String,
    pub campaign: String,
    pub mode: String,
    pub total_fixture_sets: usize,
    pub summary: ConformanceMatrixSummary,
    pub symbol_matrix: Vec<SymbolMatrixRow>,
    pub cases: Vec<ConformanceCaseRow>,
}

/// Execution outcome used by matrix builders.
#[derive(Debug, Clone)]
pub enum CaseExecution {
    Completed(DifferentialExecution),
    Error(String),
    Timeout(String),
    Crash(String),
}

impl ConformanceMatrixReport {
    /// Returns true when no failures/errors are present.
    #[must_use]
    pub const fn all_passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.errors == 0
    }
}

/// Build a deterministic differential conformance matrix from fixture sets.
#[must_use]
pub fn build_conformance_matrix(
    fixture_sets: &[FixtureSet],
    mode: MatrixMode,
    campaign: &str,
) -> ConformanceMatrixReport {
    build_conformance_matrix_with_executor(
        fixture_sets,
        mode,
        campaign,
        |function, inputs, active_mode| match execute_fixture_case(function, inputs, active_mode) {
            Ok(run) => CaseExecution::Completed(run),
            Err(err) => CaseExecution::Error(err),
        },
    )
}

/// Build a deterministic differential conformance matrix with a custom case executor.
#[must_use]
pub fn build_conformance_matrix_with_executor<F>(
    fixture_sets: &[FixtureSet],
    mode: MatrixMode,
    campaign: &str,
    mut execute_case: F,
) -> ConformanceMatrixReport
where
    F: FnMut(&str, &serde_json::Value, &str) -> CaseExecution,
{
    let mut rows = Vec::new();

    for fixture_set in fixture_sets {
        for active_mode in mode.active_modes() {
            for case in fixture_set
                .cases
                .iter()
                .filter(|case| mode_matches(active_mode, &case.mode))
            {
                let started = Instant::now();
                let execution = execute_case(&case.function, &case.inputs, active_mode);
                let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                rows.push(run_case_from_execution(
                    fixture_set,
                    case,
                    active_mode,
                    campaign,
                    execution,
                    duration_ms,
                ));
            }
        }
    }

    rows.sort_by(|a, b| {
        a.family
            .cmp(&b.family)
            .then_with(|| a.symbol.cmp(&b.symbol))
            .then_with(|| a.mode.cmp(&b.mode))
            .then_with(|| a.case_name.cmp(&b.case_name))
            .then_with(|| a.spec_section.cmp(&b.spec_section))
            .then_with(|| a.expected_output.cmp(&b.expected_output))
            .then_with(|| a.actual_output.cmp(&b.actual_output))
            .then_with(|| a.status.cmp(&b.status))
    });

    let total_cases = u64::try_from(rows.len()).unwrap_or(u64::MAX);
    let passed = u64::try_from(rows.iter().filter(|row| row.passed).count()).unwrap_or(0);
    let errors =
        u64::try_from(rows.iter().filter(|row| row.status == "error").count()).unwrap_or(0);
    let failed = total_cases.saturating_sub(passed).saturating_sub(errors);
    let pass_rate_percent = ratio_percent(passed, total_cases);

    let mut symbol_buckets: BTreeMap<(String, String), (u64, u64, u64, u64)> = BTreeMap::new();
    for row in &rows {
        let key = (row.symbol.clone(), row.mode.clone());
        let bucket = symbol_buckets.entry(key).or_insert((0, 0, 0, 0));
        bucket.0 = bucket.0.saturating_add(1);
        if row.passed {
            bucket.1 = bucket.1.saturating_add(1);
        } else if row.status == "error" {
            bucket.3 = bucket.3.saturating_add(1);
        } else {
            bucket.2 = bucket.2.saturating_add(1);
        }
    }

    let symbol_matrix = symbol_buckets
        .into_iter()
        .map(
            |((symbol, mode), (total, passed, failed, errors))| SymbolMatrixRow {
                symbol,
                mode,
                total,
                passed,
                failed,
                errors,
                pass_rate_percent: ratio_percent(passed, total),
            },
        )
        .collect();

    ConformanceMatrixReport {
        schema_version: "v1".to_string(),
        bead: "bd-l93x.2".to_string(),
        generated_at_utc: deterministic_generated_at_utc(fixture_sets),
        campaign: campaign.to_string(),
        mode: mode.as_str().to_string(),
        total_fixture_sets: fixture_sets.len(),
        summary: ConformanceMatrixSummary {
            total_cases,
            passed,
            failed,
            errors,
            pass_rate_percent,
        },
        symbol_matrix,
        cases: rows,
    }
}

fn run_case_from_execution(
    fixture_set: &FixtureSet,
    case: &FixtureCase,
    active_mode: &str,
    campaign: &str,
    execution: CaseExecution,
    duration_ms: u64,
) -> ConformanceCaseRow {
    let case_name = if case.mode.trim().eq_ignore_ascii_case("both") {
        format!("{} [{}]", case.name, active_mode)
    } else {
        case.name.clone()
    };

    let trace_id = format!(
        "{campaign}::{family}::{symbol}::{mode}::{case_name}",
        campaign = campaign,
        family = fixture_set.family,
        symbol = case.function,
        mode = active_mode,
        case_name = case_name
    );

    let input_hex = serde_json::to_vec(&case.inputs)
        .map(|buf| hex_encode(&buf))
        .unwrap_or_else(|_| String::new());

    match execution {
        CaseExecution::Completed(run) => {
            let match_kind = expected_output_match(&case.expected_output, &run.impl_output);
            let output_matches = match_kind.is_some();
            let host_oracle_defined = !host_oracle_is_undefined(&run.host_output);
            let host_matches = run.host_parity || !host_oracle_defined;
            let passed = output_matches && host_matches;
            let diff_offset = if !output_matches {
                first_diff_offset(&case.expected_output, &run.impl_output)
            } else if !host_matches && host_oracle_defined {
                first_diff_offset(&run.host_output, &run.impl_output)
            } else {
                None
            };
            let mut note = append_match_notes(run.note, match_kind);
            if !host_matches {
                append_note(&mut note, "host_parity=false");
            }
            ConformanceCaseRow {
                trace_id,
                family: fixture_set.family.clone(),
                symbol: case.function.clone(),
                mode: active_mode.to_string(),
                case_name,
                spec_section: case.spec_section.clone(),
                input_hex,
                expected_output: case.expected_output.clone(),
                actual_output: run.impl_output.clone(),
                host_output: Some(run.host_output),
                host_parity: Some(run.host_parity),
                note,
                status: if passed {
                    "pass".to_string()
                } else {
                    "fail".to_string()
                },
                passed,
                error: None,
                diff_offset,
                duration_ms: Some(duration_ms),
            }
        }
        CaseExecution::Error(err) => build_error_row(
            fixture_set,
            case,
            active_mode,
            trace_id,
            case_name,
            input_hex,
            format!("unsupported:{err}"),
            "error",
            Some(err),
            None,
            duration_ms,
        ),
        CaseExecution::Timeout(err) => build_error_row(
            fixture_set,
            case,
            active_mode,
            trace_id,
            case_name,
            input_hex,
            format!("timeout:{err}"),
            "timeout",
            Some(err),
            Some("isolated_timeout".to_string()),
            duration_ms,
        ),
        CaseExecution::Crash(err) => build_error_row(
            fixture_set,
            case,
            active_mode,
            trace_id,
            case_name,
            input_hex,
            format!("crash:{err}"),
            "crash",
            Some(err),
            Some("isolated_crash".to_string()),
            duration_ms,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_error_row(
    fixture_set: &FixtureSet,
    case: &FixtureCase,
    active_mode: &str,
    trace_id: String,
    case_name: String,
    input_hex: String,
    actual_output: String,
    status: &str,
    error: Option<String>,
    note: Option<String>,
    duration_ms: u64,
) -> ConformanceCaseRow {
    ConformanceCaseRow {
        trace_id,
        family: fixture_set.family.clone(),
        symbol: case.function.clone(),
        mode: active_mode.to_string(),
        case_name,
        spec_section: case.spec_section.clone(),
        input_hex,
        expected_output: case.expected_output.clone(),
        actual_output: actual_output.clone(),
        host_output: None,
        host_parity: None,
        note,
        status: status.to_string(),
        passed: false,
        error,
        diff_offset: first_diff_offset(&case.expected_output, &actual_output),
        duration_ms: Some(duration_ms),
    }
}

fn ratio_percent(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        return 0.0;
    }
    (numerator as f64 * 100.0) / denominator as f64
}

fn mode_matches(active_mode: &str, case_mode: &str) -> bool {
    let active = active_mode.trim().to_ascii_lowercase();
    let case = case_mode.trim().to_ascii_lowercase();
    case == active || case == "both"
}

fn host_oracle_is_undefined(host_output: &str) -> bool {
    host_output.trim().eq_ignore_ascii_case("UB")
}

fn deterministic_generated_at_utc(fixture_sets: &[FixtureSet]) -> String {
    if fixture_sets.is_empty() {
        return "deterministic:empty".to_string();
    }
    let mut stamps: Vec<&str> = fixture_sets
        .iter()
        .map(|set| set.captured_at.as_str())
        .collect();
    stamps.sort_unstable();
    format!(
        "deterministic:{}..{}",
        stamps.first().copied().unwrap_or("unknown"),
        stamps.last().copied().unwrap_or("unknown")
    )
}

fn hex_encode(buf: &[u8]) -> String {
    let mut out = String::with_capacity(buf.len() * 2);
    for byte in buf {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

fn first_diff_offset(expected: &str, actual: &str) -> Option<u64> {
    let a = expected.as_bytes();
    let b = actual.as_bytes();
    let min_len = a.len().min(b.len());
    for idx in 0..min_len {
        if a[idx] != b[idx] {
            return Some(u64::try_from(idx).unwrap_or(u64::MAX));
        }
    }
    if a.len() == b.len() {
        None
    } else {
        Some(u64::try_from(min_len).unwrap_or(u64::MAX))
    }
}

fn append_match_notes(
    mut note: Option<String>,
    match_kind: Option<ExpectedOutputMatch>,
) -> Option<String> {
    if let Some(kind) = match_kind
        && let Some(suffix) = crate::verify::expected_output_match_note(kind)
    {
        append_note(&mut note, suffix);
    }
    note
}

fn append_note(note: &mut Option<String>, suffix: &str) {
    match note {
        Some(existing) => {
            existing.push_str("; ");
            existing.push_str(suffix);
        }
        None => *note = Some(suffix.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::FixtureSet;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn diff_offset_detects_first_change() {
        assert_eq!(first_diff_offset("abc", "abc"), None);
        assert_eq!(first_diff_offset("abc", "axc"), Some(1));
        assert_eq!(first_diff_offset("abc", "ab"), Some(2));
    }

    #[test]
    fn matrix_builds_for_basic_fixture() -> TestResult {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {"name":"len_a","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":"strict"}
                ]
            }"#,
        )?;

        let report = build_conformance_matrix(&[fixture], MatrixMode::Strict, "unit");
        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.mode, "strict");
        assert_eq!(report.summary.total_cases, 1);
        assert_eq!(report.cases.len(), 1);
        assert_eq!(report.cases[0].symbol, "strlen");
        assert!(report.cases[0].duration_ms.is_some());
        Ok(())
    }

    #[test]
    fn matrix_trims_fixture_mode_labels() -> TestResult {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {"name":"len_a","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":" strict \n"}
                ]
            }"#,
        )?;

        let report = build_conformance_matrix_with_executor(
            &[fixture],
            MatrixMode::Strict,
            "unit",
            |_, _, active_mode| {
                assert_eq!(active_mode, "strict");
                CaseExecution::Completed(DifferentialExecution {
                    host_output: "1".to_string(),
                    impl_output: "1".to_string(),
                    host_parity: true,
                    note: None,
                })
            },
        );

        assert_eq!(
            report.summary.total_cases, 1,
            "whitespace-padded fixture modes should not silently drop cases"
        );
        assert_eq!(report.summary.passed, 1);
        assert_eq!(report.cases[0].mode, "strict");
        Ok(())
    }

    #[test]
    fn matrix_trims_both_mode_before_disambiguating_case_names() -> TestResult {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {"name":"len_a","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":" both \n"}
                ]
            }"#,
        )?;

        let report = build_conformance_matrix_with_executor(
            &[fixture],
            MatrixMode::Both,
            "unit",
            |_, _, _| {
                CaseExecution::Completed(DifferentialExecution {
                    host_output: "1".to_string(),
                    impl_output: "1".to_string(),
                    host_parity: true,
                    note: None,
                })
            },
        );

        assert_eq!(report.summary.total_cases, 2);
        assert!(
            report
                .cases
                .iter()
                .any(|row| row.case_name == "len_a [strict]"),
            "strict row should be disambiguated even when fixture mode has whitespace"
        );
        assert!(
            report
                .cases
                .iter()
                .any(|row| row.case_name == "len_a [hardened]"),
            "hardened row should be disambiguated even when fixture mode has whitespace"
        );
        assert!(
            report
                .cases
                .iter()
                .any(|row| row.trace_id == "unit::string/strlen::strlen::strict::len_a [strict]"),
            "trace_id should use the same disambiguated case name as the row"
        );
        assert!(
            report.cases.iter().any(
                |row| row.trace_id == "unit::string/strlen::strlen::hardened::len_a [hardened]"
            ),
            "trace_id should use the same disambiguated case name as the row"
        );
        Ok(())
    }

    #[test]
    fn tolerant_numeric_match_accepts_small_rounding_delta() {
        assert_eq!(
            expected_output_match("2.718281828459045", "2.7182818284590455"),
            Some(ExpectedOutputMatch::NumericTolerance)
        );
        assert_eq!(
            expected_output_match("1.3", "1.2999999999999998"),
            Some(ExpectedOutputMatch::NumericTolerance)
        );
        assert_eq!(expected_output_match("1.3", "1.31"), None);
    }

    #[test]
    fn tolerant_numeric_match_accepts_scanf_float_storage_delta() {
        assert_eq!(
            expected_output_match("1:[1.5e10]", "1:[15000000512]"),
            Some(ExpectedOutputMatch::NumericTolerance)
        );
        assert_eq!(
            expected_output_match("1:[123.4]", "1:[123.400002]"),
            Some(ExpectedOutputMatch::NumericTolerance)
        );
        assert_eq!(expected_output_match("1:[42]", "1:[43]"), None);
    }

    #[test]
    fn regex_contract_match_honors_expected_output_patterns() {
        assert_eq!(
            expected_output_match("^0x[0-9a-f]+$", "0x1234abcd"),
            Some(ExpectedOutputMatch::Pattern)
        );
        assert_eq!(
            expected_output_match("^\\(nil\\)$|^0x0+$", "(nil)"),
            Some(ExpectedOutputMatch::Pattern)
        );
        assert_eq!(
            expected_output_match("^0x[0-9a-f]+$", "not-a-pointer"),
            None
        );
        assert_eq!(
            expected_output_match("literal", "literal"),
            Some(ExpectedOutputMatch::Exact)
        );
    }

    #[test]
    fn matrix_supports_timeout_and_crash_outcomes() -> TestResult {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {"name":"timeout_case","function":"__timeout_case","spec_section":"N/A","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":"strict"},
                    {"name":"crash_case","function":"__crash_case","spec_section":"N/A","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":"strict"}
                ]
            }"#,
        )?;

        let report = build_conformance_matrix_with_executor(
            &[fixture],
            MatrixMode::Strict,
            "unit",
            |f, _, _| match f {
                "__timeout_case" => CaseExecution::Timeout("timed out".to_string()),
                "__crash_case" => CaseExecution::Crash("signal=6".to_string()),
                _ => CaseExecution::Error("unexpected".to_string()),
            },
        );

        assert_eq!(report.summary.total_cases, 2);
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.failed, 2);
        assert_eq!(report.summary.errors, 0);
        assert!(report.cases.iter().any(|row| row.status == "timeout"));
        assert!(report.cases.iter().any(|row| row.status == "crash"));
        Ok(())
    }

    #[test]
    fn matrix_fails_defined_host_parity_mismatch() -> TestResult {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {"name":"host_mismatch","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":"strict"}
                ]
            }"#,
        )?;

        let report = build_conformance_matrix_with_executor(
            &[fixture],
            MatrixMode::Strict,
            "unit",
            |_, _, _| {
                CaseExecution::Completed(DifferentialExecution {
                    host_output: "2".to_string(),
                    impl_output: "1".to_string(),
                    host_parity: false,
                    note: None,
                })
            },
        );

        assert_eq!(report.summary.total_cases, 1);
        assert_eq!(report.summary.passed, 0);
        assert_eq!(report.summary.failed, 1);
        let row = report.cases.first().ok_or("missing matrix row")?;
        assert_eq!(row.status, "fail");
        assert!(!row.passed);
        assert_eq!(row.actual_output, "1");
        assert_eq!(row.host_output.as_deref(), Some("2"));
        assert_eq!(row.host_parity, Some(false));
        assert_eq!(row.note.as_deref(), Some("host_parity=false"));
        assert_eq!(
            row.diff_offset,
            Some(0),
            "host-parity-only failures should report the host-vs-actual divergence offset"
        );
        Ok(())
    }

    #[test]
    fn matrix_does_not_require_parity_for_undefined_host_oracle() -> TestResult {
        for host_output in ["UB", "ub", " UB\n"] {
            let fixture = FixtureSet::from_json(
                r#"{
                    "version":"v1",
                    "family":"string/strlen",
                    "captured_at":"2026-02-13T00:00:00Z",
                    "cases":[
                        {"name":"unterminated_hardened","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97]},"expected_output":"1","expected_errno":0,"mode":"hardened"}
                    ]
                }"#,
            )?;

            let report = build_conformance_matrix_with_executor(
                &[fixture],
                MatrixMode::Hardened,
                "unit",
                |_, _, _| {
                    CaseExecution::Completed(DifferentialExecution {
                        host_output: host_output.to_string(),
                        impl_output: "1".to_string(),
                        host_parity: false,
                        note: None,
                    })
                },
            );

            assert_eq!(report.summary.total_cases, 1);
            assert_eq!(report.summary.passed, 1);
            assert_eq!(report.summary.failed, 0);
            let row = report.cases.first().ok_or("missing matrix row")?;
            assert_eq!(row.status, "pass");
            assert!(row.passed);
            assert_eq!(row.host_output.as_deref(), Some(host_output));
            assert_eq!(row.host_parity, Some(false));
        }
        Ok(())
    }
}
