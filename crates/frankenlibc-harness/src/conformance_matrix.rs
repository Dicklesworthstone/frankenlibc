//! Differential conformance matrix generation (bd-l93x.2).
//!
//! This module executes fixture cases against host-vs-implementation paths and
//! emits a machine-readable matrix with symbol-level aggregation.

use std::collections::BTreeMap;
use std::time::Instant;

use regex::Regex;
use serde::{Deserialize, Serialize};

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
    let case_name = if case.mode.eq_ignore_ascii_case("both") {
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
        case_name = case.name
    );

    let input_hex = serde_json::to_vec(&case.inputs)
        .map(|buf| hex_encode(&buf))
        .unwrap_or_else(|_| String::new());

    match execution {
        CaseExecution::Completed(run) => {
            let exact_match = run.impl_output == case.expected_output;
            let tolerance_match =
                !exact_match && tolerant_numeric_match(&case.expected_output, &run.impl_output);
            let pattern_match = !exact_match
                && !tolerance_match
                && regex_contract_match(&case.expected_output, &run.impl_output);
            let passed = exact_match || tolerance_match || pattern_match;
            let diff_offset = if passed {
                None
            } else {
                first_diff_offset(&case.expected_output, &run.impl_output)
            };
            let note = append_match_notes(run.note, tolerance_match, pattern_match);
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
    let active = active_mode.to_ascii_lowercase();
    let case = case_mode.to_ascii_lowercase();
    case == active || case == "both"
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
    tolerance_match: bool,
    pattern_match: bool,
) -> Option<String> {
    if tolerance_match {
        append_note(&mut note, "numeric_tolerance_match");
    }
    if pattern_match {
        append_note(&mut note, "expected_output_pattern_match");
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

fn regex_contract_match(expected: &str, actual: &str) -> bool {
    if !expected.starts_with('^') || !expected.ends_with('$') {
        return false;
    }

    match Regex::new(expected) {
        Ok(pattern) => pattern.is_match(actual),
        Err(_) => false,
    }
}

fn tolerant_numeric_match(expected: &str, actual: &str) -> bool {
    if tolerant_return_values_match(expected, actual) {
        return true;
    }

    let exp = match expected.parse::<f64>() {
        Ok(v) => v,
        Err(_) => return false,
    };
    let act = match actual.parse::<f64>() {
        Ok(v) => v,
        Err(_) => return false,
    };

    if exp.is_nan() && act.is_nan() {
        return true;
    }
    if exp.is_infinite() || act.is_infinite() {
        return exp == act;
    }

    let diff = (exp - act).abs();
    let scale = exp.abs().max(act.abs()).max(1.0);
    diff <= 1e-12 * scale
}

fn tolerant_return_values_match(expected: &str, actual: &str) -> bool {
    let Some((expected_ret, expected_values)) = split_return_values(expected) else {
        return false;
    };
    let Some((actual_ret, actual_values)) = split_return_values(actual) else {
        return false;
    };
    if expected_ret != actual_ret || expected_values.len() != actual_values.len() {
        return false;
    }
    expected_values
        .iter()
        .zip(actual_values.iter())
        .all(|(expected, actual)| tolerant_return_value_match(expected, actual))
}

fn split_return_values(text: &str) -> Option<(&str, Vec<&str>)> {
    let (ret, values) = text.split_once(":[")?;
    let values = values.strip_suffix(']')?;
    if values.is_empty() {
        return Some((ret, Vec::new()));
    }
    Some((ret, values.split(',').collect()))
}

fn tolerant_return_value_match(expected: &str, actual: &str) -> bool {
    if expected == actual {
        return true;
    }
    if !looks_float_like(expected) && !looks_float_like(actual) {
        return false;
    }
    let Ok(exp) = expected.parse::<f64>() else {
        return false;
    };
    let Ok(act) = actual.parse::<f64>() else {
        return false;
    };
    if exp.is_nan() && act.is_nan() {
        return true;
    }
    if exp.is_infinite() || act.is_infinite() {
        return exp == act;
    }
    let diff = (exp - act).abs();
    let scale = exp.abs().max(act.abs()).max(1.0);
    diff <= 1e-6 * scale
}

fn looks_float_like(value: &str) -> bool {
    value.contains('.') || value.contains('e') || value.contains('E')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::FixtureSet;

    #[test]
    fn diff_offset_detects_first_change() {
        assert_eq!(first_diff_offset("abc", "abc"), None);
        assert_eq!(first_diff_offset("abc", "axc"), Some(1));
        assert_eq!(first_diff_offset("abc", "ab"), Some(2));
    }

    #[test]
    fn matrix_builds_for_basic_fixture() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-13T00:00:00Z",
                "cases":[
                    {"name":"len_a","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[97,0]},"expected_output":"1","expected_errno":0,"mode":"strict"}
                ]
            }"#,
        )
        .expect("fixture should parse");

        let report = build_conformance_matrix(&[fixture], MatrixMode::Strict, "unit");
        assert_eq!(report.schema_version, "v1");
        assert_eq!(report.mode, "strict");
        assert_eq!(report.summary.total_cases, 1);
        assert_eq!(report.cases.len(), 1);
        assert_eq!(report.cases[0].symbol, "strlen");
        assert!(report.cases[0].duration_ms.is_some());
    }

    #[test]
    fn tolerant_numeric_match_accepts_small_rounding_delta() {
        assert!(tolerant_numeric_match(
            "2.718281828459045",
            "2.7182818284590455"
        ));
        assert!(tolerant_numeric_match("1.3", "1.2999999999999998"));
        assert!(!tolerant_numeric_match("1.3", "1.31"));
    }

    #[test]
    fn tolerant_numeric_match_accepts_scanf_float_storage_delta() {
        assert!(tolerant_numeric_match("1:[1.5e10]", "1:[15000000512]"));
        assert!(tolerant_numeric_match("1:[123.4]", "1:[123.400002]"));
        assert!(!tolerant_numeric_match("1:[42]", "1:[43]"));
    }

    #[test]
    fn regex_contract_match_honors_expected_output_patterns() {
        assert!(regex_contract_match("^0x[0-9a-f]+$", "0x1234abcd"));
        assert!(regex_contract_match("^\\(nil\\)$|^0x0+$", "(nil)"));
        assert!(!regex_contract_match("^0x[0-9a-f]+$", "not-a-pointer"));
        assert!(!regex_contract_match("literal", "literal"));
    }

    #[test]
    fn matrix_supports_timeout_and_crash_outcomes() {
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
        )
        .expect("fixture should parse");

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
    }
}
