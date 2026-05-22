//! Output comparison and verification.

use std::collections::BTreeSet;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// How an actual output satisfied a fixture expected-output contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedOutputMatch {
    /// The output matched byte-for-byte.
    Exact,
    /// The output matched within the fixture numeric tolerance.
    NumericTolerance,
    /// The expected output was an anchored regex contract that matched.
    Pattern,
}

/// Return the match class for a fixture expected-output contract.
#[must_use]
pub fn expected_output_match(expected: &str, actual: &str) -> Option<ExpectedOutputMatch> {
    if expected == actual {
        return Some(ExpectedOutputMatch::Exact);
    }
    if tolerant_numeric_match(expected, actual) {
        return Some(ExpectedOutputMatch::NumericTolerance);
    }
    if regex_contract_match(expected, actual) {
        return Some(ExpectedOutputMatch::Pattern);
    }
    None
}

/// Stable note suffix for non-exact expected-output matches.
#[must_use]
pub const fn expected_output_match_note(kind: ExpectedOutputMatch) -> Option<&'static str> {
    match kind {
        ExpectedOutputMatch::Exact => None,
        ExpectedOutputMatch::NumericTolerance => Some("numeric_tolerance_match"),
        ExpectedOutputMatch::Pattern => Some("expected_output_pattern_match"),
    }
}

/// Canonical actual value for deterministic verification reports.
#[must_use]
pub fn report_actual_output(
    expected: &str,
    actual: &str,
    kind: Option<ExpectedOutputMatch>,
) -> String {
    match kind {
        Some(ExpectedOutputMatch::Pattern) => format!("PATTERN_MATCH:{expected}"),
        _ => actual.to_string(),
    }
}

/// Canonical output fragment for deterministic diagnostic notes.
#[must_use]
pub fn report_note_output(output: &str) -> String {
    if output.eq_ignore_ascii_case("nan") || output.eq_ignore_ascii_case("-nan") {
        "nan".to_string()
    } else {
        output.to_string()
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

    if !looks_float_like(expected) {
        return false;
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

/// Result of verifying a single fixture case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Stable trace identifier for this execution.
    ///
    /// Contract:
    /// - deterministic within a run
    /// - includes enough context to locate the failing symbol without re-running
    pub trace_id: String,
    /// Campaign name (e.g. `fixture-verify`).
    pub campaign: String,
    /// Fixture family (e.g. `string/strlen`).
    pub family: String,
    /// ABI symbol/function under test (e.g. `memcpy`).
    pub symbol: String,
    /// Execution mode (`strict` or `hardened`).
    pub mode: String,
    /// Name of the test case.
    pub case_name: String,
    /// POSIX/C spec section reference.
    pub spec_section: String,
    /// Whether the case passed.
    pub passed: bool,
    /// Expected output.
    pub expected: String,
    /// Actual output from our implementation.
    pub actual: String,
    /// Host-glibc oracle output when the fixture executor reached the host path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_output: Option<String>,
    /// Whether our implementation matched the host-glibc oracle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_parity: Option<bool>,
    /// Diff if the case failed.
    pub diff: Option<String>,
}

/// Aggregate verification summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationSummary {
    /// Total cases run.
    pub total: usize,
    /// Cases passed.
    pub passed: usize,
    /// Cases failed.
    pub failed: usize,
    /// Individual results.
    pub results: Vec<VerificationResult>,
}

impl VerificationSummary {
    /// Build a summary from a list of results.
    #[must_use]
    pub fn from_results(results: Vec<VerificationResult>) -> Self {
        let total = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = total - passed;
        Self {
            total,
            passed,
            failed,
            results,
        }
    }

    /// Returns true if all cases passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Returns results for a specific symbol.
    #[must_use]
    pub fn results_for_symbol(&self, symbol: &str) -> Vec<&VerificationResult> {
        self.results.iter().filter(|r| r.symbol == symbol).collect()
    }

    /// Returns all failing results.
    #[must_use]
    pub fn failures(&self) -> Vec<&VerificationResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }

    /// Fixture families with no reported host-glibc oracle result.
    #[must_use]
    pub fn families_without_host_parity_oracle(&self) -> Vec<String> {
        let all_families: BTreeSet<&str> =
            self.results.iter().map(|row| row.family.as_str()).collect();
        let families_with_oracle: BTreeSet<&str> = self
            .results
            .iter()
            .filter(|row| row.host_parity.is_some())
            .map(|row| row.family.as_str())
            .collect();
        all_families
            .difference(&families_with_oracle)
            .map(|family| (*family).to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_result(symbol: &str, passed: bool) -> VerificationResult {
        VerificationResult {
            trace_id: format!("test::{}::strict::case1", symbol),
            campaign: "test".into(),
            family: "string/ops".into(),
            symbol: symbol.into(),
            mode: "strict".into(),
            case_name: "case1".into(),
            spec_section: "POSIX.1".into(),
            passed,
            expected: "ok".into(),
            actual: if passed { "ok".into() } else { "fail".into() },
            host_output: Some("ok".into()),
            host_parity: Some(passed),
            diff: if passed {
                None
            } else {
                Some("-ok\n+fail\n".into())
            },
        }
    }

    #[test]
    fn summary_empty_results() {
        let s = VerificationSummary::from_results(vec![]);
        assert_eq!(s.total, 0);
        assert_eq!(s.passed, 0);
        assert_eq!(s.failed, 0);
        assert!(s.all_passed());
    }

    #[test]
    fn summary_all_pass() {
        let results = vec![
            make_result("memcpy", true),
            make_result("strlen", true),
            make_result("strcmp", true),
        ];
        let s = VerificationSummary::from_results(results);
        assert_eq!(s.total, 3);
        assert_eq!(s.passed, 3);
        assert_eq!(s.failed, 0);
        assert!(s.all_passed());
    }

    #[test]
    fn summary_mixed_results() {
        let results = vec![
            make_result("memcpy", true),
            make_result("strlen", false),
            make_result("strcmp", true),
            make_result("strcat", false),
        ];
        let s = VerificationSummary::from_results(results);
        assert_eq!(s.total, 4);
        assert_eq!(s.passed, 2);
        assert_eq!(s.failed, 2);
        assert!(!s.all_passed());
    }

    #[test]
    fn summary_all_fail() {
        let results = vec![make_result("memcpy", false), make_result("strlen", false)];
        let s = VerificationSummary::from_results(results);
        assert_eq!(s.total, 2);
        assert_eq!(s.passed, 0);
        assert_eq!(s.failed, 2);
        assert!(!s.all_passed());
    }

    #[test]
    fn results_for_symbol_filters_correctly() {
        let results = vec![
            make_result("memcpy", true),
            make_result("strlen", false),
            make_result("memcpy", false),
        ];
        let s = VerificationSummary::from_results(results);
        let memcpy = s.results_for_symbol("memcpy");
        assert_eq!(memcpy.len(), 2);
        let strlen = s.results_for_symbol("strlen");
        assert_eq!(strlen.len(), 1);
        let missing = s.results_for_symbol("nonexistent");
        assert!(missing.is_empty());
    }

    #[test]
    fn failures_returns_only_failed() {
        let results = vec![
            make_result("memcpy", true),
            make_result("strlen", false),
            make_result("strcmp", true),
            make_result("strcat", false),
        ];
        let s = VerificationSummary::from_results(results);
        let fails = s.failures();
        assert_eq!(fails.len(), 2);
        assert!(fails.iter().all(|r| !r.passed));
        assert!(fails.iter().any(|r| r.symbol == "strlen"));
        assert!(fails.iter().any(|r| r.symbol == "strcat"));
    }

    #[test]
    fn verification_result_serialization_roundtrip() {
        let r = make_result("memcpy", true);
        let json = serde_json::to_string(&r).unwrap();
        let deserialized: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.trace_id, r.trace_id);
        assert_eq!(deserialized.symbol, r.symbol);
        assert_eq!(deserialized.passed, r.passed);
        assert_eq!(deserialized.host_output, r.host_output);
        assert_eq!(deserialized.host_parity, r.host_parity);
        assert_eq!(deserialized.diff, r.diff);
    }

    #[test]
    fn verification_result_failed_has_diff() {
        let r = make_result("strlen", false);
        assert!(r.diff.is_some());
        assert!(r.diff.unwrap().contains("-ok"));
    }

    #[test]
    fn verification_result_passed_has_no_diff() {
        let r = make_result("strlen", true);
        assert!(r.diff.is_none());
    }

    #[test]
    fn expected_output_match_accepts_small_rounding_delta() {
        assert_eq!(
            expected_output_match("2.718281828459045", "2.7182818284590455"),
            Some(ExpectedOutputMatch::NumericTolerance)
        );
        assert_eq!(
            expected_output_match("1.3", "1.2999999999999998"),
            Some(ExpectedOutputMatch::NumericTolerance)
        );
        assert_eq!(expected_output_match("1.3", "1.31"), None);
        assert_eq!(expected_output_match("42", "42.00000000000001"), None);
    }

    #[test]
    fn expected_output_match_accepts_scanf_float_storage_delta() {
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
    fn expected_output_match_honors_anchored_regex_contracts() {
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
    fn report_actual_output_scrubs_pattern_matches() {
        let kind = expected_output_match("^0x[0-9a-f]+$", "0x1234abcd");
        assert_eq!(
            report_actual_output("^0x[0-9a-f]+$", "0x1234abcd", kind),
            "PATTERN_MATCH:^0x[0-9a-f]+$"
        );
    }

    #[test]
    fn report_note_output_canonicalizes_nan_sign() {
        assert_eq!(report_note_output("-nan"), "nan");
        assert_eq!(report_note_output("nan"), "nan");
        assert_eq!(report_note_output("value"), "value");
    }

    #[test]
    fn summary_serialization_roundtrip() {
        let results = vec![make_result("memcpy", true), make_result("strlen", false)];
        let s = VerificationSummary::from_results(results);
        let json = serde_json::to_string(&s).unwrap();
        let deserialized: VerificationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total, 2);
        assert_eq!(deserialized.passed, 1);
        assert_eq!(deserialized.failed, 1);
        assert_eq!(deserialized.results.len(), 2);
    }

    #[test]
    fn summary_reports_families_without_host_parity_oracle() {
        let mut with_oracle = make_result("memcpy", true);
        with_oracle.family = "string/memcpy".into();

        let mut missing_oracle = make_result("strlen", true);
        missing_oracle.family = "string/strlen".into();
        missing_oracle.host_output = None;
        missing_oracle.host_parity = None;

        let summary = VerificationSummary::from_results(vec![with_oracle, missing_oracle]);
        assert_eq!(
            summary.families_without_host_parity_oracle(),
            vec!["string/strlen".to_string()]
        );
    }
}
