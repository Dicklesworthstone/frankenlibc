//! Output comparison and verification.

use serde::{Deserialize, Serialize};

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
    fn summary_serialization_roundtrip() {
        let results = vec![
            make_result("memcpy", true),
            make_result("strlen", false),
        ];
        let s = VerificationSummary::from_results(results);
        let json = serde_json::to_string(&s).unwrap();
        let deserialized: VerificationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.total, 2);
        assert_eq!(deserialized.passed, 1);
        assert_eq!(deserialized.failed, 1);
        assert_eq!(deserialized.results.len(), 2);
    }
}
