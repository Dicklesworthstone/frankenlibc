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
}
