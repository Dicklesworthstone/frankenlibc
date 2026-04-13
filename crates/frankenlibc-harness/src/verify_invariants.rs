//! Invariant verification for stdio entrypoints.
//!
//! Loads machine-checkable invariants from `tests/conformance/stdio_invariants.v1.json`
//! and verifies them against fixture runs.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Schema for a single invariant definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    /// Function name (e.g., "fopen", "fread").
    pub function: String,
    /// Spec section reference.
    pub spec_section: String,
    /// Human-readable description.
    pub description: String,
    /// Pre-conditions that must hold before the call.
    pub pre_conditions: Vec<String>,
    /// Post-conditions that must hold after the call.
    pub post_conditions: Vec<String>,
    /// SafetyState lattice transitions.
    pub lattice_transition: LatticeTransition,
    /// Optional notes.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Lattice state transitions for an operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LatticeTransition {
    /// Conditional transitions (success/failure paths).
    Conditional(HashMap<String, String>),
}

/// Full invariants file schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantsFile {
    /// Schema version.
    pub version: String,
    /// Schema identifier.
    pub schema: String,
    /// Capture timestamp.
    pub captured_at: String,
    /// Description of the invariants file.
    pub description: String,
    /// DSL documentation.
    pub dsl: DslDoc,
    /// List of invariants.
    pub invariants: Vec<Invariant>,
    /// Lattice state definitions.
    pub lattice_states: HashMap<String, String>,
}

/// DSL documentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DslDoc {
    pub description: String,
    pub operators: HashMap<String, String>,
}

/// Result of checking a single invariant against a fixture case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantCheckResult {
    /// Trace identifier.
    pub trace_id: String,
    /// Function being tested.
    pub function: String,
    /// Fixture case name.
    pub case_name: String,
    /// Execution mode (strict/hardened).
    pub mode: String,
    /// Invariant category (pre/post).
    pub invariant_type: String,
    /// The invariant expression that was checked.
    pub expression: String,
    /// Whether the invariant held.
    pub passed: bool,
    /// Diagnostic message if failed.
    pub diagnostic: Option<String>,
}

/// Summary of invariant verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantVerificationSummary {
    /// Total invariant checks performed.
    pub total_checks: usize,
    /// Checks that passed.
    pub passed: usize,
    /// Checks that failed.
    pub failed: usize,
    /// Per-function breakdown.
    pub by_function: HashMap<String, FunctionCheckSummary>,
    /// All individual results.
    pub results: Vec<InvariantCheckResult>,
}

/// Per-function check summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionCheckSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
}

impl InvariantVerificationSummary {
    /// Build a summary from check results.
    #[must_use]
    pub fn from_results(results: Vec<InvariantCheckResult>) -> Self {
        let total_checks = results.len();
        let passed = results.iter().filter(|r| r.passed).count();
        let failed = total_checks - passed;

        let mut by_function: HashMap<String, FunctionCheckSummary> = HashMap::new();
        for r in &results {
            let entry = by_function.entry(r.function.clone()).or_default();
            entry.total += 1;
            if r.passed {
                entry.passed += 1;
            } else {
                entry.failed += 1;
            }
        }

        Self {
            total_checks,
            passed,
            failed,
            by_function,
            results,
        }
    }

    /// Returns true if all invariant checks passed.
    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }

    /// Returns all failing checks.
    #[must_use]
    pub fn failures(&self) -> Vec<&InvariantCheckResult> {
        self.results.iter().filter(|r| !r.passed).collect()
    }
}

/// Load invariants from the JSON file.
pub fn load_invariants(path: &Path) -> Result<InvariantsFile, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read invariants file: {e}"))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse invariants JSON: {e}"))
}

/// Load invariants from the default location.
pub fn load_default_invariants() -> Result<InvariantsFile, String> {
    // Look for the file relative to the workspace root.
    let paths = [
        "tests/conformance/stdio_invariants.v1.json",
        "../tests/conformance/stdio_invariants.v1.json",
        "../../tests/conformance/stdio_invariants.v1.json",
    ];

    for p in paths {
        let path = Path::new(p);
        if path.exists() {
            return load_invariants(path);
        }
    }

    Err("stdio_invariants.v1.json not found".to_string())
}

/// Get invariant for a specific function.
pub fn get_invariant_for_function<'a>(
    invariants: &'a InvariantsFile,
    function: &str,
) -> Option<&'a Invariant> {
    invariants
        .invariants
        .iter()
        .find(|i| i.function == function)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_stdio_invariants() {
        // Try to load from workspace root.
        let result = load_default_invariants();
        if let Ok(invariants) = result {
            assert_eq!(invariants.version, "v1");
            assert_eq!(invariants.schema, "stdio_invariants");
            assert!(!invariants.invariants.is_empty());

            // Verify we have the expected functions.
            let functions: Vec<&str> = invariants
                .invariants
                .iter()
                .map(|i| i.function.as_str())
                .collect();
            assert!(functions.contains(&"fopen"));
            assert!(functions.contains(&"fread"));
            assert!(functions.contains(&"fwrite"));
            assert!(functions.contains(&"fseek"));
            assert!(functions.contains(&"ftell"));
            assert!(functions.contains(&"fclose"));
            assert!(functions.contains(&"ungetc"));
            assert!(functions.contains(&"fflush"));
            assert!(functions.contains(&"fileno"));
            assert!(functions.contains(&"feof"));
            assert!(functions.contains(&"ferror"));
            assert!(functions.contains(&"clearerr"));
        }
        // If file not found, test is skipped (might be running from different directory).
    }

    #[test]
    fn invariant_summary_construction() {
        let results = vec![
            InvariantCheckResult {
                trace_id: "t1".into(),
                function: "fopen".into(),
                case_name: "case1".into(),
                mode: "strict".into(),
                invariant_type: "post".into(),
                expression: "return != NULL".into(),
                passed: true,
                diagnostic: None,
            },
            InvariantCheckResult {
                trace_id: "t2".into(),
                function: "fopen".into(),
                case_name: "case2".into(),
                mode: "strict".into(),
                invariant_type: "post".into(),
                expression: "errno == ENOENT".into(),
                passed: false,
                diagnostic: Some("errno was 0".into()),
            },
        ];

        let summary = InvariantVerificationSummary::from_results(results);
        assert_eq!(summary.total_checks, 2);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.failed, 1);
        assert!(!summary.all_passed());
        assert_eq!(summary.failures().len(), 1);
    }
}
