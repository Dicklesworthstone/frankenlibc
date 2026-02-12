//! Test execution engine.

use crate::fixtures::FixtureSet;
use crate::verify::VerificationResult;
use crate::{FixtureCase, diff};
use frankenlibc_conformance::execute_fixture_case;

/// Runs a fixture set and collects verification results.
pub struct TestRunner {
    /// Name of the test campaign.
    pub campaign: String,
    /// Mode being tested (strict or hardened).
    pub mode: String,
}

impl TestRunner {
    /// Create a new test runner.
    #[must_use]
    pub fn new(campaign: impl Into<String>, mode: impl Into<String>) -> Self {
        Self {
            campaign: campaign.into(),
            mode: mode.into(),
        }
    }

    /// Run all fixtures in a set and return results.
    pub fn run(&self, fixture_set: &FixtureSet) -> Vec<VerificationResult> {
        fixture_set
            .cases
            .iter()
            .filter(|case| mode_matches(&self.mode, &case.mode))
            .map(|case| {
                let (actual, diff) = execute_case(case, &self.mode);
                let case_name = if case.mode.eq_ignore_ascii_case("both") {
                    format!("{} [{}]", case.name, self.mode)
                } else {
                    case.name.clone()
                };
                let trace_id = format!(
                    "{campaign}::{family}::{symbol}::{mode}::{case_name}",
                    campaign = self.campaign.as_str(),
                    family = fixture_set.family.as_str(),
                    symbol = case.function.as_str(),
                    mode = self.mode.as_str(),
                    case_name = case.name.as_str()
                );
                VerificationResult {
                    trace_id,
                    campaign: self.campaign.clone(),
                    family: fixture_set.family.clone(),
                    symbol: case.function.clone(),
                    mode: self.mode.clone(),
                    case_name,
                    spec_section: case.spec_section.clone(),
                    passed: actual == case.expected_output,
                    expected: case.expected_output.clone(),
                    actual,
                    diff,
                }
            })
            .collect()
    }
}

fn mode_matches(active_mode: &str, case_mode: &str) -> bool {
    let active = active_mode.to_ascii_lowercase();
    let case = case_mode.to_ascii_lowercase();
    case == active || case == "both"
}

fn execute_case(case: &FixtureCase, active_mode: &str) -> (String, Option<String>) {
    // Fixture cases with mode=both should execute under the runner's active mode.
    let execution = execute_fixture_case(&case.function, &case.inputs, active_mode);
    match execution {
        Ok(run) => {
            let mut notes = Vec::new();
            if active_mode.eq_ignore_ascii_case("strict") && !run.host_parity {
                notes.push(format!(
                    "strict host parity mismatch: host={}, impl={}",
                    run.host_output, run.impl_output
                ));
            }
            if let Some(note) = run.note.clone() {
                notes.push(note);
            }

            let mut diff_out = None;
            if run.impl_output != case.expected_output {
                diff_out = Some(diff::render_diff(&case.expected_output, &run.impl_output));
            } else if !notes.is_empty() {
                diff_out = Some(notes.join("\n"));
            }

            (run.impl_output, diff_out)
        }
        Err(err) => {
            let actual = format!("unsupported:{err}");
            let diff_out = Some(diff::render_diff(&case.expected_output, &actual));
            (actual, diff_out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixtureSet;

    #[test]
    fn strict_runner_executes_matching_cases() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/memcpy",
                "captured_at":"2026-02-09T00:00:00Z",
                "cases":[
                    {"name":"strict_copy","function":"memcpy","spec_section":"POSIX memcpy","inputs":{"src":[1,2,3],"dst_len":3,"n":2},"expected_output":"[1, 2, 0]","expected_errno":0,"mode":"strict"},
                    {"name":"hard_copy","function":"memcpy","spec_section":"POSIX memcpy","inputs":{"src":[1,2,3],"dst_len":3,"n":3},"expected_output":"[1, 2, 3]","expected_errno":0,"mode":"hardened"}
                ]
            }"#,
        )
        .expect("valid fixture json");

        let strict = TestRunner::new("smoke", "strict").run(&fixture);
        assert_eq!(strict.len(), 1);
        assert!(strict[0].passed);
        assert_eq!(strict[0].symbol, "memcpy");
        assert_eq!(strict[0].mode, "strict");
        assert!(strict[0].trace_id.contains("smoke::"));
    }

    #[test]
    fn hardened_runner_executes_matching_cases() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-09T00:00:00Z",
                "cases":[
                    {"name":"strict_len","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[65,0]},"expected_output":"1","expected_errno":0,"mode":"strict"},
                    {"name":"hard_len","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[70,79,79,0]},"expected_output":"3","expected_errno":0,"mode":"hardened"}
                ]
            }"#,
        )
        .expect("valid fixture json");

        let hardened = TestRunner::new("smoke", "hardened").run(&fixture);
        assert_eq!(hardened.len(), 1);
        assert!(hardened[0].passed);
        assert_eq!(hardened[0].symbol, "strlen");
        assert_eq!(hardened[0].mode, "hardened");
    }

    #[test]
    fn both_mode_fixture_executes_under_active_mode() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-09T00:00:00Z",
                "cases":[
                    {"name":"len_both","function":"strlen","spec_section":"POSIX strlen","inputs":{"s":[65,0]},"expected_output":"1","expected_errno":0,"mode":"both"}
                ]
            }"#,
        )
        .expect("valid fixture json");

        let strict = TestRunner::new("both", "strict").run(&fixture);
        assert_eq!(strict.len(), 1);
        assert!(strict[0].passed);
        assert_eq!(strict[0].case_name, "len_both [strict]");
        assert_eq!(strict[0].mode, "strict");

        let hardened = TestRunner::new("both", "hardened").run(&fixture);
        assert_eq!(hardened.len(), 1);
        assert!(hardened[0].passed);
        assert_eq!(hardened[0].case_name, "len_both [hardened]");
        assert_eq!(hardened[0].mode, "hardened");
    }

    #[test]
    fn strict_marks_overflow_fixture_as_ub() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/memcpy",
                "captured_at":"2026-02-09T00:00:00Z",
                "cases":[
                    {"name":"strict_overflow","function":"memcpy","spec_section":"TSM strict","inputs":{"src":[1,2,3,4],"dst_len":2,"n":4},"expected_output":"UB","expected_errno":0,"mode":"strict"}
                ]
            }"#,
        )
        .expect("valid fixture json");

        let strict = TestRunner::new("ub", "strict").run(&fixture);
        assert_eq!(strict.len(), 1);
        assert!(strict[0].passed);
        assert_eq!(strict[0].symbol, "memcpy");
    }

    #[test]
    fn hardened_truncates_unterminated_strlen_fixture() {
        let fixture = FixtureSet::from_json(
            r#"{
                "version":"v1",
                "family":"string/strlen",
                "captured_at":"2026-02-09T00:00:00Z",
                "cases":[
                    {"name":"hard_unterminated","function":"strlen","spec_section":"TSM hardened","inputs":{"s":[1,2,3]},"expected_output":"3","expected_errno":0,"mode":"hardened"}
                ]
            }"#,
        )
        .expect("valid fixture json");

        let hardened = TestRunner::new("hard", "hardened").run(&fixture);
        assert_eq!(hardened.len(), 1);
        assert!(hardened[0].passed);
        assert_eq!(hardened[0].symbol, "strlen");
    }
}
