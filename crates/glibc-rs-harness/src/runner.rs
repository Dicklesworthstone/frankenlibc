//! Test execution engine.

use crate::fixtures::FixtureSet;
use crate::verify::VerificationResult;
use crate::{FixtureCase, diff};

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
                let (actual, diff) = execute_case(case);
                VerificationResult {
                    case_name: case.name.clone(),
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

fn execute_case(case: &FixtureCase) -> (String, Option<String>) {
    let actual = match case.function.as_str() {
        "memcpy" => simulate_memcpy(case),
        "strlen" => simulate_strlen(case),
        _ => format!("unsupported:{}", case.function),
    };
    let diff = if actual == case.expected_output {
        None
    } else {
        Some(diff::render_diff(&case.expected_output, &actual))
    };
    (actual, diff)
}

fn simulate_memcpy(case: &FixtureCase) -> String {
    let src = case
        .inputs
        .get("src")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_u64())
        .map(|v| v as u8)
        .collect::<Vec<u8>>();
    let dst_len = case
        .inputs
        .get("dst_len")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let n = case
        .inputs
        .get("n")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0) as usize;
    let is_strict = case.mode.eq_ignore_ascii_case("strict");

    // Strict mode preserves C UB semantics for overflow attempts.
    if is_strict && n > dst_len {
        return String::from("UB");
    }

    let mut dst = vec![0u8; dst_len];
    let count = n.min(src.len()).min(dst.len());
    if count > 0 {
        dst[..count].copy_from_slice(&src[..count]);
    }
    format!("{dst:?}")
}

fn simulate_strlen(case: &FixtureCase) -> String {
    let bytes = case
        .inputs
        .get("s")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_u64())
        .map(|v| v as u8)
        .collect::<Vec<u8>>();
    let is_strict = case.mode.eq_ignore_ascii_case("strict");
    match bytes.iter().position(|b| *b == 0) {
        Some(len) => len.to_string(),
        None if is_strict => String::from("UB"),
        None => bytes.len().to_string(),
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
    }
}
