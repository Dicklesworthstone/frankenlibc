//! Hermetic safe-default fixture log policy for bd-j1u6u.2.

use regex::Regex;
use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const REQUIRED_OUTPUT_TOKENS: &[&str] = &["symbol=", "mode=", "failure_signature="];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn policy_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/safe_default_fixture_hermeticity_policy.v1.json")
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn string_array<'a>(value: &'a Value, key: &str) -> TestResult<Vec<&'a str>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("policy.{key} must be an array")))?
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .ok_or_else(|| test_error(format!("policy.{key} entries must be strings")))
        })
        .collect()
}

fn regex_specs(value: &Value, key: &str) -> TestResult<Vec<(String, Regex)>> {
    value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| test_error(format!("policy.{key} must be an array")))?
        .iter()
        .map(|entry| {
            let id = entry
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| test_error(format!("policy.{key} entry missing id")))?;
            let pattern = entry
                .get("pattern")
                .and_then(Value::as_str)
                .ok_or_else(|| test_error(format!("policy.{key}.{id} missing pattern")))?;
            let regex = Regex::new(pattern)
                .map_err(|err| test_error(format!("policy.{key}.{id} regex invalid: {err}")))?;
            Ok((id.to_string(), regex))
        })
        .collect()
}

fn fixture_paths(root: &Path) -> TestResult<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let dir = root.join("tests/conformance/fixtures");
    for entry in std::fs::read_dir(&dir)
        .map_err(|err| test_error(format!("{} should be readable: {err}", dir.display())))?
    {
        let path = entry?.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

fn dotted_field<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn dotted_str<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    dotted_field(value, path).and_then(Value::as_str)
}

fn contains_marker(text: &str, markers: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    markers
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase()))
}

fn is_safe_default_case(case: &Value, markers: &[&str]) -> bool {
    [
        "expected_output",
        "inputs.expected_class",
        "inputs.safe_default_rationale",
        "inputs.oracle_kind",
        "inputs.divergence_policy",
    ]
    .iter()
    .filter_map(|field| dotted_str(case, field))
    .any(|text| contains_marker(text, markers))
}

fn host_differential_exempt(case: &Value, policy: &Value) -> bool {
    let Some(exemption) = policy.get("host_differential_exemption") else {
        return false;
    };
    let oracle_kind = dotted_str(case, "inputs.oracle_kind").unwrap_or_default();
    let divergence_policy = dotted_str(case, "inputs.divergence_policy").unwrap_or_default();
    let allowed_kinds = exemption
        .get("required_oracle_kinds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|kind| kind == oracle_kind);
    let required_prefix = exemption
        .get("required_divergence_policy_prefix")
        .and_then(Value::as_str)
        .unwrap_or("allow_ambient_capture:");
    allowed_kinds && divergence_policy.starts_with(required_prefix)
}

fn case_label(path: &Path, index: usize, case: &Value) -> String {
    let name = case
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or("<unnamed>");
    let function = case
        .get("function")
        .and_then(Value::as_str)
        .unwrap_or("<unknown>");
    format!("{} cases[{index}] {function}/{name}", path.display())
}

fn lint_safe_default_case(path: &Path, index: usize, case: &Value, policy: &Value) -> TestResult {
    let label = case_label(path, index, case);
    let expected_output = dotted_str(case, "expected_output")
        .ok_or_else(|| test_error(format!("{label} missing expected_output")))?;
    for field in string_array(policy, "required_case_fields")? {
        if dotted_str(case, field).unwrap_or_default().is_empty() {
            return Err(test_error(format!(
                "{label} missing required field {field}"
            )));
        }
    }
    for token in string_array(policy, "required_output_tokens")? {
        if !expected_output.contains(token) {
            return Err(test_error(format!(
                "{label} expected_output missing required token {token}"
            )));
        }
    }

    if !host_differential_exempt(case, policy) {
        for token in string_array(policy, "forbidden_expected_output_tokens")? {
            if expected_output.contains(token) {
                return Err(test_error(format!(
                    "{label} expected_output leaks forbidden token {token}: {expected_output}"
                )));
            }
        }
        for (id, regex) in regex_specs(policy, "forbidden_expected_output_regexes")? {
            if regex.is_match(expected_output) {
                return Err(test_error(format!(
                    "{label} expected_output matches forbidden regex {id}: {expected_output}"
                )));
            }
        }
    }

    let metadata = [
        "spec_section",
        "inputs.strict_behavior",
        "inputs.hardened_behavior",
        "inputs.safe_default_rationale",
        "inputs.oracle_source",
        "inputs.oracle_kind",
        "inputs.divergence_policy",
    ]
    .iter()
    .filter_map(|field| dotted_str(case, field))
    .collect::<Vec<_>>()
    .join("\n");
    for (id, regex) in regex_specs(policy, "forbidden_metadata_regexes")? {
        if regex.is_match(&metadata) {
            return Err(test_error(format!(
                "{label} metadata matches forbidden regex {id}: {metadata}"
            )));
        }
    }
    Ok(())
}

fn lint_fixture_value(path: &Path, fixture: &Value, policy: &Value) -> TestResult<usize> {
    let markers = string_array(policy, "safe_default_markers")?;
    let mut checked = 0usize;
    let Some(cases) = fixture.get("cases").and_then(Value::as_array) else {
        return Ok(checked);
    };
    for (index, case) in cases.iter().enumerate() {
        if is_safe_default_case(case, &markers) {
            lint_safe_default_case(path, index, case, policy)?;
            checked += 1;
        }
    }
    Ok(checked)
}

#[test]
fn policy_manifest_declares_safe_default_hermeticity_contract() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    assert_eq!(policy["schema_version"].as_str(), Some("v1"));
    assert_eq!(policy["bead_id"].as_str(), Some("bd-j1u6u.2"));
    assert_eq!(
        policy["gate_id"].as_str(),
        Some("safe-default-fixture-hermeticity-v1")
    );
    assert_eq!(
        policy["fixture_glob"].as_str(),
        Some("tests/conformance/fixtures/*.json")
    );
    assert_eq!(
        string_array(&policy, "required_output_tokens")?,
        REQUIRED_OUTPUT_TOKENS
    );
    assert!(!string_array(&policy, "safe_default_markers")?.is_empty());
    assert!(!string_array(&policy, "forbidden_expected_output_tokens")?.is_empty());
    assert!(!regex_specs(&policy, "forbidden_expected_output_regexes")?.is_empty());
    assert!(!regex_specs(&policy, "forbidden_metadata_regexes")?.is_empty());
    Ok(())
}

#[test]
fn canonical_safe_default_fixtures_do_not_leak_ambient_state() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let mut checked_cases = 0usize;
    for path in fixture_paths(&root)? {
        let fixture = load_json(&path)?;
        checked_cases += lint_fixture_value(&path, &fixture, &policy)?;
    }
    assert!(
        checked_cases >= 20,
        "policy should cover a real safe-default corpus, checked only {checked_cases} cases"
    );
    Ok(())
}

#[test]
fn policy_positive_examples_pass() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let fixture = serde_json::json!({
        "cases": [{
            "name": "safe_default_classified",
            "function": "example_safe_default",
            "spec_section": "example safe-default contract",
            "inputs": {
                "expected_class": "safe-default-null-handle",
                "strict_behavior": "returns a classified NULL handle",
                "hardened_behavior": "same deterministic classified result",
                "safe_default_rationale": "ambient host state is intentionally not consulted",
                "oracle_source": "FrankenLibC deterministic contract",
                "oracle_kind": "native_safe_default",
                "divergence_policy": "intentional local contract"
            },
            "expected_output": "symbol=example_safe_default;mode=strict;expected_class=safe-default-null-handle;actual=RETURN_PTR=NULL;failure_signature=none"
        }]
    });
    assert_eq!(
        lint_fixture_value(Path::new("positive.json"), &fixture, &policy)?,
        1
    );
    Ok(())
}

#[test]
fn policy_negative_examples_fail_closed() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let leaking_fixture = serde_json::json!({
        "cases": [{
            "name": "safe_default_leaks_pid_and_path",
            "function": "example_safe_default",
            "spec_section": "example safe-default contract",
            "inputs": {
                "expected_class": "safe-default-null-handle",
                "strict_behavior": "returns a classified NULL handle",
                "hardened_behavior": "same deterministic classified result",
                "safe_default_rationale": "ambient host state is intentionally not consulted",
                "oracle_source": "FrankenLibC deterministic contract",
                "oracle_kind": "native_safe_default",
                "divergence_policy": "intentional local contract"
            },
            "expected_output": "symbol=example_safe_default;mode=strict;expected_class=safe-default-null-handle;actual=RETURN_PTR=NULL;pid=1234;path=/tmp/leak;failure_signature=none"
        }]
    });
    let err = lint_fixture_value(Path::new("negative.json"), &leaking_fixture, &policy)
        .expect_err("safe-default output leak must fail closed");
    let message = err.to_string();
    assert!(
        message.contains("pid=") || message.contains("absolute-temp-path"),
        "unexpected failure message: {message}"
    );
    Ok(())
}
