//! RCH validation provenance policy for bd-j1u6u.4.

use regex::Regex;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn policy_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/rch_validation_provenance_policy.v1.json")
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

fn required_fields_present(value: &Value, fields: &[&str], label: &str) -> TestResult {
    for field in fields {
        if value.get(field).is_none() {
            return Err(test_error(format!(
                "{label} missing required field {field}"
            )));
        }
    }
    Ok(())
}

fn command_requirements(policy: &Value) -> TestResult<BTreeMap<&str, Vec<&str>>> {
    let entries = policy
        .get("command_class_requirements")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("policy.command_class_requirements must be an array"))?;
    let mut requirements = BTreeMap::new();
    for entry in entries {
        let class = entry
            .get("class")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("command_class_requirements entry missing class"))?;
        let tokens = entry
            .get("command_must_contain")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                test_error(format!(
                    "command_class_requirements.{class} missing command_must_contain"
                ))
            })?
            .iter()
            .map(|token| {
                token.as_str().ok_or_else(|| {
                    test_error(format!(
                        "command_class_requirements.{class}.command_must_contain entries must be strings"
                    ))
                })
            })
            .collect::<TestResult<Vec<_>>>()?;
        requirements.insert(class, tokens);
    }
    Ok(requirements)
}

fn command_text_field<'a>(command: &'a Value, field: &str, label: &str) -> TestResult<&'a str> {
    command
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| test_error(format!("{label} field {field} must be a string")))
}

fn command_exit_status(command: &Value, label: &str) -> TestResult<i64> {
    command
        .get("exit_status")
        .and_then(Value::as_i64)
        .ok_or_else(|| test_error(format!("{label} field exit_status must be an integer")))
}

fn command_local_fallback(command: &Value, label: &str) -> TestResult<bool> {
    command
        .get("local_fallback_observed")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            test_error(format!(
                "{label} field local_fallback_observed must be a boolean"
            ))
        })
}

fn validate_proof_bundle(bundle: &Value, policy: &Value) -> TestResult {
    required_fields_present(
        bundle,
        &string_array(policy, "required_summary_fields")?,
        "proof bundle",
    )?;
    if bundle["schema_version"].as_str() != policy["schema_version"].as_str() {
        return Err(test_error(
            "proof bundle schema_version does not match policy",
        ));
    }
    if bundle["kind"].as_str() != policy["proof_bundle_kind"].as_str() {
        return Err(test_error("proof bundle kind does not match policy"));
    }

    let commit_regex = Regex::new(
        policy
            .get("source_commit_regex")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("policy.source_commit_regex missing"))?,
    )?;
    let source_commit = bundle
        .get("source_commit")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error("proof bundle source_commit must be a string"))?;
    if !commit_regex.is_match(source_commit) {
        return Err(test_error(format!(
            "proof bundle source_commit has invalid shape: {source_commit}"
        )));
    }

    let remote_host_regex = Regex::new(
        policy
            .get("remote_host_id_regex")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("policy.remote_host_id_regex missing"))?,
    )?;
    let exit_status_success = policy
        .get("exit_status_success")
        .and_then(Value::as_i64)
        .ok_or_else(|| test_error("policy.exit_status_success must be an integer"))?;
    let local_fallback_must_be = policy
        .get("local_fallback_must_be")
        .and_then(Value::as_bool)
        .ok_or_else(|| test_error("policy.local_fallback_must_be must be a boolean"))?;
    let required_record_fields = string_array(policy, "required_record_fields")?;
    let forbidden_output_markers = string_array(policy, "forbidden_output_markers")?;
    let command_requirements = command_requirements(policy)?;
    let required_classes = string_array(policy, "required_command_classes")?
        .into_iter()
        .collect::<BTreeSet<_>>();

    let commands = bundle
        .get("commands")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("proof bundle commands must be an array"))?;
    let mut seen_classes = BTreeSet::new();
    for (index, command) in commands.iter().enumerate() {
        let label = format!("commands[{index}]");
        required_fields_present(command, &required_record_fields, &label)?;

        let class = command_text_field(command, "class", &label)?;
        let command_text = command_text_field(command, "command", &label)?;
        let remote_host_id = command_text_field(command, "remote_host_id", &label)?;
        let stdout = command_text_field(command, "stdout", &label)?;
        let stderr = command_text_field(command, "stderr", &label)?;

        if !remote_host_regex.is_match(remote_host_id) {
            return Err(test_error(format!(
                "{label} remote_host_id is not an rch worker id: {remote_host_id}"
            )));
        }
        if command_exit_status(command, &label)? != exit_status_success {
            return Err(test_error(format!("{label} did not exit successfully")));
        }
        if command_local_fallback(command, &label)? != local_fallback_must_be {
            return Err(test_error(format!("{label} records local fallback")));
        }

        let output = format!("{stdout}\n{stderr}");
        for marker in &forbidden_output_markers {
            if output.contains(marker) {
                return Err(test_error(format!(
                    "{label} output contains forbidden marker {marker}"
                )));
            }
        }

        if let Some(required_tokens) = command_requirements.get(class) {
            for token in required_tokens {
                if !command_text.contains(token) {
                    return Err(test_error(format!(
                        "{label} command for {class} missing token {token}: {command_text}"
                    )));
                }
            }
            seen_classes.insert(class);
        }
    }

    let missing = required_classes
        .difference(&seen_classes)
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(test_error(format!(
            "proof bundle missing required command classes: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

fn valid_proof_bundle() -> Value {
    json!({
        "schema_version": "v1",
        "kind": "conformance_bead_rch_validation_proof",
        "bead_id": "bd-example",
        "source_commit": "0123456789abcdef",
        "commands": [
            {
                "class": "cargo_test",
                "command": "RCH_FORCE_REMOTE=true rch exec -- cargo test -p frankenlibc-harness --test example_conformance_test -- --nocapture",
                "remote_host_id": "vmi1227854",
                "exit_status": 0,
                "local_fallback_observed": false,
                "stdout": "remote vmi1227854\nrunning 1 test\ntest result: ok",
                "stderr": ""
            },
            {
                "class": "cargo_check",
                "command": "RCH_FORCE_REMOTE=true rch exec -- cargo check -p frankenlibc-harness",
                "remote_host_id": "vmi1293453",
                "exit_status": 0,
                "local_fallback_observed": false,
                "stdout": "remote vmi1293453\nFinished dev profile",
                "stderr": ""
            },
            {
                "class": "cargo_clippy",
                "command": "RCH_FORCE_REMOTE=true rch exec -- cargo clippy -p frankenlibc-harness --test example_conformance_test -- -D warnings",
                "remote_host_id": "vmi1153651",
                "exit_status": 0,
                "local_fallback_observed": false,
                "stdout": "remote vmi1153651\nFinished dev profile",
                "stderr": ""
            }
        ]
    })
}

#[test]
fn policy_manifest_declares_rch_validation_provenance_contract() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    assert_eq!(policy["schema_version"].as_str(), Some("v1"));
    assert_eq!(policy["bead_id"].as_str(), Some("bd-j1u6u.4"));
    assert_eq!(
        policy["gate_id"].as_str(),
        Some("rch-validation-provenance-v1")
    );
    assert_eq!(
        policy["proof_bundle_kind"].as_str(),
        Some("conformance_bead_rch_validation_proof")
    );
    assert_eq!(
        string_array(&policy, "required_command_classes")?,
        vec!["cargo_test", "cargo_check", "cargo_clippy"]
    );
    assert!(Regex::new(policy["remote_host_id_regex"].as_str().unwrap()).is_ok());
    assert!(Regex::new(policy["source_commit_regex"].as_str().unwrap()).is_ok());
    assert!(string_array(&policy, "forbidden_output_markers")?.contains(&"[RCH] local"));
    Ok(())
}

#[test]
fn valid_proof_bundle_satisfies_remote_cargo_surface() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    validate_proof_bundle(&valid_proof_bundle(), &policy)
}

#[test]
fn proof_bundle_rejects_local_fallback_marker() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let mut bundle = valid_proof_bundle();
    bundle["commands"][0]["stdout"] = json!("[RCH] local (remote execution failed)");
    let err = validate_proof_bundle(&bundle, &policy).unwrap_err();
    assert!(err.to_string().contains("forbidden marker"));
    Ok(())
}

#[test]
fn proof_bundle_rejects_missing_remote_host_id() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let mut bundle = valid_proof_bundle();
    bundle["commands"][1]["remote_host_id"] = json!("");
    let err = validate_proof_bundle(&bundle, &policy).unwrap_err();
    assert!(err.to_string().contains("remote_host_id"));
    Ok(())
}

#[test]
fn proof_bundle_rejects_nonzero_exit_status() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let mut bundle = valid_proof_bundle();
    bundle["commands"][2]["exit_status"] = json!(101);
    let err = validate_proof_bundle(&bundle, &policy).unwrap_err();
    assert!(err.to_string().contains("did not exit successfully"));
    Ok(())
}

#[test]
fn proof_bundle_rejects_missing_required_command_class() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let mut bundle = valid_proof_bundle();
    bundle["commands"].as_array_mut().unwrap().pop();
    let err = validate_proof_bundle(&bundle, &policy).unwrap_err();
    assert!(err.to_string().contains("cargo_clippy"));
    Ok(())
}

#[test]
fn proof_bundle_rejects_incomplete_command_surface() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let mut bundle = valid_proof_bundle();
    bundle["commands"][2]["command"] =
        json!("RCH_FORCE_REMOTE=true rch exec -- cargo clippy -p frankenlibc-harness");
    let err = validate_proof_bundle(&bundle, &policy).unwrap_err();
    assert!(err.to_string().contains("-D warnings"));
    Ok(())
}
