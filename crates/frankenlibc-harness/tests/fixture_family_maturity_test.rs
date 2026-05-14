//! Fixture-family maturity claim policy for bd-j1u6u.5.

use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn policy_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fixture_family_maturity_policy.v1.json")
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

fn state_requirements(policy: &Value) -> TestResult<BTreeMap<&str, BTreeSet<&str>>> {
    let entries = policy
        .get("state_requirements")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("policy.state_requirements must be an array"))?;
    let mut requirements = BTreeMap::new();
    for entry in entries {
        let state = entry
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| test_error("state requirement missing state"))?;
        let kinds = entry
            .get("required_evidence_kinds")
            .and_then(Value::as_array)
            .ok_or_else(|| test_error(format!("{state} missing required_evidence_kinds")))?
            .iter()
            .map(|kind| {
                kind.as_str()
                    .ok_or_else(|| test_error(format!("{state} evidence kinds must be strings")))
            })
            .collect::<TestResult<BTreeSet<_>>>()?;
        requirements.insert(state, kinds);
    }
    Ok(requirements)
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

fn claim_text_implies_replacement_ready(claim_text: &str, policy: &Value) -> TestResult<bool> {
    let lower = claim_text.to_ascii_lowercase();
    Ok(string_array(policy, "replacement_ready_claim_markers")?
        .iter()
        .any(|marker| lower.contains(&marker.to_ascii_lowercase())))
}

fn evidence_kinds(claim: &Value) -> TestResult<BTreeSet<&str>> {
    let evidence = claim
        .get("evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| test_error("claim.evidence must be an array"))?;
    evidence
        .iter()
        .map(|entry| {
            entry
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| test_error("evidence entry missing string kind"))
        })
        .collect()
}

fn validate_maturity_claim(claim: &Value, policy: &Value) -> TestResult {
    required_fields_present(
        claim,
        &string_array(policy, "required_claim_fields")?,
        "maturity claim",
    )?;
    if claim["schema_version"].as_str() != policy["schema_version"].as_str() {
        return Err(test_error(
            "maturity claim schema_version does not match policy",
        ));
    }
    if claim["kind"].as_str() != policy["claim_bundle_kind"].as_str() {
        return Err(test_error("maturity claim kind does not match policy"));
    }

    let claimed_state = claim
        .get("claimed_state")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error("claim.claimed_state must be a string"))?;
    let claim_text = claim
        .get("claim_text")
        .and_then(Value::as_str)
        .ok_or_else(|| test_error("claim.claim_text must be a string"))?;
    let requirements = state_requirements(policy)?;
    let effective_state = if claim_text_implies_replacement_ready(claim_text, policy)? {
        "replacement_ready"
    } else {
        claimed_state
    };
    let required = requirements
        .get(effective_state)
        .ok_or_else(|| test_error(format!("unknown maturity state {effective_state}")))?;
    let observed = evidence_kinds(claim)?;
    let missing = required.difference(&observed).copied().collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(test_error(format!(
            "{effective_state} claim missing evidence kinds: {}",
            missing.join(", ")
        )));
    }

    if effective_state == "replacement_ready" {
        let safe_default_only = string_array(policy, "safe_default_only_evidence_kinds")?
            .into_iter()
            .collect::<BTreeSet<_>>();
        if !observed.is_empty() && observed.is_subset(&safe_default_only) {
            return Err(test_error(
                "replacement_ready cannot be supported by safe-default-only evidence",
            ));
        }
    }
    Ok(())
}

fn base_claim(claimed_state: &str, claim_text: &str, evidence_kinds: &[&str]) -> Value {
    json!({
        "schema_version": "v1",
        "kind": "fixture_family_maturity_claim",
        "family": "rpc_legacy_network_wave03",
        "claimed_state": claimed_state,
        "claim_text": claim_text,
        "evidence": evidence_kinds
            .iter()
            .map(|kind| json!({ "kind": kind }))
            .collect::<Vec<_>>()
    })
}

#[test]
fn policy_manifest_declares_fixture_family_maturity_contract() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    assert_eq!(policy["schema_version"].as_str(), Some("v1"));
    assert_eq!(policy["bead_id"].as_str(), Some("bd-j1u6u.5"));
    assert_eq!(
        policy["gate_id"].as_str(),
        Some("fixture-family-maturity-v1")
    );
    assert_eq!(
        policy["claim_bundle_kind"].as_str(),
        Some("fixture_family_maturity_claim")
    );
    assert_eq!(
        string_array(&policy, "maturity_order")?,
        vec![
            "structural_coverage",
            "deterministic_safe_default",
            "host_differential_parity",
            "replacement_ready"
        ]
    );
    assert!(
        string_array(&policy, "replacement_ready_claim_markers")?.contains(&"replacement-ready")
    );
    assert!(state_requirements(&policy)?.contains_key("replacement_ready"));
    Ok(())
}

#[test]
fn deterministic_safe_default_claim_requires_explicit_safe_default_evidence() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let claim = base_claim(
        "deterministic_safe_default",
        "deterministic safe-default coverage only",
        &[
            "safe_default_rows",
            "explicit_oracle_kind",
            "divergence_policy",
        ],
    );
    validate_maturity_claim(&claim, &policy)
}

#[test]
fn replacement_ready_claim_accepts_full_parity_evidence() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let claim = base_claim(
        "replacement_ready",
        "family is replacement-ready for this bounded surface",
        &[
            "strict_rows",
            "hardened_rows",
            "host_parity_rows",
            "isolated_execution",
            "non_safe_default_oracle",
            "no_uncovered_required_symbols",
        ],
    );
    validate_maturity_claim(&claim, &policy)
}

#[test]
fn replacement_ready_claim_rejects_safe_default_only_evidence() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let claim = base_claim(
        "replacement_ready",
        "family is replacement-ready",
        &[
            "safe_default_rows",
            "explicit_oracle_kind",
            "divergence_policy",
        ],
    );
    let err = validate_maturity_claim(&claim, &policy).unwrap_err();
    assert!(err.to_string().contains("replacement_ready"));
    Ok(())
}

#[test]
fn replacement_ready_wording_escalates_lower_state_claim() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let claim = base_claim(
        "deterministic_safe_default",
        "safe-default fixtures prove this is full replacement ready",
        &[
            "safe_default_rows",
            "explicit_oracle_kind",
            "divergence_policy",
        ],
    );
    let err = validate_maturity_claim(&claim, &policy).unwrap_err();
    assert!(err.to_string().contains("replacement_ready"));
    Ok(())
}

#[test]
fn host_differential_claim_requires_isolated_strict_and_hardened_rows() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let claim = base_claim(
        "host_differential_parity",
        "host differential parity with isolated execution",
        &[
            "strict_rows",
            "hardened_rows",
            "host_differential_oracle",
            "isolated_execution",
        ],
    );
    validate_maturity_claim(&claim, &policy)
}

#[test]
fn host_differential_claim_rejects_missing_hardened_rows() -> TestResult {
    let root = repo_root();
    let policy = load_json(&policy_path(&root))?;
    let claim = base_claim(
        "host_differential_parity",
        "host differential parity with isolated execution",
        &[
            "strict_rows",
            "host_differential_oracle",
            "isolated_execution",
        ],
    );
    let err = validate_maturity_claim(&claim, &policy).unwrap_err();
    assert!(err.to_string().contains("hardened_rows"));
    Ok(())
}
