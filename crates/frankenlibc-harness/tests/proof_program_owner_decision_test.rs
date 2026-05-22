//! Contract tests for the WS7 proof-program owner decision (bd-e4phe.1).
//!
//! The decision is intentionally conservative: until machine-checked theorem
//! artifacts are committed, public claims must describe proof notes, tested
//! invariant catalogs, and proof-obligation tracking.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Component, Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn decision_path() -> PathBuf {
    workspace_root().join("tests/conformance/proof_program_owner_decision.v1.json")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn read_text(path: &Path) -> Result<String, Box<dyn Error>> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn workspace_path(root: &Path, rel_path: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = Path::new(rel_path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir))
    {
        return Err(test_error(format!(
            "source ref path should stay under workspace root: {rel_path}"
        )));
    }
    Ok(root.join(path))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, Box<dyn Error>> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("missing field {key}")))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, Box<dyn Error>> {
    field(value, key)?
        .as_str()
        .ok_or_else(|| test_error(format!("field {key} should be a string")))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a [Value], Box<dyn Error>> {
    field(value, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| test_error(format!("field {key} should be an array")))
}

#[test]
fn decision_records_conservative_reframe_choice() -> TestResult {
    let manifest = load_json(&decision_path())?;
    assert_eq!(
        string_field(&manifest, "schema")?,
        "proof_program_owner_decision.v1"
    );
    assert_eq!(string_field(&manifest, "bead")?, "bd-e4phe.1");

    let decision = field(&manifest, "decision")?;
    assert_eq!(
        string_field(decision, "choice")?,
        "reframe_as_tested_invariant_catalogs"
    );
    assert_eq!(
        string_field(decision, "machine_checked_formal_proof_status")?,
        "none_committed"
    );
    assert_eq!(
        string_field(decision, "mechanization_strategy")?,
        "future_followup_beads"
    );
    assert!(
        string_field(decision, "decision_basis")?.contains("No Lean, Coq, Kani"),
        "decision basis should name the missing proof-artifact classes"
    );

    Ok(())
}

#[test]
fn claim_policy_blocks_theorem_level_overclaiming() -> TestResult {
    let manifest = load_json(&decision_path())?;
    let policy = field(&manifest, "claim_policy")?;
    assert_eq!(
        string_field(policy, "allow_public_claim")?,
        "tested_invariant_catalog"
    );

    let blocked: BTreeSet<&str> = array_field(policy, "block_public_claims")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("blocked claim should be a string"))
        })
        .collect::<Result<_, _>>()?;
    for claim in [
        "completed_machine_checked_formal_proofs",
        "lean_coq_kani_artifacts_committed",
        "theorem_level_completeness",
    ] {
        assert!(blocked.contains(claim), "claim policy should block {claim}");
    }

    let required_wording: BTreeSet<&str> = array_field(policy, "required_current_wording")?
        .iter()
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| test_error("required wording should be a string"))
        })
        .collect::<Result<_, _>>()?;
    for wording in [
        "no machine-checked formal proof artifacts are committed yet",
        "proof notes and invariant rationale",
        "not completed machine-checked proof artifacts",
    ] {
        assert!(
            required_wording.contains(wording),
            "claim policy should require wording: {wording}"
        );
    }

    Ok(())
}

#[test]
fn mechanization_bead_is_deferred_until_real_proof_artifacts_exist() -> TestResult {
    let manifest = load_json(&decision_path())?;
    let decision = field(&manifest, "decision")?;
    let deferral = field(&manifest, "mechanization_deferral")?;

    assert_eq!(string_field(deferral, "bead")?, "bd-e4phe.2");
    assert_eq!(
        string_field(deferral, "status")?,
        "deferred_by_owner_decision"
    );
    assert_eq!(
        string_field(decision, "choice")?,
        "reframe_as_tested_invariant_catalogs"
    );
    assert_eq!(
        string_field(decision, "machine_checked_formal_proof_status")?,
        "none_committed"
    );
    assert!(
        string_field(deferral, "ci_policy")?.contains("honestly scoped language"),
        "CI policy should follow the reframe path instead of requiring fake proof artifacts"
    );
    assert!(
        string_field(deferral, "future_activation_rule")?.contains("machine-checked"),
        "future activation should require real machine-checked artifacts"
    );

    let required_theorems: BTreeSet<&str> = array_field(deferral, "required_future_artifacts")?
        .iter()
        .map(|value| string_field(value, "theorem"))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        required_theorems,
        BTreeSet::from([
            "Galois connection soundness",
            "lattice monotonicity",
            "SOS barrier nonnegativity",
            "healing completeness"
        ])
    );

    for artifact in array_field(deferral, "required_future_artifacts")? {
        assert_eq!(string_field(artifact, "current_status")?, "deferred");
        assert!(
            string_field(artifact, "artifact_kind")?.contains("machine-checked proof"),
            "future artifact kind should stay explicit"
        );
    }

    let dependent = array_field(&manifest, "dependent_beads")?
        .iter()
        .find(|value| string_field(value, "id").ok() == Some("bd-e4phe.2"))
        .ok_or_else(|| test_error("bd-e4phe.2 dependent bead should be listed"))?;
    assert_eq!(
        string_field(dependent, "current_status")?,
        "deferred_by_owner_decision"
    );
    assert!(
        string_field(dependent, "unblock_rule")?.contains("honestly-scoped-language"),
        "bd-e4phe.2 unblock rule should point E2E at the reframe path"
    );

    Ok(())
}

#[test]
fn cited_readme_and_feature_parity_lines_match_decision() -> TestResult {
    let root = workspace_root();
    let manifest = load_json(&decision_path())?;

    for source_ref in array_field(&manifest, "source_refs")? {
        let rel_path = string_field(source_ref, "path")?;
        let line = field(source_ref, "line")?
            .as_u64()
            .ok_or_else(|| test_error("source_refs.line should be a positive integer"))?;
        assert!(line > 0, "source_refs.line should be positive");
        let expected = string_field(source_ref, "must_contain")?;
        let contents = read_text(&workspace_path(&root, rel_path)?)?;
        let line_index = usize::try_from(line - 1)
            .map_err(|err| test_error(format!("line index conversion failed: {err}")))?;
        let actual = contents
            .lines()
            .nth(line_index)
            .ok_or_else(|| test_error(format!("{rel_path}:{line} should exist")))?;
        assert!(
            actual.contains(expected),
            "{rel_path}:{line} should contain {expected:?}, got {actual:?}"
        );
    }

    Ok(())
}

#[test]
fn dependent_beads_keep_followup_work_explicit() -> TestResult {
    let manifest = load_json(&decision_path())?;
    let dependents: BTreeSet<&str> = array_field(&manifest, "dependent_beads")?
        .iter()
        .map(|value| string_field(value, "id"))
        .collect::<Result<_, _>>()?;

    assert_eq!(
        dependents,
        BTreeSet::from(["bd-e4phe.2", "bd-e4phe.3", "bd-e4phe.4"])
    );

    for source_ref in array_field(&manifest, "dependent_beads")? {
        assert!(
            !string_field(source_ref, "decision_effect")?
                .trim()
                .is_empty(),
            "each dependent bead should have a decision effect"
        );
    }

    Ok(())
}
