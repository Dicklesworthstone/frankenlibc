//! Integration test: proof-carrying policy table audit (bd-bp8fl.9.3)
//!
//! Re-grounds the runtime_math/policy_table.rs PCPT loader against
//! `tests/conformance/proof_carrying_policy_audit.v1.json`. Every audit
//! anchor — schema constants, required TLVs, PolicyTableError variants,
//! required negative- and positive-test names — must currently exist in
//! the source. Fail-closed: drift in any anchor blocks claim advancement
//! at every replacement level.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
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

fn as_str<'a>(value: &'a Value, context: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .ok_or_else(|| test_error(format!("{context} must be a string")))
}

fn as_array<'a>(value: &'a Value, context: &str) -> Result<&'a Vec<Value>, Box<dyn Error>> {
    value
        .as_array()
        .ok_or_else(|| test_error(format!("{context} must be an array")))
}

fn audit_path() -> PathBuf {
    workspace_root().join("tests/conformance/proof_carrying_policy_audit.v1.json")
}

fn policy_source_path() -> PathBuf {
    workspace_root().join("crates/frankenlibc-membrane/src/runtime_math/policy_table.rs")
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "audit_row_id",
    "anchor_kind",
    "subject_path",
    "expected",
    "actual",
    "verifier_decision",
    "freshness_state",
    "policy_id",
    "proof_hash",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "missing_constant",
    "constant_drift",
    "missing_error_variant",
    "missing_required_tlv",
    "missing_negative_test",
    "stale_source_commit",
    "verifier_failure",
];

#[test]
fn audit_artifact_is_well_formed() -> TestResult {
    let audit = load_json(&audit_path())?;
    ensure_eq(
        audit["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(audit["bead"].as_str(), Some("bd-bp8fl.9.3"), "bead")?;
    ensure(
        !audit["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let subject = &audit["subject"];
    let module = as_str(&subject["module"], "subject.module")?;
    ensure(
        workspace_root().join(module).exists(),
        format!("subject.module must exist on disk: {module}"),
    )?;
    let design = as_str(&subject["design_doc"], "subject.design_doc")?;
    ensure(
        workspace_root().join(design).exists(),
        format!("subject.design_doc must exist on disk: {design}"),
    )?;

    let inputs = audit["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for key in [
        "policy_table_source",
        "design_doc",
        "feature_parity_gap_ledger",
        "proof_obligations_binder",
    ] {
        let path = inputs
            .get(key)
            .and_then(|v| v.as_str())
            .ok_or_else(|| test_error(format!("inputs.{key} must be a string")))?;
        ensure(
            workspace_root().join(path).exists(),
            format!("inputs.{key} must reference an existing artifact: {path}"),
        )?;
    }

    let log_fields: Vec<&str> = as_array(&audit["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &audit["policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_audit_anchors_resolve"),
        "policy.default_decision",
    )?;
    let allow: Vec<&str> = as_array(&policy["allow_status"], "policy.allow_status")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        !allow.contains(&"DONE"),
        "policy.allow_status must not include DONE",
    )?;
    let block_status: Vec<&str> = as_array(
        &policy["block_status_without_evidence"],
        "policy.block_status",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    ensure(
        block_status.contains(&"DONE"),
        "policy must block DONE without evidence",
    )?;
    let block_levels: Vec<&str> = as_array(
        &policy["block_replacement_levels_without_evidence"],
        "policy.block_replacement_levels",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for level in ["L1", "L2", "L3"] {
        ensure(
            block_levels.contains(&level),
            format!("policy must block replacement level {level}"),
        )?;
    }
    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "policy.rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure(
            rejected.contains(kind),
            format!("policy.rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn schema_constants_resolve_in_policy_source() -> TestResult {
    let audit = load_json(&audit_path())?;
    let source = read_text(&policy_source_path())?;

    for entry in as_array(&audit["schema_constants"], "schema_constants")? {
        let id = as_str(&entry["id"], "schema_constants[].id")?;
        let pattern = as_str(
            &entry["source_pattern"],
            "schema_constants[].source_pattern",
        )?;
        ensure(
            source.contains(pattern),
            format!(
                "schema constant {id}: source pattern {pattern:?} not found in policy_table.rs — drift detected"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn required_tlvs_are_referenced_in_policy_source() -> TestResult {
    let audit = load_json(&audit_path())?;
    let source = read_text(&policy_source_path())?;

    for entry in as_array(&audit["required_tlvs"], "required_tlvs")? {
        let tlv_type = as_str(&entry["tlv_type"], "required_tlvs[].tlv_type")?;
        let name = as_str(&entry["name"], "required_tlvs[].name")?;
        let missing = as_str(&entry["missing_error"], "required_tlvs[].missing_error")?;
        // Source uses both `0x0001`/`0x0002`/`0x0003` literal forms and the
        // capitalised lower-case literals `0x0001u16`/etc. Match by the bare
        // hex literal as it appears in `extract_required_tlvs`.
        ensure(
            source.contains(tlv_type),
            format!(
                "required TLV {name} ({tlv_type}): not referenced in policy_table.rs — drift detected"
            ),
        )?;
        ensure(
            source.contains(missing),
            format!(
                "required TLV {name}: missing-error variant {missing} not present in policy_table.rs"
            ),
        )?;
        if let Some(size) = entry.get("required_size").and_then(|v| v.as_u64()) {
            // The proof_digest size invariant is encoded as `tlv.v.len() != 32`.
            let needle = format!("tlv.v.len() != {size}");
            ensure(
                source.contains(&needle),
                format!(
                    "required TLV {name}: size invariant {needle:?} not enforced in policy_table.rs"
                ),
            )?;
        }
    }
    Ok(())
}

#[test]
fn error_variants_resolve_in_policy_source() -> TestResult {
    let audit = load_json(&audit_path())?;
    let source = read_text(&policy_source_path())?;

    let variants: Vec<&str> = as_array(&audit["error_variants"], "error_variants")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure(
        !variants.is_empty(),
        "error_variants must declare at least one variant",
    )?;

    let enum_section_start = source
        .find("pub enum PolicyTableError {")
        .ok_or_else(|| test_error("PolicyTableError enum not found in policy_table.rs"))?;
    let enum_section = &source[enum_section_start..];
    let enum_section_end = enum_section
        .find("\n}\n")
        .ok_or_else(|| test_error("PolicyTableError enum terminator not found"))?;
    let enum_body = &enum_section[..enum_section_end];

    let mut seen = BTreeSet::new();
    for variant in &variants {
        let needles = [format!("    {variant},"), format!("    {variant} {{")];
        let found = needles.iter().any(|n| enum_body.contains(n));
        ensure(
            found,
            format!("PolicyTableError variant {variant} not found in enum body — drift detected"),
        )?;
        ensure(
            seen.insert((*variant).to_string()),
            format!("audit lists PolicyTableError variant {variant} more than once"),
        )?;

        // Also require the variant to appear in the Display impl so user-facing
        // diagnostics stay current.
        let display_marker = format!("Self::{variant}");
        ensure(
            source.contains(&display_marker),
            format!("PolicyTableError::{variant} not surfaced in Display impl — diagnostics drift"),
        )?;
    }
    Ok(())
}

#[test]
fn required_negative_tests_resolve_in_policy_source() -> TestResult {
    let audit = load_json(&audit_path())?;
    let source = read_text(&policy_source_path())?;

    let mut seen = BTreeSet::new();
    for entry in as_array(&audit["required_negative_tests"], "required_negative_tests")? {
        let name = as_str(&entry["test_name"], "required_negative_tests[].test_name")?;
        let variant = as_str(
            &entry["error_variant"],
            "required_negative_tests[].error_variant",
        )?;
        let needle = format!("    fn {name}()");
        ensure(
            source.contains(&needle),
            format!(
                "required negative test {name} not found in policy_table.rs (looking for `{needle}`)"
            ),
        )?;
        ensure(
            source.contains(variant),
            format!(
                "required negative test {name}: cited error variant {variant} not present in policy_table.rs"
            ),
        )?;
        ensure(
            seen.insert(name.to_string()),
            format!("audit lists negative test {name} more than once"),
        )?;
    }
    Ok(())
}

#[test]
fn required_positive_tests_resolve_in_policy_source() -> TestResult {
    let audit = load_json(&audit_path())?;
    let source = read_text(&policy_source_path())?;
    let mut seen = BTreeSet::new();
    for entry in as_array(&audit["required_positive_tests"], "required_positive_tests")? {
        let name = as_str(entry, "required_positive_tests[]")?;
        let needle = format!("    fn {name}()");
        ensure(
            source.contains(&needle),
            format!("required positive test {name} not found in policy_table.rs"),
        )?;
        ensure(
            seen.insert(name.to_string()),
            format!("audit lists positive test {name} more than once"),
        )?;
    }
    Ok(())
}

#[test]
fn verification_command_targets_policy_table_tests() -> TestResult {
    let audit = load_json(&audit_path())?;
    let cmd = as_str(&audit["verification_command"], "verification_command")?;
    for marker in [
        "rch exec",
        "cargo test",
        "-p frankenlibc-membrane",
        "policy_table",
    ] {
        ensure(
            cmd.contains(marker),
            format!("verification_command must mention {marker}: got {cmd}"),
        )?;
    }
    Ok(())
}

#[test]
fn audit_consuming_gates_exist() -> TestResult {
    let audit = load_json(&audit_path())?;
    let root = workspace_root();
    let gates = as_array(&audit["consuming_gates"], "consuming_gates")?;
    ensure(
        !gates.is_empty(),
        "audit must list at least one consuming_gates entry",
    )?;
    for gate in gates {
        let path = as_str(gate, "consuming_gates[]")?;
        ensure(
            root.join(path).exists(),
            format!("consuming gate {path} not found"),
        )?;
    }
    Ok(())
}
