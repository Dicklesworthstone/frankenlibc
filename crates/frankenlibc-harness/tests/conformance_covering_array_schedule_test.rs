//! Conformance gate for `tests/conformance/conformance_covering_array_schedule.v1.json`
//! (bd-juvqm.13).
//!
//! Enforces the pairwise (t=2) covering-array contract for the next
//! hard-part fixture wave. Failure mode is fail-closed: a missing
//! pair, an unknown factor value, a duplicate vector id, or a stale
//! source_commit prevents the schedule from advancing.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn manifest_path() -> PathBuf {
    workspace_root().join("tests/conformance/conformance_covering_array_schedule.v1.json")
}

fn load_manifest() -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(manifest_path())
        .map_err(|err| test_error(format!("manifest should be readable: {err}")))?;
    serde_json::from_str(&text)
        .map_err(|err| test_error(format!("manifest should parse as JSON: {err}")))
}

/// Extract the (factor_name -> Vec<value>) map from the manifest.
fn factors(manifest: &Value) -> Result<BTreeMap<String, Vec<String>>, Box<dyn Error>> {
    let factors = manifest["factors"]
        .as_object()
        .ok_or_else(|| test_error("manifest.factors must be an object"))?;
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, info) in factors {
        let values = info["values"]
            .as_array()
            .ok_or_else(|| test_error(format!("factor {name} missing values array")))?;
        let vs: Vec<String> = values
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        ensure(!vs.is_empty(), format!("factor {name} has no values"))?;
        out.insert(name.clone(), vs);
    }
    Ok(out)
}

fn vectors(manifest: &Value) -> Result<&Vec<Value>, Box<dyn Error>> {
    manifest["vectors"]
        .as_array()
        .ok_or_else(|| test_error("manifest.vectors must be an array"))
}

#[test]
fn manifest_has_required_top_level_shape() -> TestResult {
    let m = load_manifest()?;
    ensure(m["schema_version"] == "v1", "schema_version must be v1")?;
    ensure(m["bead"] == "bd-juvqm.13", "bead must be bd-juvqm.13")?;
    ensure(
        m["manifest_id"] == "conformance-covering-array-schedule",
        "manifest_id mismatch",
    )?;
    ensure(
        m["source_commit"]
            .as_str()
            .map(|s| s.len() == 40)
            .unwrap_or(false),
        "source_commit must be a 40-char SHA",
    )?;
    ensure(m["coverage_strength"] == 2, "coverage_strength must be 2")?;
    ensure(
        m["upgrade_trigger_t3"]
            .as_str()
            .map(|s| s.len() > 60)
            .unwrap_or(false),
        "upgrade_trigger_t3 must be a non-trivial string",
    )?;
    let policy = m["policy"]
        .as_object()
        .ok_or_else(|| test_error("policy must be object"))?;
    for required in [
        "auto_create_fixtures",
        "skipped_combinations_require_rationale",
        "missing_pair_result",
        "duplicate_vector_id_result",
        "unknown_factor_value_result",
        "stale_source_commit_result",
    ] {
        ensure(
            policy.get(required).is_some(),
            format!("policy.{required} must be present"),
        )?;
    }
    ensure(
        policy["auto_create_fixtures"] == Value::Bool(false),
        "policy.auto_create_fixtures must be false",
    )?;
    Ok(())
}

#[test]
fn factor_count_and_value_count_are_non_trivial() -> TestResult {
    let m = load_manifest()?;
    let f = factors(&m)?;
    ensure(
        f.len() >= 5,
        format!("expected >=5 factors; got {}", f.len()),
    )?;
    for (name, values) in &f {
        ensure(
            values.len() >= 2,
            format!("factor {name} must have >=2 values; got {}", values.len()),
        )?;
    }
    Ok(())
}

#[test]
fn every_vector_has_one_value_per_factor_and_value_is_known() -> TestResult {
    let m = load_manifest()?;
    let f = factors(&m)?;
    let v = vectors(&m)?;
    for vec in v {
        let id = vec["vector_id"].as_str().unwrap_or("?");
        for (factor_name, allowed) in &f {
            let assigned = vec[factor_name].as_str().unwrap_or("");
            ensure(
                !assigned.is_empty(),
                format!("vector {id} missing factor {factor_name}"),
            )?;
            ensure(
                allowed.iter().any(|v| v == assigned),
                format!(
                    "vector {id} factor {factor_name} value {assigned} not in allowed set {:?}",
                    allowed
                ),
            )?;
        }
    }
    Ok(())
}

#[test]
fn vector_ids_are_unique() -> TestResult {
    let m = load_manifest()?;
    let v = vectors(&m)?;
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for vec in v {
        let id = vec["vector_id"].as_str().unwrap_or("").to_string();
        ensure(
            seen.insert(id.clone()),
            format!("duplicate vector_id: {id}"),
        )?;
    }
    Ok(())
}

#[test]
fn every_factor_pair_is_covered_by_at_least_one_vector() -> TestResult {
    let m = load_manifest()?;
    let f = factors(&m)?;
    let v = vectors(&m)?;

    // Build the set of all required (factor_a, val_a, factor_b, val_b) pairs
    let factor_names: Vec<&String> = f.keys().collect();
    let mut required: BTreeSet<(String, String, String, String)> = BTreeSet::new();
    for i in 0..factor_names.len() {
        for j in (i + 1)..factor_names.len() {
            let a = factor_names[i];
            let b = factor_names[j];
            for va in &f[a] {
                for vb in &f[b] {
                    required.insert((a.clone(), va.clone(), b.clone(), vb.clone()));
                }
            }
        }
    }

    // Subtract pairs covered by each vector
    for vec in v {
        for i in 0..factor_names.len() {
            for j in (i + 1)..factor_names.len() {
                let a = factor_names[i];
                let b = factor_names[j];
                let va = vec[a].as_str().unwrap_or("");
                let vb = vec[b].as_str().unwrap_or("");
                if va.is_empty() || vb.is_empty() {
                    continue;
                }
                required.remove(&(a.clone(), va.to_string(), b.clone(), vb.to_string()));
            }
        }
    }

    if !required.is_empty() {
        let preview: Vec<String> = required
            .iter()
            .take(10)
            .map(|(a, va, b, vb)| format!("({a}={va}, {b}={vb})"))
            .collect();
        return Err(test_error(format!(
            "covering-array schedule is missing {} factor pairs (showing up to 10): {}",
            required.len(),
            preview.join(", ")
        )));
    }
    Ok(())
}

#[test]
fn expected_counts_match_live_manifest() -> TestResult {
    let m = load_manifest()?;
    let f = factors(&m)?;
    let v = vectors(&m)?;
    let factor_names: Vec<&String> = f.keys().collect();

    // expected_pair_count = sum over factor pairs of (|values_a| * |values_b|)
    let mut expected_pairs = 0usize;
    for i in 0..factor_names.len() {
        for j in (i + 1)..factor_names.len() {
            expected_pairs += f[factor_names[i]].len() * f[factor_names[j]].len();
        }
    }
    let recorded_pairs = m["expected_pair_count"].as_u64().unwrap_or(0) as usize;
    ensure(
        recorded_pairs == expected_pairs,
        format!(
            "expected_pair_count {recorded_pairs} != computed {expected_pairs} (regenerate manifest if factors changed)"
        ),
    )?;

    let recorded_vecs = m["expected_vector_count"].as_u64().unwrap_or(0) as usize;
    ensure(
        recorded_vecs == v.len(),
        format!(
            "expected_vector_count {recorded_vecs} != live vectors.len() {} (manifest is stale)",
            v.len()
        ),
    )?;
    Ok(())
}

#[test]
fn downstream_fixture_families_are_named_and_well_formed() -> TestResult {
    let m = load_manifest()?;
    let families = m["downstream_fixture_families"]
        .as_array()
        .ok_or_else(|| test_error("downstream_fixture_families must be an array"))?;
    ensure(
        families.len() >= 2,
        format!(
            "expected >=2 downstream fixture families to anchor the schedule; got {}",
            families.len()
        ),
    )?;
    let f = factors(&m)?;
    let known_factors: BTreeSet<&String> = f.keys().collect();
    for fam in families {
        let id = fam["family_id"].as_str().unwrap_or("");
        ensure(!id.is_empty(), "family_id must be non-empty")?;
        ensure(
            fam["scope"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false),
            format!("family {id} scope must be non-empty"),
        )?;
        ensure(
            fam["rationale"]
                .as_str()
                .map(|s| s.len() > 30)
                .unwrap_or(false),
            format!("family {id} rationale must be non-trivial"),
        )?;
        let consumed = fam["consumes_factors"]
            .as_array()
            .ok_or_else(|| test_error(format!("family {id} consumes_factors missing")))?;
        for c in consumed {
            let cname = c.as_str().unwrap_or("").to_string();
            ensure(
                known_factors.contains(&cname),
                format!("family {id} consumes_factors entry {cname} is not a known factor"),
            )?;
        }
    }
    Ok(())
}

#[test]
fn skipped_combinations_each_have_a_rationale() -> TestResult {
    let m = load_manifest()?;
    if let Some(skipped) = m["skipped_combinations"].as_array() {
        for entry in skipped {
            let pat = entry["pattern"].as_str().unwrap_or("");
            ensure(
                !pat.is_empty(),
                format!("skipped_combinations entry missing pattern: {entry}"),
            )?;
            ensure(
                entry["rationale"]
                    .as_str()
                    .map(|s| s.len() > 40)
                    .unwrap_or(false),
                format!("skipped_combinations {pat} rationale must be non-trivial"),
            )?;
            ensure(
                entry["permitted"].is_boolean(),
                format!("skipped_combinations {pat} permitted must be a boolean"),
            )?;
        }
    }
    Ok(())
}
