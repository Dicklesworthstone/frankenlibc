//! Integration test: proof traceability freshness gate (bd-bp8fl.9.6)
//!
//! Re-validates every `source_ref` in
//! `tests/conformance/proof_obligations_binder.v1.json` against the current
//! working tree, instead of trusting the frozen
//! `proof_binder_validation.v1.json` snapshot. Fails closed when any source
//! ref points at a missing file or an out-of-range line, when the snapshot
//! envelope diverges from the binder, or when category coverage regresses.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
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

fn gate_path() -> PathBuf {
    workspace_root().join("tests/conformance/proof_traceability_freshness_gate.v1.json")
}

fn binder_path() -> PathBuf {
    workspace_root().join("tests/conformance/proof_obligations_binder.v1.json")
}

fn validation_path() -> PathBuf {
    workspace_root().join("tests/conformance/proof_binder_validation.v1.json")
}

fn traceability_check_path() -> PathBuf {
    workspace_root().join("tests/conformance/proof_traceability_check.json")
}

const REQUIRED_LOG_FIELDS: &[&str] = &[
    "trace_id",
    "bead_id",
    "obligation_id",
    "category",
    "source_ref",
    "ref_kind",
    "freshness_state",
    "verifier_status",
    "expected",
    "actual",
    "claim_id",
    "claim_decision",
    "artifact_refs",
    "source_commit",
    "failure_signature",
];

const REJECTED_EVIDENCE_KINDS: &[&str] = &[
    "stale_source_ref",
    "missing_file",
    "out_of_range_line",
    "binder_invalid",
    "obligation_count_drift",
    "envelope_violations",
];

fn count_lines(path: &Path) -> Result<usize, Box<dyn Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    // Use newline count + 1 if the file does not end in a newline.
    let nl_count = content.bytes().filter(|b| *b == b'\n').count();
    let last_nl = content.ends_with('\n');
    let lines = if content.is_empty() {
        0
    } else if last_nl {
        nl_count
    } else {
        nl_count + 1
    };
    Ok(lines)
}

#[derive(Debug, Clone)]
struct ParsedRef<'a> {
    path: &'a str,
    line: Option<u64>,
    kind: &'static str,
}

fn parse_source_ref(raw: &str) -> ParsedRef<'_> {
    if let Some((path, line_str)) = raw.rsplit_once(':')
        && let Ok(line) = line_str.parse::<u64>()
    {
        return ParsedRef {
            path,
            line: Some(line),
            kind: "file_line",
        };
    }
    ParsedRef {
        path: raw,
        line: None,
        kind: "file_only",
    }
}

#[test]
fn gate_artifact_is_well_formed() -> TestResult {
    let gate = load_json(&gate_path())?;
    ensure_eq(
        gate["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(gate["bead"].as_str(), Some("bd-bp8fl.9.6"), "bead")?;
    ensure(
        !gate["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let inputs = gate["inputs"]
        .as_object()
        .ok_or_else(|| test_error("inputs must be an object"))?;
    for key in [
        "proof_obligations_binder",
        "proof_binder_validation",
        "proof_traceability_check",
        "feature_parity",
        "feature_parity_gap_ledger",
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

    let log_fields: Vec<&str> = as_array(&gate["required_log_fields"], "required_log_fields")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    ensure_eq(
        log_fields,
        REQUIRED_LOG_FIELDS.to_vec(),
        "required_log_fields",
    )?;

    let policy = &gate["freshness_policy"];
    ensure_eq(
        policy["default_decision"].as_str(),
        Some("block_until_all_source_refs_resolve"),
        "freshness_policy.default_decision",
    )?;
    let ref_kinds: Vec<&str> = as_array(&policy["ref_kinds_required"], "ref_kinds_required")?
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect();
    for kind in ["file_line", "file_only"] {
        ensure(
            ref_kinds.contains(&kind),
            format!("ref_kinds_required must include {kind}"),
        )?;
    }
    let rejected: Vec<&str> = as_array(
        &policy["rejected_evidence_kinds"],
        "rejected_evidence_kinds",
    )?
    .iter()
    .map(|v| v.as_str().unwrap_or_default())
    .collect();
    for kind in REJECTED_EVIDENCE_KINDS {
        ensure(
            rejected.contains(kind),
            format!("rejected_evidence_kinds must include {kind}"),
        )?;
    }
    Ok(())
}

#[test]
fn every_binder_source_ref_resolves_in_current_tree() -> TestResult {
    let binder = load_json(&binder_path())?;
    let obligations = as_array(&binder["obligations"], "binder.obligations")?;

    let root = workspace_root();
    let mut total_refs = 0usize;
    let mut unique: BTreeSet<String> = BTreeSet::new();

    for obligation in obligations {
        let id = as_str(&obligation["id"], "obligation.id")?;
        let refs = obligation
            .get("source_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for raw in refs {
            let raw = as_str(&raw, "source_ref")?;
            total_refs += 1;
            unique.insert(raw.to_string());
            let parsed = parse_source_ref(raw);
            let abs = root.join(parsed.path);
            ensure(
                abs.exists(),
                format!(
                    "{id}: source_ref {raw}: file {} is missing in current tree (kind={})",
                    parsed.path, parsed.kind
                ),
            )?;
            if let Some(line) = parsed.line {
                let n = count_lines(&abs)?;
                ensure(
                    line as usize >= 1 && (line as usize) <= n,
                    format!(
                        "{id}: source_ref {raw}: line {line} out of range (file has {n} lines)"
                    ),
                )?;
            }
        }
    }
    ensure(
        total_refs > 0,
        "binder must declare at least one source_ref",
    )?;
    ensure(
        !unique.is_empty(),
        "binder must declare at least one unique source_ref",
    )?;
    Ok(())
}

#[test]
fn validation_envelope_matches_binder() -> TestResult {
    let binder = load_json(&binder_path())?;
    let validation = load_json(&validation_path())?;
    let traceability = load_json(&traceability_check_path())?;
    let gate = load_json(&gate_path())?;
    let env_req = &gate["freshness_policy"]["envelope_requirements"];

    if env_req["binder_valid"].as_bool().unwrap_or(true) {
        ensure_eq(
            validation["binder_valid"].as_bool(),
            Some(true),
            "proof_binder_validation.binder_valid",
        )?;
        ensure_eq(
            traceability["binder_valid"].as_bool(),
            Some(true),
            "proof_traceability_check.binder_valid",
        )?;
    }
    let max_violations = env_req["total_violations_max"].as_u64().unwrap_or(0);
    let actual_violations = validation["total_violations"].as_u64().unwrap_or(u64::MAX);
    ensure(
        actual_violations <= max_violations,
        format!(
            "proof_binder_validation.total_violations {actual_violations} exceeds policy max {max_violations}"
        ),
    )?;

    if env_req["obligation_count_must_match_binder"]
        .as_bool()
        .unwrap_or(true)
    {
        let binder_count = as_array(&binder["obligations"], "binder.obligations")?.len();
        let validation_count =
            as_array(&validation["obligations"], "validation.obligations")?.len();
        let traceability_count =
            as_array(&traceability["obligations"], "traceability.obligations")?.len();
        ensure_eq(
            validation_count,
            binder_count,
            "proof_binder_validation obligation count must match binder",
        )?;
        ensure_eq(
            traceability_count,
            binder_count,
            "proof_traceability_check obligation count must match binder",
        )?;
        let total_obligations = validation["total_obligations"].as_u64().unwrap_or(0) as usize;
        ensure_eq(
            total_obligations,
            binder_count,
            "proof_binder_validation.total_obligations must equal binder obligation count",
        )?;
    }

    if env_req["categories_covered_must_match_binder"]
        .as_bool()
        .unwrap_or(true)
    {
        let mut binder_cats: BTreeSet<String> = BTreeSet::new();
        for obligation in as_array(&binder["obligations"], "binder.obligations")? {
            if let Some(c) = obligation["category"].as_str() {
                binder_cats.insert(c.to_string());
            }
        }
        let validation_cats: BTreeSet<String> = validation["categories_covered"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        ensure_eq(
            validation_cats,
            binder_cats,
            "categories_covered must equal the union of binder categories",
        )?;
    }

    Ok(())
}

#[test]
fn binder_obligation_ids_are_unique_and_match_validation_ids() -> TestResult {
    let binder = load_json(&binder_path())?;
    let validation = load_json(&validation_path())?;
    let mut binder_ids: Vec<String> = Vec::new();
    let mut binder_id_set: BTreeSet<String> = BTreeSet::new();
    for obligation in as_array(&binder["obligations"], "binder.obligations")? {
        let id = as_str(&obligation["id"], "obligation.id")?.to_string();
        ensure(
            binder_id_set.insert(id.clone()),
            format!("duplicate obligation id in binder: {id}"),
        )?;
        binder_ids.push(id);
    }
    let mut validation_ids: BTreeSet<String> = BTreeSet::new();
    for obligation in as_array(&validation["obligations"], "validation.obligations")? {
        let id = as_str(&obligation["obligation_id"], "validation.obligation_id")?.to_string();
        ensure(
            validation_ids.insert(id.clone()),
            format!("duplicate obligation id in validation: {id}"),
        )?;
    }
    ensure_eq(
        binder_id_set,
        validation_ids,
        "binder obligation ids must match validation obligation ids",
    )?;

    Ok(())
}

#[test]
fn binder_categories_are_in_scope_and_meet_minimum_coverage() -> TestResult {
    let gate = load_json(&gate_path())?;
    let binder = load_json(&binder_path())?;

    let in_scope: BTreeSet<&str> = as_array(&gate["categories_in_scope"], "categories_in_scope")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let categories_meta = binder["categories"]
        .as_object()
        .ok_or_else(|| test_error("binder.categories must be an object"))?;
    let binder_categories: BTreeSet<&str> = categories_meta.keys().map(|s| s.as_str()).collect();

    for cat in &binder_categories {
        ensure(
            in_scope.contains(cat),
            format!(
                "binder declares category {cat} which is not listed in proof_traceability_freshness_gate.categories_in_scope"
            ),
        )?;
    }

    let mut counts: HashMap<&str, u64> = HashMap::new();
    for obligation in as_array(&binder["obligations"], "binder.obligations")? {
        if let Some(c) = obligation["category"].as_str() {
            *counts.entry(c).or_default() += 1;
        }
    }
    let minimums = gate["minimum_obligations_per_category"]
        .as_object()
        .ok_or_else(|| test_error("minimum_obligations_per_category must be an object"))?;
    for (cat, min) in minimums {
        let min = min.as_u64().unwrap_or(0);
        let actual = counts.get(cat.as_str()).copied().unwrap_or(0);
        ensure(
            actual >= min,
            format!(
                "category {cat}: binder has {actual} obligations, gate requires at least {min}"
            ),
        )?;
    }
    Ok(())
}

#[test]
fn doc_proof_anchors_resolve_with_correct_extension() -> TestResult {
    // Walk every source_ref that lives under one of `doc_proof_dirs`; require
    // it to end with `doc_proof_extension` and to exist on disk. This catches
    // proof prose moved or renamed without updating the binder.
    let gate = load_json(&gate_path())?;
    let binder = load_json(&binder_path())?;
    let dirs: Vec<&str> = as_array(&gate["doc_proof_dirs"], "doc_proof_dirs")?
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    let ext = as_str(&gate["doc_proof_extension"], "doc_proof_extension")?;
    let root = workspace_root();
    let mut seen = 0usize;
    for obligation in as_array(&binder["obligations"], "binder.obligations")? {
        let id = as_str(&obligation["id"], "obligation.id")?;
        for raw in obligation
            .get("source_refs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let raw = as_str(&raw, "source_ref")?;
            let parsed = parse_source_ref(raw);
            if !dirs.iter().any(|d| parsed.path.starts_with(d)) {
                continue;
            }
            seen += 1;
            ensure(
                parsed.path.ends_with(ext),
                format!(
                    "{id}: doc-proof source_ref {raw} must end with {ext} (got {})",
                    parsed.path
                ),
            )?;
            ensure(
                root.join(parsed.path).exists(),
                format!("{id}: doc-proof source_ref {raw}: file missing in current tree"),
            )?;
        }
    }
    ensure(
        seen > 0,
        "no doc-proof anchors found — gate must observe at least one proof prose anchor",
    )?;
    Ok(())
}

#[test]
fn evidence_artifacts_resolve_in_current_tree() -> TestResult {
    // Every entry in `evidence_artifacts` must currently exist; `gates` must
    // currently exist. This is an additional drift detector beyond source_refs.
    let binder = load_json(&binder_path())?;
    let root = workspace_root();
    let mut seen_evidence: BTreeMap<String, usize> = BTreeMap::new();
    let mut seen_gates: BTreeMap<String, usize> = BTreeMap::new();
    for obligation in as_array(&binder["obligations"], "binder.obligations")? {
        let id = as_str(&obligation["id"], "obligation.id")?;
        for evidence in obligation
            .get("evidence_artifacts")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let path = as_str(&evidence, "evidence_artifact")?;
            ensure(
                root.join(path).exists(),
                format!("{id}: evidence_artifact {path} missing in current tree"),
            )?;
            *seen_evidence.entry(path.to_string()).or_default() += 1;
        }
        for gate in obligation
            .get("gates")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
        {
            let path = as_str(&gate, "gate")?;
            ensure(
                root.join(path).exists(),
                format!("{id}: gate script {path} missing in current tree"),
            )?;
            *seen_gates.entry(path.to_string()).or_default() += 1;
        }
    }
    ensure(
        !seen_evidence.is_empty(),
        "binder must reference at least one evidence artifact",
    )?;
    ensure(
        !seen_gates.is_empty(),
        "binder must reference at least one gate script",
    )?;
    Ok(())
}
