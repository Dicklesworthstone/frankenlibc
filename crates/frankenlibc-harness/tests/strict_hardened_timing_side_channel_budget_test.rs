//! Conformance gate for `tests/conformance/strict_hardened_timing_side_channel_budget.v1.json`
//! (bd-juvqm.12).
//!
//! Locks the timing side-channel budget contract for representative
//! pointer / allocator / string / stdio / pthread paths across strict
//! and hardened modes. The gate validates the manifest itself plus
//! exercises the rejection logic against synthetic positive and
//! negative report fixtures, so the contract is testable today
//! without a live timing-measurement run.

use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    workspace_root().join("tests/conformance/strict_hardened_timing_side_channel_budget.v1.json")
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let text = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&text)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn manifest() -> Result<Value, Box<dyn Error>> {
    load_json(&manifest_path())
}

fn git_stdout(root: &Path, args: &[&str]) -> Result<String, Box<dyn Error>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|err| test_error(format!("run git {args:?}: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(test_error(format!("git {args:?} failed: {stderr}")));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| test_error(format!("git {args:?} emitted non-utf8 stdout: {err}")))
}

fn is_hex_commit(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn validate_manifest_source_commit_freshness(manifest: &Value) -> TestResult {
    let source_commit = manifest["source_commit"]
        .as_str()
        .ok_or_else(|| test_error("source_commit must be a string"))?;
    ensure(
        is_hex_commit(source_commit),
        "source_commit must be a 40-character git commit",
    )?;

    let policy = manifest["policy"]
        .as_object()
        .ok_or_else(|| test_error("policy must be object"))?;
    ensure(
        policy["fail_closed_when_source_commit_stale"]
            .as_bool()
            .unwrap_or(false),
        "policy.fail_closed_when_source_commit_stale must be true",
    )?;
    ensure(
        policy["stale_source_commit_freshness_target"].as_str() == Some("current git HEAD"),
        "policy.stale_source_commit_freshness_target must be current git HEAD",
    )?;

    let freshness = manifest["source_commit_freshness"]
        .as_object()
        .ok_or_else(|| test_error("source_commit_freshness must be object"))?;
    ensure(
        freshness["require_no_tracked_source_changes_since_source_commit"]
            .as_bool()
            .unwrap_or(false),
        "source_commit_freshness must require no tracked source changes",
    )?;
    let roots = freshness["tracked_source_roots"]
        .as_array()
        .ok_or_else(|| test_error("tracked_source_roots must be array"))?;
    ensure(!roots.is_empty(), "tracked_source_roots must not be empty")?;
    let root_strings: Vec<&str> = roots
        .iter()
        .map(|root| {
            root.as_str()
                .ok_or_else(|| test_error("tracked_source_roots entries must be strings"))
        })
        .collect::<Result<_, _>>()?;

    let repo = workspace_root();
    git_stdout(
        &repo,
        &["cat-file", "-e", &format!("{source_commit}^{{commit}}")],
    )?;
    let commit_range = format!("{source_commit}..HEAD");
    let mut args = vec!["diff", "--name-only", commit_range.as_str(), "--"];
    args.extend(root_strings);
    let changed = git_stdout(&repo, &args)?;
    let changed_paths: Vec<&str> = changed.lines().filter(|line| !line.is_empty()).collect();
    ensure(
        changed_paths.is_empty(),
        format!(
            "source_commit {source_commit} is stale for strict/hardened timing roots: {changed_paths:?}"
        ),
    )
}

#[test]
fn manifest_has_required_top_level_shape() -> TestResult {
    let m = manifest()?;
    ensure(m["schema_version"] == "v1", "schema_version must be v1")?;
    ensure(m["bead"] == "bd-juvqm.12", "bead must be bd-juvqm.12")?;
    ensure(
        m["manifest_id"] == "strict-hardened-timing-side-channel-budget",
        "manifest_id mismatch",
    )?;
    ensure(
        m["source_commit"]
            .as_str()
            .map(|s| s.len() == 40)
            .unwrap_or(false),
        "source_commit must be 40-char SHA",
    )?;
    let policy = m["policy"]
        .as_object()
        .ok_or_else(|| test_error("policy must be object"))?;
    for k in [
        "default_decision",
        "fail_closed_when_missing_mode_pair",
        "fail_closed_when_artifact_refs_missing",
        "fail_closed_when_p99_delta_exceeds_budget",
        "fail_closed_when_p99_delta_amplifies_with_input_class",
        "fail_closed_when_source_commit_stale",
        "amplification_threshold_ratio",
        "rejected_evidence_kinds",
    ] {
        ensure(
            policy.get(k).is_some(),
            format!("policy.{k} must be present"),
        )?;
    }
    let amp = policy["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(0.0);
    ensure(
        (1.5..=10.0).contains(&amp),
        format!("amplification_threshold_ratio must be in [1.5, 10.0]; got {amp}"),
    )?;
    Ok(())
}

#[test]
fn manifest_source_commit_is_fresh_for_timing_budget_roots() -> TestResult {
    let m = manifest()?;
    validate_manifest_source_commit_freshness(&m)
}

#[test]
fn fixture_invalid_manifest_source_commit_is_rejected() -> TestResult {
    let mut m = manifest()?;
    m["source_commit"] = Value::String("0000000000000000000000000000000000000000".to_string());
    let err = validate_manifest_source_commit_freshness(&m)
        .expect_err("invalid manifest source_commit must be rejected");
    ensure(
        err.to_string().contains("cat-file") || err.to_string().contains("source_commit"),
        format!("unexpected invalid source_commit error: {err}"),
    )
}

#[test]
fn fixture_stale_manifest_source_commit_is_rejected() -> TestResult {
    let mut m = manifest()?;
    m["source_commit"] = Value::String("4052e3a5f1b0414f74cce5027269f33df6ad30fa".to_string());
    let err = validate_manifest_source_commit_freshness(&m)
        .expect_err("stale manifest source_commit must be rejected");
    ensure(
        err.to_string().contains("stale") || err.to_string().contains("cat-file"),
        format!("unexpected stale source_commit error: {err}"),
    )
}

#[test]
fn paths_cover_required_subsystems_with_budgets() -> TestResult {
    let m = manifest()?;
    let paths = m["paths"]
        .as_array()
        .ok_or_else(|| test_error("paths must be array"))?;
    let owners: BTreeSet<String> = paths
        .iter()
        .filter_map(|p| p["owner_subsystem"].as_str().map(|s| s.to_string()))
        .collect();
    for required in ["membrane", "allocator", "string", "stdio", "pthread"] {
        ensure(
            owners.contains(required),
            format!("paths missing owner_subsystem {required}"),
        )?;
    }
    for p in paths {
        let id = p["path_id"].as_str().unwrap_or("?");
        let budget = p["allowed_p99_delta_budget_ns"].as_i64().unwrap_or(-1);
        ensure(
            budget >= 0,
            format!("path {id} allowed_p99_delta_budget_ns must be >=0"),
        )?;
        ensure(
            p["intentional_divergence"].is_boolean(),
            format!("path {id} intentional_divergence must be boolean"),
        )?;
        ensure(
            p["intentional_divergence_rationale"]
                .as_str()
                .map(|s| s.len() > 30)
                .unwrap_or(false),
            format!("path {id} intentional_divergence_rationale must be non-trivial"),
        )?;
    }
    Ok(())
}

#[test]
fn input_classes_include_typical_boundary_adversarial() -> TestResult {
    let m = manifest()?;
    let classes: BTreeSet<String> = m["input_classes"]
        .as_array()
        .ok_or_else(|| test_error("input_classes must be array"))?
        .iter()
        .filter_map(|c| c["input_class_id"].as_str().map(|s| s.to_string()))
        .collect();
    for required in ["typical", "boundary", "adversarial"] {
        ensure(
            classes.contains(required),
            format!("input_classes missing {required}"),
        )?;
    }
    Ok(())
}

#[test]
fn rejected_evidence_kinds_include_required_set() -> TestResult {
    let m = manifest()?;
    let kinds: BTreeSet<String> = m["policy"]["rejected_evidence_kinds"]
        .as_array()
        .ok_or_else(|| test_error("rejected_evidence_kinds must be array"))?
        .iter()
        .filter_map(|k| k.as_str().map(|s| s.to_string()))
        .collect();
    for required in [
        "missing_mode_pair",
        "missing_artifact_refs",
        "over_budget_p99_delta",
        "amplification_above_threshold",
        "stale_source_commit",
        "missing_required_field",
    ] {
        ensure(
            kinds.contains(required),
            format!("rejected_evidence_kinds missing {required}"),
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Synthetic fixtures: rejection logic exercised without a live run.
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Row {
    path_id: String,
    input_class: String,
    strict_p99_ns: f64,
    hardened_p99_ns: f64,
    allowed_budget_ns: i64,
    amplification_ratio: f64,
    artifact_refs: Vec<String>,
    source_commit: String,
}

fn judge_rows(
    rows: &[Row],
    manifest_source_commit: &str,
    required_paths: &BTreeSet<String>,
    amp_threshold: f64,
) -> Result<(), String> {
    // missing_mode_pair: every (path_id, input_class) row must
    // carry both strict and hardened p99 (encoded as two finite
    // numbers per row in this synthetic schema).
    if rows.is_empty() {
        return Err("EMPTY::EMPTY::missing_required_field".to_string());
    }
    let seen_paths: BTreeSet<String> = rows.iter().map(|r| r.path_id.clone()).collect();
    for required in required_paths {
        if !seen_paths.contains(required) {
            return Err(format!("{required}::ALL::missing_mode_pair"));
        }
    }
    for r in rows {
        if r.source_commit != manifest_source_commit {
            return Err(format!(
                "{}::{}::stale_source_commit",
                r.path_id, r.input_class
            ));
        }
        if r.artifact_refs.is_empty() {
            return Err(format!(
                "{}::{}::missing_artifact_refs",
                r.path_id, r.input_class
            ));
        }
        if !r.strict_p99_ns.is_finite() || !r.hardened_p99_ns.is_finite() {
            return Err(format!(
                "{}::{}::missing_required_field",
                r.path_id, r.input_class
            ));
        }
        let delta = r.hardened_p99_ns - r.strict_p99_ns;
        if delta > r.allowed_budget_ns as f64 {
            return Err(format!(
                "{}::{}::over_budget_p99_delta",
                r.path_id, r.input_class
            ));
        }
        if r.amplification_ratio > amp_threshold {
            return Err(format!(
                "{}::{}::amplification_above_threshold",
                r.path_id, r.input_class
            ));
        }
    }
    Ok(())
}

fn required_paths_set(m: &Value) -> BTreeSet<String> {
    m["paths"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|p| p["path_id"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn well_formed_rows(commit: &str) -> Vec<Row> {
    vec![
        Row {
            path_id: "pointer.validate_region".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 18.0,
            hardened_p99_ns: 200.0,
            allowed_budget_ns: 200,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "allocator.malloc_fastpath".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 30.0,
            hardened_p99_ns: 170.0,
            allowed_budget_ns: 150,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "string.memcmp".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 12.0,
            hardened_p99_ns: 55.0,
            allowed_budget_ns: 50,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "stdio.fread_small".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 100.0,
            hardened_p99_ns: 350.0,
            allowed_budget_ns: 250,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
        Row {
            path_id: "pthread.mutex_lock_uncontended".to_string(),
            input_class: "typical".to_string(),
            strict_p99_ns: 25.0,
            hardened_p99_ns: 125.0,
            allowed_budget_ns: 100,
            amplification_ratio: 1.0,
            artifact_refs: vec![
                "target/conformance/high_core_tail_baseline.rows.jsonl".to_string(),
            ],
            source_commit: commit.to_string(),
        },
    ]
}

#[test]
fn positive_fixture_well_formed_rows_pass() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let rows = well_formed_rows(&commit);
    judge_rows(&rows, &commit, &paths, amp).map_err(test_error)?;
    Ok(())
}

#[test]
fn negative_fixture_missing_mode_pair_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    // Drop one path entirely.
    let mut rows = well_formed_rows(&commit);
    rows.retain(|r| r.path_id != "string.memcmp");
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "missing path row should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_mode_pair"),
        format!("rejection should be missing_mode_pair; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_missing_artifact_refs_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    rows[0].artifact_refs.clear();
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "empty artifact_refs should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_artifact_refs"),
        format!("rejection should be missing_artifact_refs; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_over_budget_delta_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    // Push pointer.validate_region delta over budget (200ns cap).
    rows[0].hardened_p99_ns = 500.0; // strict was 18.0, delta = 482 > 200
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "over-budget delta should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::over_budget_p99_delta"),
        format!("rejection should be over_budget_p99_delta; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_amplification_above_threshold_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    // Boost amplification on the first row past threshold (3.0).
    rows[0].amplification_ratio = 5.0;
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(
        err.is_err(),
        "amplification above threshold should be rejected",
    )?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::amplification_above_threshold"),
        format!("rejection should be amplification_above_threshold; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_stale_source_commit_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    rows[0].source_commit = "0000000000000000000000000000000000000000".to_string();
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "stale source_commit should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::stale_source_commit"),
        format!("rejection should be stale_source_commit; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn negative_fixture_non_finite_quantile_rejected() -> TestResult {
    let m = manifest()?;
    let commit = m["source_commit"].as_str().unwrap().to_string();
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .unwrap_or(3.0);
    let paths = required_paths_set(&m);
    let mut rows = well_formed_rows(&commit);
    rows[0].strict_p99_ns = f64::NAN;
    let err = judge_rows(&rows, &commit, &paths, amp);
    ensure(err.is_err(), "NaN strict_p99 should be rejected")?;
    let sig = err.err().unwrap();
    ensure(
        sig.contains("::missing_required_field"),
        format!("rejection should be missing_required_field; got: {sig}"),
    )?;
    Ok(())
}

#[test]
fn anchored_baseline_manifest_exists_on_disk() -> TestResult {
    let m = manifest()?;
    let path = m["anchored_baseline_manifest"].as_str().unwrap_or("");
    ensure(!path.is_empty(), "anchored_baseline_manifest must be set")?;
    let abs = workspace_root().join(path);
    ensure(
        abs.exists(),
        format!("anchored_baseline_manifest {path} does not exist on disk"),
    )?;
    Ok(())
}

// ── P99 delta helper integration tests (bd-hp41p) ────────────────────

#[test]
fn manifest_delta_helper_contract_pins_function_names_and_error_variants() -> TestResult {
    let m = manifest()?;
    let helper = &m["delta_helper_contract"];
    ensure(
        helper["p99_delta_function"].as_str().unwrap_or("")
            == "frankenlibc_harness::tail_stats::compute_p99_delta",
        "p99_delta_function",
    )?;
    ensure(
        helper["validator_function"].as_str().unwrap_or("")
            == "frankenlibc_harness::tail_stats::validate_p99_delta_against_budget",
        "validator_function",
    )?;
    ensure(
        helper["p99_delta_takes_absolute_value"]
            .as_bool()
            .unwrap_or(false),
        "p99_delta_takes_absolute_value",
    )?;
    let variants: BTreeSet<&str> = helper["validator_error_variants"]
        .as_array()
        .ok_or_else(|| test_error("validator_error_variants"))?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let expected: BTreeSet<&str> = [
        "OverBudget",
        "AmplificationAboveThreshold",
        "InsufficientSamples",
        "CiIndistinguishableButOverBudget",
    ]
    .into_iter()
    .collect();
    ensure(variants == expected, format!("variants: got {variants:?}"))?;
    Ok(())
}

#[test]
fn helper_validates_each_path_budget_against_synthetic_within_budget_pair() -> TestResult {
    use frankenlibc_harness::tail_stats::{
        DEFAULT_BOOTSTRAP_ITERS, MIN_SAMPLES_FOR_P99, MIN_SAMPLES_FOR_P999, TailStats,
        compute_p99_delta, validate_p99_delta_against_budget,
    };

    fn synth(p99: f64, ci_low: f64, ci_high: f64) -> TailStats {
        let n = 1000;
        TailStats {
            n,
            p50: p99 * 0.5,
            p95: p99 * 0.9,
            p99,
            p999: p99 * 1.1,
            p99_ci_low: ci_low,
            p99_ci_high: ci_high,
            sufficient_for_p99: n >= MIN_SAMPLES_FOR_P99,
            sufficient_for_p999: n >= MIN_SAMPLES_FOR_P999,
            overloaded_host: false,
            seed: 0,
            bootstrap_iters: DEFAULT_BOOTSTRAP_ITERS,
        }
    }

    let m = manifest()?;
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .ok_or_else(|| test_error("amplification_threshold_ratio"))?;
    for path in m["paths"].as_array().ok_or_else(|| test_error("paths"))? {
        let path_id = path["path_id"].as_str().unwrap_or("?");
        let budget = path["allowed_p99_delta_budget_ns"]
            .as_u64()
            .ok_or_else(|| test_error(format!("budget for {path_id}")))?;
        // Synthesize a within-budget pair with amplification well under the
        // threshold: strict=10000ns baseline, hardened=10000+budget/2.
        // ratio ≈ (10000 + half) / 10000, which is ~1.0125 for budget=250
        // — comfortably under 3.0.
        let half = (budget / 2).max(1) as f64;
        let strict_p99 = 10_000.0;
        let hardened_p99 = strict_p99 + half;
        let strict = synth(strict_p99, strict_p99 - 5.0, strict_p99 + 5.0);
        let hardened = synth(hardened_p99, hardened_p99 - 5.0, hardened_p99 + 5.0);
        let d = compute_p99_delta(&strict, &hardened);
        let res = validate_p99_delta_against_budget(&d, budget, amp);
        ensure(
            res.is_ok(),
            format!("path {path_id}: within-budget pair must validate; got {res:?}"),
        )?;
    }
    Ok(())
}

#[test]
fn helper_rejects_each_path_budget_against_synthetic_over_budget_pair() -> TestResult {
    use frankenlibc_harness::tail_stats::{
        DEFAULT_BOOTSTRAP_ITERS, MIN_SAMPLES_FOR_P99, MIN_SAMPLES_FOR_P999, P99DeltaError,
        TailStats, compute_p99_delta, validate_p99_delta_against_budget,
    };

    fn synth(p99: f64, ci_low: f64, ci_high: f64) -> TailStats {
        let n = 1000;
        TailStats {
            n,
            p50: p99 * 0.5,
            p95: p99 * 0.9,
            p99,
            p999: p99 * 1.1,
            p99_ci_low: ci_low,
            p99_ci_high: ci_high,
            sufficient_for_p99: n >= MIN_SAMPLES_FOR_P99,
            sufficient_for_p999: n >= MIN_SAMPLES_FOR_P999,
            overloaded_host: false,
            seed: 0,
            bootstrap_iters: DEFAULT_BOOTSTRAP_ITERS,
        }
    }

    let m = manifest()?;
    let amp = m["policy"]["amplification_threshold_ratio"]
        .as_f64()
        .ok_or_else(|| test_error("amplification_threshold_ratio"))?;
    for path in m["paths"].as_array().ok_or_else(|| test_error("paths"))? {
        let path_id = path["path_id"].as_str().unwrap_or("?");
        let budget = path["allowed_p99_delta_budget_ns"]
            .as_u64()
            .ok_or_else(|| test_error(format!("budget for {path_id}")))?;
        // Over-budget but with disjoint CIs and amplification within threshold.
        // strict=100, hardened=100+budget*2 — keeps amplification < 3 only when
        // budget*2 < 200 (200ns budget already maxes out 3x); we pick
        // amplification 2x by setting hardened=2*strict.
        let strict_p99 = 100.0;
        let hardened_p99 = strict_p99 + (budget as f64 * 2.0).max(50.0);
        let strict = synth(strict_p99, strict_p99 - 5.0, strict_p99 + 5.0);
        let hardened = synth(hardened_p99, hardened_p99 - 5.0, hardened_p99 + 5.0);
        let d = compute_p99_delta(&strict, &hardened);
        let res = validate_p99_delta_against_budget(&d, budget, amp);
        match res {
            Err(P99DeltaError::OverBudget) | Err(P99DeltaError::AmplificationAboveThreshold) => {}
            other => {
                return Err(test_error(format!(
                    "path {path_id}: over-budget pair must reject; got {other:?}"
                )));
            }
        }
    }
    Ok(())
}
