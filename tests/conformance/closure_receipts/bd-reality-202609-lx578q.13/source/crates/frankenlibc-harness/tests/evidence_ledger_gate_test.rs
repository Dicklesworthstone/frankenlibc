//! Evidence ledger gate tests for bd-3yr14.2.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn ledger_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/evidence_ledger.jsonl")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_evidence_ledger.sh")
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "evidence-ledger-{label}-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_ledger_rows(path: &Path) -> TestResult<Vec<Value>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line)
                .map_err(|err| test_error(format!("ledger line must parse as JSON: {err}")))
        })
        .collect()
}

fn write_ledger(path: &Path, rows: &[Value]) -> TestResult {
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row)?);
        out.push('\n');
    }
    fs::write(path, out)?;
    Ok(())
}

fn run_checker(root: &Path, ledger: &Path, report: &Path) -> TestResult<Output> {
    Command::new("bash")
        .arg(checker_path(root))
        .env("FRANKENLIBC_EVIDENCE_LEDGER", ledger)
        .env("FRANKENLIBC_EVIDENCE_LEDGER_REPORT", report)
        .current_dir(root)
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout={}\nstderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn failure_signatures(report: &Value) -> BTreeSet<String> {
    report
        .get("errors")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("failure_signature").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

#[test]
fn evidence_ledger_rows_bind_existing_artifacts() -> TestResult {
    let root = workspace_root()?;
    let rows = load_ledger_rows(&ledger_path(&root))?;
    assert!(!rows.is_empty(), "ledger must contain at least one row");

    let first = rows
        .first()
        .ok_or_else(|| test_error("missing first row"))?;
    assert_eq!(
        first["schema_version"].as_str(),
        Some("evidence_ledger_entry.v1")
    );
    assert_eq!(first["entry_index"].as_u64(), Some(0));
    let artifact_path = first["artifact_path"]
        .as_str()
        .ok_or_else(|| test_error("artifact_path must be a string"))?;
    assert!(
        root.join(artifact_path).is_file(),
        "artifact path must exist: {artifact_path}"
    );
    for field in [
        "artifact_hash",
        "source_commit",
        "generator_command",
        "tool_version",
        "prev_chain_hash",
        "chain_hash",
    ] {
        assert!(
            first.get(field).and_then(Value::as_str).is_some(),
            "ledger row missing {field}"
        );
    }
    Ok(())
}

#[test]
fn evidence_ledger_anchors_ws0_regenerated_artifacts() -> TestResult {
    let root = workspace_root()?;
    let rows = load_ledger_rows(&ledger_path(&root))?;
    let artifact_paths: BTreeSet<_> = rows
        .iter()
        .filter_map(|row| row["artifact_path"].as_str())
        .collect();
    for required in [
        "tests/conformance/reality_report.v1.json",
        "tests/conformance/ld_preload_smoke_summary.v1.json",
        "tests/conformance/proof_obligations_binder.v1.json",
        "tests/conformance/hard_parts_truth_table.v1.json",
    ] {
        assert!(
            artifact_paths.contains(required),
            "ledger must anchor regenerated WS-0 artifact {required}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_canonical_evidence_ledger() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "positive")?;
    let report_path = out_dir.join("report.json");
    let rows = load_ledger_rows(&ledger_path(&root))?;
    let output = run_checker(&root, &ledger_path(&root), &report_path)?;
    assert!(output.status.success(), "{}", output_text(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("PASS evidence ledger"),
        "{}",
        output_text(&output)
    );

    let report = load_json(&report_path)?;
    assert_eq!(report["schema_version"], "evidence_ledger_check_report.v1");
    assert_eq!(report["status"], "pass");
    assert_eq!(report["failure_signature"], "none");
    assert_eq!(
        report["checked_entry_count"].as_u64(),
        Some(rows.len() as u64)
    );
    Ok(())
}

#[test]
fn checker_rejects_artifact_hash_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "artifact-hash-drift")?;
    let bad_ledger = out_dir.join("bad_ledger.jsonl");
    let report_path = out_dir.join("report.json");
    let mut rows = load_ledger_rows(&ledger_path(&root))?;
    rows[0]["artifact_hash"] = Value::String("0".repeat(64));
    write_ledger(&bad_ledger, &rows)?;

    let output = run_checker(&root, &bad_ledger, &report_path)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert!(failure_signatures(&report).contains("artifact_hash_mismatch"));
    Ok(())
}

#[test]
fn checker_rejects_mutated_ledger_entry_chain() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "ledger-tamper")?;
    let bad_ledger = out_dir.join("bad_ledger.jsonl");
    let report_path = out_dir.join("report.json");
    let mut rows = load_ledger_rows(&ledger_path(&root))?;
    rows[0]["generator_command"] = Value::String("manually edited command".to_string());
    write_ledger(&bad_ledger, &rows)?;

    let output = run_checker(&root, &bad_ledger, &report_path)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report = load_json(&report_path)?;
    assert_eq!(report["status"], "fail");
    assert!(failure_signatures(&report).contains("ledger_chain_hash_mismatch"));
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn derive_chain(rows: &mut [Value]) -> TestResult {
    let mut previous = "0".repeat(64);
    for (index, row) in rows.iter_mut().enumerate() {
        row["entry_index"] = json!(index);
        row["prev_chain_hash"] = json!(previous);
        let mut fields = vec![
            "schema_version",
            "entry_index",
            "artifact_path",
            "artifact_hash",
            "source_commit",
            "generator_command",
            "tool_version",
            "prev_chain_hash",
        ];
        if row["schema_version"] == "evidence_ledger_entry.v2" {
            fields.extend(["artifact_revision", "superseded_revisions"]);
        }
        let payload: BTreeMap<_, _> = fields.into_iter().map(|key| (key, &row[key])).collect();
        previous = hash_bytes(&serde_json::to_vec(&payload)?);
        row["chain_hash"] = json!(previous);
    }
    Ok(())
}

fn git_output(root: &Path, args: &[&str]) -> TestResult<String> {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=LedgerTest",
            "-c",
            "user.email=ledger@example.invalid",
        ])
        .args(args)
        .current_dir(root)
        .output()?;
    assert!(output.status.success(), "{}", output_text(&output));
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

// Real two-commit repository, retained with every report. The copied checker
// reads actual Git objects; no fake Git implementation or synthetic PASS log.
fn history_fixture(label: &str) -> TestResult<(PathBuf, Vec<Value>)> {
    let workspace = workspace_root()?;
    let root = unique_output_dir(&workspace, label)?.join("repository");
    fs::create_dir_all(root.join("scripts"))?;
    for script in ["check_evidence_ledger.sh", "check_evidence_freshness.sh"] {
        fs::copy(
            workspace.join("scripts").join(script),
            root.join("scripts").join(script),
        )?;
    }
    git_output(&root, &["init", "--quiet", "--initial-branch=main"])?;
    fs::write(root.join("artifact.json"), b"old snapshot\n")?;
    git_output(&root, &["add", "--", "artifact.json"])?;
    git_output(&root, &["commit", "--quiet", "-m", "original artifact"])?;
    let old = git_output(&root, &["rev-parse", "HEAD"])?;
    fs::write(root.join("artifact.json"), b"new snapshot\n")?;
    git_output(&root, &["add", "--", "artifact.json"])?;
    git_output(&root, &["commit", "--quiet", "-m", "regenerated artifact"])?;
    let new = git_output(&root, &["rev-parse", "HEAD"])?;
    let mut rows = vec![
        json!({"schema_version":"evidence_ledger_entry.v1", "artifact_path":"artifact.json",
            "artifact_hash":hash_bytes(b"old snapshot\n"), "source_commit":old,
            "generator_command":"original producer", "tool_version":"test"}),
        json!({"schema_version":"evidence_ledger_entry.v2", "artifact_path":"artifact.json",
            "artifact_hash":hash_bytes(b"new snapshot\n"), "source_commit":new,
            "generator_command":"snapshot replay", "tool_version":"test",
            "artifact_revision":new, "superseded_revisions":[{"entry_index":0,"artifact_revision":old}]}),
    ];
    derive_chain(&mut rows)?;
    Ok((root, rows))
}

#[test]
fn checker_preserves_history_and_rejects_snapshot_corruption() -> TestResult {
    let (root, rows) = history_fixture("committed-history")?;
    let ledger = root.join("ledger.jsonl");
    let report = root.join("report.json");
    write_ledger(&ledger, &rows)?;
    let output = run_checker(&root, &ledger, &report)?;
    assert!(output.status.success(), "{}", output_text(&output));
    let clean = load_json(&report)?;
    assert_eq!(clean["checked_entry_count"], 2);
    assert_eq!(clean["current_artifact_count"], 1);
    assert_eq!(clean["committed_snapshot_count"], 2);
    let original = serde_json::to_string(&rows[0])?;

    let mut controls = Vec::new();
    controls.push((
        "unregistered_update",
        rows[..1].to_vec(),
        "artifact_hash_mismatch",
    ));
    for (name, revision, signature) in [
        (
            "wrong_current_snapshot",
            rows[0]["source_commit"].clone(),
            "artifact_hash_mismatch",
        ),
        (
            "missing_snapshot",
            json!("f".repeat(40)),
            "ledger_snapshot_unavailable",
        ),
        (
            "tree_is_not_commit",
            json!(git_output(&root, &["rev-parse", "HEAD^{tree}"])?),
            "ledger_snapshot_unavailable",
        ),
    ] {
        let mut bad = rows.clone();
        bad[1]["artifact_revision"] = revision;
        derive_chain(&mut bad)?;
        controls.push((name, bad, signature));
    }
    let mut bad = rows.clone();
    bad[1]["superseded_revisions"][0]["artifact_revision"] = rows[1]["artifact_revision"].clone();
    derive_chain(&mut bad)?;
    controls.push(("wrong_historical_snapshot", bad, "artifact_hash_mismatch"));
    for (name, bindings) in [
        ("unbound_history", json!([])),
        (
            "forward_binding",
            json!([{"entry_index":1,"artifact_revision":rows[0]["source_commit"]}]),
        ),
        (
            "duplicate_binding",
            json!([
                rows[1]["superseded_revisions"][0],
                rows[1]["superseded_revisions"][0]
            ]),
        ),
    ] {
        let mut bad = rows.clone();
        bad[1]["superseded_revisions"] = bindings;
        derive_chain(&mut bad)?;
        controls.push((name, bad, "ledger_snapshot_invalid"));
    }
    let mut bad = rows.clone();
    bad[1]["artifact_revision"] = rows[0]["source_commit"].clone();
    controls.push((
        "snapshot_field_is_chain_bound",
        bad,
        "ledger_chain_hash_mismatch",
    ));
    let mut bad = rows.clone();
    bad[0]["artifact_path"] = json!("../outside.json");
    bad[1]["artifact_path"] = json!("../outside.json");
    derive_chain(&mut bad)?;
    controls.push(("snapshot_path_escape", bad, "ledger_snapshot_invalid"));
    let mut bad = rows.clone();
    let mut downgrade = rows[1].clone();
    downgrade["schema_version"] = json!("evidence_ledger_entry.v1");
    bad.push(downgrade);
    derive_chain(&mut bad)?;
    controls.push(("schema_downgrade", bad, "ledger_snapshot_invalid"));
    assert_eq!(controls.len(), 11);
    for (name, bad, signature) in controls {
        let path = root.join(format!("{name}.jsonl"));
        let report = root.join(format!("{name}.report.json"));
        write_ledger(&path, &bad)?;
        let output = run_checker(&root, &path, &report)?;
        assert!(!output.status.success(), "{name}: {}", output_text(&output));
        assert!(
            failure_signatures(&load_json(&report)?).contains(signature),
            "{name}: {}",
            output_text(&output)
        );
    }
    // Changing only the live file is still rejected even when every committed
    // historical snapshot and every chain link remains intact.
    fs::write(root.join("artifact.json"), b"unregistered mutation\n")?;
    let output = run_checker(&root, &ledger, &report)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    assert!(failure_signatures(&load_json(&report)?).contains("artifact_hash_mismatch"));
    assert_eq!(serde_json::to_string(&rows[0])?, original);
    Ok(())
}

#[test]
fn freshness_counts_current_artifacts_without_history_dilution() -> TestResult {
    let (root, rows) = history_fixture("history-freshness")?;
    let ledger = root.join("ledger.jsonl");
    let report = root.join("report.json");
    let run = || -> TestResult<Output> {
        Ok(Command::new("bash")
            .arg(root.join("scripts/check_evidence_freshness.sh"))
            .env("FRANKENLIBC_EVIDENCE_LEDGER", &ledger)
            .env("FRANKENLIBC_EVIDENCE_FRESHNESS_REPORT", &report)
            .current_dir(&root)
            .output()?)
    };
    write_ledger(&ledger, &rows)?;
    let output = run()?;
    assert!(output.status.success(), "{}", output_text(&output));
    let clean = load_json(&report)?;
    assert_eq!(clean["observations"], 1);
    assert_eq!(clean["ledger_entry_count"], 2);
    assert_eq!(clean["divergences"], 0);
    let mut repeated = rows.clone();
    repeated.extend(std::iter::repeat_n(rows[1].clone(), 100));
    let mut divergent = rows[1].clone();
    divergent["artifact_hash"] = json!("0".repeat(64));
    repeated.push(divergent);
    derive_chain(&mut repeated)?;
    write_ledger(&ledger, &repeated)?;
    let output = run()?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let alarm = load_json(&report)?;
    assert_eq!(alarm["observations"], 1);
    assert_eq!(alarm["divergences"], 1);
    assert_eq!(alarm["state"], "alarm");
    Ok(())
}

#[test]
fn declared_source_identity_is_checked_before_success() -> TestResult {
    let (root, rows) = history_fixture("declared-source")?;
    let ledger = root.join("ledger.jsonl");
    write_ledger(&ledger, &rows)?;
    let source = rows[1]["artifact_revision"].as_str().unwrap();
    for script in ["check_evidence_ledger.sh", "check_evidence_freshness.sh"] {
        for (declared, expected) in [
            ("invalid-source".to_string(), false),
            (format!("{source}-dirty"), true),
        ] {
            let report = root.join(format!("{script}-{expected}.report.json"));
            let output = Command::new("bash")
                .arg(root.join("scripts").join(script))
                .env("FRANKENLIBC_EVIDENCE_LEDGER", &ledger)
                .env("FRANKENLIBC_EVIDENCE_LEDGER_REPORT", &report)
                .env("FRANKENLIBC_EVIDENCE_FRESHNESS_REPORT", &report)
                .env("RCH_BUILD_SOURCE", declared)
                .current_dir(&root)
                .output()?;
            assert_eq!(
                output.status.success(),
                expected,
                "{}",
                output_text(&output)
            );
            let result = load_json(&report)?;
            if expected {
                assert_eq!(result["source_commit"], source);
            } else {
                assert_eq!(result["status"], "fail");
                assert!(failure_signatures(&result).contains("invalid_source_commit"));
            }
        }
    }
    Ok(())
}
