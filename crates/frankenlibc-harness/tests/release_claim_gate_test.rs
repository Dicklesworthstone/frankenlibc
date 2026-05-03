use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| "workspace root not found".into())
}

fn unique_output_path(name: &str) -> TestResult<PathBuf> {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    Ok(workspace_root()?.join(format!(
        "target/release_claim_gate_test/{name}.{}.{}.json",
        std::process::id(),
        id
    )))
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn run_gate(args: &[String]) -> TestResult<Output> {
    run_gate_with_env(args, &[])
}

fn run_gate_with_env(args: &[String], envs: &[(&str, String)]) -> TestResult<Output> {
    let mut command =
        Command::new(workspace_root()?.join("scripts/release/check_replacement_claim_evidence.sh"));
    command.args(args);
    for (name, value) in envs {
        command.env(name, value);
    }
    Ok(command.output()?)
}

fn read_report(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_file(path: &Path, contents: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

fn rel_path(path: &Path) -> TestResult<String> {
    Ok(path
        .strip_prefix(workspace_root()?)?
        .to_string_lossy()
        .into_owned())
}

fn release_claim_refs(extra_refs: &[String]) -> TestResult<String> {
    let mut refs = vec![
        "tests/conformance/replacement_levels.json".to_owned(),
        "support_matrix.json".to_owned(),
        "tests/conformance/claim_reconciliation_report.v1.json".to_owned(),
        "tests/conformance/l1_crt_startup_tls_proof_matrix.v1.json".to_owned(),
    ];
    refs.extend(extra_refs.iter().cloned());
    Ok(refs
        .into_iter()
        .map(|value| format!(r#""{value}""#))
        .collect::<Vec<_>>()
        .join(", "))
}

#[test]
fn current_l0_release_policy_passes_without_l1_evidence() -> TestResult {
    let report = unique_output_path("current-l0-report")?;
    let log = unique_output_path("current-l0-log")?;
    let output = run_gate(&[
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        output.status.success(),
        "current L0 release policy must pass\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report_json = read_report(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("pass"));
    assert_eq!(report_json["current_release_level"].as_str(), Some("L0"));
    Ok(())
}

#[test]
fn l1_release_tag_without_evidence_file_fails_closed() -> TestResult {
    let claims = unique_output_path("missing-l1-claims")?;
    let report = unique_output_path("missing-l1-report")?;
    let log = unique_output_path("missing-l1-log")?;
    if let Some(parent) = claims.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &claims,
        r#"{
  "schema_version": "v1",
  "claims": [
    {
      "id": "bad-l1-tag",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": ["tests/conformance/replacement_levels.json"]
    }
  ]
}
"#,
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "L1 tag without proof matrix evidence must fail"
    );

    let report_json = read_report(&report)?;
    assert_eq!(report_json["status"].as_str(), Some("fail"));
    assert_eq!(report_json["failed_claim_count"].as_u64(), Some(1));
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_missing_l1_evidence"),
        "missing-evidence failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l2_release_tag_without_standalone_matrix_fails_closed() -> TestResult {
    let claims = unique_output_path("missing-l2-claims")?;
    let report = unique_output_path("missing-l2-report")?;
    let log = unique_output_path("missing-l2-log")?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "bad-l2-tag",
      "tag": "v9.9.9-L2",
      "claimed_level": "L2",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[])?
        ),
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "L2 tag without standalone evidence must fail"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_missing_l2_evidence"),
        "missing-L2 failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn l3_release_tag_without_standalone_matrix_fails_closed() -> TestResult {
    let claims = unique_output_path("missing-l3-claims")?;
    let report = unique_output_path("missing-l3-report")?;
    let log = unique_output_path("missing-l3-log")?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "bad-l3-tag",
      "tag": "v9.9.9-L3",
      "claimed_level": "L3",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[])?
        ),
    )?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "L3 tag without standalone evidence must fail"
    );
    let report_json = read_report(&report)?;
    let signature = report_json["claims"][0]["failure_signature"]
        .as_str()
        .unwrap_or_default();
    assert!(
        signature.contains("release_claim_missing_l2_evidence")
            && signature.contains("release_claim_missing_l3_evidence"),
        "missing-L2/L3 failures not found: {report_json}"
    );
    Ok(())
}

#[test]
fn stale_support_matrix_fixture_blocks_l1_claim() -> TestResult {
    let support = unique_output_path("stale-support-matrix")?;
    let claims = unique_output_path("stale-support-claims")?;
    let report = unique_output_path("stale-support-report")?;
    let log = unique_output_path("stale-support-log")?;
    write_file(
        &support,
        r#"{
  "version": 2,
  "generated_at_utc": "2000-01-01T00:00:00Z",
  "symbols": [
    {"symbol": "puts", "status": "Implemented"}
  ]
}
"#,
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "stale-support-l1",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&support)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_SUPPORT_MATRIX", path_arg(&support))],
    )?;

    assert!(
        !output.status.success(),
        "stale support matrix evidence must fail"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_stale_support_matrix_evidence"),
        "stale-support failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn stubbed_support_matrix_fixture_blocks_l1_claim() -> TestResult {
    let support = unique_output_path("stubbed-support-matrix")?;
    let claims = unique_output_path("stubbed-support-claims")?;
    let report = unique_output_path("stubbed-support-report")?;
    let log = unique_output_path("stubbed-support-log")?;
    write_file(
        &support,
        r#"{
  "version": 2,
  "generated_at_utc": "2026-05-03T00:00:00Z",
  "symbols": [
    {"symbol": "puts", "status": "Stub"}
  ]
}
"#,
    )?;
    write_file(
        &claims,
        &format!(
            r#"{{
  "schema_version": "v1",
  "claims": [
    {{
      "id": "stubbed-support-l1",
      "tag": "v9.9.9-L1",
      "claimed_level": "L1",
      "artifact_refs": [{}]
    }}
  ]
}}
"#,
            release_claim_refs(&[rel_path(&support)?])?
        ),
    )?;

    let output = run_gate_with_env(
        &[
            "--claims".to_owned(),
            path_arg(&claims),
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_SUPPORT_MATRIX", path_arg(&support))],
    )?;

    assert!(
        !output.status.success(),
        "Stub status in support matrix must block L1 release claims"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_support_matrix_stubs_present"),
        "stubbed-support failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn contradictory_readme_claim_blocks_current_policy() -> TestResult {
    let readme = unique_output_path("contradictory-readme")?;
    let report = unique_output_path("contradictory-readme-report")?;
    let log = unique_output_path("contradictory-readme-log")?;
    write_file(
        &readme,
        "Declared replacement level claim: **L2 - Partial Replacement**.\n",
    )?;

    let output = run_gate_with_env(
        &[
            "--report".to_owned(),
            path_arg(&report),
            "--log".to_owned(),
            path_arg(&log),
        ],
        &[("FRANKENLIBC_README", path_arg(&readme))],
    )?;

    assert!(
        !output.status.success(),
        "README claim above current release level must fail"
    );
    let report_json = read_report(&report)?;
    assert!(
        report_json["claims"][0]["failure_signature"]
            .as_str()
            .unwrap_or_default()
            .contains("release_claim_readme_overclaims_current_release_level"),
        "README overclaim failure not found: {report_json}"
    );
    Ok(())
}

#[test]
fn malformed_claims_json_without_claims_array_fails() -> TestResult {
    let claims = unique_output_path("malformed-claims")?;
    let report = unique_output_path("malformed-claims-report")?;
    let log = unique_output_path("malformed-claims-log")?;
    write_file(&claims, r#"{"schema_version":"v1","claim":{}}"#)?;

    let output = run_gate(&[
        "--claims".to_owned(),
        path_arg(&claims),
        "--report".to_owned(),
        path_arg(&report),
        "--log".to_owned(),
        path_arg(&log),
    ])?;

    assert!(
        !output.status.success(),
        "claims JSON without claims array must fail"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("claims array"),
        "schema failure should name the missing claims array\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
