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
    Ok(
        Command::new(workspace_root()?.join("scripts/release/check_replacement_claim_evidence.sh"))
            .args(args)
            .output()?,
    )
}

fn read_report(path: &Path) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
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
