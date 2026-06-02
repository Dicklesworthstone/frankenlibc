use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/placeholder_fixture_output_triage.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_placeholder_fixture_output_triage.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "placeholder_fixture_output_triage_{label}_{}_{}",
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .arg("--validate-only")
        .current_dir(root)
        .env("PLACEHOLDER_FIXTURE_OUTPUT_TRIAGE_CONTRACT", contract)
        .env(
            "PLACEHOLDER_FIXTURE_OUTPUT_TRIAGE_REPORT",
            out_dir.join("placeholder_fixture_output_triage.report.json"),
        )
        .env(
            "PLACEHOLDER_FIXTURE_OUTPUT_TRIAGE_LOG",
            out_dir.join("placeholder_fixture_output_triage.log.jsonl"),
        )
        .output()?)
}

fn output_text(output: &Output) -> String {
    format!(
        "status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn git_head(root: &Path) -> TestResult<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(output_text(&output)).into());
    }
    let head = String::from_utf8(output.stdout)?.trim().to_owned();
    if head.is_empty() {
        return Err(io::Error::other("git rev-parse HEAD returned empty output").into());
    }
    Ok(head)
}

fn required_string_set(value: &Value, field: &str) -> TestResult<BTreeSet<String>> {
    Ok(value[field]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("{field} array")))?
        .iter()
        .map(|item| {
            item.as_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, format!("{field} string"))
                })
                .map(str::to_owned)
        })
        .collect::<Result<_, _>>()?)
}

#[test]
fn manifest_binds_placeholder_triage_sources() -> TestResult {
    let root = workspace_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("placeholder_fixture_output_triage.v1")
    );
    assert_eq!(manifest["generated_by_bead"].as_str(), Some("bd-0agsk.14"));
    assert_eq!(
        manifest["canonical_command"].as_str(),
        Some("scripts/check_placeholder_fixture_output_triage.sh --validate-only")
    );

    let source_todos = required_string_set(&manifest, "source_todo_ids")?;
    assert_eq!(
        source_todos,
        BTreeSet::from([
            "TODO-0401".to_string(),
            "TODO-0402".to_string(),
            "TODO-0404".to_string(),
        ])
    );

    let artifacts = manifest["input_artifacts"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "input_artifacts array"))?;
    for artifact in artifacts {
        let artifact = artifact
            .as_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "artifact string"))?;
        assert!(
            root.join(artifact).is_file(),
            "input artifact should exist: {artifact}"
        );
    }

    let findings = manifest["triage_findings"]
        .as_array()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "triage_findings array"))?;
    assert_eq!(
        manifest["triage_summary"]["finding_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        manifest["triage_summary"]["finding_count"].as_u64(),
        Some(findings.len() as u64)
    );
    assert_eq!(
        manifest["triage_summary"]["confirmed_real_blocker_count"].as_u64(),
        Some(0)
    );
    assert_eq!(
        manifest["triage_summary"]["follow_up_beads_created"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    let finding_ids: BTreeSet<&str> = findings
        .iter()
        .filter_map(|finding| finding["id"].as_str())
        .collect();
    assert!(finding_ids.contains("time_ops_symbolic_nondeterministic_outputs"));
    assert!(finding_ids.contains("termios_ops_environment_flexible_tcgetattr"));

    for finding in findings {
        assert_eq!(finding["real_blocker"].as_bool(), Some(false));
        assert!(
            finding["harness_evidence"]
                .as_array()
                .is_some_and(|evidence| !evidence.is_empty()),
            "finding must bind harness evidence: {finding}"
        );
    }

    Ok(())
}

#[test]
fn checker_emits_pass_report_and_jsonl() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "pass")?;
    let expected_commit = git_head(&root)?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("placeholder_fixture_output_triage.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("placeholder_fixture_output_triage.report.v1")
    );
    assert_eq!(report["bead"].as_str(), Some("bd-0agsk.14"));
    assert_eq!(
        report["source_commit"].as_str(),
        Some(expected_commit.as_str())
    );
    assert_ne!(report["source_commit"].as_str(), Some("unknown"));
    assert_eq!(report["mode"].as_str(), Some("validate-only"));
    assert_eq!(report["outcome"].as_str(), Some("pass"));
    assert_eq!(report["failure_signature"].as_str(), Some("none"));
    assert_eq!(report["summary"]["finding_count"].as_u64(), Some(2));
    assert_eq!(report["summary"]["real_blocker_count"].as_u64(), Some(0));
    assert_eq!(
        report["summary"]["time_placeholder_counts"]["POSITIVE_INT"].as_u64(),
        Some(2)
    );
    assert_eq!(
        report["summary"]["time_placeholder_counts"]["NON_NEGATIVE"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["summary"]["time_placeholder_counts"]["TM_STRUCT"].as_u64(),
        Some(1)
    );
    assert_eq!(
        report["summary"]["termios_placeholder_counts"]["0_OR_ENOTTY"].as_u64(),
        Some(2)
    );

    let rows = read_jsonl(&out_dir.join("placeholder_fixture_output_triage.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"].as_str(),
        Some("placeholder_fixture_output_triage_validated")
    );
    assert_eq!(
        rows[0]["source_commit"].as_str(),
        Some(expected_commit.as_str())
    );
    assert_ne!(rows[0]["source_commit"].as_str(), Some("unknown"));
    assert_eq!(rows[0]["outcome"].as_str(), Some("pass"));
    assert_eq!(rows[0]["failure_signature"].as_str(), Some("none"));
    assert_eq!(rows[0]["summary"]["real_blocker_count"].as_u64(), Some(0));

    Ok(())
}

#[test]
fn checker_rejects_wrong_generated_bead() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_out_dir(&root, "wrong_bead")?;
    let mut manifest = read_json(&contract_path(&root))?;
    manifest["generated_by_bead"] = json!("bd-wrong");
    let mutated = out_dir.join("placeholder_fixture_output_triage_wrong_bead.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject wrong generated_by_bead:\n{}",
        output_text(&output)
    );

    let report = read_json(&out_dir.join("placeholder_fixture_output_triage.report.json"))?;
    assert_eq!(report["outcome"].as_str(), Some("fail"));
    assert_eq!(
        report["failure_signature"].as_str(),
        Some("generated_by_bead")
    );
    assert_eq!(report["summary"]["actual"].as_str(), Some("bd-wrong"));

    let rows = read_jsonl(&out_dir.join("placeholder_fixture_output_triage.log.jsonl"))?;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0]["event"].as_str(),
        Some("placeholder_fixture_output_triage_failed")
    );
    assert_eq!(rows[0]["outcome"].as_str(), Some("fail"));
    assert_eq!(
        rows[0]["failure_signature"].as_str(),
        Some("generated_by_bead")
    );

    Ok(())
}
