use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> TestResult<PathBuf> {
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
    root.join("tests/conformance/printf_fuzz_family_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_printf_fuzz_family_completion_contract.sh")
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
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = root.join("target/conformance").join(format!(
        "printf_fuzz_family_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_PRINTF_FUZZ_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_PRINTF_FUZZ_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_PRINTF_FUZZ_COMPLETION_REPORT",
            out_dir.join("printf_fuzz_family_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_PRINTF_FUZZ_COMPLETION_LOG",
            out_dir.join("printf_fuzz_family_completion_contract.log.jsonl"),
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

fn target_names(manifest: &Value) -> TestResult<BTreeSet<String>> {
    let targets = manifest["required_targets"]
        .as_array()
        .ok_or("required_targets should be an array")?;
    let mut names = BTreeSet::new();
    for entry in targets {
        names.insert(
            entry["target"]
                .as_str()
                .ok_or("target should be a string")?
                .to_string(),
        );
    }
    Ok(names)
}

#[test]
fn manifest_binds_printf_fuzz_family_completion_items() -> TestResult {
    let root = repo_root()?;
    let manifest = read_json(&contract_path(&root))?;

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("printf_fuzz_family_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-1oz.3"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-1oz.3.1")
    );
    assert_eq!(
        target_names(&manifest)?,
        BTreeSet::from([
            "fuzz_asprintf".to_string(),
            "fuzz_printf".to_string(),
            "fuzz_printf_adversarial".to_string(),
        ])
    );

    let missing_items: BTreeSet<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings should be an array")?
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert_eq!(
        missing_items,
        BTreeSet::from([
            "tests.e2e.primary",
            "tests.fuzz.primary",
            "tests.unit.primary",
        ])
    );

    let source_artifacts = manifest["source_artifacts"]
        .as_array()
        .ok_or("source_artifacts should be an array")?;
    assert_eq!(source_artifacts.len(), 7);
    for artifact in source_artifacts {
        let path = artifact["path"].as_str().ok_or("artifact path")?;
        assert!(root.join(path).is_file(), "missing artifact {path}");
    }

    Ok(())
}

#[test]
fn checker_validates_printf_fuzz_family_contract() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = read_json(&out_dir.join("printf_fuzz_family_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-1oz.3"));
    assert_eq!(report["completion_debt_bead"].as_str(), Some("bd-1oz.3.1"));
    assert_eq!(report["required_targets"].as_array().map(Vec::len), Some(3));
    let events: BTreeSet<_> = report["events"]
        .as_array()
        .ok_or("events should be an array")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    for event in [
        "printf_fuzz_family.e2e_runner_list",
        "printf_fuzz_family.runtime_target",
        "printf_fuzz_family.source_artifact",
        "printf_fuzz_family.target_contract",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }

    let rows = read_jsonl(&out_dir.join("printf_fuzz_family_completion_contract.log.jsonl"))?;
    assert!(
        rows.iter()
            .any(|row| row["event"].as_str() == Some("printf_fuzz_family.completion_contract")),
        "checker should emit completion telemetry"
    );

    Ok(())
}

#[test]
fn nightly_runner_lists_only_printf_family_targets() -> TestResult {
    let root = repo_root()?;
    let output = Command::new("bash")
        .arg("scripts/fuzz_nightly.sh")
        .arg("--target-group")
        .arg("printf-family")
        .arg("--list-targets")
        .current_dir(&root)
        .output()?;
    assert!(output.status.success(), "{}", output_text(&output));
    let targets: Vec<_> = String::from_utf8(output.stdout)?
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        targets,
        vec![
            "fuzz_printf".to_string(),
            "fuzz_printf_adversarial".to_string(),
            "fuzz_asprintf".to_string(),
        ]
    );
    Ok(())
}

#[test]
fn checker_rejects_rch_cargo_without_remote_requirement() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_rch_remote")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let commands = manifest["runtime_target"]["allowed_command_prefixes"]
        .as_array_mut()
        .ok_or("allowed_command_prefixes should be mutable")?;
    let command = commands
        .iter_mut()
        .find(|entry| {
            entry
                .as_str()
                .is_some_and(|value| value.contains("cargo test"))
        })
        .ok_or("cargo test command should exist")?;
    let command_text = command
        .as_str()
        .ok_or("cargo test command should be a string")?
        .replacen("RCH_REQUIRE_REMOTE=1 ", "", 1);
    *command = json!(command_text);

    let mutated = out_dir.join("missing_rch_remote.contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for non-remote rch cargo\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("RCH_REQUIRE_REMOTE=1"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn checker_rejects_rch_cargo_without_target_dir() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_cargo_target_dir")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let commands = manifest["runtime_target"]["allowed_command_prefixes"]
        .as_array_mut()
        .ok_or("allowed_command_prefixes should be mutable")?;
    let command = commands
        .iter_mut()
        .find(|entry| {
            entry
                .as_str()
                .is_some_and(|value| value.contains("cargo check"))
        })
        .ok_or("cargo check command should exist")?;
    let command_text = command
        .as_str()
        .ok_or("cargo check command should be a string")?
        .replacen("env CARGO_TARGET_DIR=<target> ", "", 1);
    *command = json!(command_text);

    let mutated = out_dir.join("missing_cargo_target_dir.contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for rch cargo without target dir\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("CARGO_TARGET_DIR"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_runner_target_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_runner_target")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let targets = manifest["required_targets"]
        .as_array_mut()
        .ok_or("required_targets should be mutable")?;
    targets.retain(|entry| entry["target"].as_str() != Some("fuzz_asprintf"));

    let mutated = out_dir.join("missing_runner_target.contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing target\n{}",
        output_text(&output)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required_targets must be")
            || stderr.contains("runner target list drifted"),
        "unexpected stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_corpus_seed_binding() -> TestResult {
    let root = repo_root()?;
    let out_dir = unique_out_dir(&root, "missing_seed")?;
    let mut manifest = read_json(&contract_path(&root))?;
    let targets = manifest["required_targets"]
        .as_array_mut()
        .ok_or("required_targets should be mutable")?;
    let printf = targets
        .iter_mut()
        .find(|entry| entry["target"].as_str() == Some("fuzz_printf"))
        .ok_or("fuzz_printf target should exist")?;
    printf["corpus"]["required_seeds"] = json!(["seed_does_not_exist"]);

    let mutated = out_dir.join("missing_seed.contract.json");
    write_json(&mutated, &manifest)?;
    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should fail for missing seed\n{}",
        output_text(&output)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("corpus missing seed"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
