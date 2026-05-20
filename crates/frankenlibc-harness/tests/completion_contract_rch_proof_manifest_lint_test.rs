use frankenlibc_harness::structured_log::validate_log_line;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate directory has workspace parent")
        .parent()
        .expect("workspace parent has repo parent")
        .to_path_buf()
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/completion_contract_rch_proof_manifest_lint.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_completion_contract_rch_proof_manifest_lint.sh")
}

fn read_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "completion_contract_rch_proof_manifest_lint_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_RCH_PROOF_LINT_MANIFEST", manifest)
        .env("FRANKENLIBC_RCH_PROOF_LINT_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_RCH_PROOF_LINT_REPORT",
            out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"),
        )
        .env(
            "FRANKENLIBC_RCH_PROOF_LINT_LOG",
            out_dir.join("completion_contract_rch_proof_manifest_lint.log.jsonl"),
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

fn mutate_strings(value: &mut Value, mutate: &mut impl FnMut(&mut String)) {
    match value {
        Value::String(text) => mutate(text),
        Value::Array(items) => {
            for item in items {
                mutate_strings(item, mutate);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                mutate_strings(item, mutate);
            }
        }
        _ => {}
    }
}

fn retain_strings(value: &mut Value, keep: &impl Fn(&str) -> bool) {
    match value {
        Value::Array(items) => {
            items.retain(|item| !matches!(item, Value::String(text) if !keep(text)));
            for item in items {
                retain_strings(item, keep);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                retain_strings(item, keep);
            }
        }
        _ => {}
    }
}

fn strip_target_dir(command: &str) -> String {
    if let (Some(start), Some(cargo_start)) = (
        command.find("env CARGO_TARGET_DIR="),
        command.find(" cargo "),
    ) {
        let mut result = String::new();
        result.push_str(&command[..start]);
        result.push_str("env");
        result.push_str(&command[cargo_start..]);
        result
    } else {
        command.to_string()
    }
}

fn move_target_dir_before_rch_exec(command: &str) -> String {
    const NEEDLE: &str = "rch exec -- env CARGO_TARGET_DIR=";
    let Some(start) = command.find(NEEDLE) else {
        return command.to_string();
    };
    let target_start = start + "rch exec -- env ".len();
    let Some(cargo_offset) = command[target_start..].find(" cargo ") else {
        return command.to_string();
    };
    let cargo_start = target_start + cargo_offset;
    let target_env = &command[target_start..cargo_start];

    let mut result = String::new();
    result.push_str(&command[..start]);
    result.push_str(target_env);
    result.push(' ');
    result.push_str("rch exec --");
    result.push_str(&command[cargo_start..]);
    result
}

fn write_variant_manifest(
    root: &Path,
    label: &str,
    mutate_contract: impl FnOnce(&mut Value),
) -> TestResult<PathBuf> {
    let out_dir = unique_out_dir(root, label)?;
    let source_contract =
        root.join("tests/conformance/string_memory_hotpaths_wave10_completion_contract.v1.json");
    let contract_path = out_dir.join(format!("{label}_contract.v1.json"));
    let mut contract = read_json(&source_contract)?;
    mutate_contract(&mut contract);
    write_json(&contract_path, &contract)?;

    let mut manifest = read_json(&manifest_path(root))?;
    manifest["contract_paths"] = serde_json::json!([contract_path]);
    manifest["expected_positive_contracts"] = serde_json::json!([label]);
    let manifest_path = out_dir.join(format!("{label}_manifest.v1.json"));
    write_json(&manifest_path, &manifest)?;
    Ok(manifest_path)
}

fn assert_failure_signature(report: &Value, expected_code: &str) {
    let found = report["errors"]
        .as_array()
        .expect("errors must be array")
        .iter()
        .any(|error| {
            error["failure_signature"]
                .as_str()
                .is_some_and(|actual| actual.eq(expected_code))
        });
    assert!(
        found,
        "expected failure signature {expected_code}, report={report:#}"
    );
}

#[test]
fn manifest_names_positive_completion_contracts_and_policy() -> TestResult {
    let root = repo_root();
    let manifest = read_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("completion_contract_rch_proof_manifest_lint.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-waaa6.4"));

    let contracts: Vec<&str> = manifest["contract_paths"]
        .as_array()
        .ok_or("contract_paths must be array")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(contracts.len(), 5);
    for required in [
        "string_memory_hotpaths_wave05_completion_contract.v1.json",
        "string_memory_hotpaths_wave06_completion_contract.v1.json",
        "string_memory_hotpaths_wave10_completion_contract.v1.json",
        "string_memory_hotpaths_wave11_completion_contract.v1.json",
        "unistd_process_filesystem_wave05_completion_contract.v1.json",
    ] {
        assert!(
            contracts.iter().any(|path| path.ends_with(required)),
            "manifest missing positive contract {required}"
        );
    }
    let launcher_only_contracts: Vec<&str> = manifest["launcher_only_contract_paths"]
        .as_array()
        .ok_or("launcher_only_contract_paths must be array")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(launcher_only_contracts.len(), 2);
    for required in [
        "raw_syscall_veneer_completion_contract.v1.json",
        "math_core_diff_completion_contract.v1.json",
    ] {
        assert!(
            launcher_only_contracts
                .iter()
                .any(|path| path.ends_with(required)),
            "manifest missing launcher-only contract {required}"
        );
    }
    assert_eq!(
        manifest["policy"]["required_remote_env"].as_str(),
        Some("RCH_FORCE_REMOTE=true")
    );
    assert_eq!(
        manifest["policy"]["fail_closed_remote_env"].as_str(),
        Some("RCH_REQUIRE_REMOTE=1")
    );
    assert!(manifest["policy"]["legacy_remote_env_markers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|marker| marker.as_str() == Some("RCH_FORCE_REMOTE=true")));
    let fail_closed_contracts: Vec<&str> = manifest["fail_closed_contract_paths"]
        .as_array()
        .ok_or("fail_closed_contract_paths must be array")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(fail_closed_contracts.len(), 1);
    assert!(
        fail_closed_contracts
            .iter()
            .any(|path| path.ends_with("completion_contract_rch_proof_manifest_lint.v1.json")),
        "manifest must lint its own current fail-closed RCH proof commands"
    );
    assert!(manifest["policy"]["forbidden_proof_markers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|marker| marker.as_str() == Some("[RCH] local")));
    assert!(manifest["policy"]["forbidden_proof_markers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|marker| marker.as_str() == Some("remote execution failed")));
    for required_code in [
        "missing_rch_exec_env",
        "shell_wrapped_cargo",
        "missing_fail_closed_remote_env",
        "legacy_remote_env_marker",
    ] {
        assert!(
            manifest["required_failure_signatures"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry
                    .as_str()
                    .is_some_and(|actual| actual.eq(required_code))),
            "manifest must require failure signature {required_code}"
        );
    }
    Ok(())
}

#[test]
fn checker_accepts_positive_contracts_and_emits_structured_artifacts() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "positive")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("completion_contract_rch_proof_manifest_lint.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["contract_count"].as_u64(), Some(8));
    assert_eq!(report["summary"]["strict_contract_count"].as_u64(), Some(5));
    assert_eq!(
        report["summary"]["launcher_only_contract_count"].as_u64(),
        Some(2)
    );
    assert_eq!(
        report["summary"]["fail_closed_contract_count"].as_u64(),
        Some(1)
    );
    assert_eq!(report["summary"]["failed_contracts"].as_u64(), Some(0));
    assert!(
        report["summary"]["cargo_command_count"]
            .as_u64()
            .unwrap_or(0)
            >= 34
    );

    let log = std::fs::read_to_string(
        out_dir.join("completion_contract_rch_proof_manifest_lint.log.jsonl"),
    )?;
    let rows: Vec<Value> = log
        .lines()
        .map(serde_json::from_str)
        .collect::<Result<_, _>>()?;
    assert_eq!(rows.len(), 8);
    for (index, line) in log.lines().enumerate() {
        validate_log_line(line, index + 1).map_err(|errors| {
            std::io::Error::other(format!("structured log validation failed: {errors:?}"))
        })?;
    }
    Ok(())
}

#[test]
fn checker_rejects_bare_cargo_command() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "bare_cargo", |contract| {
        let mut changed = false;
        mutate_strings(contract, &mut |text| {
            if !changed && text.contains("cargo test") {
                *text = text
                    .split(" cargo ")
                    .nth(1)
                    .map(|tail| format!("cargo {tail}"))
                    .unwrap_or_else(|| "cargo test -p frankenlibc-harness --test string_memory_hotpaths_wave10_completion_contract_test".to_string());
                changed = true;
            }
        });
    })?;
    let out_dir = unique_out_dir(&root, "bare_cargo_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "bare_cargo_command");
    Ok(())
}

#[test]
fn checker_rejects_missing_remote_env() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "missing_remote_env", |contract| {
        let mut changed = false;
        mutate_strings(contract, &mut |text| {
            if !changed && text.contains("cargo check") {
                *text = text.replace("RCH_FORCE_REMOTE=true ", "");
                changed = true;
            }
        });
    })?;
    let out_dir = unique_out_dir(&root, "missing_remote_env_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "missing_remote_env");
    Ok(())
}

#[test]
fn checker_rejects_legacy_remote_marker_for_fail_closed_contracts() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "legacy_fail_closed_remote")?;
    let mutated = out_dir.join("legacy_fail_closed_manifest.v1.json");
    let mut manifest = read_json(&manifest_path(&root))?;
    manifest["fail_closed_contract_paths"] =
        serde_json::json!([mutated.to_string_lossy().to_string()]);

    let mut changed = false;
    let commands = manifest["required_validation_commands"]
        .as_array_mut()
        .ok_or("required_validation_commands must be array")?;
    for command in commands {
        let Some(text) = command.as_str() else {
            continue;
        };
        if !changed && text.contains("RCH_REQUIRE_REMOTE=1") && text.contains("cargo test") {
            *command = Value::String(text.replace("RCH_REQUIRE_REMOTE=1", "RCH_FORCE_REMOTE=true"));
            changed = true;
        }
    }
    assert!(
        changed,
        "test must mutate a fail-closed cargo proof command"
    );
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "legacy_remote_env_marker");
    Ok(())
}

#[test]
fn checker_rejects_missing_rch_exec() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "missing_rch_exec", |contract| {
        let mut changed = false;
        mutate_strings(contract, &mut |text| {
            if !changed && text.contains("cargo clippy") {
                *text = text.replace("rch exec -- ", "");
                changed = true;
            }
        });
    })?;
    let out_dir = unique_out_dir(&root, "missing_rch_exec_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "missing_rch_exec");
    Ok(())
}

#[test]
fn checker_rejects_non_env_rch_exec_payload() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "non_env_payload", |contract| {
        let mut changed = false;
        mutate_strings(contract, &mut |text| {
            if !changed && text.contains("cargo test") {
                *text = move_target_dir_before_rch_exec(text);
                changed = true;
            }
        });
    })?;
    let out_dir = unique_out_dir(&root, "non_env_payload_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "missing_rch_exec_env");
    Ok(())
}

#[test]
fn checker_rejects_shell_wrapped_cargo_payload() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "shell_wrapped_payload", |contract| {
        let mut changed = false;
        mutate_strings(contract, &mut |text| {
            if !changed && text.contains("cargo clippy") {
                *text = "RCH_FORCE_REMOTE=true RCH_VISIBILITY=summary rch exec -- bash -c 'cargo clippy -p frankenlibc-harness --test completion_contract_rch_proof_manifest_lint_test -- -D warnings'".to_string();
                changed = true;
            }
        });
    })?;
    let out_dir = unique_out_dir(&root, "shell_wrapped_payload_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "shell_wrapped_cargo");
    Ok(())
}

#[test]
fn checker_rejects_missing_isolated_target_dir() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "missing_target_dir", |contract| {
        let mut changed = false;
        mutate_strings(contract, &mut |text| {
            if !changed && text.contains("cargo test") {
                *text = strip_target_dir(text);
                changed = true;
            }
        });
    })?;
    let out_dir = unique_out_dir(&root, "missing_target_dir_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "missing_isolated_target_dir");
    Ok(())
}

#[test]
fn checker_rejects_missing_targeted_clippy_lane() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "missing_clippy_lane", |contract| {
        retain_strings(contract, &|text| !text.contains("cargo clippy"));
    })?;
    let out_dir = unique_out_dir(&root, "missing_clippy_lane_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "missing_targeted_clippy_lane");
    Ok(())
}

#[test]
fn checker_rejects_local_fallback_marker() -> TestResult {
    let root = repo_root();
    let manifest = write_variant_manifest(&root, "local_fallback_marker", |contract| {
        contract["proof_note"] = serde_json::json!("remote execution failed");
    })?;
    let out_dir = unique_out_dir(&root, "local_fallback_marker_out")?;
    let output = run_checker(&root, &manifest, &out_dir)?;
    assert!(!output.status.success(), "{}", output_text(&output));
    let report =
        read_json(&out_dir.join("completion_contract_rch_proof_manifest_lint.report.json"))?;
    assert_failure_signature(&report, "local_fallback_marker");
    Ok(())
}
