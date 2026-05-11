use serde_json::{Value, json};
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

fn contract_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/fuzz_gap_abi_modules_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_fuzz_gap_abi_modules_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_out_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let out = root.join("target/conformance").join(format!(
        "fuzz_gap_abi_modules_completion_contract_{label}_{}_{}",
        std::process::id(),
        stamp
    ));
    std::fs::create_dir_all(&out)?;
    Ok(out)
}

fn run_checker(root: &Path, contract: &Path, out_dir: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(checker_path(root))
        .current_dir(root)
        .env("FRANKENLIBC_FUZZ_GAP_COMPLETION_CONTRACT", contract)
        .env("FRANKENLIBC_FUZZ_GAP_COMPLETION_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_FUZZ_GAP_COMPLETION_REPORT",
            out_dir.join("fuzz_gap_abi_modules_completion_contract.report.json"),
        )
        .env(
            "FRANKENLIBC_FUZZ_GAP_COMPLETION_LOG",
            out_dir.join("fuzz_gap_abi_modules_completion_contract.log.jsonl"),
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

fn string_array(value: &Value) -> TestResult<Vec<String>> {
    Ok(value
        .as_array()
        .ok_or("expected array")?
        .iter()
        .map(|item| item.as_str().ok_or("expected string").map(str::to_owned))
        .collect::<Result<Vec<_>, _>>()?)
}

fn read_jsonl(path: &Path) -> TestResult<Vec<Value>> {
    std::fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| Ok(serde_json::from_str::<Value>(line)?))
        .collect()
}

#[test]
fn manifest_binds_required_fuzz_gap_modules() -> TestResult {
    let root = repo_root();
    let manifest = load_json(&contract_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("fuzz_gap_abi_modules_completion_contract.v1")
    );
    assert_eq!(manifest["original_bead"].as_str(), Some("bd-dvr22"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-dvr22.1")
    );

    let modules = manifest["required_module_fuzz_coverage"]
        .as_array()
        .ok_or("module coverage array")?;
    let module_ids: Vec<_> = modules
        .iter()
        .filter_map(|module| module["module_id"].as_str())
        .collect();
    for module_id in [
        "signal",
        "socket",
        "fortify",
        "setjmp",
        "mmap",
        "dlfcn",
        "pthread",
        "c11threads",
    ] {
        assert!(
            module_ids.contains(&module_id),
            "missing module {module_id}"
        );
    }

    let mut target_names = Vec::new();
    for module in modules {
        for target in module["targets"].as_array().ok_or("targets array")? {
            let name = target["name"].as_str().ok_or("target name")?;
            let path = target["path"].as_str().ok_or("target path")?;
            assert!(root.join(path).is_file(), "target source missing: {path}");
            target_names.push(name.to_owned());
        }
    }
    target_names.sort();
    assert_eq!(
        target_names,
        [
            "fuzz_c11threads",
            "fuzz_dlfcn",
            "fuzz_fortify",
            "fuzz_mmap",
            "fuzz_pthread_cond",
            "fuzz_pthread_keys",
            "fuzz_pthread_mutex",
            "fuzz_pthread_rwlock",
            "fuzz_pthread_sync_misc",
            "fuzz_setjmp",
            "fuzz_signal",
            "fuzz_socket",
        ]
    );

    let binding_ids: Vec<_> = manifest["missing_item_bindings"]
        .as_array()
        .ok_or("missing_item_bindings array")?
        .iter()
        .filter_map(|binding| binding["id"].as_str())
        .collect();
    assert!(binding_ids.contains(&"tests.fuzz.primary"));
    assert!(binding_ids.contains(&"telemetry.primary"));

    Ok(())
}

#[test]
fn checker_emits_fuzz_gap_completion_report_and_jsonl() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "pass")?;
    let output = run_checker(&root, &contract_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", output_text(&output));

    let report = load_json(&out_dir.join("fuzz_gap_abi_modules_completion_contract.report.json"))?;
    assert_eq!(
        report["schema_version"].as_str(),
        Some("fuzz_gap_abi_modules_completion_contract.report.v1")
    );
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["summary"]["module_count"].as_u64(), Some(8));
    assert_eq!(report["summary"]["target_count"].as_u64(), Some(12));
    assert_eq!(report["summary"]["cargo_bound_targets"].as_u64(), Some(12));
    assert_eq!(
        report["summary"]["architecture_bound_targets"].as_u64(),
        Some(12)
    );
    assert_eq!(report["summary"]["corpus_bound_targets"].as_u64(), Some(12));
    assert_eq!(
        report["summary"]["dictionary_bound_targets"].as_u64(),
        Some(12)
    );

    let events = string_array(&report["events"])?;
    for event in [
        "fuzz_gap_abi_modules_target_inventory",
        "fuzz_gap_abi_modules_source_anchors",
        "fuzz_gap_abi_modules_corpus_dictionary",
        "fuzz_gap_abi_modules_telemetry_summary",
        "fuzz_gap_abi_modules_completion_contract_pass",
    ] {
        assert!(events.iter().any(|value| value == event), "missing {event}");
    }

    let rows = read_jsonl(&out_dir.join("fuzz_gap_abi_modules_completion_contract.log.jsonl"))?;
    assert_eq!(rows.len(), 5);
    for row in rows {
        for field in [
            "timestamp",
            "trace_id",
            "event",
            "bead_id",
            "original_bead",
            "completion_debt_bead",
            "status",
            "outcome",
            "source_commit",
            "schema_version",
            "module_count",
            "target_count",
            "artifact_refs",
            "target_refs",
            "telemetry_refs",
            "failure_signature",
        ] {
            assert!(!row[field].is_null(), "log row missing {field}: {row}");
        }
        assert_eq!(row["bead_id"].as_str(), Some("bd-dvr22.1"));
        assert_eq!(row["module_count"].as_u64(), Some(8));
        assert_eq!(row["target_count"].as_u64(), Some(12));
        assert_eq!(row["status"].as_str(), Some("pass"));
        assert_eq!(row["failure_signature"].as_str(), Some("none"));
    }

    Ok(())
}

#[test]
fn checker_rejects_missing_required_fuzz_target() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_target")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_module_fuzz_coverage"][0]["targets"]
        .as_array_mut()
        .ok_or("targets array")?
        .push(json!({
            "name": "fuzz_missing_abi_surface",
            "path": "crates/frankenlibc-fuzz/fuzz_targets/fuzz_missing_abi_surface.rs",
            "required_text": ["missing"]
        }));
    let mutated = out_dir.join("missing_target_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing target:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("fuzz_gap_abi_modules_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("fuzz_missing_abi_surface")),
        "report should name missing fuzz target: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_missing_source_anchor() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "missing_anchor")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["required_module_fuzz_coverage"][0]["targets"][0]["required_text"]
        .as_array_mut()
        .ok_or("required_text array")?
        .push(json!("missing-signal-fuzz-anchor-for-regression-test"));
    let mutated = out_dir.join("missing_anchor_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing source anchor:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("fuzz_gap_abi_modules_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("missing-signal-fuzz-anchor-for-regression-test")),
        "report should name missing source anchor: {report}"
    );

    Ok(())
}

#[test]
fn checker_rejects_unimplemented_telemetry_event() -> TestResult {
    let root = repo_root();
    let out_dir = unique_out_dir(&root, "bad_telemetry")?;
    let mut manifest = load_json(&contract_path(&root))?;
    manifest["telemetry_contract"]["required_events"]
        .as_array_mut()
        .ok_or("required_events array")?
        .push(json!("fuzz_gap_abi_modules_unimplemented_event"));
    let mutated = out_dir.join("bad_telemetry_contract.json");
    write_json(&mutated, &manifest)?;

    let output = run_checker(&root, &mutated, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject unsupported telemetry event:\n{}",
        output_text(&output)
    );
    let report = load_json(&out_dir.join("fuzz_gap_abi_modules_completion_contract.report.json"))?;
    assert_eq!(report["status"].as_str(), Some("fail"));
    assert!(
        report["errors"]
            .as_array()
            .ok_or("errors array")?
            .iter()
            .any(|error| error
                .as_str()
                .unwrap_or("")
                .contains("fuzz_gap_abi_modules_unimplemented_event")),
        "report should name unsupported event: {report}"
    );

    Ok(())
}
