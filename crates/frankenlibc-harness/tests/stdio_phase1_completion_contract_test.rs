use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    message.into().into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("cannot resolve workspace root"))?
        .to_path_buf())
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/stdio_phase1_completion_contract.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_stdio_phase1_completion_contract.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    std::fs::write(path, serde_json::to_string_pretty(value)? + "\n")?;
    Ok(())
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before epoch: {err}")))?
        .as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "stdio-phase1-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_STDIO_PHASE1_CONTRACT", manifest)
        .env("FRANKENLIBC_STDIO_PHASE1_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_STDIO_PHASE1_REPORT",
            out_dir.join("report.json"),
        )
        .env("FRANKENLIBC_STDIO_PHASE1_LOG", out_dir.join("events.jsonl"))
        .output()
        .map_err(|err| test_error(format!("failed to run checker: {err}")))
}

fn checker_output(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn string_set(value: &Value) -> TestResult<BTreeSet<String>> {
    value
        .as_array()
        .ok_or_else(|| test_error("value should be array"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("array item should be string"))
        })
        .collect::<Result<BTreeSet<_>, _>>()
}

fn read_log_events(path: &Path) -> TestResult<BTreeSet<String>> {
    std::fs::read_to_string(path)?
        .lines()
        .map(|line| {
            let value: Value = serde_json::from_str(line)?;
            value["event"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| test_error("log row missing event"))
        })
        .collect()
}

#[test]
fn manifest_binds_stdio_phase1_completion_debt() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("stdio_phase1_completion_contract.v1")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-2vv.3.1"));
    assert_eq!(
        manifest["completion_debt_bead"].as_str(),
        Some("bd-2vv.3.1.1")
    );

    assert_eq!(
        string_set(&manifest["completion_debt_evidence"]["missing_items_closed"])?,
        BTreeSet::from([
            "tests.unit.primary".to_string(),
            "tests.e2e.primary".to_string(),
            "telemetry.primary".to_string(),
        ])
    );
    assert_eq!(
        string_set(&manifest["target_symbols"])?,
        BTreeSet::from([
            "fopen".to_string(),
            "fclose".to_string(),
            "fflush".to_string(),
            "fread".to_string(),
            "fwrite".to_string(),
            "fgetc".to_string(),
            "fputc".to_string(),
            "fgets".to_string(),
            "fputs".to_string(),
            "ungetc".to_string(),
            "fileno".to_string(),
            "setvbuf".to_string(),
            "setbuf".to_string(),
        ])
    );
    assert_eq!(
        manifest["unit_primary"]["required_test_refs"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );
    assert_eq!(
        manifest["telemetry_primary"]["required_log_fields"]
            .as_array()
            .map(Vec::len),
        Some(9)
    );
    Ok(())
}

#[test]
fn checker_accepts_contract_and_emits_report_log() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "pass")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(output.status.success(), "{}", checker_output(&output));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("PASS stdio phase1 completion contract"));

    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["bead"].as_str(), Some("bd-2vv.3.1.1"));
    assert_eq!(report["source_bead"].as_str(), Some("bd-2vv.3.1"));
    assert_eq!(report["target_symbols"].as_array().map(Vec::len), Some(13));
    assert_eq!(report["unit_bindings"].as_array().map(Vec::len), Some(9));
    assert_eq!(
        report["telemetry_events"]["completion_events"]
            .as_array()
            .map(Vec::len),
        Some(5)
    );

    let events = read_log_events(&out_dir.join("events.jsonl"))?;
    for event in [
        "stdio_phase1_completion.source_artifacts",
        "stdio_phase1_completion.unit_bindings",
        "stdio_phase1_completion.e2e_binding",
        "stdio_phase1_completion.telemetry_contract",
        "stdio_phase1_completion.completion_contract_validated",
    ] {
        assert!(events.contains(event), "missing event {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_missing_unit_ref() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-unit-ref")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["unit_primary"]["required_test_refs"][0]["name"] =
        json!("missing_stdio_phase1_unit_test");
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing unit ref"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unit refs mismatch") || stderr.contains("missing Rust test ref"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_e2e_symbol_binding() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-e2e-symbol")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["target_symbols"]
        .as_array_mut()
        .ok_or_else(|| test_error("target symbols should be array"))?
        .retain(|symbol| symbol.as_str() != Some("setbuf"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject target-symbol drift"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("target_symbols drift"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_missing_telemetry_field() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "missing-telemetry")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["telemetry_primary"]["required_log_fields"]
        .as_array_mut()
        .ok_or_else(|| test_error("required log fields should be array"))?
        .retain(|field| field.as_str() != Some("latency_ns"));
    let bad_manifest = out_dir.join("bad_contract.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker should reject missing telemetry field"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required log fields drift"),
        "{}",
        checker_output(&output)
    );
    Ok(())
}
