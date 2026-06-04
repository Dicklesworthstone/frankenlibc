use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn manifest_path(root: &Path) -> PathBuf {
    root.join("tests/conformance/abi_loader_reentrancy_lock_census.v1.json")
}

fn checker_path(root: &Path) -> PathBuf {
    root.join("scripts/check_abi_loader_reentrancy_lock_census.sh")
}

fn load_json(path: &Path) -> TestResult<Value> {
    let body = fs::read_to_string(path).map_err(|err| format!("read {path:?}: {err}"))?;
    serde_json::from_str(&body).map_err(|err| format!("parse {path:?}: {err}"))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    fs::write(
        path,
        serde_json::to_string_pretty(value).map_err(|err| format!("serialize json: {err}"))? + "\n",
    )
    .map_err(|err| format!("write {path:?}: {err}"))
}

fn unique_output_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before epoch: {err}"))?
        .as_nanos();
    let dir = root
        .join("target/conformance")
        .join(format!("{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&dir).map_err(|err| format!("create {dir:?}: {err}"))?;
    Ok(dir)
}

fn run_checker(root: &Path, manifest: &Path, out_dir: &Path) -> TestResult<Output> {
    Command::new(checker_path(root))
        .env("FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_CONTRACT", manifest)
        .env("FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_OUT_DIR", out_dir)
        .env(
            "FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "FRANKENLIBC_ABI_REENTRANCY_LOCK_CENSUS_LOG",
            out_dir.join("events.jsonl"),
        )
        .output()
        .map_err(|err| format!("run checker: {err}"))
}

fn expect_failure_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn manifest_declares_fail_closed_reentrancy_census_policy() -> TestResult {
    let root = workspace_root()?;
    let manifest = load_json(&manifest_path(&root))?;
    assert_eq!(
        manifest["manifest_id"].as_str(),
        Some("abi-loader-reentrancy-lock-census")
    );
    assert_eq!(manifest["bead"].as_str(), Some("bd-esbow"));
    assert_eq!(
        manifest["policy"]["fail_on_unclassified_surface"].as_bool(),
        Some(true)
    );
    assert_eq!(
        manifest["source_commit_freshness"]["require_no_scan_root_changes_since_source_commit"]
            .as_bool(),
        Some(true)
    );

    let surfaces = manifest["classified_surfaces"]
        .as_array()
        .ok_or_else(|| String::from("classified_surfaces must be array"))?;
    assert!(
        surfaces.len() >= 30,
        "expected broad ABI surface census; found {}",
        surfaces.len()
    );
    assert!(surfaces.iter().any(|entry| {
        entry["path"].as_str() == Some("crates/frankenlibc-abi/src/pthread_abi.rs")
            && entry["counts"]["lazy_lock_static"].as_u64() == Some(10)
    }));
    assert!(surfaces.iter().any(|entry| {
        entry["path"].as_str() == Some("crates/frankenlibc-abi/src/unistd_abi.rs")
            && entry["counts"]["thread_local_macro"].as_u64() == Some(24)
    }));
    Ok(())
}

#[test]
fn checker_accepts_current_census_and_emits_telemetry() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "abi-reentrancy-census")?;
    let output = run_checker(&root, &manifest_path(&root), &out_dir)?;
    assert!(
        output.status.success(),
        "checker failed\n{}",
        expect_failure_text(&output)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("abi_loader_reentrancy_lock_census: PASS"));
    let report = load_json(&out_dir.join("report.json"))?;
    assert_eq!(report["status"].as_str(), Some("pass"));
    assert_eq!(report["classified_file_count"].as_u64(), Some(37));
    assert_eq!(
        report["actual_surface_totals"]["thread_local_macro"].as_u64(),
        Some(79)
    );

    let log = fs::read_to_string(out_dir.join("events.jsonl"))
        .map_err(|err| format!("read telemetry log: {err}"))?;
    for event in [
        "abi_reentrancy_census_source_commit",
        "abi_reentrancy_census_scan",
        "abi_reentrancy_census_classification",
        "abi_reentrancy_census_summary",
    ] {
        assert!(log.contains(event), "telemetry log missing {event}");
    }
    Ok(())
}

#[test]
fn checker_rejects_unclassified_new_surface() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "abi-reentrancy-unclassified")?;
    let fixture_dir = out_dir.join("fixture_src");
    fs::create_dir_all(&fixture_dir).map_err(|err| format!("create fixture dir: {err}"))?;
    let fixture = fixture_dir.join("new_abi_surface.rs");
    fs::write(
        &fixture,
        "static NEW_LOCK: std::sync::OnceLock<usize> = std::sync::OnceLock::new();\n",
    )
    .map_err(|err| format!("write fixture: {err}"))?;

    let mut manifest = load_json(&manifest_path(&root))?;
    let fixture_rel = fixture
        .strip_prefix(&root)
        .map_err(|err| err.to_string())?
        .to_string_lossy()
        .to_string();
    manifest["scan_roots"]
        .as_array_mut()
        .ok_or_else(|| String::from("scan_roots must be array"))?
        .push(json!(fixture_rel));
    let bad_manifest = out_dir.join("unclassified.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker accepted unclassified surface"
    );
    assert!(
        expect_failure_text(&output).contains("unclassified_surface"),
        "missing unclassified_surface failure:\n{}",
        expect_failure_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_count_drift() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "abi-reentrancy-count-drift")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    let surfaces = manifest["classified_surfaces"]
        .as_array_mut()
        .ok_or_else(|| String::from("classified_surfaces must be array"))?;
    let pthread = surfaces
        .iter_mut()
        .find(|entry| entry["path"].as_str() == Some("crates/frankenlibc-abi/src/pthread_abi.rs"))
        .ok_or_else(|| String::from("pthread_abi census entry missing"))?;
    pthread["counts"]["lazy_lock_static"] = json!(999);
    let bad_manifest = out_dir.join("count_drift.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(!output.status.success(), "checker accepted count drift");
    assert!(
        expect_failure_text(&output).contains("count_drift"),
        "missing count_drift failure:\n{}",
        expect_failure_text(&output)
    );
    Ok(())
}

#[test]
fn checker_rejects_invalid_source_commit() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_output_dir(&root, "abi-reentrancy-bad-source-commit")?;
    let mut manifest = load_json(&manifest_path(&root))?;
    manifest["source_commit"] = json!("0000000000000000000000000000000000000000");
    let bad_manifest = out_dir.join("bad_source_commit.json");
    write_json(&bad_manifest, &manifest)?;

    let output = run_checker(&root, &bad_manifest, &out_dir)?;
    assert!(
        !output.status.success(),
        "checker accepted invalid source commit"
    );
    assert!(
        expect_failure_text(&output).contains("source_commit"),
        "missing source_commit failure:\n{}",
        expect_failure_text(&output)
    );
    Ok(())
}
