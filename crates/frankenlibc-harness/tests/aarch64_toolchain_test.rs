//! bd-gq1kz7.11: Aarch64 runtime artifact toolchain preflight test.

use serde_json::Value;
use std::error::Error;
use std::path::Path;
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<std::path::PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("crate manifest should have crates parent")?
        .parent()
        .ok_or("crates directory should have workspace parent")?
        .to_path_buf())
}

#[test]
fn toolchain_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/check_aarch64_toolchain.sh");
    assert!(script.exists(), "check_aarch64_toolchain.sh should exist");
    Ok(())
}

#[test]
fn toolchain_emits_valid_json() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_aarch64_toolchain.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("toolchain output should be valid JSON: {e}\nOutput: {stdout}"))?;

    assert_eq!(
        json.get("gate").and_then(Value::as_str),
        Some("bd-gq1kz7.11"),
        "toolchain must identify as bd-gq1kz7.11"
    );

    Ok(())
}

#[test]
fn toolchain_has_prerequisites_section() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_aarch64_toolchain.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    let prereqs = json
        .get("prerequisites")
        .ok_or("missing prerequisites section")?;

    // Must check all required prerequisites
    assert!(prereqs.get("gcc").is_some(), "must check gcc");
    assert!(prereqs.get("linker").is_some(), "must check linker");
    assert!(
        prereqs.get("rust_target").is_some(),
        "must check rust_target"
    );
    assert!(prereqs.get("sysroot").is_some(), "must check sysroot");
    assert!(
        prereqs.get("qemu_runner").is_some(),
        "must check qemu_runner"
    );

    Ok(())
}

#[test]
fn toolchain_provides_install_hints() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_aarch64_toolchain.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    let prereqs = json
        .get("prerequisites")
        .ok_or("missing prerequisites section")?;

    // Each unavailable prereq should have an install_hint
    for (name, prereq) in prereqs.as_object().ok_or("prereqs must be object")? {
        let available = prereq
            .get("available")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        if !available {
            assert!(
                prereq.get("install_hint").is_some(),
                "{name} should have install_hint when unavailable"
            );
        }
    }

    Ok(())
}

#[test]
fn toolchain_identifies_blocker() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_aarch64_toolchain.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    assert_eq!(
        json.get("blocker_for").and_then(Value::as_str),
        Some("bd-38x82.2"),
        "must identify bd-38x82.2 as the blocked bead"
    );

    Ok(())
}
