//! Harness coverage for the bd-29r.2 runtime_math snapshot coverage gate.

use std::error::Error;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const ROOT_ASSIGNMENT: &str = r#"REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)""#;
const MOD_RS_ASSIGNMENT: &str =
    r#"MOD_RS="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math/mod.rs""#;
const RT_DIR_ASSIGNMENT: &str =
    r#"RT_DIR="$REPO_ROOT/crates/frankenlibc-membrane/src/runtime_math""#;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

fn workspace_root() -> TestResult<PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("workspace root should exist"))?
        .to_path_buf())
}

fn snapshot_gate_path(root: &Path) -> PathBuf {
    root.join("scripts/check_snapshot_coverage.sh")
}

fn runtime_math_mod_path(root: &Path) -> PathBuf {
    root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs")
}

fn runtime_math_dir(root: &Path) -> PathBuf {
    root.join("crates/frankenlibc-membrane/src/runtime_math")
}

fn read_text(path: &Path) -> TestResult<String> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn write_text(path: &Path, text: &str) -> TestResult {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, text)
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn unique_dir(root: &Path, label: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let dir = root.join("target/conformance").join(format!(
        "runtime-math-snapshot-coverage-{label}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn assert_contains(haystack: &str, needle: &str) {
    assert!(
        haystack.contains(needle),
        "expected text to contain {needle:?}\ntext:\n{haystack}"
    );
}

fn output_text(output: &Output) -> String {
    format!(
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn run_gate(root: &Path, script: &Path) -> TestResult<Output> {
    Ok(Command::new("bash")
        .arg(script)
        .current_dir(root)
        .output()?)
}

fn shell_single_quote(path: &Path) -> String {
    let escaped = path.to_string_lossy().replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn replace_required(text: String, needle: &str, replacement: &str) -> TestResult<String> {
    if !text.contains(needle) {
        return Err(test_error(format!(
            "script should contain assignment marker {needle:?}"
        )));
    }
    Ok(text.replacen(needle, replacement, 1))
}

fn write_patched_gate_script(
    root: &Path,
    out_dir: &Path,
    mod_rs: &Path,
    rt_dir: &Path,
) -> TestResult<PathBuf> {
    let script = read_text(&snapshot_gate_path(root))?;
    let script = replace_required(
        script,
        ROOT_ASSIGNMENT,
        &format!("REPO_ROOT={}", shell_single_quote(root)),
    )?;
    let script = replace_required(
        script,
        MOD_RS_ASSIGNMENT,
        &format!("MOD_RS={}", shell_single_quote(mod_rs)),
    )?;
    let script = replace_required(
        script,
        RT_DIR_ASSIGNMENT,
        &format!("RT_DIR={}", shell_single_quote(rt_dir)),
    )?;

    let patched = out_dir.join("check_snapshot_coverage.sh");
    write_text(&patched, &script)?;
    Ok(patched)
}

fn copy_runtime_math_rs_files(source: &Path, dest: &Path) -> TestResult {
    std::fs::create_dir_all(dest)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            std::fs::copy(&path, dest.join(entry.file_name()))?;
        }
    }
    Ok(())
}

#[test]
fn snapshot_gate_script_pins_runtime_math_contract() -> TestResult {
    let root = workspace_root()?;
    let script = read_text(&snapshot_gate_path(&root))?;

    assert_contains(&script, "RuntimeKernelSnapshot");
    assert_contains(&script, "SNAP_PREFIX");
    assert_contains(&script, "SNAP_EXEMPT");
    assert_contains(&script, "HOT_PATH");
    assert_contains(&script, "pub mod \\K[a-z_]+");
    assert_contains(&script, "#\\[test\\]");
    assert_contains(&script, "NO_SNAPSHOT");
    assert_contains(&script, "NO_TESTS");
    assert_contains(
        &script,
        "OK: All $total runtime_math modules have snapshot coverage and unit tests.",
    );
    assert!(
        !script.contains("cargo "),
        "snapshot coverage gate should remain a local text/artifact check, not a nested cargo runner"
    );

    Ok(())
}

#[test]
fn snapshot_gate_executes_current_repository_without_cargo() -> TestResult {
    let root = workspace_root()?;
    let output = run_gate(&root, &snapshot_gate_path(&root))?;
    assert!(
        output.status.success(),
        "snapshot coverage gate should pass\n{}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "--- Summary ---");
    assert_contains(&stdout, "Total modules:");
    assert_contains(&stdout, "OK: All");
    assert_contains(
        &stdout,
        "runtime_math modules have snapshot coverage and unit tests.",
    );
    Ok(())
}

#[test]
fn snapshot_gate_rejects_missing_snapshot_field() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_dir(&root, "missing-snapshot")?;
    let original_mod = read_text(&runtime_math_mod_path(&root))?;
    let mutated_mod = original_mod
        .lines()
        .filter(|line| !line.contains("sampled_risk_bonus_ppm"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    assert_ne!(
        original_mod, mutated_mod,
        "mutation should remove the sampled_risk snapshot field"
    );

    let mod_rs = out_dir.join("mod.rs");
    write_text(&mod_rs, &mutated_mod)?;
    let script = write_patched_gate_script(&root, &out_dir, &mod_rs, &runtime_math_dir(&root))?;
    let output = run_gate(&root, &script)?;
    assert!(
        !output.status.success(),
        "mutated gate should fail for missing snapshot\n{}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "risk");
    assert_contains(&stdout, "NO_SNAPSHOT");
    assert_contains(&stdout, "COVERAGE GAPS");
    Ok(())
}

#[test]
fn snapshot_gate_rejects_missing_module_tests() -> TestResult {
    let root = workspace_root()?;
    let out_dir = unique_dir(&root, "missing-tests")?;
    let rt_dir = out_dir.join("runtime_math");
    copy_runtime_math_rs_files(&runtime_math_dir(&root), &rt_dir)?;

    let risk_rs = rt_dir.join("risk.rs");
    let original_risk = read_text(&risk_rs)?;
    let mutated_risk = original_risk.replace("#[test]", "#[allow(dead_code)]");
    assert_ne!(
        original_risk, mutated_risk,
        "mutation should remove risk.rs #[test] markers"
    );
    write_text(&risk_rs, &mutated_risk)?;

    let script =
        write_patched_gate_script(&root, &out_dir, &runtime_math_mod_path(&root), &rt_dir)?;
    let output = run_gate(&root, &script)?;
    assert!(
        !output.status.success(),
        "mutated gate should fail for missing tests\n{}",
        output_text(&output)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_contains(&stdout, "risk");
    assert_contains(&stdout, "NO_TEST");
    assert_contains(&stdout, "COVERAGE GAPS");
    Ok(())
}
