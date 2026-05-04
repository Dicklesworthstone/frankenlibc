//! Integration test: runtime_math module inventory checker (bd-bp8fl.7.8).
//!
//! The CI checker must understand the current AGENTS.md runtime_math subsection
//! format and fail with useful drift diagnostics when docs and code diverge.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(message.into()))
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest)
        .parent()
        .ok_or_else(|| test_error("crate manifest should have a crates/ parent"))?
        .parent()
        .ok_or_else(|| test_error("crates directory should have a workspace parent"))?
        .to_path_buf();
    Ok(root)
}

fn unique_temp_dir(prefix: &str) -> TestResult<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system clock should be after Unix epoch: {err}")))?
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn run_checker(agents: &Path, mod_rs: &Path, lib_rs: &Path) -> TestResult<Output> {
    let root = workspace_root()?;
    Ok(Command::new(root.join("scripts/check_module_inventory.sh"))
        .current_dir(root)
        .env("FRANKENLIBC_MODULE_INVENTORY_AGENTS", agents)
        .env("FRANKENLIBC_MODULE_INVENTORY_MOD", mod_rs)
        .env("FRANKENLIBC_MODULE_INVENTORY_LIB", lib_rs)
        .output()?)
}

fn write_fixture(
    dir: &Path,
    agents: &str,
    mod_rs: &str,
    lib_rs: &str,
) -> TestResult<(PathBuf, PathBuf, PathBuf)> {
    let agents_path = dir.join("AGENTS.md");
    let mod_path = dir.join("mod.rs");
    let lib_path = dir.join("lib.rs");
    std::fs::write(&agents_path, agents)?;
    std::fs::write(&mod_path, mod_rs)?;
    std::fs::write(&lib_path, lib_rs)?;
    Ok((agents_path, mod_path, lib_path))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn current_module_inventory_checker_passes() -> TestResult {
    let root = workspace_root()?;
    let output = run_checker(
        &root.join("AGENTS.md"),
        &root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs"),
        &root.join("crates/frankenlibc-membrane/src/lib.rs"),
    )?;
    assert!(
        output.status.success(),
        "module inventory checker failed\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    assert!(stdout(&output).contains("OK: AGENTS.md"));
    Ok(())
}

#[test]
fn checker_accepts_current_runtime_math_subsection_format() -> TestResult {
    let temp = unique_temp_dir("frankenlibc-module-inventory-current")?;
    let (agents, mod_rs, lib_rs) = write_fixture(
        &temp,
        r#"
### frankenlibc-membrane - Safety Substrate

**Runtime math control plane (`runtime_math/`):**
- `risk.rs` - Risk envelope
- `bandit.rs` - Router

**Standalone membrane modules:**
- `hji_reachability.rs` - Top-level live controller

### frankenlibc-core - Safe Implementations

Mandatory live modules in `frankenlibc-membrane/src/runtime_math/`:

| Module | Purpose |
|--------|---------|
| `risk.rs` | Required runtime module |
| `hji_reachability.rs` | Required top-level live controller |
"#,
        "pub mod bandit;\npub mod risk;\n",
        "pub mod hji_reachability;\n",
    )?;
    let output = run_checker(&agents, &mod_rs, &lib_rs)?;
    assert!(
        output.status.success(),
        "current subsection fixture should pass\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    Ok(())
}

#[test]
fn checker_reports_drift_with_diagnostics() -> TestResult {
    let temp = unique_temp_dir("frankenlibc-module-inventory-drift")?;
    let (agents, mod_rs, lib_rs) = write_fixture(
        &temp,
        r#"
### frankenlibc-membrane - Safety Substrate

**Runtime math control plane (`runtime_math/`):**
- `risk.rs` - Risk envelope
- `missing_module.rs` - Missing docs-only module

### frankenlibc-core - Safe Implementations
"#,
        "pub mod risk;\n",
        "",
    )?;
    let output = run_checker(&agents, &mod_rs, &lib_rs)?;
    assert!(
        !output.status.success(),
        "drift fixture should fail\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let out = stdout(&output);
    assert!(out.contains("DRIFT: In AGENTS.md but NOT in runtime_math/mod.rs"));
    assert!(out.contains("missing_module"));
    assert!(out.contains("DRIFT DETECTED"));
    Ok(())
}
