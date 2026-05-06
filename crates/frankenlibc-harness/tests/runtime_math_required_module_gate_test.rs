use serde_json::{Value, json};
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct GateRun {
    output: Output,
    out_dir: PathBuf,
}

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| test_error("workspace root"))?
        .to_path_buf())
}

fn unique_dir(root: &Path, prefix: &str) -> TestResult<PathBuf> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| test_error(format!("system time before UNIX_EPOCH: {err}")))?
        .as_nanos();
    let dir = root
        .join("target")
        .join("test-runtime-math-required-module-gate")
        .join(format!("{prefix}-{stamp}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn load_json(path: &Path) -> TestResult<Value> {
    let content = std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn write_json(path: &Path, value: &Value) -> TestResult {
    let content = serde_json::to_string_pretty(value)
        .map_err(|err| test_error(format!("{} serialization failed: {err}", path.display())))?;
    std::fs::write(path, format!("{content}\n"))
        .map_err(|err| test_error(format!("{} write failed: {err}", path.display())))
}

fn object_mut<'a>(
    value: &'a mut Value,
    key: &str,
    context: &str,
) -> TestResult<&'a mut serde_json::Map<String, Value>> {
    value
        .get_mut(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_object_mut()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an object")))
}

fn array_mut<'a>(value: &'a mut Value, key: &str, context: &str) -> TestResult<&'a mut Vec<Value>> {
    value
        .get_mut(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_array_mut()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an array")))
}

fn string_field<'a>(value: &'a Value, key: &str, context: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_str()
        .ok_or_else(|| test_error(format!("{context}.{key} must be a string")))
}

fn same_text(left: &str, right: &str) -> bool {
    left.chars().eq(right.chars())
}

fn u64_field(value: &Value, key: &str, context: &str) -> TestResult<u64> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_u64()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an unsigned integer")))
}

fn run_gate(root: &Path, label: &str, envs: &[(&str, &Path)]) -> TestResult<GateRun> {
    let out_dir = unique_dir(root, label)?;
    let mut command = Command::new(root.join("scripts/check_runtime_math_required_module_gate.sh"));
    command
        .arg("--validate-only")
        .current_dir(root)
        .env(
            "RUNTIME_MATH_REQUIRED_MODULE_GATE_REPORT",
            out_dir.join("report.json"),
        )
        .env(
            "RUNTIME_MATH_REQUIRED_MODULE_GATE_LOG",
            out_dir.join("log.jsonl"),
        );
    for (name, value) in envs {
        command.env(name, value);
    }
    Ok(GateRun {
        output: command.output()?,
        out_dir,
    })
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn report(run: &GateRun) -> TestResult<Value> {
    load_json(&run.out_dir.join("report.json"))
}

fn ensure_failure(run: &GateRun, signature: &str) -> TestResult {
    ensure(
        !run.output.status.success(),
        format!(
            "mutated gate should fail for {signature}\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;
    ensure(
        stderr(&run.output).contains(&format!("FAIL[{signature}]")),
        format!(
            "stderr should expose failure signature {signature}\nstderr:\n{}",
            stderr(&run.output)
        ),
    )?;
    let report = report(run)?;
    ensure(
        same_text(
            string_field(&report, "failure_signature", "report")?,
            signature,
        ),
        format!("report.failure_signature should be {signature}"),
    )
}

#[test]
fn required_module_gate_passes_current_contract() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_runtime_math_required_module_gate.sh");
    ensure(script.exists(), "required-module gate script must exist")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        ensure(
            perms.mode() & 0o111 != 0,
            "required-module gate script must be executable",
        )?;
    }

    let run = run_gate(&root, "current", &[])?;
    ensure(
        run.output.status.success(),
        format!(
            "required-module gate should pass\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;

    let report = report(&run)?;
    ensure(
        same_text(string_field(&report, "outcome", "report")?, "pass"),
        "report.outcome should be pass",
    )?;
    ensure(
        same_text(
            string_field(&report, "failure_signature", "report")?,
            "none",
        ),
        "report.failure_signature should be none",
    )?;
    let summary = report
        .get("summary")
        .ok_or_else(|| test_error("report.summary is missing"))?;
    ensure(
        u64_field(summary, "runtime_math_pub_mod_count", "report.summary")? == 69,
        "report summary should cover 69 runtime_math pub mod rows",
    )?;
    ensure(
        u64_field(summary, "docs_runtime_math_linked_rows", "report.summary")? == 12,
        "report summary should classify 12 AGENTS rows as runtime_math-linked",
    )?;
    ensure(
        u64_field(summary, "docs_stale_external_rows", "report.summary")? == 2,
        "report summary should classify 2 AGENTS rows as stale standalone modules",
    )
}

#[test]
fn gate_fails_when_runtime_math_pub_mod_is_missing() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_dir(&root, "missing-module")?;
    let source = root.join("crates/frankenlibc-membrane/src/runtime_math/mod.rs");
    let original = std::fs::read_to_string(&source)?;
    let mutated = original.replace("pub mod risk;\n", "");
    ensure(
        mutated != original,
        "mutation should remove the risk pub mod declaration",
    )?;
    let mod_path = dir.join("mod.rs");
    std::fs::write(&mod_path, mutated)?;

    let run = run_gate(
        &root,
        "missing-module-run",
        &[(
            "RUNTIME_MATH_REQUIRED_MODULE_GATE_MOD_RS",
            mod_path.as_path(),
        )],
    )?;
    ensure_failure(&run, "missing_module")
}

#[test]
fn gate_fails_when_linkage_row_is_missing() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_dir(&root, "unlinked-module")?;
    let mut linkage = load_json(&root.join("tests/runtime_math/runtime_math_linkage.v1.json"))?;
    let modules = object_mut(&mut linkage, "modules", "linkage")?;
    ensure(
        modules.remove("risk").is_some(),
        "mutation should remove the risk linkage row",
    )?;
    let linkage_path = dir.join("runtime_math_linkage.mutated.json");
    write_json(&linkage_path, &linkage)?;

    let run = run_gate(
        &root,
        "unlinked-module-run",
        &[(
            "RUNTIME_MATH_REQUIRED_MODULE_GATE_LINKAGE",
            linkage_path.as_path(),
        )],
    )?;
    ensure_failure(&run, "unlinked_module")
}

#[test]
fn gate_fails_when_research_module_leaks_into_production_manifest() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_dir(&root, "retired-module-leakage")?;
    let mut manifest =
        load_json(&root.join("tests/runtime_math/production_kernel_manifest.v1.json"))?;
    let production_modules = array_mut(&mut manifest, "production_modules", "manifest")?;
    ensure(
        !production_modules
            .iter()
            .any(|module| module.as_str() == Some("admm_budget")),
        "admm_budget should start outside production_modules",
    )?;
    production_modules.push(json!("admm_budget"));
    let manifest_path = dir.join("production_kernel_manifest.mutated.json");
    write_json(&manifest_path, &manifest)?;

    let run = run_gate(
        &root,
        "retired-module-leakage-run",
        &[(
            "RUNTIME_MATH_REQUIRED_MODULE_GATE_MANIFEST",
            manifest_path.as_path(),
        )],
    )?;
    ensure_failure(&run, "retired_module_leakage")
}
