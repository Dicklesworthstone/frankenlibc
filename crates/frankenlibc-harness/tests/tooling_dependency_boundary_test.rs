use serde_json::Value;
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
        .join("test-tooling-dependency-boundary")
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

fn u64_field(value: &Value, key: &str, context: &str) -> TestResult<u64> {
    value
        .get(key)
        .ok_or_else(|| test_error(format!("{context}.{key} is missing")))?
        .as_u64()
        .ok_or_else(|| test_error(format!("{context}.{key} must be an unsigned integer")))
}

fn same_text(left: &str, right: &str) -> bool {
    left.chars().eq(right.chars())
}

fn run_gate(root: &Path, label: &str, envs: &[(&str, &Path)]) -> TestResult<GateRun> {
    let out_dir = unique_dir(root, label)?;
    let mut command = Command::new(root.join("scripts/check_tooling_dependency_boundary.sh"));
    command
        .arg("--validate-only")
        .current_dir(root)
        .env("TOOLING_DEP_BOUNDARY_REPORT", out_dir.join("report.json"))
        .env("TOOLING_DEP_BOUNDARY_LOG", out_dir.join("log.jsonl"));
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
fn tooling_dependency_boundary_gate_passes_current_contract() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_tooling_dependency_boundary.sh");
    ensure(script.exists(), "tooling boundary gate script must exist")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script)?.permissions();
        ensure(
            perms.mode() & 0o111 != 0,
            "tooling boundary gate script must be executable",
        )?;
    }

    let run = run_gate(&root, "current", &[])?;
    ensure(
        run.output.status.success(),
        format!(
            "tooling boundary gate should pass\nstdout:\n{}\nstderr:\n{}",
            stdout(&run.output),
            stderr(&run.output)
        ),
    )?;

    let report = report(&run)?;
    ensure(
        same_text(string_field(&report, "outcome", "report")?, "pass"),
        "report.outcome should be pass",
    )?;
    let summary = report
        .get("summary")
        .ok_or_else(|| test_error("report.summary is missing"))?;
    ensure(
        u64_field(
            summary,
            "runtime_dependency_leakage_count",
            "report.summary",
        )? == 0,
        "runtime dependency leakage count should stay zero",
    )?;
    ensure(
        u64_field(summary, "feature_path_proof_count", "report.summary")? == 7,
        "feature path proof count should match the contract",
    )
}

#[test]
fn gate_fails_when_tooling_dependency_leaks_into_runtime_crate() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_dir(&root, "runtime-leakage")?;
    let source = root.join("crates/frankenlibc-abi/Cargo.toml");
    let original = std::fs::read_to_string(&source)?;
    let marker = "\n[dev-dependencies]\n";
    ensure(
        original.contains(marker),
        "ABI Cargo.toml should contain a dev-dependencies section",
    )?;
    let mutated = original.replace(
        marker,
        "\nasupersync-conformance = { workspace = true }\n\n[dev-dependencies]\n",
    );
    let manifest_path = dir.join("frankenlibc-abi.leaked.Cargo.toml");
    std::fs::write(&manifest_path, mutated)?;

    let run = run_gate(
        &root,
        "runtime-leakage-run",
        &[("TOOLING_DEP_BOUNDARY_ABI_CARGO", manifest_path.as_path())],
    )?;
    ensure_failure(&run, "runtime_dependency_leakage")
}

#[test]
fn gate_fails_when_feature_path_proof_is_missing() -> TestResult {
    let root = workspace_root()?;
    let dir = unique_dir(&root, "missing-feature-proof")?;
    let source = root.join("tests/conformance/tooling_dependency_boundary.v1.json");
    let mut contract = load_json(&source)?;
    let proofs = array_mut(&mut contract, "feature_path_proofs", "contract")?;
    ensure(
        !proofs.is_empty(),
        "contract should have at least one feature path proof",
    )?;
    proofs.remove(0);
    let contract_path = dir.join("tooling_dependency_boundary.mutated.json");
    write_json(&contract_path, &contract)?;

    let run = run_gate(
        &root,
        "missing-feature-proof-run",
        &[("TOOLING_DEP_BOUNDARY_CONTRACT", contract_path.as_path())],
    )?;
    ensure_failure(&run, "feature_path_proof_missing")
}
