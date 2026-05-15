use std::error::Error;
use std::path::PathBuf;
use std::process::Command;

type TestResult = Result<(), Box<dyn Error>>;

fn repo_root() -> Result<PathBuf, Box<dyn Error>> {
    Ok(PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?)
}

#[test]
fn separation_logic_annotations_gate_passes_in_strict_mode() -> TestResult {
    let root = repo_root()?;
    let script = root.join("scripts/check_separation_logic_annotations.sh");
    assert!(script.exists(), "missing script: {}", script.display());

    let output = Command::new("bash")
        .arg(&script)
        .arg("--strict")
        .current_dir(&root)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "annotation gate failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    assert!(stdout.contains("\"targets\": 5"), "unexpected target count");
    assert!(
        stdout.contains("\"coverage_pct\""),
        "expected structured coverage field in JSON output"
    );
    for alias in [
        "validate_pointer",
        "generation_check",
        "check_bounds",
        "quarantine_enter",
        "repair_apply",
    ] {
        assert!(
            stdout.contains(alias),
            "missing alias {} in annotation coverage output",
            alias
        );
    }
    Ok(())
}
