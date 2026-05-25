//! bd-gq1kz7.9: Host-backed surface burn-down dashboard test.

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
fn burndown_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/host_backed_burndown.sh");
    assert!(script.exists(), "host_backed_burndown.sh should exist");
    Ok(())
}

#[test]
fn burndown_emits_valid_json() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/host_backed_burndown.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("burndown output should be valid JSON: {e}\nOutput: {stdout}"))?;

    assert_eq!(
        json.get("status").and_then(Value::as_str),
        Some("ok"),
        "burndown should return ok status"
    );

    assert!(
        json.get("summary").is_some(),
        "burndown must have summary field"
    );

    assert!(
        json.get("by_module").is_some(),
        "burndown must have by_module field"
    );

    assert_eq!(
        json.get("gate").and_then(Value::as_str),
        Some("bd-gq1kz7.9"),
        "burndown must identify as bd-gq1kz7.9"
    );

    Ok(())
}

#[test]
fn burndown_summary_has_required_fields() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/host_backed_burndown.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    let summary = json.get("summary").ok_or("missing summary")?;

    assert!(
        summary.get("total_symbols").is_some(),
        "summary must have total_symbols"
    );
    assert!(
        summary.get("wraps_host_libc").is_some(),
        "summary must have wraps_host_libc"
    );
    assert!(
        summary.get("standalone_capable").is_some(),
        "summary must have standalone_capable"
    );
    assert!(
        summary.get("standalone_percent").is_some(),
        "summary must have standalone_percent"
    );

    // Verify reasonable values
    let total = summary
        .get("total_symbols")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let standalone = summary
        .get("standalone_capable")
        .and_then(Value::as_u64)
        .unwrap_or(0);

    assert!(total > 4000, "should have >4000 total symbols");
    assert!(
        standalone > 3900,
        "should have >3900 standalone-capable symbols"
    );
    assert!(standalone <= total, "standalone <= total");

    Ok(())
}

#[test]
fn burndown_modules_are_grouped() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/host_backed_burndown.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    let modules = json
        .get("by_module")
        .and_then(Value::as_array)
        .ok_or("by_module must be array")?;

    // Each module entry must have required fields
    for entry in modules {
        assert!(
            entry.get("module").is_some(),
            "module entry must have module name"
        );
        assert!(entry.get("count").is_some(), "module entry must have count");
        assert!(
            entry.get("symbols").is_some(),
            "module entry must have symbols list"
        );
        assert!(
            entry.get("risk").is_some(),
            "module entry must have risk level"
        );
    }

    Ok(())
}
