//! bd-gq1kz7.15: NSS unsupported overlay exhaustiveness checker test.

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
fn nss_overlay_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/check_nss_overlay.sh");
    assert!(script.exists(), "check_nss_overlay.sh should exist");
    Ok(())
}

#[test]
fn nss_overlay_emits_valid_json() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_nss_overlay.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("nss overlay output should be valid JSON: {e}\nOutput: {stdout}"))?;

    assert_eq!(
        json.get("gate").and_then(Value::as_str),
        Some("bd-gq1kz7.15"),
        "nss overlay must identify as bd-gq1kz7.15"
    );

    Ok(())
}

#[test]
fn nss_overlay_documents_unsupported_backends() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_nss_overlay.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    let policy = json
        .get("nss_overlay_policy")
        .ok_or("missing nss_overlay_policy")?;

    // Must document files and dns as supported
    assert_eq!(
        policy.get("files_backend").and_then(Value::as_str),
        Some("supported"),
        "files backend must be supported"
    );
    assert_eq!(
        policy.get("dns_backend").and_then(Value::as_str),
        Some("supported"),
        "dns backend must be supported"
    );

    // Must list unsupported backends
    let unsupported = policy
        .get("unsupported_backends")
        .and_then(Value::as_array)
        .ok_or("missing unsupported_backends")?;

    assert!(!unsupported.is_empty(), "must list unsupported backends");

    // Must have ldap in unsupported list
    let has_ldap = unsupported
        .iter()
        .any(|v| v.as_str() == Some("ldap"));
    assert!(has_ldap, "ldap must be listed as unsupported");

    Ok(())
}

#[test]
fn nss_overlay_passes_with_all_functions_implemented() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_nss_overlay.sh");

    let output = Command::new(&script).current_dir(&root).output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)?;

    assert_eq!(
        json.get("status").and_then(Value::as_str),
        Some("pass"),
        "nss overlay should pass (all functions implemented)"
    );

    let summary = json.get("summary").ok_or("missing summary")?;
    let missing = summary
        .get("missing")
        .and_then(Value::as_u64)
        .unwrap_or(999);

    assert_eq!(missing, 0, "should have 0 missing NSS functions");

    Ok(())
}
