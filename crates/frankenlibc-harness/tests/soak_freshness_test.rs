//! bd-gq1kz7.14: WS8 soak artifact freshness preflight test.

use std::error::Error;
use std::path::Path;

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
fn soak_freshness_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/check_soak_artifact_freshness.sh");
    assert!(
        script.exists(),
        "check_soak_artifact_freshness.sh should exist"
    );
    Ok(())
}

#[test]
fn soak_freshness_script_is_executable() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let script = workspace_root()?.join("scripts/check_soak_artifact_freshness.sh");
    let perms = std::fs::metadata(&script)?.permissions();
    assert!(perms.mode() & 0o111 != 0, "script should be executable");
    Ok(())
}
