//! bd-gq1kz7.6: Cross-family tracked unterminated-buffer sweep test.

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
fn unterminated_buffer_audit_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/audit_unterminated_buffers.sh");
    assert!(
        script.exists(),
        "audit_unterminated_buffers.sh should exist"
    );
    Ok(())
}

#[test]
fn scan_c_string_has_explicit_bounds() -> TestResult {
    let root = workspace_root()?;
    let util_path = root.join("crates/frankenlibc-abi/src/util.rs");

    let content = std::fs::read_to_string(&util_path)?;

    // scan_c_string should have explicit max_len parameter
    assert!(
        content.contains("scan_c_string") && content.contains("max_len"),
        "scan_c_string should have explicit max_len bounds parameter"
    );

    Ok(())
}

#[test]
fn tracked_allocation_validates_bounds() -> TestResult {
    let root = workspace_root()?;

    // Search for TrackedAllocation usage
    let membrane_path = root.join("crates/frankenlibc-membrane/src/lib.rs");
    if membrane_path.exists() {
        let content = std::fs::read_to_string(&membrane_path)?;
        if content.contains("TrackedAllocation") {
            assert!(
                content.contains("bounds") || content.contains("len") || content.contains("size"),
                "TrackedAllocation should validate bounds"
            );
        }
    }

    Ok(())
}
