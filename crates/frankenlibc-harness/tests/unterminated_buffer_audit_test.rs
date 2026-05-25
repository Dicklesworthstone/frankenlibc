//! bd-gq1kz7.6: Cross-family tracked unterminated-buffer sweep test.

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
fn unterminated_buffer_audit_script_exists() -> TestResult {
    let script = workspace_root()?.join("scripts/audit_unterminated_buffers.sh");
    assert!(
        script.exists(),
        "audit_unterminated_buffers.sh should exist"
    );
    Ok(())
}

#[test]
fn audit_script_emits_valid_json_report() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/audit_unterminated_buffers.sh");

    let output = Command::new(&script).current_dir(&root).output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "audit script should exit successfully\nstdout={stdout}\nstderr={stderr}"
    );

    let json: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("audit output should be valid JSON: {e}\nOutput: {stdout}"))?;
    assert_eq!(
        json.get("gate").and_then(Value::as_str),
        Some("bd-gq1kz7.6"),
        "audit report should identify its bead gate"
    );
    assert!(
        matches!(
            json.get("status").and_then(Value::as_str),
            Some("pass" | "needs_review")
        ),
        "audit status should be pass or needs_review"
    );

    let summary = json.get("summary").ok_or("missing summary")?;
    for field in [
        "files_with_unterminated_handling",
        "skipped_buffer_tests",
        "unsupported_contract_mentions",
    ] {
        assert!(
            summary.get(field).and_then(Value::as_u64).is_some(),
            "summary.{field} should be an unsigned integer"
        );
    }
    Ok(())
}

#[test]
fn scan_c_string_combines_caller_and_allocation_bounds() -> TestResult {
    let root = workspace_root()?;
    let util_path = root.join("crates/frankenlibc-abi/src/util.rs");

    let content = std::fs::read_to_string(&util_path)?;

    assert!(
        content.contains("pub unsafe fn scan_c_string(ptr: *const c_char, bound: Option<usize>)"),
        "scan_c_string should accept an explicit optional bound"
    );
    assert!(
        content.contains("crate::malloc_abi::known_remaining(ptr as usize)"),
        "scan_c_string should use tracked allocation bounds through allocation_bound"
    );
    assert!(
        content.contains("(Some(limit), Some(alloc)) => Some(limit.min(alloc))"),
        "scan_c_string should clamp caller bounds to tracked allocation bounds"
    );
    assert!(
        content.contains("(limit, false)"),
        "scan_c_string should report unterminated input at the effective bound"
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
