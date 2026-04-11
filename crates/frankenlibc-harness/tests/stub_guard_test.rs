//! Integration test: stub guard (bd-1h4)
//!
//! Validates that:
//! 1. No todo!/unimplemented!/panic! appears in ABI crate source.
//! 2. Stub census JSON is present, parseable, and has zero reachable stubs.
//! 3. Support matrix is present and all Implemented/RawSyscall symbols
//!    do not have reachable todo!() on their code paths.
//!
//! Run: cargo test -p frankenlibc-harness --test stub_guard_test

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn abi_source_mentions_export(content: &str, symbol: &str) -> bool {
    let fn_pattern = format!("extern \"C\" fn {symbol}");
    let export_name_pattern = format!("export_name = \"{symbol}\"");
    let static_pattern = format!("pub static {symbol}");
    let static_mut_pattern = format!("pub static mut {symbol}");
    let macro_arg_fn_pattern = format!("!({symbol}(");
    let macro_arg_value_pattern = format!("!({symbol},");

    content.contains(&fn_pattern)
        || content.contains(&export_name_pattern)
        || content.contains(&static_pattern)
        || content.contains(&static_mut_pattern)
        || content.contains(&macro_arg_fn_pattern)
        || content.contains(&macro_arg_value_pattern)
}

fn supported_via_host_visible_symbol(symbol: &str) -> bool {
    matches!(
        symbol,
        "_IO_2_1_stdin_" | "_IO_2_1_stdout_" | "_IO_2_1_stderr_"
    )
}

#[test]
fn no_todo_in_abi_crate() {
    let root = workspace_root();
    let abi_src = root.join("crates/frankenlibc-abi/src");

    let output = Command::new("grep")
        .args([
            "-rn",
            r"todo!\|unimplemented!\|panic!",
            abi_src.to_str().unwrap(),
        ])
        .output()
        .expect("grep should execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Filter out test-related lines and #[should_panic]
    let violations: Vec<&str> = stdout
        .lines()
        .filter(|l| !l.contains("#[should_panic"))
        .filter(|l| !l.contains("// test"))
        .filter(|l| !l.contains("#[cfg(test)"))
        .collect();

    assert!(
        violations.is_empty(),
        "ABI crate must not contain todo!/unimplemented!/panic!:\n{}",
        violations.join("\n")
    );
}

#[test]
fn census_exists_and_no_reachable_stubs() {
    let root = workspace_root();
    let census_path = root.join("tests/conformance/stub_census.json");

    // Regenerate census if missing
    if !census_path.exists() {
        let status = Command::new("bash")
            .arg(root.join("scripts/stub_census.sh"))
            .status()
            .expect("stub_census.sh should execute");
        assert!(status.success(), "stub_census.sh should succeed");
    }

    let content =
        std::fs::read_to_string(&census_path).expect("stub_census.json should be readable");
    let census: serde_json::Value =
        serde_json::from_str(&content).expect("stub_census.json should be valid JSON");

    let reachable = census["summary"]["reachable_stubs"]
        .as_u64()
        .expect("reachable_stubs should be a number");

    assert_eq!(
        reachable, 0,
        "No todo!/unimplemented! should be reachable from ABI exports.\n\
         Found {} reachable stub(s). Run scripts/stub_census.sh for details.",
        reachable
    );
}

#[test]
fn census_is_deterministic() {
    let root = workspace_root();
    let census_path = root.join("tests/conformance/stub_census.json");

    // Run census twice and compare (excluding timestamp)
    let run_census = || {
        Command::new("bash")
            .arg(root.join("scripts/stub_census.sh"))
            .output()
            .expect("stub_census.sh should execute")
    };

    let _ = run_census();
    let content1 = std::fs::read_to_string(&census_path).unwrap();
    let mut v1: serde_json::Value = serde_json::from_str(&content1).unwrap();

    let _ = run_census();
    let content2 = std::fs::read_to_string(&census_path).unwrap();
    let mut v2: serde_json::Value = serde_json::from_str(&content2).unwrap();

    // Remove timestamp for comparison
    v1.as_object_mut().unwrap().remove("generated_utc");
    v2.as_object_mut().unwrap().remove("generated_utc");

    assert_eq!(
        v1, v2,
        "Stub census must produce identical output on repeated runs"
    );
}

#[test]
fn support_matrix_exists_and_valid() {
    let root = workspace_root();
    let matrix_path = root.join("support_matrix.json");

    assert!(
        matrix_path.exists(),
        "support_matrix.json must exist at workspace root"
    );

    let content = std::fs::read_to_string(&matrix_path).unwrap();
    let matrix: serde_json::Value =
        serde_json::from_str(&content).expect("support_matrix.json should be valid JSON");

    let symbols = matrix["symbols"]
        .as_array()
        .expect("symbols should be an array");

    assert!(
        !symbols.is_empty(),
        "support matrix should contain at least one symbol"
    );

    // Verify each symbol has required fields
    for sym in symbols {
        let name = sym["symbol"].as_str().unwrap_or("<missing>");
        assert!(
            sym["status"].is_string(),
            "symbol '{}' missing 'status' field",
            name
        );
        assert!(
            sym["module"].is_string(),
            "symbol '{}' missing 'module' field",
            name
        );

        let status = sym["status"].as_str().unwrap();
        assert!(
            [
                "Implemented",
                "RawSyscall",
                "WrapsHostLibc",
                "GlibcCallThrough",
                "Stub",
            ]
            .contains(&status),
            "symbol '{}' has invalid status: '{}'",
            name,
            status
        );
    }
}

#[test]
fn implemented_symbols_have_abi_exports() {
    let root = workspace_root();
    let matrix_path = root.join("support_matrix.json");
    let abi_src = root.join("crates/frankenlibc-abi/src");

    let content = std::fs::read_to_string(&matrix_path).unwrap();
    let matrix: serde_json::Value = serde_json::from_str(&content).unwrap();

    // Collect ABI source files once and check symbols against direct exports,
    // exported statics, export_name aliases, and macro-generated wrappers.
    let mut abi_sources = Vec::new();
    for entry in std::fs::read_dir(&abi_src).expect("should read abi src dir") {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        abi_sources.push(std::fs::read_to_string(&path).unwrap());
    }

    let symbols = matrix["symbols"].as_array().unwrap();
    let mut missing = Vec::new();

    for sym in symbols {
        let name = sym["symbol"].as_str().unwrap();
        let status = sym["status"].as_str().unwrap();

        // Only check Implemented and RawSyscall — these must have some ABI
        // export surface in source, which may be a direct function, a global,
        // an export_name alias, or a macro-generated wrapper.
        if matches!(status, "Implemented" | "RawSyscall")
            && !supported_via_host_visible_symbol(name)
            && !abi_sources
                .iter()
                .any(|content| abi_source_mentions_export(content, name))
        {
            missing.push(format!("  {} ({})", name, status));
        }
    }

    assert!(
        missing.is_empty(),
        "Implemented/RawSyscall symbols must have ABI exports:\n{}",
        missing.join("\n")
    );
}
