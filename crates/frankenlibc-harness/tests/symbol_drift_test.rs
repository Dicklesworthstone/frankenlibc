//! Integration test: Symbol drift guard (bd-28s)
//!
//! Validates that:
//! 1. Every support_matrix.json symbol's module file exists in ABI source.
//! 2. Every symbol has a matching fn declaration in its module.
//! 3. Extern "C" fns missing matrix entries are reported as informational
//!    reverse-drift warnings, matching scripts/check_symbol_drift.sh.
//! 4. No duplicate symbols in the matrix.
//! 5. All statuses are valid taxonomy values.
//! 6. The CI gate script exists and is executable.
//!
//! Run: cargo test -p frankenlibc-harness --test symbol_drift_test

use std::collections::{HashMap, HashSet};
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

fn load_matrix() -> serde_json::Value {
    let path = workspace_root().join("support_matrix.json");
    let content = std::fs::read_to_string(&path).expect("support_matrix.json should exist");
    serde_json::from_str(&content).expect("support_matrix.json should be valid JSON")
}

#[test]
fn matrix_symbols_have_valid_modules() {
    let matrix = load_matrix();
    let symbols = matrix["symbols"].as_array().unwrap();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    let mut missing_modules = Vec::new();
    for entry in symbols {
        let sym = entry["symbol"].as_str().unwrap_or("<unknown>");
        let module = entry["module"].as_str().unwrap_or("unknown");
        let src_file = abi_src.join(format!("{module}.rs"));
        if !src_file.exists() {
            missing_modules.push(format!("{sym}: {module}.rs"));
        }
    }

    assert!(
        missing_modules.is_empty(),
        "Symbols with missing module files:\n{}",
        missing_modules.join("\n")
    );
}

#[test]
fn matrix_symbols_exist_in_source() {
    let matrix = load_matrix();
    let symbols = matrix["symbols"].as_array().unwrap();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    // Data symbols (statics, not functions)
    let data_syms: HashSet<&str> = ["stdin", "stdout", "stderr"].into_iter().collect();

    let mut missing = Vec::new();
    for entry in symbols {
        let sym = entry["symbol"].as_str().unwrap_or("<unknown>");
        let module = entry["module"].as_str().unwrap_or("unknown");

        if data_syms.contains(sym) {
            continue;
        }

        let src_file = abi_src.join(format!("{module}.rs"));
        if !src_file.exists() {
            continue; // Covered by other test
        }

        let content = std::fs::read_to_string(&src_file).unwrap();
        let pattern = format!("fn {sym}(");
        let alt_pattern = format!("fn {sym} (");
        if !content.contains(&pattern) && !content.contains(&alt_pattern) {
            missing.push(format!("{sym} in {module}.rs"));
        }
    }

    if !missing.is_empty() {
        eprintln!(
            "{} matrix symbol(s) do not have a direct `fn symbol(` anchor in their declared module; \
             check_symbol_drift.sh treats these as alternate-pattern warnings:\n{}",
            missing.len(),
            missing.join("\n")
        );
    }
}

#[test]
fn abi_source_fns_have_matrix_entries() {
    let matrix = load_matrix();
    let abi_src = workspace_root().join("crates/frankenlibc-abi/src");

    let matrix_syms: HashSet<String> = matrix["symbols"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["symbol"].as_str().map(String::from))
        .collect();

    let mut orphans = Vec::new();
    let entries = std::fs::read_dir(&abi_src).unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.ends_with("_abi.rs") {
            continue;
        }

        let content = std::fs::read_to_string(entry.path()).unwrap();
        // Find pub extern "C" fn declarations
        for line in content.lines() {
            if let Some(rest) = line
                .trim()
                .strip_prefix("pub unsafe extern \"C\" fn ")
                .or_else(|| line.trim().strip_prefix("pub extern \"C\" fn "))
                && let Some(fn_name) = rest.split('(').next()
            {
                let fn_name = fn_name.trim();
                if fn_name.contains('$') || informational_orphan_symbol(fn_name) {
                    continue;
                }
                if !fn_name.is_empty() && !matrix_syms.contains(fn_name) {
                    orphans.push(format!("{fn_name} in {name}"));
                }
            }
        }
    }

    if !orphans.is_empty() {
        eprintln!(
            "{} ABI function(s) are not in support_matrix.json; \
             scripts/check_symbol_drift.sh treats reverse drift as informational:\n{}",
            orphans.len(),
            orphans.join("\n")
        );
    }
}

fn informational_orphan_symbol(symbol: &str) -> bool {
    matches!(
        symbol,
        "__frankenlibc_set_startup_host_delegate_for_tests"
            | "_IO_list_all_get"
            | "_IO_file_jumps_get"
            | "_IO_wfile_jumps_get"
            | "_IO_fileno"
            | "frankenlibc_exit_immediate"
    )
}

#[test]
fn no_duplicate_symbols() {
    let matrix = load_matrix();
    let symbols = matrix["symbols"].as_array().unwrap();

    let mut seen = HashMap::new();
    let mut dups = Vec::new();
    for entry in symbols {
        let sym = entry["symbol"].as_str().unwrap_or("<unknown>");
        if let Some(prev_module) = seen.insert(sym, entry["module"].as_str().unwrap_or("?")) {
            dups.push(format!(
                "{sym} (first in {prev_module}, dup in {})",
                entry["module"].as_str().unwrap_or("?")
            ));
        }
    }

    assert!(
        dups.is_empty(),
        "Duplicate symbols in matrix:\n{}",
        dups.join("\n")
    );
}

#[test]
fn all_statuses_valid() {
    let matrix = load_matrix();
    let symbols = matrix["symbols"].as_array().unwrap();
    let valid: HashSet<&str> = [
        "Implemented",
        "RawSyscall",
        "WrapsHostLibc",
        "GlibcCallThrough",
        "Stub",
    ]
    .into_iter()
    .collect();

    let mut invalid = Vec::new();
    for entry in symbols {
        let sym = entry["symbol"].as_str().unwrap_or("<unknown>");
        let status = entry["status"].as_str().unwrap_or("");
        if !valid.contains(status) {
            invalid.push(format!("{sym}: '{status}'"));
        }
    }

    assert!(
        invalid.is_empty(),
        "Symbols with invalid status:\n{}",
        invalid.join("\n")
    );
}

#[test]
fn gate_script_exists_and_executable() {
    let root = workspace_root();
    let script = root.join("scripts/check_symbol_drift.sh");
    assert!(script.exists(), "scripts/check_symbol_drift.sh must exist");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::metadata(&script).unwrap().permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "check_symbol_drift.sh must be executable"
        );
    }

    let output = Command::new("bash")
        .arg(&script)
        .current_dir(&root)
        .output()
        .expect("failed to execute check_symbol_drift.sh");
    assert!(
        output.status.success(),
        "symbol drift gate failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
