//! Meta-gate: paired CLI-contract meta-gate tests stay source-level and do
//! not import `std::process::Command` (bd-ctfp9). These files validate the
//! manifest/test corpus shape; they should not spawn subprocesses while
//! doing so.

use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn line_without_string_literals(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    let mut in_string = false;

    while let Some(ch) = chars.next() {
        if in_string {
            if ch == '\\' {
                let _ = chars.next();
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            continue;
        }
        out.push(ch);
    }

    out
}

fn imports_process_command(body: &str) -> usize {
    body.lines()
        .filter(|line| {
            let line = line.trim_start();
            if line.starts_with("//") {
                return false;
            }
            let line = line_without_string_literals(line);
            line == "use std::process::Command;"
                || line.starts_with("use std::process::{Command")
                || line.contains("use std::process::{") && line.contains("Command")
                || line.contains("std::process::Command::")
        })
        .count()
}

#[test]
fn paired_gate_meta_tests_do_not_import_process_command() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.starts_with("cli_contract_paired_gate_") || !stem.ends_with("_test.rs") {
            continue;
        }
        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let count = imports_process_command(&body);
        if count > 0 {
            violations.push(format!(
                "{stem}: imports or references std::process::Command {count} time(s)"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 15,
        "expected at least 15 paired CLI-contract meta-gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired-gate subprocess import violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn process_command_import_detector_handles_canonical_forms() {
    assert_eq!(imports_process_command("use std::process::Command;"), 1);
    assert_eq!(
        imports_process_command("use std::process::{Command, Output};"),
        1
    );
    assert_eq!(
        imports_process_command("std::process::Command::new(bin)"),
        1
    );
    assert_eq!(
        imports_process_command("let run = std::process::Command::new(bin);"),
        1
    );
    assert_eq!(imports_process_command("// use std::process::Command;"), 0);
    assert_eq!(
        imports_process_command("assert!(body.contains(\"std::process::Command::new\"));"),
        0
    );
    assert_eq!(imports_process_command("use std::path::PathBuf;"), 0);
    assert_eq!(
        imports_process_command("src.contains(\"Command::Variant\")"),
        0
    );
}
