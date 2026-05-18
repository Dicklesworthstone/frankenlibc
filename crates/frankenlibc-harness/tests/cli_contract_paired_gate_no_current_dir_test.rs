//! Meta-gate: paired CLI-contract meta-gate tests stay source-level and do
//! not mutate or override the process working directory (bd-92g0t). These
//! gates validate manifest/test corpus shape; working-directory mutation
//! belongs in explicitly classified integration or E2E lanes.

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

fn code_without_comments_and_literals(body: &str) -> String {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        String,
        Char,
    }

    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    let mut state = State::Code;
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        match state {
            State::Code => match ch {
                '/' if chars.peek() == Some(&'/') => {
                    let _ = chars.next();
                    state = State::LineComment;
                }
                '/' if chars.peek() == Some(&'*') => {
                    let _ = chars.next();
                    state = State::BlockComment;
                }
                '"' => {
                    state = State::String;
                    escaped = false;
                }
                '\'' => {
                    state = State::Char;
                    escaped = false;
                }
                _ => out.push(ch),
            },
            State::LineComment => {
                if ch == '\n' {
                    out.push('\n');
                    state = State::Code;
                }
            }
            State::BlockComment => {
                if ch == '*' && chars.peek() == Some(&'/') {
                    let _ = chars.next();
                    state = State::Code;
                } else if ch == '\n' {
                    out.push('\n');
                }
            }
            State::String => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    state = State::Code;
                }
            }
            State::Char => {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '\'' {
                    state = State::Code;
                }
            }
        }
    }

    out
}

fn contains_working_dir_mutation(body: &str) -> bool {
    let code = code_without_comments_and_literals(body);
    let full_path = ["std::env::", "set", "_current_dir"].concat();
    let module_path = ["env::", "set", "_current_dir"].concat();
    let bare_call = ["set", "_current_dir("].concat();
    let command_current_dir = [".", "current", "_dir("].concat();

    code.contains(&full_path)
        || code.contains(&module_path)
        || code.contains(&bare_call)
        || code.contains(&command_current_dir)
}

#[test]
fn no_paired_gate_meta_test_mutates_working_directory() -> TestResult {
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
        if contains_working_dir_mutation(&body) {
            violations.push(format!(
                "{stem}: contains process working-directory mutation or child cwd override"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 25,
        "expected at least 25 paired CLI-contract meta-gate tests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} paired-gate current-dir violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn current_dir_detector_handles_canonical_forms() {
    let std_call = ["std::env::", "set", "_current_dir(&root);"].concat();
    let env_call = ["env::", "set", "_current_dir(&root);"].concat();
    let bare_call = ["set", "_current_dir(&root);"].concat();
    let command_call = ["Command::new(bin).", "current", "_dir(&root).output()?;"].concat();
    let comment_call = ["// Command::new(bin).", "current", "_dir(&root)"].concat();
    let block_comment_call = [
        "/* std::env::",
        "set",
        "_current_dir(&root); */ let ok = true;",
    ]
    .concat();
    let literal_call = [
        "assert!(body.contains(\"std::env::",
        "set",
        "_current_dir\"));",
    ]
    .concat();

    assert!(contains_working_dir_mutation(&std_call));
    assert!(contains_working_dir_mutation(&env_call));
    assert!(contains_working_dir_mutation(&bare_call));
    assert!(contains_working_dir_mutation(&command_call));
    assert!(!contains_working_dir_mutation(&comment_call));
    assert!(!contains_working_dir_mutation(&block_comment_call));
    assert!(!contains_working_dir_mutation(&literal_call));
    assert!(!contains_working_dir_mutation(
        "let current_directory = workspace_root()?;"
    ));
}
