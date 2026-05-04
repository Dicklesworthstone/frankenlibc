//! Regression test for destructive cleanup in shell check gates (bd-awo68).
//!
//! Check gates are safe to run only if their cleanup paths preserve artifacts
//! and respect the repo rule against destructive filesystem or Git cleanup.

use std::error::Error;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn is_check_gate(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("check_") && name.ends_with(".sh")
}

fn non_comment_text(line: &str) -> &str {
    line.split_once('#')
        .map_or(line, |(before_comment, _)| before_comment)
        .trim()
}

enum ViolationKind<'a> {
    ForbiddenPattern(&'a str),
    TrapBasedDeletion,
}

struct Violation<'a> {
    script_index: usize,
    line: usize,
    kind: ViolationKind<'a>,
}

#[test]
fn check_gate_scripts_do_not_install_destructive_cleanup() -> TestResult {
    let root = workspace_root();
    let script_dir = root.join("scripts");
    let forbidden = [
        "rm -rf",
        "rm -fr",
        "git reset --hard",
        "git clean -fd",
        "git clean -df",
        "git clean -xfd",
        "git clean -xdf",
    ];

    let mut violations = Vec::new();
    let mut scripts = Vec::new();
    for entry in std::fs::read_dir(&script_dir)
        .map_err(|_| test_error("scripts directory should be readable"))?
    {
        let path = entry?.path();
        if !is_check_gate(&path) {
            continue;
        }
        let script_index = scripts.len();
        scripts.push(
            path.strip_prefix(&root)
                .unwrap_or(path.as_path())
                .to_path_buf(),
        );
        let content = std::fs::read_to_string(&path)
            .map_err(|_| test_error("check gate script should be readable"))?;
        for (idx, line) in content.lines().enumerate() {
            let code = non_comment_text(line);
            if code.is_empty() {
                continue;
            }
            for pattern in forbidden {
                if code.contains(pattern) {
                    violations.push(Violation {
                        script_index,
                        line: idx + 1,
                        kind: ViolationKind::ForbiddenPattern(pattern),
                    });
                }
            }
            if code.starts_with("trap ") && code.contains(" rm ") {
                violations.push(Violation {
                    script_index,
                    line: idx + 1,
                    kind: ViolationKind::TrapBasedDeletion,
                });
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        let mut message = String::from("destructive check-gate cleanup found:\n");
        for violation in violations {
            let rel = scripts
                .get(violation.script_index)
                .map(PathBuf::as_path)
                .unwrap_or_else(|| Path::new("<unknown>"))
                .display();
            match violation.kind {
                ViolationKind::ForbiddenPattern(pattern) => {
                    let _ = writeln!(message, "{rel}:{} contains `{}`", violation.line, pattern);
                }
                ViolationKind::TrapBasedDeletion => {
                    let _ = writeln!(
                        message,
                        "{rel}:{} installs trap-based file deletion",
                        violation.line
                    );
                }
            }
        }
        Err(test_error(message))
    }
}
