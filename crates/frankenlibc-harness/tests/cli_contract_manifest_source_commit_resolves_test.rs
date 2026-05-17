//! Meta-gate: every `tests/conformance/*_cli_contract.v1.json` manifest
//! declares a `source_commit` that resolves to a real commit object in this
//! repository (bd-5zmd3), and that the referenced commit is an ancestor of
//! HEAD (bd-yckpc). This closes the gap left by shape-only checks: a lowercase
//! hex string is not enough evidence if the referenced commit is not part of
//! the repository history.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

const REQUIRED_HISTORY_ANCHOR: &str = "e27df0e51f8e1ec83782e882537f9f522918b62d";

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn commit_object_ref(commit: &str) -> String {
    format!("{commit}^{{commit}}")
}

fn git_ref_exists(root: &Path, git_ref: &str) -> TestResult<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("cat-file")
        .arg("-e")
        .arg(git_ref)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("spawn git cat-file for `{git_ref}`: {e}"))?;
    Ok(status.success())
}

fn git_commit_exists(root: &Path, commit: &str) -> TestResult<bool> {
    git_ref_exists(root, &commit_object_ref(commit))
}

fn git_commit_is_ancestor(root: &Path, ancestor: &str, descendant: &str) -> TestResult<bool> {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("merge-base")
        .arg("--is-ancestor")
        .arg(ancestor)
        .arg(descendant)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| {
            format!("spawn git merge-base --is-ancestor `{ancestor}` `{descendant}`: {e}")
        })?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        Some(code) => Err(format!(
            "git merge-base --is-ancestor `{ancestor}` `{descendant}` exited with {code}"
        )),
        None => Err(format!(
            "git merge-base --is-ancestor `{ancestor}` `{descendant}` terminated by signal"
        )),
    }
}

fn repository_has_usable_history(root: &Path) -> TestResult<bool> {
    Ok(git_ref_exists(root, "HEAD^{commit}")? && git_commit_exists(root, REQUIRED_HISTORY_ANCHOR)?)
}

#[test]
fn every_cli_contract_manifest_source_commit_resolves_to_repo_commit() -> TestResult {
    let root = workspace_root()?;
    if !repository_has_usable_history(&root)? {
        eprintln!(
            "skipping cli_contract source_commit resolution check because this checkout lacks the required git history anchor {REQUIRED_HISTORY_ANCHOR}"
        );
        return Ok(());
    }

    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }

        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(source_commit) = manifest.get("source_commit") else {
            violations.push(format!("{name}: missing source_commit field"));
            checked += 1;
            continue;
        };
        let Some(source_commit) = source_commit.as_str() else {
            violations.push(format!("{name}: source_commit must be a string"));
            checked += 1;
            continue;
        };
        if !git_commit_exists(&root, source_commit)? {
            violations.push(format!(
                "{name}: source_commit `{source_commit}` does not resolve to a commit object"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract source_commit resolution violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn every_cli_contract_manifest_source_commit_is_ancestor_of_head() -> TestResult {
    let root = workspace_root()?;
    if !repository_has_usable_history(&root)? {
        eprintln!(
            "skipping cli_contract source_commit ancestry check because this checkout lacks the required git history anchor {REQUIRED_HISTORY_ANCHOR}"
        );
        return Ok(());
    }

    let conformance_dir = root.join("tests").join("conformance");
    let entries = std::fs::read_dir(&conformance_dir)
        .map_err(|e| format!("read_dir {conformance_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.ends_with("_cli_contract.v1.json") {
            continue;
        }

        let body = std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        let manifest: Value =
            serde_json::from_str(&body).map_err(|e| format!("parse {name}: {e}"))?;
        let Some(source_commit) = manifest.get("source_commit") else {
            violations.push(format!("{name}: missing source_commit field"));
            checked += 1;
            continue;
        };
        let Some(source_commit) = source_commit.as_str() else {
            violations.push(format!("{name}: source_commit must be a string"));
            checked += 1;
            continue;
        };
        if !git_commit_is_ancestor(&root, source_commit, "HEAD")? {
            violations.push(format!(
                "{name}: source_commit `{source_commit}` is not an ancestor of HEAD"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 CLI contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} CLI contract source_commit ancestry violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn commit_object_ref_uses_git_commit_peeling_syntax() {
    assert_eq!(
        commit_object_ref("01234567"),
        "01234567^{commit}",
        "git cat-file must reject blobs and trees that share object-id syntax"
    );
}
