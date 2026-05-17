//! Meta-gate: every `*_cli_contract.v1.json` manifest's `bead` value
//! matches the canonical beads_rust pattern: `bd-` followed by one or
//! more lowercase alnum characters, optionally followed by `.N`
//! (parent.child sub-bead) dotted segments (bd-k8znp). Catches
//! uppercase, punctuation, or whitespace drift in bead ids while
//! accommodating the existing dotted sub-bead convention
//! (e.g. `bd-2tq.4`).

use std::path::{Path, PathBuf};

use serde_json::Value;

type TestResult<T = ()> = Result<T, String>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("could not derive workspace root from {manifest}"))
}

fn matches_canonical_bead_pattern(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("bd-") else {
        return false;
    };
    if rest.is_empty() {
        return false;
    }
    // First segment: lowercase alnum
    let mut chars = rest.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit() => {}
        _ => return false,
    }
    // Rest can be alnum or `.` (sub-bead separator); no consecutive dots,
    // no leading/trailing dot.
    let mut prev_dot = false;
    for c in chars {
        if c == '.' {
            if prev_dot {
                return false;
            }
            prev_dot = true;
        } else if c.is_ascii_lowercase() || c.is_ascii_digit() {
            prev_dot = false;
        } else {
            return false;
        }
    }
    !prev_dot
}

#[test]
fn every_cli_contract_bead_matches_canonical_pattern() -> TestResult {
    let root = workspace_root()?;
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
        let Some(b) = manifest.get("bead").and_then(Value::as_str) else {
            violations.push(format!("{name}: missing bead"));
            checked += 1;
            continue;
        };
        if !matches_canonical_bead_pattern(b) {
            violations.push(format!(
                "{name}: bead `{b}` does not match canonical bd-<alnum>(.<alnum>)* pattern"
            ));
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 cli_contract manifests; found {checked}"
    );

    if !violations.is_empty() {
        return Err(format!(
            "{} bead-pattern violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn canonical_bead_pattern_validator_handles_canonical_forms() {
    assert!(matches_canonical_bead_pattern("bd-abc123"));
    assert!(matches_canonical_bead_pattern("bd-foo"));
    assert!(matches_canonical_bead_pattern("bd-2tq.4"));
    assert!(matches_canonical_bead_pattern("bd-0agsk.3"));
    assert!(matches_canonical_bead_pattern("bd-a.b.c"));
    assert!(!matches_canonical_bead_pattern("bd-"));
    assert!(!matches_canonical_bead_pattern("bd-Foo"));
    assert!(!matches_canonical_bead_pattern("bd-foo-bar"));
    assert!(!matches_canonical_bead_pattern("bd-foo..bar"));
    assert!(!matches_canonical_bead_pattern("bd-foo."));
    assert!(!matches_canonical_bead_pattern("bd-.foo"));
    assert!(!matches_canonical_bead_pattern("foo-bar"));
    assert!(!matches_canonical_bead_pattern(""));
}
