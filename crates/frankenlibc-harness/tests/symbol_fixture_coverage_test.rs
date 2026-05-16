//! Integration test: Symbol fixture coverage matrix (bd-15n.1)
//!
//! Validates that:
//! 1. The canonical artifact exists and has required schema fields.
//! 2. Summary totals are consistent with symbol/family rows.
//! 3. Uncovered/weak family lists are consistent with family coverage math.
//! 4. Generator + drift-check scripts exist and are executable.
//! 5. Drift-check script passes on clean checkout.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{error::Error, io};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn workspace_root() -> TestResult<PathBuf> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates_dir = manifest
        .parent()
        .ok_or_else(|| io::Error::other("frankenlibc-harness manifest should have a parent"))?;
    let root = crates_dir.parent().ok_or_else(|| {
        io::Error::other("frankenlibc-harness manifest should live below workspace root")
    })?;
    Ok(root.to_path_buf())
}

fn load_artifact() -> TestResult<serde_json::Value> {
    let path = workspace_root()?.join("tests/conformance/symbol_fixture_coverage.v1.json");
    let content = std::fs::read_to_string(&path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("failed to read {}: {err}", path.display()),
        )
    })?;
    Ok(serde_json::from_str(&content).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("failed to parse {} as JSON: {err}", path.display()),
        )
    })?)
}

#[test]
fn artifact_exists_and_valid() -> TestResult {
    let doc = load_artifact()?;

    assert_eq!(
        doc["schema_version"].as_u64(),
        Some(1),
        "schema_version must be 1"
    );
    assert_eq!(doc["bead"].as_str(), Some("bd-15n.1"), "bead id mismatch");
    assert!(doc["summary"].is_object(), "Missing summary");
    assert!(doc["families"].is_array(), "Missing families[]");
    assert!(doc["symbols"].is_array(), "Missing symbols[]");
    assert!(
        doc["uncovered_target_families"].is_array(),
        "Missing uncovered_target_families[]"
    );
    assert!(
        doc["weak_target_families"].is_array(),
        "Missing weak_target_families[]"
    );
    assert!(doc["ownership_map"].is_array(), "Missing ownership_map[]");
    Ok(())
}

#[test]
fn summary_counts_consistent() -> TestResult {
    let doc = load_artifact()?;
    let summary = &doc["summary"];
    let symbols = json_array(&doc["symbols"], "symbols")?;
    let families = json_array(&doc["families"], "families")?;

    assert_eq!(
        json_u64(
            &summary["total_exported_symbols"],
            "summary.total_exported_symbols"
        )? as usize,
        symbols.len(),
        "total_exported_symbols mismatch"
    );

    let covered_exported = symbols
        .iter()
        .filter(|row| bool_or_false(&row["covered"]))
        .count();
    assert_eq!(
        json_u64(
            &summary["covered_exported_symbols"],
            "summary.covered_exported_symbols"
        )? as usize,
        covered_exported,
        "covered_exported_symbols mismatch"
    );

    let target_total: u64 = families
        .iter()
        .map(|row| u64_or_zero(&row["target_total"]))
        .sum();
    let target_covered: u64 = families
        .iter()
        .map(|row| u64_or_zero(&row["target_covered"]))
        .sum();
    let target_uncovered: u64 = families
        .iter()
        .map(|row| u64_or_zero(&row["target_uncovered"]))
        .sum();

    assert_eq!(
        json_u64(
            &summary["target_total_symbols"],
            "summary.target_total_symbols"
        )?,
        target_total,
        "target_total_symbols mismatch"
    );
    assert_eq!(
        json_u64(
            &summary["target_covered_symbols"],
            "summary.target_covered_symbols"
        )?,
        target_covered,
        "target_covered_symbols mismatch"
    );
    assert_eq!(
        json_u64(
            &summary["target_uncovered_symbols"],
            "summary.target_uncovered_symbols"
        )?,
        target_uncovered,
        "target_uncovered_symbols mismatch"
    );
    Ok(())
}

#[test]
fn uncovered_and_weak_lists_consistent() -> TestResult {
    let doc = load_artifact()?;
    let summary = &doc["summary"];
    let families = json_array(&doc["families"], "families")?;

    let expected_uncovered: std::collections::BTreeSet<String> = families
        .iter()
        .filter(|row| {
            u64_or_zero(&row["target_total"]) > 0 && u64_or_zero(&row["target_covered"]) == 0
        })
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    let actual_uncovered: std::collections::BTreeSet<String> = doc["uncovered_target_families"]
        .as_array()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "uncovered_target_families should be an array",
            )
        })?
        .iter()
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    assert_eq!(
        expected_uncovered, actual_uncovered,
        "uncovered_target_families must match family rows"
    );

    let weak_threshold = json_f64(
        &summary["weak_family_threshold_pct"],
        "summary.weak_family_threshold_pct",
    )?;
    let expected_weak: std::collections::BTreeSet<String> = families
        .iter()
        .filter(|row| {
            let total = u64_or_zero(&row["target_total"]);
            let pct = f64_or_zero(&row["target_coverage_pct"]);
            total > 0 && pct > 0.0 && pct < weak_threshold
        })
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    let actual_weak: std::collections::BTreeSet<String> = doc["weak_target_families"]
        .as_array()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "weak_target_families should be an array",
            )
        })?
        .iter()
        .filter_map(|row| row["module"].as_str().map(String::from))
        .collect();
    assert_eq!(
        expected_weak, actual_weak,
        "weak_target_families must match family rows"
    );
    Ok(())
}

#[test]
fn scripts_exist_and_executable() -> TestResult {
    let root = workspace_root()?;
    let scripts = [
        "scripts/generate_symbol_fixture_coverage.py",
        "scripts/check_symbol_fixture_coverage.sh",
    ];

    for rel in scripts {
        let path = root.join(rel);
        assert!(path.exists(), "{rel} must exist");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&path)?.permissions();
            assert!(perms.mode() & 0o111 != 0, "{rel} must be executable");
        }
    }
    Ok(())
}

#[test]
fn drift_gate_script_passes() -> TestResult {
    let root = workspace_root()?;
    let script = root.join("scripts/check_symbol_fixture_coverage.sh");
    let output = Command::new(&script).current_dir(&root).output()?;

    assert!(
        output.status.success(),
        "check_symbol_fixture_coverage.sh failed\nstatus={:?}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn json_array<'a>(
    value: &'a serde_json::Value,
    description: &str,
) -> TestResult<&'a Vec<serde_json::Value>> {
    value.as_array().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be an array"),
        )
        .into()
    })
}

fn json_u64(value: &serde_json::Value, description: &str) -> TestResult<u64> {
    value.as_u64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be an unsigned integer"),
        )
        .into()
    })
}

fn json_f64(value: &serde_json::Value, description: &str) -> TestResult<f64> {
    value.as_f64().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{description} should be a number"),
        )
        .into()
    })
}

fn bool_or_false(value: &serde_json::Value) -> bool {
    value.as_bool().is_some_and(|value| value)
}

fn u64_or_zero(value: &serde_json::Value) -> u64 {
    value.as_u64().map_or(0, |value| value)
}

fn f64_or_zero(value: &serde_json::Value) -> f64 {
    value.as_f64().map_or(0.0, |value| value)
}
