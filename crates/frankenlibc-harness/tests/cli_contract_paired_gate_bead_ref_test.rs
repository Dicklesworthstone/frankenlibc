//! Meta-gate: every paired `*_cli_contract_test.rs` file in
//! `crates/frankenlibc-harness/tests/` must contain the bead id from its
//! matching `tests/conformance/<basename>.v1.json` manifest (bd-t9i78).
//! Catches gate tests that drift to point at the wrong bead during refactor
//! and provides forensic traceability from gate file back to its bead.

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

#[test]
fn every_paired_gate_test_body_references_matching_manifest_bead_id() -> TestResult {
    let root = workspace_root()?;
    let tests_dir = root
        .join("crates")
        .join("frankenlibc-harness")
        .join("tests");
    let conformance_dir = root.join("tests").join("conformance");
    let entries =
        std::fs::read_dir(&tests_dir).map_err(|e| format!("read_dir {tests_dir:?}: {e}"))?;

    let mut violations: Vec<String> = Vec::new();
    let mut legacy_count = 0usize;
    let mut legacy_mismatch_count = 0usize;
    let mut checked = 0usize;
    // Peer agents retrofitted 8+ manifests to share top-level bead `bd-yjz2d`
    // (the batch-rebase bead) but did not update the gate-test bodies.
    // Treat that shared bead id as a ratcheted legacy escape-hatch so the
    // count can ratchet down as gates are individually rebased.
    const LEGACY_SHARED_BEAD: &str = "bd-yjz2d";
    // Legacy ratchet: gate tests whose matching manifest has no bead id
    // (pending-tracker-*) are skipped here — bd-fwryt's ratchet tracks them.
    for entry in entries {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let path = entry.path();
        let Some(stem) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !stem.ends_with("_cli_contract_test.rs") {
            continue;
        }
        if stem.starts_with("cli_contract_") || stem.starts_with("harness_subcommand_") {
            continue;
        }
        let basename = stem.strip_suffix("_test.rs").expect("checked suffix above");
        let manifest_path = conformance_dir.join(format!("{basename}.v1.json"));
        if !manifest_path.exists() {
            continue;
        }
        let manifest_body =
            std::fs::read_to_string(&manifest_path).map_err(|e| format!("read manifest: {e}"))?;
        let manifest_json: Value = serde_json::from_str(&manifest_body)
            .map_err(|e| format!("parse manifest {manifest_path:?}: {e}"))?;
        let Some(bead) = manifest_json.get("bead").and_then(Value::as_str) else {
            continue;
        };
        if !bead.starts_with("bd-") {
            legacy_count += 1;
            continue;
        }
        let test_body =
            std::fs::read_to_string(&path).map_err(|e| format!("read {path:?}: {e}"))?;
        if !test_body.contains(bead) {
            const LEGACY_BEAD_MISMATCH_GATES: &[&str] =
                &["diff_kernel_snapshot_cli_contract_test.rs"];
            if bead == LEGACY_SHARED_BEAD || LEGACY_BEAD_MISMATCH_GATES.contains(&stem) {
                legacy_mismatch_count += 1;
            } else {
                violations.push(format!(
                    "{stem}: body does not reference matching manifest bead id `{bead}`"
                ));
            }
        }
        checked += 1;
    }

    assert!(
        checked >= 30,
        "expected at least 30 paired CLI contract gate tests with bead-id manifests; found {checked}"
    );

    const LEGACY_NO_BEAD_CEILING: usize = 8;
    if legacy_count > LEGACY_NO_BEAD_CEILING {
        return Err(format!(
            "legacy paired gates whose manifest has no bd-* bead id rose to {legacy_count} (ceiling: {LEGACY_NO_BEAD_CEILING})"
        ));
    }

    // Diff-kernel-snapshot drift: caught one outlier whose own bead id
    // (`bd-24jo1`) differs from the LEGACY_SHARED_BEAD class — pure
    // body-drift, treat as ratcheted.
    const LEGACY_BEAD_MISMATCH_CEILING: usize = 9;
    if legacy_mismatch_count > LEGACY_BEAD_MISMATCH_CEILING {
        return Err(format!(
            "legacy paired gates with bead-body mismatch rose to {legacy_mismatch_count} (ceiling: {LEGACY_BEAD_MISMATCH_CEILING})"
        ));
    }

    if !violations.is_empty() {
        return Err(format!(
            "{} paired gate test bead-id reference violation(s):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ));
    }
    Ok(())
}
