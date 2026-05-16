//! Meta-gate: every clap Subcommand variant in harness.rs must have a paired
//! `tests/conformance/<kebab_subcommand_with_underscores>_cli_contract.v1.json`
//! manifest (bd-intan).
//!
//! This is a ratchet: as new harness subcommands ship, this gate forces the
//! pairing of a conformance manifest so the audit gap never reopens.

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

fn kebab(camel: &str) -> String {
    let mut out = String::with_capacity(camel.len() + 4);
    for (i, c) in camel.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('-');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

fn extract_command_variants(harness_rs: &str) -> Vec<String> {
    let mut variants = Vec::new();
    let mut in_enum = false;
    let mut depth = 0i32;
    for line in harness_rs.lines() {
        let trimmed = line.trim_start();
        if !in_enum {
            if trimmed.starts_with("enum Command") {
                in_enum = true;
                depth += line.matches('{').count() as i32;
                depth -= line.matches('}').count() as i32;
            }
            continue;
        }
        depth += line.matches('{').count() as i32;
        depth -= line.matches('}').count() as i32;
        if depth <= 0 {
            break;
        }
        if let Some(name) = trimmed.split_whitespace().next()
            && name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        {
            let cleaned: String = name
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if !cleaned.is_empty() {
                variants.push(cleaned);
            }
        }
    }
    variants
}

#[test]
fn every_subcommand_variant_has_matching_cli_contract_manifest() -> TestResult {
    let root = workspace_root()?;
    let harness_rs = std::fs::read_to_string(
        root.join("crates")
            .join("frankenlibc-harness")
            .join("src")
            .join("bin")
            .join("harness.rs"),
    )
    .map_err(|e| format!("read harness.rs: {e}"))?;

    let variants = extract_command_variants(&harness_rs);
    assert!(
        variants.len() >= 60,
        "expected at least 60 Command variants; found {} (parser drift?)",
        variants.len()
    );

    let conformance_dir = root.join("tests").join("conformance");
    let mut missing: Vec<String> = Vec::new();
    for variant in &variants {
        let kebab_name = kebab(variant);
        let filename = format!("{}_cli_contract.v1.json", kebab_name.replace('-', "_"));
        let manifest_path = conformance_dir.join(&filename);
        if !manifest_path.exists() {
            missing.push(format!("{variant} -> tests/conformance/{filename}"));
        }
    }

    if !missing.is_empty() {
        return Err(format!(
            "{} harness Subcommand variant(s) lack a paired CLI contract manifest:\n  {}",
            missing.len(),
            missing.join("\n  ")
        ));
    }
    Ok(())
}

#[test]
fn kebab_conversion_round_trips_known_examples() {
    assert_eq!(kebab("SnapshotKernel"), "snapshot-kernel");
    assert_eq!(
        kebab("RuntimeMathDeterminismProofs"),
        "runtime-math-determinism-proofs"
    );
    assert_eq!(
        kebab("RecommendHealingForCanonicalClass"),
        "recommend-healing-for-canonical-class"
    );
    assert_eq!(kebab("Capture"), "capture");
    assert_eq!(kebab("VerifyPcpt"), "verify-pcpt");
}
