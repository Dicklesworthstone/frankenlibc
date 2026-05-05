//! Golden artifact: SHA-256 fingerprint of `crates/frankenlibc-abi/
//! version_scripts/libc.map`'s exported symbol set (bd-yzm3v).
//!
//! `tests/conformance/libc_map_export_golden.v1.json` freezes:
//!
//!   * `total_export_count` — number of unique exported symbols across
//!     every GLIBC_2.x global block (deduplicated).
//!   * `blocks_count` — number of `GLIBC_2.x { ... }` version blocks.
//!   * `exports_sha256` — SHA-256 over `\n`.join(sorted(unique exports)).
//!   * `block_names_sha256` — SHA-256 over `\n`.join(sorted(block names)).
//!
//! Any silent addition / deletion of an exported symbol — or a renamed
//! GLIBC version block — fails one of these checks with the live
//! fingerprint visible alongside the frozen one. The artifact is a
//! tamper-evident snapshot, not a coverage check; symbol_universe_
//! normalization_test continues to enforce structural invariants.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::error::Error;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

fn test_error(message: impl Into<String>) -> Box<dyn Error> {
    std::io::Error::other(message.into()).into()
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(test_error(message))
    }
}

fn ensure_eq<T>(actual: T, expected: T, context: impl Into<String>) -> TestResult
where
    T: std::fmt::Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(test_error(format!(
            "{}: expected {:?}, got {:?}",
            context.into(),
            expected,
            actual
        )))
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> Result<String, Box<dyn Error>> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let content = read_text(path)?;
    serde_json::from_str(&content)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn libc_map_path() -> PathBuf {
    workspace_root().join("crates/frankenlibc-abi/version_scripts/libc.map")
}

fn golden_path() -> PathBuf {
    workspace_root().join("tests/conformance/libc_map_export_golden.v1.json")
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Walk the linker version-script grammar with just enough fidelity to
/// extract the canonical export set. Each `GLIBC_2.x { global: ... ;
/// local: *; };` block contributes its global identifiers (one per line,
/// terminated by `;`). Comments (`/* ... */` and `//`) and the `local:`
/// section are skipped. Block names ending in `;` after the closing
/// brace mark the GLIBC_2.x version anchor.
fn parse_libc_map(text: &str) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut exports: BTreeSet<String> = BTreeSet::new();
    let mut block_names: BTreeSet<String> = BTreeSet::new();

    let mut in_block_comment = false;
    let mut current_block: Option<String> = None;
    let mut in_global = false;
    let mut in_local = false;

    for raw in text.lines() {
        let mut line = raw.trim().to_string();
        // Strip block-comment runs that fully or partially span the line.
        loop {
            if in_block_comment {
                if let Some(end) = line.find("*/") {
                    line = line[end + 2..].to_string();
                    in_block_comment = false;
                } else {
                    line.clear();
                    break;
                }
            }
            if let Some(start) = line.find("/*") {
                if let Some(end) = line[start + 2..].find("*/") {
                    let after = start + 2 + end + 2;
                    line = format!("{}{}", &line[..start], &line[after..]);
                    continue;
                } else {
                    line = line[..start].to_string();
                    in_block_comment = true;
                    break;
                }
            }
            break;
        }
        // Strip line comments.
        if let Some(pos) = line.find("//") {
            line = line[..pos].to_string();
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if current_block.is_none() {
            // Looking for `GLIBC_2.x {` start.
            if let Some(brace) = line.find('{') {
                let name = line[..brace].trim();
                if name.starts_with("GLIBC_") {
                    current_block = Some(name.to_string());
                    block_names.insert(name.to_string());
                    in_global = false;
                    in_local = false;
                }
            }
            continue;
        }

        if line.starts_with("global:") {
            in_global = true;
            in_local = false;
            continue;
        }
        if line.starts_with("local:") {
            in_global = false;
            in_local = true;
            continue;
        }
        if line.starts_with('}') {
            current_block = None;
            in_global = false;
            in_local = false;
            continue;
        }

        if in_local {
            // Skip `*;` and any other local-section content.
            continue;
        }

        // In global section (or implicit-global before any `global:` / `local:`).
        // Each export line is `<symbol>;` possibly with leading whitespace and
        // an optional trailing comment. Stop at `;`.
        let candidate = if in_global || (!in_local) {
            if let Some(semi) = line.find(';') {
                line[..semi].trim()
            } else {
                ""
            }
        } else {
            ""
        };
        if candidate.is_empty() {
            continue;
        }
        // Skip pseudo-tokens that are not symbols (e.g. wildcard `*`).
        if candidate == "*" {
            continue;
        }
        // Skip `} GLIBC_2.x` style trailing inheritance markers — those
        // appear at end-of-block lines starting with `}`. Already handled
        // by the `}` branch above, but defend against weird spacing here.
        if candidate.contains('{') || candidate.contains('}') {
            continue;
        }
        // Symbols are bare C identifiers (`[A-Za-z_][A-Za-z0-9_]*`).
        if candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            exports.insert(candidate.to_string());
        }
    }

    (exports, block_names)
}

fn fingerprint_set(set: &BTreeSet<String>) -> [u8; 32] {
    let joined = set.iter().cloned().collect::<Vec<_>>().join("\n");
    Sha256::digest(joined.as_bytes()).into()
}

#[test]
fn libc_map_parses_and_yields_a_non_trivial_export_set() -> TestResult {
    let map = read_text(&libc_map_path())?;
    let (exports, blocks) = parse_libc_map(&map);
    ensure(
        exports.len() >= 100,
        format!(
            "libc.map parser must yield at least 100 unique exports; got {}",
            exports.len()
        ),
    )?;
    ensure(
        !blocks.is_empty(),
        "libc.map parser must find at least one GLIBC_2.x version block",
    )?;
    // The base GLIBC_2.2.5 block is always present.
    ensure(
        blocks.contains("GLIBC_2.2.5"),
        format!("libc.map must declare GLIBC_2.2.5; found blocks: {blocks:?}"),
    )?;
    Ok(())
}

#[test]
fn export_set_fingerprint_matches_golden_artifact() -> TestResult {
    let golden = load_json(&golden_path())?;
    ensure_eq(
        golden["schema_version"].as_str(),
        Some("v1"),
        "schema_version",
    )?;
    ensure_eq(golden["bead"].as_str(), Some("bd-yzm3v"), "bead")?;
    ensure(
        !golden["source_commit"]
            .as_str()
            .unwrap_or_default()
            .is_empty(),
        "source_commit must be set",
    )?;

    let map = read_text(&libc_map_path())?;
    let (exports, blocks) = parse_libc_map(&map);

    let live_total = exports.len();
    let golden_total = golden["total_export_count"]
        .as_u64()
        .ok_or_else(|| test_error("total_export_count must be u64"))?
        as usize;
    ensure_eq(
        live_total,
        golden_total,
        "total_export_count drift: any silent addition/deletion of an exported libc.so symbol fails here",
    )?;

    let live_blocks_count = blocks.len();
    let golden_blocks_count = golden["blocks_count"]
        .as_u64()
        .ok_or_else(|| test_error("blocks_count must be u64"))?
        as usize;
    ensure_eq(
        live_blocks_count,
        golden_blocks_count,
        "blocks_count drift: GLIBC_2.x version-block count changed",
    )?;

    let live_exports_hash = hex_lower(&fingerprint_set(&exports));
    let golden_exports_hash = golden["exports_sha256"].as_str().unwrap_or_default();
    ensure_eq(
        live_exports_hash.clone(),
        golden_exports_hash.to_string(),
        "exports_sha256 drift: the canonical sorted-deduped export-set fingerprint changed; review the diff against tests/conformance/libc_map_export_golden.v1.json before regenerating",
    )?;

    let live_block_names_hash = hex_lower(&fingerprint_set(&blocks));
    let golden_block_names_hash = golden["block_names_sha256"].as_str().unwrap_or_default();
    ensure_eq(
        live_block_names_hash,
        golden_block_names_hash.to_string(),
        "block_names_sha256 drift: a GLIBC_2.x version-block name was added/removed/renamed",
    )?;
    Ok(())
}
