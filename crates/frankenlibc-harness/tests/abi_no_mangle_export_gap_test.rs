//! Conformance gate: every `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))] pub unsafe extern "C" fn`
//! implementation in `crates/frankenlibc-abi/src/*.rs` must also appear in
//! `crates/frankenlibc-abi/version_scripts/libc.map` (bd-13bi6).
//!
//! Prior export-gap fixes:
//!
//!   bd-0j2ha  19 ns_* libresolv helpers were no_mangle-implemented but
//!             unexported.
//!   bd-owc4z  __dn_count_labels was no_mangle-implemented but unexported.
//!
//! This gate locks the pattern in: any future no_mangle ABI symbol that
//! lands without a matching version_script entry fails this test with a
//! list of the offending names. An explicit allowlist (loaded from
//! `tests/conformance/abi_no_mangle_export_gap_allowlist.v1.json`) freezes
//! the current intentional baseline for no_mangle symbols that are not part
//! of the libc.so ABI surface.

use serde_json::Value;
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

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_text(path: &Path) -> Result<String, Box<dyn Error>> {
    std::fs::read_to_string(path)
        .map_err(|err| test_error(format!("{} should be readable: {err}", path.display())))
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    serde_json::from_str(&read_text(path)?)
        .map_err(|err| test_error(format!("{} should parse as JSON: {err}", path.display())))
}

fn libc_map_path() -> PathBuf {
    workspace_root().join("crates/frankenlibc-abi/version_scripts/libc.map")
}

fn abi_src_dir() -> PathBuf {
    workspace_root().join("crates/frankenlibc-abi/src")
}

fn allowlist_path() -> PathBuf {
    workspace_root().join("tests/conformance/abi_no_mangle_export_gap_allowlist.v1.json")
}

/// Extract the set of bare-identifier exports from libc.map. Reuses the
/// same parser strategy as the libc.map golden test: walk lines, track
/// `global:` / `local:` sections, skip comments, accept C identifiers
/// terminated by `;`. The two parsers must agree on the canonical set.
fn parse_exports(text: &str) -> BTreeSet<String> {
    let mut exports: BTreeSet<String> = BTreeSet::new();
    let mut in_block_comment = false;
    let mut current_block: Option<String> = None;
    let mut in_local = false;

    for raw in text.lines() {
        let mut line = raw.trim().to_string();
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
        if let Some(pos) = line.find("//") {
            line = line[..pos].to_string();
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if current_block.is_none() {
            if let Some(brace) = line.find('{') {
                let name = line[..brace].trim();
                if name.starts_with("GLIBC_") || name.starts_with("GCC_") {
                    current_block = Some(name.to_string());
                    in_local = false;
                }
            }
            continue;
        }
        if line.starts_with("global:") {
            in_local = false;
            continue;
        }
        if line.starts_with("local:") {
            in_local = true;
            continue;
        }
        if line.starts_with('}') {
            current_block = None;
            in_local = false;
            continue;
        }
        if in_local {
            continue;
        }
        let candidate = if let Some(semi) = line.find(';') {
            line[..semi].trim()
        } else {
            ""
        };
        if candidate.is_empty()
            || candidate == "*"
            || candidate.contains('{')
            || candidate.contains('}')
        {
            continue;
        }
        if candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            exports.insert(candidate.to_string());
        }
    }
    exports
}

/// Scan abi/src/*.rs for `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`
/// followed by a `pub unsafe extern "C" fn NAME(` declaration. Returns the
/// set of NAME tokens.
fn parse_no_mangle_decls() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut symbols: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(abi_src_dir())? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let text = read_text(&path)?;
        let lines: Vec<&str> = text.lines().collect();
        let marker = "#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]";
        for (i, line) in lines.iter().enumerate() {
            if !line.contains(marker) {
                continue;
            }
            // The next 5 lines should hold the `pub unsafe extern "C" fn NAME(`
            // declaration. Allow attribute lines (`#[allow(...)]`,
            // `#[track_caller]`) between the marker and the `fn`.
            for offset in 1..=5 {
                let idx = i + offset;
                if idx >= lines.len() {
                    break;
                }
                let l = lines[idx].trim_start();
                if let Some(rest) = l.strip_prefix("pub unsafe extern \"C\" fn ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        symbols.insert(name);
                    }
                    break;
                }
                if let Some(rest) = l.strip_prefix("pub unsafe extern \"C-unwind\" fn ") {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    if !name.is_empty() {
                        symbols.insert(name);
                    }
                    break;
                }
                if l.starts_with("pub static") || l.starts_with("pub static mut") {
                    // no_mangle on a static; not in scope of this gate.
                    break;
                }
                // Attribute lines or doc comments - keep scanning forward.
                if !l.starts_with('#') && !l.starts_with("///") && !l.starts_with("//") {
                    break;
                }
            }
        }
    }
    Ok(symbols)
}

fn load_allowlist() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let path = allowlist_path();
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let json = load_json(&path)?;
    let arr = json["allowlist"]
        .as_array()
        .ok_or_else(|| test_error("allowlist must be an array under 'allowlist' key"))?;
    let mut set = BTreeSet::new();
    for v in arr {
        if let Some(s) = v.as_str() {
            set.insert(s.to_string());
        }
    }
    Ok(set)
}

#[test]
fn parser_extracts_a_non_trivial_no_mangle_set() -> TestResult {
    // Sanity floor: the abi crate has hundreds of no_mangle exports
    // (4000+ in libc.map). If our scanner returns < 100 names, the
    // marker pattern has changed and the gate would silently degrade.
    let symbols = parse_no_mangle_decls()?;
    ensure(
        symbols.len() >= 100,
        format!(
            "no_mangle scanner must find at least 100 symbols across abi/src/*.rs; got {}",
            symbols.len()
        ),
    )?;
    Ok(())
}

#[test]
fn every_no_mangle_implementation_is_exported_in_libc_map() -> TestResult {
    let symbols = parse_no_mangle_decls()?;
    let map = read_text(&libc_map_path())?;
    let exports = parse_exports(&map);
    let allowlist = load_allowlist()?;

    let missing: Vec<&String> = symbols
        .iter()
        .filter(|s| !exports.contains(s.as_str()) && !allowlist.contains(s.as_str()))
        .collect();

    ensure(
        missing.is_empty(),
        format!(
            "{} no_mangle ABI symbol(s) implemented in abi/src/*.rs but NOT exported in libc.map and NOT on the allowlist:\n  {}",
            missing.len(),
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        ),
    )?;
    Ok(())
}

#[test]
fn allowlist_entries_each_have_a_real_no_mangle_implementation() -> TestResult {
    // If a symbol appears on the allowlist but no longer has a no_mangle
    // implementation, the allowlist entry is stale and should be removed.
    // Keeping it would accumulate dead exceptions over time.
    let symbols = parse_no_mangle_decls()?;
    let allowlist = load_allowlist()?;
    let stale: Vec<&String> = allowlist
        .iter()
        .filter(|s| !symbols.contains(s.as_str()))
        .collect();
    ensure(
        stale.is_empty(),
        format!(
            "{} allowlist entry(ies) no longer correspond to a no_mangle ABI implementation:\n  {}",
            stale.len(),
            stale
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n  ")
        ),
    )?;
    Ok(())
}
