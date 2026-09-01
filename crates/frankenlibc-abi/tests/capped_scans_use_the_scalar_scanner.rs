#![cfg(target_os = "linux")]

//! Which `scan_c_string` does a bare call in this crate resolve to?
//!
//! There are TWO, and their read footprints differ by a page fault:
//!
//! * `crate::util::scan_c_string` walks BYTE BY BYTE and stops at the
//!   terminator, so a `bound` may be a defensive CAP — a ceiling the
//!   implementation invented for a string of unknown length, over a pointer it
//!   does not own.
//! * `crate::string_abi::scan_c_string` is the SWAR/SIMD scanner. Its bounded
//!   arm treats `bound` as a PROMISE of readable bytes and loads whole 128-byte
//!   windows under it — correct for `memchr(p, c, n)`, and a fault for a capped
//!   scan of a string that ends flush against a page boundary.
//!
//! Twenty modules `use crate::util::scan_c_string`, so an unqualified
//! `scan_c_string(p, Some(cap))` anywhere in them is the safe one. That is the
//! whole reason the capped sites are sound, and it is invisible at the call
//! site: the two calls are spelled identically.
//!
//! ## Why this is a gate and not a comment
//!
//! bd-defensive-cap-scan-sweep-fhk28c enumerated six defensive-cap call sites —
//! `numeric_string_scan_bound` and `env_name_scan_bound` in stdlib_abi,
//! `program_name_scan_bound` in startup_abi, `ARGP_TEXT_SCAN_LIMIT` and
//! `DATEMSK_PATH_SCAN_LIMIT` in unistd_abi, `MAX_PUBLISHED_PROGNAME_BYTES` in
//! err_abi — and classified all six as carrying the SIMD scanner's footprint.
//! They do not. Every one of those four files imports the scalar scanner, and
//! `bounded_scan_guard_page_safety::published_progname_scan_never_reads_into_guard_page`
//! measures two of them surviving a guard-flush string. The bead was written
//! from the other function's contract, which is exactly the mistake the shared
//! name invites.
//!
//! A single `use crate::string_abi::scan_c_string;` added to any of those files
//! would silently re-point every bare call in it at the window-loading scanner
//! and reintroduce the footprint the bead described — with no diff at the call
//! sites at all. This test refuses that import.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Blank out `//` and `/* */` comments so a module that DOCUMENTS the trap — as
/// `util.rs` and `string_abi.rs` now both do — is not reported as committing it.
fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'/' {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i] == b'/' && i + 1 < b.len() && b[i + 1] == b'*' {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else {
            out.push(b[i] as char);
            i += 1;
        }
    }
    out
}

fn rust_sources() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(src_dir()).expect("read src/");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        if let Ok(text) = std::fs::read_to_string(&path) {
            out.push((name, strip_comments(&text)));
        }
    }
    assert!(
        out.len() > 20,
        "only {} source files found; the scan is broken and this gate would be vacuous",
        out.len()
    );
    out
}

/// The four modules bd-defensive-cap-scan-sweep-fhk28c named. Each holds at
/// least one defensive-cap scan and must keep the scalar scanner in scope.
const CAPPED_SCAN_MODULES: &[&str] = &[
    "err_abi.rs",
    "startup_abi.rs",
    "stdlib_abi.rs",
    "unistd_abi.rs",
];

#[test]
fn no_module_imports_the_simd_scanner_by_name() {
    let mut offenders = Vec::new();
    for (name, text) in rust_sources() {
        // A `use` of the SIMD scanner is what would re-point bare calls. Matching
        // the import rather than the call is deliberate: the call sites are
        // spelled identically either way, so the import is the only place the
        // choice is visible.
        for line in text.lines() {
            let t = line.trim();
            if !t.starts_with("use ") {
                continue;
            }
            if t.contains("string_abi::scan_c_string")
                || (t.contains("string_abi::") && t.contains("{") && t.contains("scan_c_string"))
            {
                offenders.push(format!("{name}: {t}"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "these modules import the SWAR scanner by name, so every unqualified \
         `scan_c_string(p, Some(cap))` in them now loads 128-byte windows under a \
         bound that is only a CAP:\n  {}\n\
         Call `crate::string_abi::scan_c_string` fully qualified where the bound \
         really is a promise of readable bytes, or use \
         `scan_c_string_nul_or_bound` where it is a ceiling.",
        offenders.join("\n  ")
    );
}

#[test]
fn the_capped_scan_modules_import_the_scalar_scanner() {
    let sources = rust_sources();
    let mut missing = Vec::new();
    for module in CAPPED_SCAN_MODULES {
        let Some((_, text)) = sources.iter().find(|(name, _)| name == module) else {
            panic!("{module} is listed as a capped-scan module but is not in src/");
        };
        if !text.contains("use crate::util::scan_c_string")
            && !text.contains("util::{ArtifactHashMap, artifact_hash_map, scan_c_string}")
            && !(text.contains("use crate::util::{") && text.contains("scan_c_string"))
        {
            missing.push(*module);
        }
    }
    assert!(
        missing.is_empty(),
        "these modules hold defensive-cap scans but no longer import the scalar \
         `util::scan_c_string`, so their bare `scan_c_string` calls resolve \
         somewhere this gate cannot vouch for: {missing:?}"
    );
}

/// The two functions must stay DIFFERENT. If `util::scan_c_string` ever grows a
/// windowed fast path, every capped site inherits the footprint at once and the
/// import check above would still pass.
#[test]
fn the_scalar_scanner_is_still_scalar() {
    let text = std::fs::read_to_string(src_dir().join("util.rs")).expect("read util.rs");
    let body_start = text
        .find("pub unsafe fn scan_c_string")
        .expect("util::scan_c_string must exist");
    let body = &strip_comments(&text[body_start..])[..1200.min(text.len() - body_start)];
    for forbidden in ["Simd", "from_slice", "to_bitmask", "u64::from_ne_bytes"] {
        assert!(
            !body.contains(forbidden),
            "util::scan_c_string now contains `{forbidden}`, i.e. it reads more than \
             one byte at a time. Every defensive-cap caller in the crate hands it a \
             bound that is a CEILING over memory it does not own, so a windowed load \
             there faults on a string flush against a page boundary — see \
             bd-defensive-cap-scan-sweep-fhk28c and \
             tests/bounded_scan_guard_page_safety.rs."
        );
    }
}
