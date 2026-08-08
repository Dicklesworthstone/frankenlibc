//! Ratchet: a module declared `#[cfg(not(test))]` must not contain an inline
//! `#[cfg(test)]` block (bd-0z7a1y).
//!
//! `crates/frankenlibc-abi/src/lib.rs` gates most ABI modules with
//! `#[cfg(not(test))] pub mod <name>;`. An inner `#[cfg(test)]` block in such a
//! module is dead BY CONSTRUCTION — the two cfgs are mutually exclusive, so the
//! block compiles in neither build. Tests written there never run, never appear
//! in `cargo test -p frankenlibc-abi --lib -- --list`, and are never reported as
//! skipped. That is the failure mode that hid 293 tests for weeks (bd-r71n1b),
//! reached here through a cfg pair rather than a link error.
//!
//! This is a RATCHET, not a clean bill of health. The modules in
//! `KNOWN_DEAD_INLINE_TESTS` already carry the pattern and are recorded as debt
//! with their `#[test]` counts; the test fails if a module NOT on that list
//! acquires it, and also fails if a listed module is cleaned up but left on the
//! list, so the list cannot rot into a permanent excuse.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Modules already carrying dead inline `#[cfg(test)]` blocks when this ratchet
/// was introduced, with the number of `#[test]` functions stranded in each.
/// Total: 54 dead test functions. Burning these down is tracked separately —
/// each needs its assertions moved to `crates/frankenlibc-abi/tests/`, which is
/// not mechanical because many touch module-private items.
/// `err_abi` and `malloc_abi` are deliberately ABSENT: their only occurrences of
/// the attribute are inside COMMENTS (err_abi's comment records this very trap,
/// per bd-ul4pyl). A first pass of this survey counted them because it scanned
/// raw text — the same comment-blindness the support-matrix scanner had in
/// bd-4habm0 — and the ratchet's own `cleaned` check caught the mistake.
const KNOWN_DEAD_INLINE_TESTS: &[(&str, usize)] = &[
    ("c11threads_abi", 5),
    ("fenv_abi", 11),
    ("glibc_internal_abi", 4),
    ("grp_abi", 2),
    ("iconv_abi", 6),
    ("io_internal_abi", 5),
    ("pthread_abi", 6),
    ("stdio_abi", 6),
    ("termios_abi", 6),
    ("unistd_abi", 1),
    ("wchar_abi", 2),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Blank out `//` and `/* */` comments before scanning for the attribute.
///
/// Without this the ratchet reports a module that merely *documents* the trap —
/// including efun_abi.rs, whose replacement comment quotes the attribute it is
/// warning about. Same comment-blindness defect as bd-4habm0, where the
/// support-matrix scanner counted a doc comment as a host call.
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

/// Does this module carry a real (non-comment) inline `#[cfg(test)]` block?
fn has_dead_inline_block(text: &str) -> bool {
    strip_comments(text).contains("#[cfg(test)]")
}

/// Module names declared `#[cfg(not(test))] pub mod <name>;` in lib.rs.
fn gated_modules() -> BTreeSet<String> {
    let lib = std::fs::read_to_string(src_dir().join("lib.rs")).expect("read lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    let mut out = BTreeSet::new();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains("cfg(not(test))") {
            continue;
        }
        // The declaration is on one of the next couple of lines (other
        // attributes may intervene).
        for probe in lines.iter().skip(i + 1).take(3) {
            let t = probe.trim();
            if let Some(rest) = t.strip_prefix("pub mod ")
                && let Some(name) = rest.strip_suffix(';')
            {
                out.insert(name.to_string());
                break;
            }
            if !t.starts_with('#') {
                break;
            }
        }
    }
    assert!(
        out.len() > 20,
        "only {} gated modules found; the lib.rs parse is probably broken, \
         which would make this ratchet vacuous",
        out.len()
    );
    out
}

#[test]
fn no_new_module_gains_a_dead_inline_test_block() {
    let known: BTreeSet<&str> = KNOWN_DEAD_INLINE_TESTS.iter().map(|(m, _)| *m).collect();
    let mut offenders = Vec::new();
    let mut cleaned = Vec::new();

    for module in gated_modules() {
        let path = src_dir().join(format!("{module}.rs"));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // directory module or otherwise not a single file
        };
        let has_dead_block = has_dead_inline_block(&text);
        let listed = known.contains(module.as_str());

        if has_dead_block && !listed {
            let n = strip_comments(&text).matches("#[test]").count();
            offenders.push(format!(
                "{module} ({n} #[test] fns stranded) — this module is \
                 #[cfg(not(test))] in lib.rs, so its #[cfg(test)] block can \
                 never compile"
            ));
        }
        if !has_dead_block && listed {
            cleaned.push(module);
        }
    }

    assert!(
        offenders.is_empty(),
        "new dead inline test block(s) added to #[cfg(not(test))] module(s):\n  {}\n\
         Put the assertions in crates/frankenlibc-abi/tests/ instead, where they \
         actually run.",
        offenders.join("\n  ")
    );
    assert!(
        cleaned.is_empty(),
        "these modules no longer contain a dead #[cfg(test)] block and must be \
         REMOVED from KNOWN_DEAD_INLINE_TESTS so the ratchet keeps tightening: {cleaned:?}"
    );
}

/// The debt list must describe reality: every listed module has to exist and
/// still be gated, otherwise the list is quietly protecting nothing.
#[test]
fn known_dead_inline_test_list_is_accurate() {
    let gated = gated_modules();
    for (module, _) in KNOWN_DEAD_INLINE_TESTS {
        assert!(
            gated.contains(*module),
            "{module} is on the known-dead list but is not #[cfg(not(test))]-gated \
             in lib.rs; the list is stale"
        );
        let path = src_dir().join(format!("{module}.rs"));
        assert!(path.is_file(), "{module}.rs listed but missing at {path:?}");
    }
}

/// The module this bead named must be clean: its dead `test_helpers` block is
/// gone and its real coverage lives in `tests/efun_abi_test.rs`.
#[test]
fn efun_abi_has_no_dead_inline_block() {
    let text = std::fs::read_to_string(src_dir().join("efun_abi.rs")).expect("read efun_abi.rs");
    assert!(
        !has_dead_inline_block(&text),
        "efun_abi.rs regained a #[cfg(test)] block; it is #[cfg(not(test))]-gated, \
         so the block cannot compile"
    );
}
