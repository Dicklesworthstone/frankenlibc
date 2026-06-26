//! Differential probe: frankenlibc glob vs glibc glob over a deterministic
//! on-disk tree created in a unique tempdir. Covers sort order, hidden-file
//! handling (`*` excludes dotfiles, `.*` includes . / .. / .hidden), ranges,
//! GLOB_MARK (trailing slash on dirs), GLOB_NOCHECK (return pattern on no
//! match), subdirectory patterns, and GLOB_NOMATCH. glibc reference captured
//! from a C probe on an identical tree; results are compared as tempdir-relative
//! names in returned (sorted) order.

use std::fs;
use std::path::{Path, PathBuf};

use frankenlibc_core::string::glob::{
    GLOB_BRACE, GLOB_MARK, GLOB_NOCHECK, GLOB_NOMAGIC, GLOB_NOMATCH, glob_expand,
};

fn make_tree() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "fl_glob_probe_{}_{:p}",
        std::process::id(),
        &dir as *const _
    ));
    fs::create_dir_all(&dir).unwrap();
    for f in ["Foo", "a.txt", "b.txt", "bar", "c.txt", "d.log", ".hidden"] {
        fs::write(dir.join(f), b"").unwrap();
    }
    fs::create_dir_all(dir.join("sub")).unwrap();
    fs::write(dir.join("sub/x.txt"), b"").unwrap();
    dir
}

fn run(dir: &Path, relpat: &str, flags: i32) -> String {
    let mut pat = dir.to_str().unwrap().as_bytes().to_vec();
    pat.push(b'/');
    pat.extend_from_slice(relpat.as_bytes());
    pat.push(0);
    let prefix = {
        let mut p = dir.to_str().unwrap().as_bytes().to_vec();
        p.push(b'/');
        p
    };
    match glob_expand(&pat, flags) {
        Ok(res) => {
            let names: Vec<String> = res
                .paths
                .iter()
                .map(|p| {
                    let rel = if p.starts_with(&prefix) {
                        &p[prefix.len()..]
                    } else {
                        &p[..]
                    };
                    String::from_utf8_lossy(rel).into_owned()
                })
                .collect();
            format!("0: {}", names.join(" "))
        }
        Err(e) => format!("{e}"),
    }
}

#[test]
fn glob_differential_battery() {
    let dir = make_tree();

    // (relpat, flags, glibc result), captured from a C glob probe.
    let cases: &[(&str, i32, &str)] = &[
        ("*.txt", 0, "0: a.txt b.txt c.txt"),
        ("*", 0, "0: Foo a.txt b.txt bar c.txt d.log sub"),
        // glibc returns ". .. .hidden" here because its readdir yields "." and
        // ".." which the explicit leading dot in ".*" matches. frankenlibc's
        // glob (built on Rust std::fs::read_dir, which omits "."/"..") now
        // re-introduces the two synthetic entries to match glibc (bd-2g7oyh.91).
        (".*", 0, "0: . .. .hidden"),
        ("[ab]*", 0, "0: a.txt b.txt bar"),
        ("*.xyz", 0, &format!("{GLOB_NOMATCH}")),
        ("*.xyz", GLOB_NOCHECK, "0: *.xyz"),
        ("*", GLOB_MARK, "0: Foo a.txt b.txt bar c.txt d.log sub/"),
        ("?.txt", 0, "0: a.txt b.txt c.txt"),
        ("sub/*", 0, "0: sub/x.txt"),
        ("[c-z]*", 0, "0: c.txt d.log sub"),
        ("*.log", GLOB_MARK, "0: d.log"),
        ("BAR", GLOB_NOCHECK, "0: BAR"),
        // GLOB_NOMAGIC: a magic-free pattern with no match returns the pattern
        // itself (like GLOB_NOCHECK), but only for magic-free patterns — a magic
        // pattern with no match still yields GLOB_NOMATCH. A pattern that does
        // match returns the matches regardless. (glibc <glob.h> semantics.)
        ("BAZ", GLOB_NOMAGIC, "0: BAZ"), // magic-free, no match -> pattern
        ("Foo", GLOB_NOMAGIC, "0: Foo"), // magic-free, matches -> match
        ("*.xyz", GLOB_NOMAGIC, &format!("{GLOB_NOMATCH}")), // magic, no match -> NOMATCH
        ("*.txt", GLOB_NOMAGIC, "0: a.txt b.txt c.txt"), // magic, matches -> matches
    ];

    let mut diffs = Vec::new();
    for (relpat, flags, expected) in cases {
        let got = run(&dir, relpat, *flags);
        if got != *expected {
            diffs.push(format!(
                "glob({relpat:?}, 0x{flags:x}): frankenlibc={got:?} glibc={expected:?}"
            ));
        }
    }

    let _ = fs::remove_dir_all(&dir);

    assert!(
        diffs.is_empty(),
        "glob diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}

fn make_brace_tree() -> PathBuf {
    let mut dir = std::env::temp_dir();
    dir.push(format!(
        "fl_glob_brace_{}_{:p}",
        std::process::id(),
        &dir as *const _
    ));
    fs::create_dir_all(&dir).unwrap();
    for f in [
        "a1b", "a2b", "a3b", "ac", "ad", "bc", "bd", "abe", "ace", "ade", "abc", "x", "xfoo",
        "file.c", "file.h", "p", "q", "1", "2", "3",
    ] {
        fs::write(dir.join(f), b"").unwrap();
    }
    dir
}

/// GLOB_BRACE differential vs glibc: comma alternation, cartesian product,
/// nesting, empty alternatives, single-element ({x}->x) and empty ({}->"")
/// braces, batch-concatenation order (no global sort), no de-duplication, no
/// numeric-range support ({1..3} is literal), and GLOB_NOCHECK fallback to the
/// original brace pattern. glibc reference captured from a C GLOB_BRACE probe.
#[test]
fn glob_brace_differential_battery() {
    let dir = make_brace_tree();

    let cases: &[(&str, i32, &str)] = &[
        ("a{1,2,3}b", GLOB_BRACE, "0: a1b a2b a3b"),
        ("{a,b}{c,d}", GLOB_BRACE, "0: ac ad bc bd"),
        ("a{b,{c,d}}e", GLOB_BRACE, "0: abe ace ade"),
        ("x{,foo}", GLOB_BRACE, "0: x xfoo"),
        ("a{b}c", GLOB_BRACE, "0: abc"),
        ("a{}c", GLOB_BRACE, "0: ac"),
        ("file.{c,h}", GLOB_BRACE, "0: file.c file.h"),
        ("{q,p}", GLOB_BRACE, "0: q p"),    // batch order, NOT sorted
        ("{a,a}c", GLOB_BRACE, "0: ac ac"), // no de-duplication
        ("{1..3}", GLOB_BRACE, &format!("{GLOB_NOMATCH}")), // ranges unsupported -> literal, no match
        ("zz{x,y}", GLOB_BRACE, &format!("{GLOB_NOMATCH}")),
        ("zz{x,y}", GLOB_BRACE | GLOB_NOCHECK, "0: zz{x,y}"), // original pattern on total no-match
    ];

    let mut diffs = Vec::new();
    for (relpat, flags, expected) in cases {
        let got = run(&dir, relpat, *flags);
        if got != *expected {
            diffs.push(format!(
                "glob({relpat:?}, 0x{flags:x}): frankenlibc={got:?} glibc={expected:?}"
            ));
        }
    }

    let _ = fs::remove_dir_all(&dir);

    assert!(
        diffs.is_empty(),
        "GLOB_BRACE diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
