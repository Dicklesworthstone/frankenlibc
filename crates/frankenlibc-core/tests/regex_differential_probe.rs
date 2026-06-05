//! Differential probe: frankenlibc regex (Thompson NFA + Pike VM) vs glibc
//! regcomp/regexec on whole-match bounds. Covers POSIX leftmost-longest
//! semantics (a|ab -> longest), BRE vs ERE syntax, anchors, quantifiers,
//! intervals, char classes, ICASE, NEWLINE, NOTBOL/NOTEOL, and empty matches.
//! glibc reference (rm_so, rm_eo) captured from a C probe.
//!
//! Semantic flags are mapped to frankenlibc-core's own REG_* constants (which
//! differ from glibc's numeric values for REG_NEWLINE/REG_NOSUB); the C probe
//! used glibc's. The comparison is therefore behaviour-level, not value-level.

use frankenlibc_core::string::regex::{
    REG_EXTENDED, REG_ICASE, REG_NEWLINE, REG_NOTBOL, REG_NOTEOL, regex_compile, regex_match_bounds,
};

struct Case {
    pat: &'static str,
    ere: bool,
    icase: bool,
    newline: bool,
    notbol: bool,
    noteol: bool,
    input: &'static str,
}

fn run(c: &Case) -> String {
    let mut cflags = 0;
    if c.ere {
        cflags |= REG_EXTENDED;
    }
    if c.icase {
        cflags |= REG_ICASE;
    }
    if c.newline {
        cflags |= REG_NEWLINE;
    }
    let compiled = match regex_compile(c.pat.as_bytes(), cflags) {
        Ok(c) => c,
        Err(_) => return "ERR".to_string(),
    };
    let mut eflags = 0;
    if c.notbol {
        eflags |= REG_NOTBOL;
    }
    if c.noteol {
        eflags |= REG_NOTEOL;
    }
    match regex_match_bounds(&compiled, c.input.as_bytes(), eflags) {
        Some((s, e)) => format!("{s} {e}"),
        None => "-1 -1".to_string(),
    }
}

#[test]
fn regex_differential_battery() {
    macro_rules! c {
        ($pat:expr, $ere:expr, $icase:expr, $nl:expr, $nb:expr, $ne:expr, $in:expr) => {
            Case {
                pat: $pat,
                ere: $ere,
                icase: $icase,
                newline: $nl,
                notbol: $nb,
                noteol: $ne,
                input: $in,
            }
        };
    }
    let cases = [
        c!("a+", false, false, false, false, false, "xaaay"),
        c!("a+", true, false, false, false, false, "xaaay"),
        c!("a|ab", true, false, false, false, false, "ab"),
        c!("(a|ab)(c|bcd)", true, false, false, false, false, "abcd"),
        c!("a*", true, false, false, false, false, ""),
        c!("^abc$", true, false, false, false, false, "abc"),
        c!("[0-9]+", true, false, false, false, false, "abc123def"),
        c!(".*", true, false, false, false, false, "hello"),
        c!("a.c", true, false, false, false, false, "abc"),
        c!("colou?r", true, false, false, false, false, "color"),
        c!("(ab)*", true, false, false, false, false, "ababab"),
        c!("x", true, false, false, false, false, "abc"),
        c!("[[:digit:]]+", true, false, false, false, false, "x42y"),
        c!("a{2,3}", true, false, false, false, false, "aaaa"),
        c!("^$", true, false, false, false, false, ""),
        c!("a\\{2\\}", false, false, false, false, false, "aaa"),
        c!("\\(ab\\)*", false, false, false, false, false, "abab"),
        c!("ABC", true, true, false, false, false, "xabcy"),
        c!("b|a", true, false, false, false, false, "ab"),
        c!("(foo|foobar)", true, false, false, false, false, "foobar"),
        c!("^b", true, false, true, false, false, "a\nb"),
        c!("[^a]+", true, false, false, false, false, "aaabbb"),
        c!("abc", true, false, false, true, false, "abc"),
        c!("^abc", true, false, false, true, false, "abc"),
        c!("abc$", true, false, false, false, true, "abc"),
        c!("(a*)(a*)", true, false, false, false, false, "aaa"),
        c!("a?", true, false, false, false, false, "b"),
        c!("\\.", false, false, false, false, false, "a.b"),
        c!("[a-c]+", true, false, false, false, false, "zzabcabczz"),
    ];

    let glibc = [
        "-1 -1", "1 4", "0 2", "0 4", "0 0", "0 3", "3 6", "0 5", "0 3", "0 5", "0 6", "-1 -1",
        "1 3", "0 3", "0 0", "0 2", "0 4", "1 4", "0 1", "0 6", "2 3", "3 6", "0 3", "-1 -1",
        "-1 -1", "0 3", "0 0", "1 2", "2 8",
    ];

    assert_eq!(cases.len(), glibc.len(), "battery length mismatch");

    let mut diffs = Vec::new();
    for (i, c) in cases.iter().enumerate() {
        let got = run(c);
        if got != glibc[i] {
            diffs.push(format!(
                "case {i}: pat={:?} ere={} icase={} nl={} nb={} ne={} in={:?} -> frankenlibc={got:?} glibc={:?}",
                c.pat, c.ere, c.icase, c.newline, c.notbol, c.noteol, c.input, glibc[i]
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "regex diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
