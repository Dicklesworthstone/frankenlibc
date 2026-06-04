//! Differential probe: frankenlibc fnmatch vs glibc fnmatch over an edge-case
//! battery. Prints `1`/`0` (match/nomatch) per case; compared offline against a
//! glibc C reference. Run with `--nocapture`.

use frankenlibc_core::string::fnmatch::{FnmatchFlags, fnmatch_match};

// glibc FNM_ bit values (match frankenlibc FnmatchFlags bits).
const PATHNAME: u32 = 1 << 0;
const NOESCAPE: u32 = 1 << 1;
const PERIOD: u32 = 1 << 2;
const LEADING_DIR: u32 = 1 << 3;
const CASEFOLD: u32 = 1 << 4;

#[test]
fn fnmatch_differential_battery() {
    let cases: &[(&str, &str, u32)] = &[
        ("*", "abc", 0),
        ("a*c", "abc", 0),
        ("a?c", "abc", 0),
        ("a?c", "ac", 0),
        ("[a-c]", "b", 0),
        ("[a-c]", "d", 0),
        ("[!a-c]", "d", 0),
        ("[!a-c]", "b", 0),
        ("[]a]", "]", 0),
        ("[]a]", "a", 0),
        ("[^a]", "b", 0),
        ("[^a]", "a", 0),
        ("[a-]", "-", 0),
        ("[a-]", "a", 0),
        ("[-a]", "-", 0),
        ("[[:alpha:]]", "x", 0),
        ("[[:alpha:]]", "5", 0),
        ("[[:digit:]]", "5", 0),
        ("[![:digit:]]", "x", 0),
        ("a\\*c", "a*c", 0),
        ("a\\*c", "abc", 0),
        ("a\\*c", "a*c", NOESCAPE),
        ("*", "a/b", PATHNAME),
        ("a/b", "a/b", PATHNAME),
        ("a*b", "a/b", PATHNAME),
        ("a*", "a/b/c", PATHNAME | LEADING_DIR),
        ("*", ".x", PERIOD),
        ("*", ".x", 0),
        (".*", ".x", PERIOD),
        ("?x", ".x", PERIOD),
        ("/a/.b", "/a/.b", PATHNAME | PERIOD),
        ("/a/*", "/a/.b", PATHNAME | PERIOD),
        ("ABC", "abc", CASEFOLD),
        ("[A-Z]", "a", CASEFOLD),
        ("a[b", "a[b", 0),
        ("a[", "a[", 0),
        ("[", "[", 0),
        ("\\", "\\", 0),
        ("[a-c]*", "bcd", 0),
        ("**", "a/b", PATHNAME),
        ("[z-a]", "b", 0),
        ("x", "", 0),
        ("", "", 0),
        ("", "x", 0),
        ("*?", "ab", 0),
        ("a*b*c", "axbyc", 0),
        ("[!]", "]", 0),
    ];

    // glibc reference results (1=match, 0=nomatch), captured from a C probe.
    let glibc: &[u8] = &[
        1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1,
        0, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0,
    ];

    let mut diffs = Vec::new();
    for (i, &(pat, txt, fl)) in cases.iter().enumerate() {
        let got = fnmatch_match(pat.as_bytes(), txt.as_bytes(), FnmatchFlags::from_bits(fl));
        let got_n = if got { 1u8 } else { 0u8 };
        let exp = glibc[i];
        if got_n != exp {
            diffs.push(format!(
                "case {i}: pat={pat:?} txt={txt:?} flags={fl:#x} -> frankenlibc={got_n} glibc={exp}"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "fnmatch diverges from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
