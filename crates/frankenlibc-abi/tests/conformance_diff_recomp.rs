//! Conformance gate for the V7/BSD re_comp/re_exec interface vs host glibc.
//! glibc's re_comp uses the GNU default syntax (re_syntax_options == 0), where
//! bare `+`/`?` are quantifiers and escaped `\+`/`\?` are literal — the OPPOSITE
//! of POSIX BRE. fl's re_comp now translates a V7 pattern to the BRE its engine
//! compiles. Expected results were captured from a gcc oracle calling the real
//! glibc re_comp/re_exec.
//!
//! NOTE: glibc's syntax-0 dialect does NOT support intervals `\{n,m\}` or POSIX
//! `[[:class:]]` (they are taken literally), whereas fl's BRE engine does — so
//! those constructs are deliberately NOT covered here (a pre-existing
//! engine-superset limitation, tracked separately).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::glibc_internal_abi as g;
use std::ffi::CString;

// (pattern, string, glibc re_exec result: 1=match, 0=no match)
const CASES: &[(&str, &str, i32)] = &[
    ("a.c", "abc", 1), ("a.c", "axc", 1), ("a.c", "ac", 0),
    ("^foo$", "foo", 1), ("^foo$", "foobar", 0),
    ("[0-9]+", "abc123", 1), ("[0-9]+", "abcdef", 0),
    ("a*", "bbb", 1), ("\\(ab\\)*", "ababab", 1), ("hello", "world", 0),
    ("a+", "aaa", 1), ("a+", "b", 0),
    ("a?b", "b", 1), ("a?b", "ab", 1), ("a?b", "xb", 1),
    ("[a+]", "+", 1), ("[a+]", "x", 0),
    ("a\\+", "a+", 1), ("a\\+", "aa", 0),
    ("a\\?", "a?", 1), ("a\\?", "ab", 0),
    ("+a", "+a", 1), ("+a", "a", 0),
    ("\\(a\\)+", "aaa", 1), ("\\(ab\\)+c", "ababc", 1),
    ("colou?r", "color", 1), ("colou?r", "colour", 1),
    ("a?", "x", 1), ("go+gle", "gooogle", 1), ("go+gle", "gogle", 1),
    ("[]a]", "]", 1), ("x[]a]y", "x]y", 1),
];

#[test]
fn recomp_matches_glibc() {
    let mut div: Vec<String> = Vec::new();
    for &(pat, s, want) in CASES {
        let cp = CString::new(pat).unwrap();
        let e = unsafe { g::re_comp(cp.as_ptr()) };
        if !e.is_null() {
            div.push(format!("re_comp({pat:?}) returned an error (want match={want})"));
            continue;
        }
        let cs = CString::new(s).unwrap();
        let got = unsafe { g::re_exec(cs.as_ptr()) };
        if got != want {
            div.push(format!("re_comp({pat:?}); re_exec({s:?}) = {got}, glibc = {want}"));
        }
    }
    // NULL pattern reuse: compile "z", then re_comp(NULL) reuses it.
    let cz = CString::new("z").unwrap();
    unsafe { g::re_comp(cz.as_ptr()) };
    if !unsafe { g::re_comp(std::ptr::null()) }.is_null() {
        div.push("re_comp(NULL) should reuse the previous pattern (return NULL)".into());
    }
    let cs = CString::new("z").unwrap();
    if unsafe { g::re_exec(cs.as_ptr()) } != 1 {
        div.push("re_exec after NULL-reuse should match".into());
    }
    assert!(div.is_empty(), "re_comp/re_exec divergences vs glibc ({}):\n  {}", div.len(), div.join("\n  "));
}
