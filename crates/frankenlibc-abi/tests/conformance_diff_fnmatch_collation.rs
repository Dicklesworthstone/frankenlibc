#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc fnmatch/setlocale oracle

//! fnmatch bracket expressions that depend on LC_COLLATE, vs host glibc.
//!
//! In en_US.UTF-8 glibc's equivalence class `[[=a=]]` is every character of
//! a's primary collation weight (A, à, Å, ā, ⓐ ...) and a range is ordered by
//! collation sequence (`[a-z]` holds à, é and ß but not B; `[B-a]` is empty)
//! -- for ASCII patterns and strings too. fl compared code points and matched
//! `[=x=]` exactly. In C.UTF-8 (no collation rules) both stay code-point /
//! exact. Each (pattern, string, flags) result is compared, plus every
//! character below U+3000 against a few brackets. Skipped per locale when the
//! host lacks it.

use frankenlibc_abi::string_abi as fl;
use std::ffi::CString;

unsafe extern "C" {
    fn fnmatch(pattern: *const i8, string: *const i8, flags: i32) -> i32;
    fn setlocale(category: i32, locale: *const i8) -> *mut i8;
}

const FNM_PATHNAME: i32 = 1;
const FNM_PERIOD: i32 = 4;
const FNM_CASEFOLD: i32 = 16;

fn both(pat: &str, s: &str, flags: i32) -> (i32, i32) {
    let p = CString::new(pat).unwrap();
    let s = CString::new(s).unwrap();
    // SAFETY: NUL-terminated pattern and string.
    let ours = unsafe { fl::fnmatch(p.as_ptr(), s.as_ptr(), flags) };
    // SAFETY: as above.
    let host = unsafe { fnmatch(p.as_ptr(), s.as_ptr(), flags) };
    (ours, host)
}

fn compare(pats: &[&str], corpus: &[&str], flags: &[i32]) {
    let mut diffs = Vec::new();
    for &pat in pats {
        for &s in corpus {
            for &f in flags {
                let (ours, host) = both(pat, s, f);
                if (ours == 0) != (host == 0) {
                    diffs.push(format!(
                        "fnmatch({pat:?}, {s:?}, {f}) fl={ours} glibc={host}"
                    ));
                }
            }
        }
    }
    for d in &diffs {
        println!("{d}");
    }
    assert!(
        diffs.is_empty(),
        "{} divergences (listed above)",
        diffs.len()
    );
}

#[test]
fn fnmatch_collation_brackets_match_glibc() {
    let corpus: &[&str] = &[
        "a", "A", "à", "Å", "ā", "ǻ", "ⓐ", "ａ", "b", "B", "e", "é", "Ê", "z", "Z", "ß", "ẞ", "ı",
        "i", "æ", "ø", "o", "1", "¹", "١", "!", ",", "\u{300}", "€", "中", "_", "[", "xay", "xÅy",
        "xBy", ".a", "a/b", "x/é", "[a-z]", "aé", "zz",
    ];
    let patterns: &[&str] = &[
        "[[=a=]]",
        "[[=à=]]",
        "[[=A=]x]",
        "[![=a=]]",
        "*[[=e=]]*",
        "[[=ß=]]",
        "[[=ø=]]",
        "[a-z]",
        "[A-Z]",
        "[B-a]",
        "[!a-z]",
        "[a-z]*",
        "x[a-z]y",
        "[[.a.]-z]",
        "[a-[.z.]]",
        "[à-é]",
        "[a-ö]",
        "[0-9]",
        "[_-a]",
        "\\[a-z]",
        "[\\a-z]",
        "?",
        "??",
        "[[:alpha:]]",
        "[[:upper:]]",
        ".[a-z]",
        "*/[a-z]",
        "a[a-zé]",
        // The byte reading (COLLSEQMB: non-ASCII bytes are 0) matches some of
        // these where the character reading does not.
        "[à-é]?",
        "[à-é][à-é]",
        "[[=e=]]?",
        "[[=à=]]?",
        "[a-é]",
        "??",
    ];
    let flags = [0, FNM_CASEFOLD, FNM_PATHNAME | FNM_PERIOD];
    let all: Vec<String> = (1u32..0x3000)
        .filter_map(char::from_u32)
        .map(String::from)
        .collect();
    let all: Vec<&str> = all.iter().map(String::as_str).collect();
    let mut ran = 0;
    for locale in [c"en_US.UTF-8", c"C.UTF-8"] {
        // SAFETY: setlocale with NUL-terminated names; this binary's only test.
        if unsafe { setlocale(libc::LC_ALL, locale.as_ptr()) }.is_null() {
            println!("SKIP: host has no {locale:?} locale");
            continue;
        }
        // SAFETY: as above, fl's own setlocale.
        let ours = unsafe { frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, locale.as_ptr()) };
        assert!(
            !ours.is_null(),
            "fl setlocale({locale:?}) failed where glibc's succeeded"
        );
        compare(patterns, corpus, &flags);
        compare(
            &["[[=a=]]", "[[=o=]]", "[a-z]", "[A-Z]", "[!a-z]"],
            &all,
            &[0],
        );
        if locale == c"en_US.UTF-8" {
            // Not vacuous: collation semantics are really in force.
            assert_eq!(both("[[=a=]]", "A", 0), (0, 0));
            assert_eq!(both("[a-z]", "é", 0), (0, 0));
            assert_ne!(both("[a-z]", "B", 0).0, 0);
        }
        ran += 1;
    }
    // SAFETY: as above.
    unsafe {
        setlocale(libc::LC_ALL, c"C".as_ptr());
        frankenlibc_abi::locale_abi::setlocale(libc::LC_ALL, c"C".as_ptr());
    }
    println!("compared in {ran} UTF-8 locales");
}
