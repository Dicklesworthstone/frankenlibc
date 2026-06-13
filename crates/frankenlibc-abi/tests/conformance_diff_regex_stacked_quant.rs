#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Stacked regex quantifiers vs host glibc (bd-aedwrn item 3). fl's BRE parser
//! used to treat a `\+`/`\?` after another quantifier as a LITERAL (`b*\+` ->
//! NOMATCH) and its ERE parser rejected any quantifier-after-quantifier
//! (`a*+` -> REG_BADRPT). glibc STACKS them: ERE `* + ? {m,n}` all wrap freely;
//! BRE `\+`/`\?` wrap any prior quantifier while a `*`/`\{` after a quantifier
//! is REG_BADRPT. Compares compile success + match offsets against glibc.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

#[repr(C)]
#[derive(Clone, Copy)]
struct M {
    so: i32,
    eo: i32,
}

unsafe extern "C" {
    fn regcomp(p: *mut c_void, pat: *const c_char, cf: c_int) -> c_int;
    fn regexec(p: *const c_void, s: *const c_char, n: usize, m: *mut c_void, ef: c_int) -> c_int;
    fn regfree(p: *mut c_void);
}

fn host(pat: &str, s: &str, cf: c_int) -> String {
    let mut re = [0u8; 64];
    let cp = CString::new(pat).unwrap();
    let cs = CString::new(s).unwrap();
    let cc = unsafe { regcomp(re.as_mut_ptr() as *mut c_void, cp.as_ptr(), cf) };
    if cc != 0 {
        return "CERR".into();
    }
    let mut m = [M { so: -1, eo: -1 }; 2];
    let r = unsafe {
        regexec(
            re.as_ptr() as *const c_void,
            cs.as_ptr(),
            2,
            m.as_mut_ptr() as *mut c_void,
            0,
        )
    };
    unsafe { regfree(re.as_mut_ptr() as *mut c_void) };
    if r != 0 {
        "NM".into()
    } else {
        format!("[{},{}]", m[0].so, m[0].eo)
    }
}
fn flx(pat: &str, s: &str, cf: c_int) -> String {
    let mut re = [0u8; 256];
    let cp = CString::new(pat).unwrap();
    let cs = CString::new(s).unwrap();
    let cc = unsafe { fl::regcomp(re.as_mut_ptr() as *mut c_void, cp.as_ptr(), cf) };
    if cc != 0 {
        return "CERR".into();
    }
    let mut m = [M { so: -1, eo: -1 }; 2];
    let r = unsafe {
        fl::regexec(
            re.as_ptr() as *const c_void,
            cs.as_ptr(),
            2,
            m.as_mut_ptr() as *mut c_void,
            0,
        )
    };
    unsafe { fl::regfree(re.as_mut_ptr() as *mut c_void) };
    if r != 0 {
        "NM".into()
    } else {
        format!("[{},{}]", m[0].so, m[0].eo)
    }
}

fn ck(pat: &str, s: &str, cf: c_int) {
    let (f, h) = (flx(pat, s, cf), host(pat, s, cf));
    assert_eq!(f, h, "regex({pat:?},{s:?},cf={cf}): fl={f} glibc={h}");
}

#[test]
fn bre_stacked_quantifiers_match_glibc() {
    let cases = [
        (r"a*\+", "aaa"),
        (r"a*\+", ""),
        (r"a*\?", "aaa"),
        (r"a*\?", ""),
        (r"a\+\?", "aa"),
        (r"a\+\?", ""),
        (r"a\?\?", "a"),
        (r"a\?\?", ""),
        (r"a\+\+", "aaa"),
        (r"a\?\+", "a"),
        (r"a\?\+", ""),
        (r"b*\+", "b"),
        (r"+*\+", ""),
        (r"+*\+", "+"),
        (r"\(a\)*\+", "aa"),
        (r"a\{2\}\+", "aa"),
        (r"a\{2\}\?", "aa"),
        // BADRPT cases: both must reject at compile time.
        (r"a\?*", "aaa"),
        (r"a\+*", "aaa"),
        (r"a**", "aaa"),
        (r"a*\{2\}", "aaa"),
        (r"a\+\{2\}", "aa"),
        (r"a\{2\}\{3\}", "aa"),
    ];
    for (p, s) in cases {
        ck(p, s, 0);
    }
}

#[test]
fn ere_stacked_quantifiers_match_glibc() {
    let cases = [
        ("a*+", "aaa"),
        ("a*?", "aaa"),
        ("a+?", "aa"),
        ("a??", "a"),
        ("a?+", "a"),
        ("a++", "aaa"),
        ("a**", "aaa"),
        ("a*{2}", "aaa"),
        ("a{2}+", "aa"),
        ("a{2}?", "aa"),
        ("a+{2}", "aaaa"),
        ("a{2}{3}", "aa"),
        ("(ab)*+", "abab"),
        ("a?*", "aaa"),
    ];
    for (p, s) in cases {
        ck(p, s, 1);
    }
}
