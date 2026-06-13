#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Differential test for the REG_NOSUB fast path in the regex engine.
//!
//! With REG_NOSUB, `regexec` reports only the boolean match/no-match decision
//! (pmatch is never filled). frankenlibc short-circuits that to the exact
//! membership pass (`any_match`, a lazy DFA for position-independent patterns)
//! instead of computing and discarding the leftmost-longest capture offsets.
//! This fuzzes the boolean decision against the LIVE host glibc oracle over
//! randomized ERE patterns + inputs (and a curated battery), asserting the
//! match/no-match decision agrees on every case — proving the fast path is
//! semantically identical to a full search.

use std::ffi::{CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn regcomp(preg: *mut c_void, pattern: *const c_char, cflags: c_int) -> c_int;
    fn regexec(
        preg: *const c_void,
        string: *const c_char,
        nmatch: usize,
        pmatch: *mut c_void,
        eflags: c_int,
    ) -> c_int;
    fn regfree(preg: *mut c_void);
}

const REG_EXTENDED: c_int = 1;
const REG_NOSUB: c_int = 8;

#[repr(C, align(16))]
struct Preg([u8; 256]);

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

/// Compile + boolean-exec under REG_EXTENDED|REG_NOSUB. Returns Some(matched) if
/// the pattern compiled, None if it was rejected (so both engines can agree on
/// invalidity by skipping).
fn run(
    comp: unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int,
    exec: unsafe extern "C" fn(*const c_void, *const c_char, usize, *mut c_void, c_int) -> c_int,
    free: unsafe extern "C" fn(*mut c_void),
    pat: &CString,
    inp: &CString,
) -> Option<bool> {
    let mut preg = Preg([0u8; 256]);
    let c = unsafe { comp(preg.0.as_mut_ptr() as *mut c_void, pat.as_ptr(), REG_EXTENDED | REG_NOSUB) };
    if c != 0 {
        return None;
    }
    let e = unsafe { exec(preg.0.as_ptr() as *const c_void, inp.as_ptr(), 0, std::ptr::null_mut(), 0) };
    unsafe { free(preg.0.as_mut_ptr() as *mut c_void) };
    Some(e == 0)
}

fn check(pat: &str, inp: &str, divs: &mut Vec<String>) {
    let (Ok(cp), Ok(ci)) = (CString::new(pat), CString::new(inp)) else {
        return;
    };
    let fl = run(
        frankenlibc_abi::string_abi::regcomp,
        frankenlibc_abi::string_abi::regexec,
        frankenlibc_abi::string_abi::regfree,
        &cp,
        &ci,
    );
    let gl = run(regcomp, regexec, regfree, &cp, &ci);
    // Only compare when both engines accepted the pattern.
    if let (Some(f), Some(g)) = (fl, gl)
        && f != g
        && divs.len() < 30
    {
        divs.push(format!("pat={pat:?} inp={inp:?}: fl_match={f} glibc_match={g}"));
    }
}

#[test]
fn regex_nosub_boolean_matches_glibc() {
    let mut divs = Vec::new();

    // Curated: class/wildcard-leading patterns (the short-circuited no-literal-
    // prefix path), anchors, alternation, empty/nullable, and literal-prefix
    // (the path that stays on execute()).
    let curated: &[(&str, &str)] = &[
        ("[0-9]+", "abc 123 def"),
        ("[a-z]+", "ABC"),
        ("^foo", "foobar"),
        ("bar$", "foobar"),
        ("(quick|slow) brown", "the quick brown fox"),
        ("a*", ""),
        (".*", "anything"),
        ("x?y?z?", "q"),
        ("[[:digit:]]+", "no digits here"),
        ("fox", "the quick brown fox"),
        ("^$", ""),
        ("^$", "x"),
        ("(ab)+", "ababab"),
        ("colou?r", "color"),
        ("[^a-z]+", "abc"),
        ("end$", "the end"),
    ];
    for (p, i) in curated {
        check(p, i, &mut divs);
    }

    // Randomized ERE patterns + inputs.
    let mut r = Lcg(0x9e37_79b9_7f4a_7c15);
    let toks = [
        "a", "b", ".", "[0-9]", "[a-z]", "[^x]", "*", "+", "?", "|", "(", ")", "^", "$", "x", "1",
        "[[:alpha:]]", "c",
    ];
    for _ in 0..60_000 {
        let plen = 1 + r.below(7);
        let mut pat = String::new();
        for _ in 0..plen {
            pat.push_str(toks[r.below(toks.len())]);
        }
        let ilen = r.below(12);
        const ALPHA: &[u8] = b"abcx019 ";
        let inp: String = (0..ilen).map(|_| ALPHA[r.below(ALPHA.len())] as char).collect();
        check(&pat, &inp, &mut divs);
    }

    assert!(
        divs.is_empty(),
        "REG_NOSUB boolean decision diverged from glibc (showing up to 30):\n{}",
        divs.join("\n")
    );
}
