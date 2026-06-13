#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Randomized differential fuzzer for POSIX BRE "literal `*` after a leading
//! anchor" semantics vs host glibc — the class the existing fuzzers explicitly
//! exclude (regex_newline_eflags_differential_fuzz skips quantifiers/anchors,
//! diff_regex_random_fuzz never combines a leading `^`/`\(`/`\|`/word-anchor
//! with a following `*`). Drives bd-aedwrn item 2.
//!
//! POSIX BRE rule: a `*` is a quantifier only when it follows a *quantifiable*
//! atom. A `*` that immediately follows a leading anchor — `^` at the start of
//! the RE / a subexpression `\(` / an alternative `\|`, or the GNU zero-width
//! assertions `\<` `\>` `\b` `\B` — is a LITERAL `*`, because those assertions
//! are not quantifiable. glibc-confirmed: BRE `^*0` is `^` + literal `*` + `0`
//! (no-match on "0"), while `^**0` is `^` + literal `*` repeated (match on "0").
//! For any pattern BOTH engines accept, match decision and capture offsets must
//! agree.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

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

const REGEX_T_BYTES: usize = 256;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct RegMatch {
    rm_so: i32,
    rm_eo: i32,
}

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

/// Build a BRE fragment that begins at a leading position (RE start, just inside
/// `\(`, or just after `\|`) and may place `*` directly after the boundary or
/// after a leading anchor — exactly the spots where `*` is a literal.
fn gen_fragment(r: &mut Lcg) -> String {
    // Optional leading anchor / assertion at the boundary.
    let lead = match r.below(7) {
        0 => "^",
        1 => "\\<",
        2 => "\\>",
        3 => "\\b",
        4 => "\\B",
        _ => "", // no leading anchor — `*` at the very start is also literal
    };
    let mut out = String::from(lead);
    // A short run of `*` and literals; the first `*` here is literal, a second
    // consecutive `*` quantifies the literal `*`, etc.
    let n = 1 + r.below(4);
    for _ in 0..n {
        match r.below(4) {
            0 => out.push('*'),
            1 => out.push('.'),
            _ => out.push(b"ab0c"[r.below(4)] as char),
        }
    }
    out
}

fn gen_pattern(r: &mut Lcg) -> String {
    match r.below(3) {
        // Top-level fragment.
        0 => gen_fragment(r),
        // Inside a `\(...\)` group: `*` right after `\(` is literal too.
        1 => format!("\\({}\\)", gen_fragment(r)),
        // Across a `\|` alternative: `*` right after `\|` is literal.
        _ => format!("{}\\|{}", gen_fragment(r), gen_fragment(r)),
    }
}

fn gen_subject(r: &mut Lcg) -> String {
    const ATOM: &[u8] = b"*ab0c.*";
    let len = r.below(8);
    (0..len)
        .map(|_| ATOM[r.below(ATOM.len())] as char)
        .collect()
}

struct Run {
    comp: c_int,
    exec: c_int,
    pm: Vec<RegMatch>,
}

fn run(
    comp_fn: unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int,
    exec_fn: unsafe extern "C" fn(*const c_void, *const c_char, usize, *mut c_void, c_int) -> c_int,
    free_fn: unsafe extern "C" fn(*mut c_void),
    pat: &CString,
    inp: &CString,
) -> Run {
    let mut preg = [0u8; REGEX_T_BYTES];
    // cflags = 0 → BRE (the only mode where this rule applies).
    let comp = unsafe { comp_fn(preg.as_mut_ptr() as *mut c_void, pat.as_ptr(), 0) };
    let mut pm = vec![RegMatch::default(); 3];
    let exec = if comp == 0 {
        let e = unsafe {
            exec_fn(
                preg.as_ptr() as *const c_void,
                inp.as_ptr(),
                3,
                pm.as_mut_ptr() as *mut c_void,
                0,
            )
        };
        unsafe { free_fn(preg.as_mut_ptr() as *mut c_void) };
        e
    } else {
        -1
    };
    Run { comp, exec, pm }
}

#[test]
fn regex_bre_anchor_star_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x9e37_79b9_7f4a_7c15);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;
    let mut validity_skips = 0u64;

    for _ in 0..200_000 {
        let pat = gen_pattern(&mut r);
        let subj = gen_subject(&mut r);
        let (Ok(cpat), Ok(cinp)) = (CString::new(pat.clone()), CString::new(subj.clone())) else {
            continue;
        };

        let fl_run = run(fl::regcomp, fl::regexec, fl::regfree, &cpat, &cinp);
        let lc_run = run(regcomp, regexec, regfree, &cpat, &cinp);

        // Skip patterns the two engines disagree on ACCEPTING (regcomp-validity
        // quirks are tracked separately in bd-2g7oyh.136).
        if (fl_run.comp == 0) != (lc_run.comp == 0) {
            validity_skips += 1;
            continue;
        }
        if fl_run.comp != 0 {
            continue;
        }
        compared += 1;
        let fl_match = fl_run.exec == 0;
        let lc_match = lc_run.exec == 0;
        if (fl_match != lc_match || (fl_match && fl_run.pm != lc_run.pm)) && divs.len() < 30 {
            divs.push(format!(
                "pat={pat:?} subj={subj:?}\n    fl   =(m={fl_match}, {:?})\n    glibc=(m={lc_match}, {:?})",
                fl_run.pm, lc_run.pm
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "regex BRE anchor-star diverged from glibc ({compared} compared, {validity_skips} validity skips):\n{}",
        divs.join("\n")
    );
    eprintln!(
        "regex BRE anchor-star fuzz: {compared} compared, {validity_skips} validity skips, 0 divergences"
    );
}
