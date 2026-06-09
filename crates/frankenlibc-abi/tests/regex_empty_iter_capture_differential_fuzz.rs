#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Characterization fuzzer (live host-glibc oracle) for POSIX submatch offsets
//! of EMPTY / NULLABLE groups under quantifiers — documents the KNOWN gap
//! bd-1djvkw. `#[ignore]`d because it currently FAILS: the whole-match decision
//! (group 0) matches glibc, but the submatch offsets of empty/nullable quantified
//! groups diverge — glibc records the participating empty span [p,p] (e.g. `()*`
//! → group1=[p,p], `.()*a` on "ba" → group1=[1,1], `(a*)*b?` on "b" → group1=[0,0]),
//! while frankenlibc's Pike VM drops them to [-1,-1]. The correct POSIX rule (a
//! `*`/`+` may take at most one empty iteration, only as the first, without a
//! trailing empty overwriting a non-empty capture) needs per-thread loop-progress
//! tracking — a real VM change, not a structural one-liner (a naive restructure
//! regresses `..(b*)+`; see bd-1djvkw). Un-ignore to drive 200k cases when fixing.
//!
//! Grammar is deliberately ERE concatenation of {literal, `.`, group, and the
//! three quantifiers} with NO top-level alternation and NO backreferences, so it
//! isolates the empty-iteration submatch mechanism — the alternation empty-capture
//! tiebreak (`A|()`) is the same class but a separate path. For any pattern BOTH
//! engines accept, the match decision and ALL capture offsets must agree.

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
const REG_EXTENDED: c_int = 1;

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

/// One atom: a literal, `.`, or a parenthesised group whose body recurses. A
/// group body is itself a short concatenation of quantified atoms, so empty and
/// nullable groups (`()`, `(a*)`, `(.?)`) arise naturally. `depth` bounds nesting
/// (and the live group count to <= 5, the pmatch capacity below).
fn gen_atom(r: &mut Lcg, depth: usize, groups: &mut usize) -> String {
    if depth > 0 && *groups < 5 && r.below(3) == 0 {
        *groups += 1;
        let body = gen_concat(r, depth - 1, groups);
        format!("({body})")
    } else if r.below(4) == 0 {
        ".".to_string()
    } else {
        (b"ab"[r.below(2)] as char).to_string()
    }
}

fn gen_quantified(r: &mut Lcg, depth: usize, groups: &mut usize) -> String {
    let atom = gen_atom(r, depth, groups);
    match r.below(5) {
        0 => format!("{atom}*"),
        1 => format!("{atom}+"),
        2 => format!("{atom}?"),
        _ => atom,
    }
}

fn gen_concat(r: &mut Lcg, depth: usize, groups: &mut usize) -> String {
    let n = 1 + r.below(3);
    (0..n).map(|_| gen_quantified(r, depth, groups)).collect()
}

fn gen_pattern(r: &mut Lcg) -> String {
    let mut groups = 0usize;
    let mut p = gen_concat(r, 2, &mut groups);
    // Ensure at least one group so captures are exercised.
    if groups == 0 {
        p = format!("({p})");
    }
    p
}

fn gen_subject(r: &mut Lcg) -> String {
    const ATOM: &[u8] = b"abab.";
    let len = r.below(6);
    (0..len).map(|_| ATOM[r.below(ATOM.len())] as char).collect()
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
    let comp = unsafe { comp_fn(preg.as_mut_ptr() as *mut c_void, pat.as_ptr(), REG_EXTENDED) };
    let mut pm = vec![RegMatch::default(); 6];
    let exec = if comp == 0 {
        let e = unsafe {
            exec_fn(
                preg.as_ptr() as *const c_void,
                inp.as_ptr(),
                6,
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
#[ignore = "bd-1djvkw PARTIAL: single-level empty/nullable-group submatch now matches glibc (RepeatExitGuard); deeply-NESTED loop-in-loop empty iterations (e.g. (.(b*)*)*) still diverge — un-ignore when the nested case lands"]
fn regex_empty_iter_capture_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0xc2b2_ae3d_27d4_eb4f);
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
        "regex empty-iteration capture diverged from glibc ({compared} compared, {validity_skips} validity skips):\n{}",
        divs.join("\n")
    );
    eprintln!(
        "regex empty-iter capture fuzz: {compared} compared, {validity_skips} validity skips, 0 divergences"
    );
}
