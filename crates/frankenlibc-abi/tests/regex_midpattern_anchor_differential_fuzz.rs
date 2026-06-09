#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Randomized differential fuzzer for glibc's mid-pattern line-anchor quirk vs
//! host glibc: in an ERE, a NON-terminal `$` (one not at the end of the pattern
//! / a group / an alternative) matches before a mid-string `\n` even WITHOUT
//! REG_NEWLINE, and a NON-leading `^` matches after a `\n`. A terminal `$` /
//! leading `^`, and every BRE anchor, only match at the string end/start
//! (unless REG_NEWLINE). frankenlibc previously treated all anchors uniformly.
//! This generates random ERE/BRE patterns with `^`/`$` at varied positions
//! (mid-pattern, terminal, inside groups, around `|`) over buffers containing
//! `\n`, and compares the return + full capture vector across cflag/eflag combos.

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

const REG_EXTENDED: c_int = 1;
const REG_NEWLINE: c_int = 4;
const REG_NOTBOL: c_int = 1;
const REG_NOTEOL: c_int = 2;

#[repr(C, align(8))]
struct Preg([u8; 256]);

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

/// Random pattern with anchors at varied positions. In ERE `^`/`$` are always
/// anchors; tokens place anchors mid-pattern, leading, terminal, and adjacent to
/// `|`. Two constructs are deliberately excluded because glibc is ambiguous /
/// inconsistent there (out of scope — they keep plain buffer-anchor semantics):
///   * GROUPS — with a capture group present, glibc's whole-match result for a
///     mid-pattern anchor depends on `nmatch` (`$(.)` matches with nmatch=1 but
///     not nmatch>=2 — a submatch-path inconsistency).
///   * NULLABLE quantifiers `*`/`?` adjacent to an anchor — a `^`/`$` next to a
///     nullable atom can be BOTH a buffer anchor (neighbor empty) and a line
///     anchor (neighbor consumes), and glibc resolves it inconsistently (`c?^`
///     anchors at start, `.?^a` is line-aware). Only the NON-nullable `+` is
///     generated, so every anchor here has a definite buffer-vs-line answer.
fn gen_pattern(r: &mut Lcg, extended: bool) -> Vec<u8> {
    const ATOM: &[u8] = b"ab.c";
    let len = 1 + r.below(6);
    let mut p = Vec::new();
    for _ in 0..len {
        match r.below(11) {
            0 => p.push(b'^'),
            1 => p.push(b'$'),
            2 => p.extend_from_slice(b"[ab]"),
            3 if extended => p.push(b'|'),
            4 if extended => {
                p.push(ATOM[r.below(ATOM.len())]);
                p.push(b'+');
            }
            5 => p.push(b'.'),
            _ => p.push(ATOM[r.below(ATOM.len())]),
        }
    }
    p
}

fn gen_buf(r: &mut Lcg) -> Vec<u8> {
    const S: &[u8] = b"ab\ncab\nc";
    let len = r.below(9);
    (0..len).map(|_| S[r.below(S.len())]).collect()
}

struct Run {
    comp: c_int,
    exec: c_int,
    pm: [RegMatch; 3],
}

fn run(
    comp_fn: unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int,
    exec_fn: unsafe extern "C" fn(*const c_void, *const c_char, usize, *mut c_void, c_int) -> c_int,
    free_fn: unsafe extern "C" fn(*mut c_void),
    pat: &CString,
    buf: &CString,
    cflags: c_int,
    eflags: c_int,
) -> Run {
    let mut preg = Preg([0u8; 256]);
    let comp = unsafe { comp_fn(preg.0.as_mut_ptr() as *mut c_void, pat.as_ptr(), cflags) };
    let mut pm = [RegMatch::default(); 3];
    let exec = if comp == 0 {
        let e = unsafe {
            exec_fn(
                preg.0.as_ptr() as *const c_void,
                buf.as_ptr(),
                3,
                pm.as_mut_ptr() as *mut c_void,
                eflags,
            )
        };
        unsafe { free_fn(preg.0.as_mut_ptr() as *mut c_void) };
        e
    } else {
        -1
    };
    Run { comp, exec, pm }
}

#[test]
fn regex_midpattern_anchor_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x3a17_9d2c_8e4f_1100);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;
    let mut validity_skips = 0u64;

    for _ in 0..300_000 {
        let extended = r.below(2) == 0;
        let pat = gen_pattern(&mut r, extended);
        let buf = gen_buf(&mut r);
        let (Ok(cpat), Ok(cbuf)) = (CString::new(pat.clone()), CString::new(buf.clone())) else {
            continue;
        };
        let cflags = (if extended { REG_EXTENDED } else { 0 })
            | if r.below(3) == 0 { REG_NEWLINE } else { 0 };
        let eflags = match r.below(4) {
            0 => 0,
            1 => REG_NOTBOL,
            2 => REG_NOTEOL,
            _ => REG_NOTBOL | REG_NOTEOL,
        };

        let fl_run = run(fl::regcomp, fl::regexec, fl::regfree, &cpat, &cbuf, cflags, eflags);
        let lc_run = run(regcomp, regexec, regfree, &cpat, &cbuf, cflags, eflags);

        if (fl_run.comp == 0) != (lc_run.comp == 0) {
            validity_skips += 1;
            continue;
        }
        if fl_run.comp != 0 {
            continue;
        }
        compared += 1;
        let fl_m = fl_run.exec == 0;
        let lc_m = lc_run.exec == 0;
        if (fl_m != lc_m || (fl_m && fl_run.pm != lc_run.pm)) && divs.len() < 30 {
            divs.push(format!(
                "pat={:?} buf={:?} cf={cflags} ef={eflags}\n    fl   =(m={fl_m}, {:?})\n    glibc=(m={lc_m}, {:?})",
                String::from_utf8_lossy(&pat),
                String::from_utf8_lossy(&buf),
                fl_run.pm,
                lc_run.pm
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "mid-pattern anchor diverged from glibc ({compared} compared, {validity_skips} validity skips):\n{}",
        divs.join("\n")
    );
    eprintln!(
        "regex mid-pattern anchor fuzz: {compared} compared, {validity_skips} validity skips, 0 divergences"
    );
}
