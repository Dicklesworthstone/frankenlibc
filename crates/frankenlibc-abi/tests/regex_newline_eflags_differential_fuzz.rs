#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Randomized differential fuzzer for the REG_NEWLINE single-character matcher
//! semantics vs host glibc — the parts `diff_regex_random_fuzz` does NOT reach:
//! it only varies cflags `{0, REG_EXTENDED}`, always passes eflags 0, and uses
//! single-line subjects. This drives MULTI-LINE subjects (embedded `\n`) against
//! `.`, positive classes, and negated classes `[^…]` under random `REG_NEWLINE`
//! (where `.` and `[^…]` must NOT match `\n`, while a positive class listing
//! `\n` does) combined with random `REG_NOTBOL` / `REG_NOTEOL`. For any pattern
//! BOTH engines accept, the match decision and capture offsets must agree
//! (validity-only mismatches skipped, per bd-2g7oyh.136). Anchors, quantifiers,
//! groups, alternation and escapes are excluded — they exercise separate
//! regex-engine bugs tracked in bd-aedwrn.

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

const REG_EXTENDED: c_int = 1;
const REG_NEWLINE: c_int = 4; // (8 is REG_NOSUB, which suppresses pmatch)
const REG_NOTBOL: c_int = 1;
const REG_NOTEOL: c_int = 2;

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

fn gen_pattern(r: &mut Lcg) -> String {
    // Isolate the REG_NEWLINE effect on the single-character matchers: `.` and a
    // negated class `[^…]` must NOT match '\n' under REG_NEWLINE, while a
    // positive class `[…\n…]` that lists '\n' DOES. Quantifiers (`* + ?`),
    // groups, alternation, escapes and top-level `^`/`$` anchors are excluded —
    // those exercise other, independent regex-engine bugs (BRE quantifier/escape
    // edges, empty-group capture offsets, GNU mid-pattern anchor line-boundary
    // semantics) tracked separately in bd-aedwrn.
    const LIT: &[u8] = b"ab0c";
    let len = 1 + r.below(6);
    let mut out = String::new();
    for _ in 0..len {
        if r.below(2) == 0 {
            // a (possibly negated) bracket class, sometimes listing '\n'
            out.push('[');
            if r.below(2) == 0 {
                out.push('^');
            }
            for _ in 0..(1 + r.below(3)) {
                out.push(b"ab0\n"[r.below(4)] as char);
            }
            out.push(']');
        } else if r.below(3) == 0 {
            out.push('.');
        } else {
            out.push(LIT[r.below(LIT.len())] as char);
        }
    }
    out
}

fn gen_subject(r: &mut Lcg) -> String {
    // Multi-line: newlines are frequent so REG_NEWLINE / NOTBOL / NOTEOL flip.
    const ATOM: &[u8] = b"ab0\nab\n";
    let len = r.below(12);
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
    cflags: c_int,
    eflags: c_int,
) -> Run {
    let mut preg = [0u8; REGEX_T_BYTES];
    let comp = unsafe { comp_fn(preg.as_mut_ptr() as *mut c_void, pat.as_ptr(), cflags) };
    let mut pm = vec![RegMatch::default(); 3];
    let exec = if comp == 0 {
        let e = unsafe {
            exec_fn(
                preg.as_ptr() as *const c_void,
                inp.as_ptr(),
                3,
                pm.as_mut_ptr() as *mut c_void,
                eflags,
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
fn regex_newline_eflags_differential_fuzz_vs_glibc() {
    let mut r = Lcg(0x4e57_1e0d_a17c_001b);
    let mut divs: Vec<String> = Vec::new();
    let mut compared = 0u64;
    let mut validity_skips = 0u64;

    for _ in 0..120_000 {
        let pat = gen_pattern(&mut r);
        let subj = gen_subject(&mut r);
        let (Ok(cpat), Ok(cinp)) = (CString::new(pat.clone()), CString::new(subj.clone())) else {
            continue;
        };
        let cflags = match r.below(4) {
            0 => 0,
            1 => REG_EXTENDED,
            2 => REG_NEWLINE,
            _ => REG_EXTENDED | REG_NEWLINE,
        };
        let eflags = match r.below(4) {
            0 => 0,
            1 => REG_NOTBOL,
            2 => REG_NOTEOL,
            _ => REG_NOTBOL | REG_NOTEOL,
        };

        let fl_run = run(
            fl::regcomp,
            fl::regexec,
            fl::regfree,
            &cpat,
            &cinp,
            cflags,
            eflags,
        );
        let lc_run = run(regcomp, regexec, regfree, &cpat, &cinp, cflags, eflags);

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
                "pat={pat:?} subj={subj:?} cflags={cflags} eflags={eflags}\n    fl   =(m={fl_match}, {:?})\n    glibc=(m={lc_match}, {:?})",
                fl_run.pm, lc_run.pm
            ));
        }
    }

    assert!(
        divs.is_empty(),
        "regex newline/eflags diverged from glibc ({compared} compared, {validity_skips} validity skips):\n{}",
        divs.join("\n")
    );
    eprintln!(
        "regex newline/eflags fuzz: {compared} compared, {validity_skips} validity skips, 0 divergences"
    );
}
