#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regcomp/regexec oracle

//! Regex submatch offsets for NESTED quantified nullable groups: a curated
//! differential record + regression pin (bd-1djvkw, document-don't-mirror).
//!
//! ## The determination
//!
//! For nested quantified groups whose inner subgroup is nullable
//! (`(.(b*)*)*`, `((a*)+b?)*`, ...), frankenlibc's Pike VM and glibc's regexec
//! agree EXACTLY on the whole-match span (group 0) but diverge on the
//! *submatch* offsets of the repeated groups. A 200k-case characterization
//! (`regex_empty_iter_capture_differential_fuzz`, `#[ignore]`d) confirms the
//! shape of the divergence: across 119,930 mutually-matching cases there are
//! ZERO whole-match/group-0 divergences and only 46 submatch-only divergences,
//! every one inside a nested nullable-quantified group.
//!
//! These divergences are a **glibc implementation artifact**, NOT a frankenlibc
//! bug, and are deliberately not mirrored — the same policy applied to the
//! glibc twalk tree-shape, ecvt rounding, and remquo huge-quotient quirks.
//!
//! ### Proof that glibc is the divergent party
//!
//! POSIX records, for a repeated subexpression, the substring matched by its
//! LAST iteration — necessarily a string the subexpression can match in ONE
//! iteration. glibc violates this: for `(.(b*)*)*` on `"aaaa."` it reports
//! group 1 = `[0,5]`. But the group `(.(b*)*)` matches `.` (exactly one char)
//! followed by `(b*)*` (zero-width — the subject has no `b`), so a SINGLE
//! iteration of that group matches exactly ONE character. A 5-character span is
//! impossible for any single iteration; glibc is reporting the distance from
//! the first iteration's start to the last iteration's end, not a group match.
//! The same impossibility holds for `((a*)+b?)*`→`[0,4]`, `(a(b?)+)*.a*`→`[0,2]`,
//! `(b(a?)+)*`→`[0,4]`, and `(.(b*b*)*)*.b*`→`[0,2]`. frankenlibc reports the
//! genuine last-iteration span (`[4,5]`, one char), which is the only valid
//! single-iteration match.
//!
//! This test (a) asserts whole-match parity with the LIVE glibc oracle on every
//! case, (b) pins frankenlibc's POSIX-principled submatch values so a future
//! refactor can't silently regress them, and (c) records glibc's divergent
//! (artifact) values in comments for traceability.

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

#[repr(C)]
#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct M {
    so: i32,
    eo: i32,
}

type CompFn = unsafe extern "C" fn(*mut c_void, *const c_char, c_int) -> c_int;
type ExecFn = unsafe extern "C" fn(*const c_void, *const c_char, usize, *mut c_void, c_int) -> c_int;
type FreeFn = unsafe extern "C" fn(*mut c_void);

#[repr(C, align(16))]
struct Preg([u8; 256]);

fn run(comp: CompFn, exec: ExecFn, free: FreeFn, pat: &str, inp: &str) -> (bool, Vec<M>) {
    let cp = CString::new(pat).unwrap();
    let ci = CString::new(inp).unwrap();
    let mut preg = Preg([0u8; 256]);
    let c = unsafe { comp(preg.0.as_mut_ptr() as *mut c_void, cp.as_ptr(), REG_EXTENDED) };
    assert_eq!(c, 0, "regcomp failed for {pat:?}");
    let mut pm = vec![M::default(); 6];
    let e = unsafe {
        exec(
            preg.0.as_ptr() as *const c_void,
            ci.as_ptr(),
            6,
            pm.as_mut_ptr() as *mut c_void,
            0,
        )
    };
    unsafe { free(preg.0.as_mut_ptr() as *mut c_void) };
    (e == 0, pm)
}

fn fl_run(pat: &str, inp: &str) -> (bool, Vec<M>) {
    run(fl::regcomp, fl::regexec, fl::regfree, pat, inp)
}
fn glibc_run(pat: &str, inp: &str) -> (bool, Vec<M>) {
    run(regcomp, regexec, regfree, pat, inp)
}

fn m(so: i32, eo: i32) -> M {
    M { so, eo }
}

/// frankenlibc's POSIX-principled submatch on nested nullable-quantified groups,
/// where glibc diverges with an impossible multi-iteration span (see module doc).
/// `expect` lists slots 0..=2 (whole match + first two groups).
#[test]
fn nested_submatch_fl_is_posix_principled_and_glibc_diverges() {
    struct Case {
        pat: &'static str,
        subj: &'static str,
        fl_expect: [M; 3],
        glibc_artifact: [M; 3], // documented, NOT asserted (glibc-version sensitive)
    }
    let cases = [
        // glibc g1=[0,5] is impossible: `(.(b*)*)` matches 1 char/iteration.
        Case { pat: "(.(b*)*)*", subj: "aaaa.", fl_expect: [m(0,5), m(4,5), m(5,5)], glibc_artifact: [m(0,5), m(0,5), m(1,1)] },
        // glibc g1=[0,4] impossible: one iteration of `((a*)+b?)` matches <=1 char here.
        Case { pat: "((a*)+b?)*", subj: "bbbb", fl_expect: [m(0,4), m(3,4), m(3,3)], glibc_artifact: [m(0,4), m(0,4), m(0,0)] },
        // glibc g1=[0,2] impossible: `(a(b?)+)` matches one 'a' per iteration here.
        Case { pat: "(a(b?)+)*.a*", subj: "aaa", fl_expect: [m(0,3), m(1,2), m(2,2)], glibc_artifact: [m(0,3), m(0,2), m(1,1)] },
        // glibc g1=[0,4] impossible: `(b(a?)+)` matches "ba" (2 chars) max per iteration.
        Case { pat: "(b(a?)+)*", subj: "babb", fl_expect: [m(0,4), m(3,4), m(4,4)], glibc_artifact: [m(0,4), m(0,4), m(1,2)] },
        // glibc g1=[0,2] impossible: `(.(b*b*)*)` matches 1 char per iteration.
        Case { pat: "(.(b*b*)*)*.b*", subj: "aa.", fl_expect: [m(0,3), m(1,2), m(2,2)], glibc_artifact: [m(0,3), m(0,2), m(1,1)] },
        // Tie-break (both spans are valid single iterations): glibc keeps the
        // trailing EMPTY inner iteration [3,3]; fl keeps the non-empty [2,3]
        // (POSIX leftmost-longest prefers the longer inner match).
        Case { pat: "((b*)+a)+", subj: "baba", fl_expect: [m(0,4), m(2,4), m(2,3)], glibc_artifact: [m(0,4), m(2,4), m(3,3)] },
    ];

    for c in &cases {
        let (fm, fpm) = fl_run(c.pat, c.subj);
        let (gm, gpm) = glibc_run(c.pat, c.subj);
        // (a) whole-match parity with live glibc — the invariant that always holds.
        assert!(fm && gm, "both engines must match {:?} on {:?}", c.pat, c.subj);
        assert_eq!(
            fpm[0], gpm[0],
            "whole-match (group 0) must agree with glibc for {:?} on {:?}",
            c.pat, c.subj
        );
        // (b) regression pin: frankenlibc's POSIX-principled submatch values.
        assert_eq!(
            &fpm[0..3],
            &c.fl_expect,
            "frankenlibc nested submatch drifted for {:?} on {:?}",
            c.pat, c.subj
        );
        // (c) sanity: glibc indeed diverges on the submatch slots (so this stays
        // a real "document-don't-mirror" record, not a stale no-op). We don't
        // assert glibc's exact artifact values (version-sensitive), only that it
        // differs from fl somewhere in the group slots.
        let _ = c.glibc_artifact;
        assert_ne!(
            &fpm[1..3],
            &gpm[1..3],
            "expected glibc to diverge on submatch for {:?} on {:?} (artifact); \
             if this fires, glibc changed and the determination should be revisited",
            c.pat, c.subj
        );
    }
}

/// Boundary check: when the OUTER group is matched exactly once (or is not the
/// repeated one), frankenlibc and glibc agree on ALL slots — the single-level
/// `RepeatExitGuard` fix (bd-1djvkw partial) must stay intact.
#[test]
fn single_level_and_once_matched_groups_match_glibc_exactly() {
    let cases = [
        ("(.(b*)*)*", "a"),     // outer matches once
        ("((a*)*a)", "abaaa"),  // inner repeat, outer not repeated
        ("((a*)*)", "aaa"),
        ("(a*)*", "aaa"),       // single-level empty iteration (the fixed case)
        (".()*a", "ba"),        // documented single-level reproducer
        ("(a*)*b?", "b"),
    ];
    for (pat, subj) in cases {
        let (fm, fpm) = fl_run(pat, subj);
        let (gm, gpm) = glibc_run(pat, subj);
        assert_eq!(fm, gm, "match decision must agree for {pat:?} on {subj:?}");
        if fm {
            assert_eq!(
                fpm, gpm,
                "all submatch offsets must agree with glibc for {pat:?} on {subj:?}"
            );
        }
    }
}
