//! Conformance gate for the V7/BSD re_comp/re_exec interface vs host glibc.
//! glibc's re_comp uses the GNU default syntax (re_syntax_options == 0), where
//! bare `+`/`?` are quantifiers and escaped `\+`/`\?` are literal — the OPPOSITE
//! of POSIX BRE. fl's re_comp now translates a V7 pattern to the BRE its engine
//! compiles. Expected results were captured from a gcc oracle calling the real
//! glibc re_comp/re_exec.
//!
//! Intervals (`\{n,m\}` / bare `{n,m}`) are literal in syntax 0 and the
//! preprocessor now reproduces that. The one remaining engine-superset gap is
//! POSIX `[[:class:]]`: glibc syntax 0 takes it literally while fl's BRE engine
//! recognises it, so those constructs are deliberately NOT covered here.
//!
//! ## Live arm added 2026-08-16 (bd-v0388t)
//!
//! "Expected results were captured from a gcc oracle calling the real glibc
//! re_comp/re_exec" — once, offline. The test was named `recomp_matches_glibc`
//! and never called glibc. That is a poor bargain for THIS interface in
//! particular: what these cases pin is `re_syntax_options == 0`, a GNU default
//! rather than a standard, and the table encodes it indirectly through 38
//! match/no-match answers. A single change to that default would move most of
//! the rows at once.
//!
//! The table is KEPT and the same cases now run through a dlsym-resolved
//! `re_comp`/`re_exec` as well. Each arm compiles before it executes, so within
//! one test fl's buffer and glibc's are never confused for each other.
//!
//! ACROSS tests is the part that bites, and it is why `RE_STATE` below exists:
//! the buffers are per-LIBRARY globals, not per-thread, so two tests running
//! concurrently — libtest's default — corrupt each other regardless of which
//! arm each is driving. Adding the second test to this file is what created
//! that hazard; the guard is what contains it.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use frankenlibc_abi::glibc_internal_abi as g;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type ReComp = unsafe extern "C" fn(*const c_char) -> *const c_char;
type ReExec = unsafe extern "C" fn(*const c_char) -> c_int;

fn host_re_comp() -> ReComp {
    // SAFETY: signature matches C's re_comp exactly.
    unsafe { dlsym_oracle::host_fn(c"re_comp", g::re_comp as *const ()) }
}

fn host_re_exec() -> ReExec {
    // SAFETY: signature matches C's re_exec exactly.
    unsafe { dlsym_oracle::host_fn(c"re_exec", g::re_exec as *const ()) }
}

/// Serialises every test in this file, because `re_comp`/`re_exec` are NOT
/// REENTRANT — in fl or in glibc.
///
/// The V7/BSD interface holds ONE compiled pattern per library in a process
/// global: fl in `RE_COMPILED_BUF`, glibc in its own static. `re_comp` writes
/// it and `re_exec` reads it, so two threads interleaving compile/exec pairs
/// will execute one thread's subject against the other's pattern. That is a
/// caller error against the API's contract, not a defect in either
/// implementation.
///
/// MEASURED, not theorised (2026-08-16). This file had one test until a live
/// glibc arm was added, and libtest runs tests in PARALLEL by default. Every
/// verification run of the new arm had used `--test-threads=1`, so the hazard
/// stayed invisible until a placement/contention sweep ran the suite the way
/// CI does. It failed exactly as the shape predicts:
///
/// ```text
///   re_comp("\(ab\)*"); re_exec("ababab") = 0, glibc = 1
///   re_comp("\(a\)+");  re_exec("aaa")    = 0, glibc = 1
///   re_comp("a?");      re_exec("x")      = 0, glibc = 1
/// ```
///
/// — subjects matched against the wrong pattern, in both directions.
///
/// A new test in this file MUST take this guard. `into_inner` on poison is
/// deliberate: a panic in one test has already been reported, and turning it
/// into a second, misleading "poisoned mutex" failure in the next test would
/// hide the original.
static RE_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

// (pattern, string, glibc re_exec result: 1=match, 0=no match)
const CASES: &[(&str, &str, i32)] = &[
    ("a.c", "abc", 1),
    ("a.c", "axc", 1),
    ("a.c", "ac", 0),
    ("^foo$", "foo", 1),
    ("^foo$", "foobar", 0),
    ("[0-9]+", "abc123", 1),
    ("[0-9]+", "abcdef", 0),
    ("a*", "bbb", 1),
    ("\\(ab\\)*", "ababab", 1),
    ("hello", "world", 0),
    ("a+", "aaa", 1),
    ("a+", "b", 0),
    ("a?b", "b", 1),
    ("a?b", "ab", 1),
    ("a?b", "xb", 1),
    ("[a+]", "+", 1),
    ("[a+]", "x", 0),
    ("a\\+", "a+", 1),
    ("a\\+", "aa", 0),
    ("a\\?", "a?", 1),
    ("a\\?", "ab", 0),
    ("+a", "+a", 1),
    ("+a", "a", 0),
    ("\\(a\\)+", "aaa", 1),
    ("\\(ab\\)+c", "ababc", 1),
    ("colou?r", "color", 1),
    ("colou?r", "colour", 1),
    ("a?", "x", 1),
    ("go+gle", "gooogle", 1),
    ("go+gle", "gogle", 1),
    ("[]a]", "]", 1),
    ("x[]a]y", "x]y", 1),
    // glibc syntax-0 has NO intervals: \{n,m\} and bare {n,m} are literal braces.
    ("a\\{2,3\\}", "a{2,3}", 1),
    ("a\\{2,3\\}", "aaa", 0),
    ("a{2}", "a{2}", 1),
    ("a{2}", "aa", 0),
    ("x\\{1\\}y", "x{1}y", 1),
    ("x\\{1\\}y", "xy", 0),
];

#[test]
fn recomp_matches_glibc() {
    let _re_state = RE_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let mut div: Vec<String> = Vec::new();
    for &(pat, s, want) in CASES {
        let cp = CString::new(pat).unwrap();
        let e = unsafe { g::re_comp(cp.as_ptr()) };
        if !e.is_null() {
            div.push(format!(
                "re_comp({pat:?}) returned an error (want match={want})"
            ));
            continue;
        }
        let cs = CString::new(s).unwrap();
        let got = unsafe { g::re_exec(cs.as_ptr()) };
        if got != want {
            div.push(format!(
                "re_comp({pat:?}); re_exec({s:?}) = {got}, glibc = {want}"
            ));
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
    assert!(
        div.is_empty(),
        "re_comp/re_exec divergences vs glibc ({}):\n  {}",
        div.len(),
        div.join("\n  ")
    );
}

/// The same 38 cases, against the glibc that is actually running.
///
/// Each arm compiles and then executes its own pattern before the other arm is
/// touched, because `re_comp` stores the compiled pattern in a per-library
/// global and interleaving the two would compare whichever buffer was written
/// last.
#[test]
fn recomp_matches_live_glibc_on_the_same_cases() {
    let _re_state = RE_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let comp = host_re_comp();
    let exec = host_re_exec();
    let mut fl_vs_live: Vec<String> = Vec::new();
    let mut host_moved: Vec<String> = Vec::new();
    let mut compared = 0usize;

    for &(pat, s, want) in CASES {
        let cp = CString::new(pat).unwrap();
        let cs = CString::new(s).unwrap();

        let fl_err = unsafe { g::re_comp(cp.as_ptr()) };
        let fl_got = if fl_err.is_null() {
            unsafe { g::re_exec(cs.as_ptr()) }
        } else {
            -1
        };

        // SAFETY: both pointers are NUL-terminated CStrings that outlive the calls.
        let host_err = unsafe { comp(cp.as_ptr()) };
        let host_got = if host_err.is_null() {
            // SAFETY: the host arm compiled successfully, so its buffer is live.
            unsafe { exec(cs.as_ptr()) }
        } else {
            -1
        };

        compared += 1;
        // A compile error is encoded as -1 rather than skipped: "one arm
        // rejected the pattern" is a divergence, not an absence of data.
        if fl_got != host_got {
            fl_vs_live.push(format!(
                "re_comp({pat:?}); re_exec({s:?}): fl={fl_got} live={host_got} \
                 (-1 = re_comp reported an error)"
            ));
        }
        if host_got != want {
            host_moved.push(format!(
                "re_comp({pat:?}); re_exec({s:?}): live={host_got} golden={want}"
            ));
        }
    }

    // NULL-pattern reuse, through the host arm this time.
    let cz = CString::new("z").unwrap();
    // SAFETY: NUL-terminated pattern, then the documented NULL reuse form.
    unsafe {
        assert!(
            comp(cz.as_ptr()).is_null(),
            "live glibc re_comp(\"z\") reported an error"
        );
        assert!(
            comp(std::ptr::null()).is_null(),
            "live glibc re_comp(NULL) should reuse the previous pattern"
        );
        assert_eq!(
            exec(cz.as_ptr()),
            1,
            "live glibc re_exec after NULL-reuse should match"
        );
    }

    assert_eq!(compared, CASES.len(), "not every case reached the live arm");
    assert!(
        fl_vs_live.is_empty() && host_moved.is_empty(),
        "re_comp/re_exec: {} fl-vs-live divergence(s), {} case(s) where LIVE GLIBC differs from \
         the frozen golden (that second list means the host's re_syntax_options default moved, \
         not fl):\n  {}\n  {}",
        fl_vs_live.len(),
        host_moved.len(),
        fl_vs_live.join("\n  "),
        host_moved.join("\n  ")
    );
}
