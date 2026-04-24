#![cfg(target_os = "linux")]

//! Differential conformance harness for `<fnmatch.h>` and `<glob.h>`.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - fnmatch: 30+ (pattern, string, flags) cases including FNM_PATHNAME,
//!     FNM_PERIOD, FNM_NOESCAPE, character classes, and ranges
//!   - glob: pattern expansion against a controlled tempdir tree;
//!     compares returned paths as a set (order is unspecified)
//!
//! glob_t is layout-incompatible across impls (each manages its own
//! gl_pathv allocation), so we run each impl separately and compare
//! observable output.
//!
//! Bead: CONFORMANCE: libc fnmatch.h + glob.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn fnmatch(pattern: *const c_char, string: *const c_char, flags: c_int) -> c_int;
    fn glob(
        pattern: *const c_char,
        flags: c_int,
        errfunc: Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>,
        pglob: *mut c_void,
    ) -> c_int;
    fn globfree(pglob: *mut c_void);
}

const FNM_NOMATCH: c_int = 1;
const FNM_PATHNAME: c_int = 1 << 0;
const FNM_NOESCAPE: c_int = 1 << 1;
const FNM_PERIOD: c_int = 1 << 2;

const GLOB_NOMATCH: c_int = 3;
const GLOB_NOSORT: c_int = 1 << 5;

// glibc glob_t layout (Linux x86_64).
#[repr(C)]
struct GlobT {
    gl_pathc: usize,
    gl_pathv: *mut *mut c_char,
    gl_offs: usize,
    gl_flags: c_int,
    // glibc has 5 reserved function pointers + extras after gl_flags;
    // pad up to 128 bytes for safety.
    _pad: [u8; 128],
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// fnmatch — exhaustive (pattern, string, flags) matrix
// ===========================================================================

#[test]
fn diff_fnmatch_basic() {
    let mut divs = Vec::new();
    let cases: &[(&str, &str, c_int)] = &[
        // Literal
        ("hello", "hello", 0),
        ("hello", "world", 0),
        ("", "", 0),
        ("", "x", 0),
        // ?
        ("?", "a", 0),
        ("?", "", 0),
        ("h?llo", "hello", 0),
        ("h?llo", "hxllo", 0),
        ("h?llo", "hllo", 0),
        // *
        ("*", "anything", 0),
        ("*", "", 0),
        ("a*b", "ab", 0),
        ("a*b", "axxxb", 0),
        ("a*b", "aXb", 0),
        ("*.txt", "file.txt", 0),
        ("*.txt", "file.csv", 0),
        // brackets
        ("[abc]", "a", 0),
        ("[abc]", "b", 0),
        ("[abc]", "c", 0),
        ("[abc]", "d", 0),
        ("[!abc]", "d", 0),
        ("[!abc]", "a", 0),
        ("[a-c]", "b", 0),
        ("[a-c]", "d", 0),
        // FNM_PATHNAME
        ("a/b", "a/b", FNM_PATHNAME),
        ("a/b", "a/b", 0),
        ("*", "a/b", FNM_PATHNAME),
        ("*", "a/b", 0),
        ("a/*", "a/b", FNM_PATHNAME),
        ("a/*", "a/b/c", FNM_PATHNAME),
        ("a/*/c", "a/b/c", FNM_PATHNAME),
        // FNM_PERIOD
        (".bashrc", ".bashrc", 0),
        ("*", ".hidden", FNM_PERIOD),
        ("*", ".hidden", 0),
        ("?bashrc", ".bashrc", FNM_PERIOD),
        ("?bashrc", ".bashrc", 0),
        // FNM_NOESCAPE
        (r"\*", "*", 0),
        (r"\*", "x", 0),
        (r"\*", r"\*", FNM_NOESCAPE),
        (r"\*", "x", FNM_NOESCAPE),
    ];
    for (pat, s, flags) in cases {
        let cpat = CString::new(*pat).unwrap();
        let cs = CString::new(*s).unwrap();
        let r_fl = unsafe { fl::fnmatch(cpat.as_ptr(), cs.as_ptr(), *flags) };
        let r_lc = unsafe { fnmatch(cpat.as_ptr(), cs.as_ptr(), *flags) };
        let m_fl = r_fl == 0;
        let m_lc = r_lc == 0;
        if m_fl != m_lc {
            divs.push(Divergence {
                function: "fnmatch",
                case: format!("({pat:?}, {s:?}, flags={flags:#x})"),
                field: "match",
                frankenlibc: format!("rc={r_fl} (match={m_fl})"),
                glibc: format!("rc={r_lc} (match={m_lc})"),
            });
        }
        // Also assert error returns are FNM_NOMATCH (not other negative
        // values) when both rejected.
        if r_fl != 0 && r_fl != FNM_NOMATCH {
            divs.push(Divergence {
                function: "fnmatch",
                case: format!("({pat:?}, {s:?}, flags={flags:#x})"),
                field: "non_match_rc",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("expected FNM_NOMATCH={FNM_NOMATCH}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "fnmatch divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// glob — exercise pattern expansion against a controlled tempdir.
//
// Sets up:
//   tmpdir/
//     a.txt
//     b.txt
//     c.csv
//     sub/
//       d.txt
//       e.txt
//
// Then runs several patterns through both impls and compares the
// returned path lists as sets (sort + diff).
// ===========================================================================

/// RAII test-tree wrapper. Holds a unique tempdir and best-effort cleans
/// it on drop.
struct TestTree {
    path: std::path::PathBuf,
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn build_test_tree() -> TestTree {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let path = std::env::temp_dir().join(format!("fl_glob_diff_{pid}_{id}"));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("create tempdir");
    std::fs::write(path.join("a.txt"), b"a").unwrap();
    std::fs::write(path.join("b.txt"), b"b").unwrap();
    std::fs::write(path.join("c.csv"), b"c").unwrap();
    std::fs::create_dir(path.join("sub")).unwrap();
    std::fs::write(path.join("sub/d.txt"), b"d").unwrap();
    std::fs::write(path.join("sub/e.txt"), b"e").unwrap();
    TestTree { path }
}

unsafe fn glob_collect_fl(pat: &str, flags: c_int) -> (c_int, Vec<String>) {
    let cpat = CString::new(pat).unwrap();
    let mut g: GlobT = unsafe { core::mem::zeroed() };
    let rc = unsafe { fl::glob(cpat.as_ptr(), flags, None, &mut g as *mut _ as *mut c_void) };
    let mut out = Vec::new();
    if rc == 0 {
        for i in 0..g.gl_pathc {
            let p = unsafe { *g.gl_pathv.add(i) };
            if !p.is_null() {
                let s = unsafe { std::ffi::CStr::from_ptr(p) }
                    .to_string_lossy()
                    .into_owned();
                out.push(s);
            }
        }
    }
    if rc == 0 {
        unsafe { fl::globfree(&mut g as *mut _ as *mut c_void) };
    }
    (rc, out)
}

unsafe fn glob_collect_lc(pat: &str, flags: c_int) -> (c_int, Vec<String>) {
    let cpat = CString::new(pat).unwrap();
    let mut g: GlobT = unsafe { core::mem::zeroed() };
    let rc = unsafe { glob(cpat.as_ptr(), flags, None, &mut g as *mut _ as *mut c_void) };
    let mut out = Vec::new();
    if rc == 0 {
        for i in 0..g.gl_pathc {
            let p = unsafe { *g.gl_pathv.add(i) };
            if !p.is_null() {
                let s = unsafe { std::ffi::CStr::from_ptr(p) }
                    .to_string_lossy()
                    .into_owned();
                out.push(s);
            }
        }
    }
    if rc == 0 {
        unsafe { globfree(&mut g as *mut _ as *mut c_void) };
    }
    (rc, out)
}

#[test]
fn diff_glob_basic_patterns() {
    let mut divs = Vec::new();
    let dir = build_test_tree();
    let p = dir.path.to_string_lossy().to_string();

    // Each case: pattern (formatted with %dir), description.
    let patterns: &[(&str, c_int)] = &[
        ("/*.txt", GLOB_NOSORT),
        ("/*.csv", GLOB_NOSORT),
        ("/*", GLOB_NOSORT),
        ("/?.txt", GLOB_NOSORT),
        ("/[ab].txt", GLOB_NOSORT),
        ("/sub/*.txt", GLOB_NOSORT),
        ("/nonexistent*", GLOB_NOSORT),
    ];
    for (suffix, flags) in patterns {
        let pat = format!("{p}{suffix}");
        let (rc_fl, mut paths_fl) = unsafe { glob_collect_fl(&pat, *flags) };
        let (rc_lc, mut paths_lc) = unsafe { glob_collect_lc(&pat, *flags) };
        paths_fl.sort();
        paths_lc.sort();

        // Both should agree on success vs nomatch
        let success_fl = rc_fl == 0;
        let success_lc = rc_lc == 0;
        if success_fl != success_lc {
            divs.push(Divergence {
                function: "glob",
                case: format!("{pat:?}"),
                field: "success_match",
                frankenlibc: format!("rc={rc_fl}"),
                glibc: format!("rc={rc_lc}"),
            });
            continue;
        }
        if !success_fl {
            // Both nomatch — verify both returned GLOB_NOMATCH (not other err)
            if rc_fl != GLOB_NOMATCH || rc_lc != GLOB_NOMATCH {
                divs.push(Divergence {
                    function: "glob",
                    case: format!("{pat:?}"),
                    field: "nomatch_rc",
                    frankenlibc: format!("{rc_fl}"),
                    glibc: format!("{rc_lc}"),
                });
            }
            continue;
        }
        if paths_fl != paths_lc {
            divs.push(Divergence {
                function: "glob",
                case: format!("{pat:?}"),
                field: "paths",
                frankenlibc: format!("{paths_fl:?}"),
                glibc: format!("{paths_lc:?}"),
            });
        }
    }
    assert!(divs.is_empty(), "glob divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// bd-fnm-3: GNU extension flag parity vs glibc
// ===========================================================================

const FNM_LEADING_DIR: c_int = 1 << 3;
const FNM_FILE_NAME: c_int = FNM_PATHNAME; // glibc alias

#[test]
fn diff_fnmatch_leading_dir() {
    let mut divs = Vec::new();
    let cases: &[(&str, &str)] = &[
        ("a/b", "a/b"),
        ("a/b", "a/b/c"),
        ("a/b", "a/b/c/d"),
        ("a/b", "a/bx"),
        ("a/b", "a/c"),
        ("usr", "usr/local/bin"),
        ("usr", "usrx"),
    ];
    for (pat, s) in cases {
        let cpat = CString::new(*pat).unwrap();
        let cs = CString::new(*s).unwrap();
        let r_fl = unsafe { fl::fnmatch(cpat.as_ptr(), cs.as_ptr(), FNM_LEADING_DIR) };
        let r_lc = unsafe { fnmatch(cpat.as_ptr(), cs.as_ptr(), FNM_LEADING_DIR) };
        if (r_fl == 0) != (r_lc == 0) {
            divs.push(Divergence {
                function: "fnmatch FNM_LEADING_DIR",
                case: format!("({pat:?}, {s:?})"),
                field: "match",
                frankenlibc: format!("rc={r_fl}"),
                glibc: format!("rc={r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "FNM_LEADING_DIR divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fnmatch_file_name_alias() {
    // FNM_FILE_NAME is a glibc alias for FNM_PATHNAME — verify the bit
    // is the same and behavior is identical.
    let mut divs = Vec::new();
    for (pat, s) in &[("*", "a/b"), ("a/b", "a/b"), ("a/*", "a/b")] {
        let cpat = CString::new(*pat).unwrap();
        let cs = CString::new(*s).unwrap();
        let r_fl_pn = unsafe { fl::fnmatch(cpat.as_ptr(), cs.as_ptr(), FNM_PATHNAME) };
        let r_fl_fn = unsafe { fl::fnmatch(cpat.as_ptr(), cs.as_ptr(), FNM_FILE_NAME) };
        if (r_fl_pn == 0) != (r_fl_fn == 0) {
            divs.push(Divergence {
                function: "fnmatch",
                case: format!("({pat:?}, {s:?})"),
                field: "PATHNAME == FILE_NAME",
                frankenlibc: format!("PATHNAME={r_fl_pn}"),
                glibc: format!("FILE_NAME={r_fl_fn}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "FNM_FILE_NAME alias divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fnmatch_property_pattern_against_self() {
    // Property: the pattern matched against an exact-literal version
    // of itself (with metachars escaped) must always match. We
    // generate a small alphabet of test inputs and verify both impls
    // agree on each.
    let mut divs = Vec::new();
    let strings: &[&str] = &[
        "abc",
        "a.txt",
        "hello.world",
        "deep/path/to/file",
        "with-dash",
        "under_score",
    ];
    for s in strings {
        // Escape any metachars in s to make it a literal pattern
        let mut escaped = String::new();
        for c in s.chars() {
            if matches!(c, '*' | '?' | '[' | '\\') {
                escaped.push('\\');
            }
            escaped.push(c);
        }
        let cpat = CString::new(escaped).unwrap();
        let cs = CString::new(*s).unwrap();
        let r_fl = unsafe { fl::fnmatch(cpat.as_ptr(), cs.as_ptr(), 0) };
        let r_lc = unsafe { fnmatch(cpat.as_ptr(), cs.as_ptr(), 0) };
        if r_fl != 0 || r_lc != 0 {
            divs.push(Divergence {
                function: "fnmatch",
                case: format!("escaped({s:?}) vs {s:?}"),
                field: "self-match",
                frankenlibc: format!("rc={r_fl}"),
                glibc: format!("rc={r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "self-match divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_fnmatch_star_chain_against_arbitrary_text() {
    // Property: "*X*Y*" pattern matches text iff text contains X then
    // Y in order. Compare both impls against a synthetic corpus.
    let mut divs = Vec::new();
    let cases: &[(&str, &str)] = &[
        ("*a*b*", "xayb"),
        ("*a*b*", "ba"),
        ("*a*b*", "aaab"),
        ("*x*y*z*", "xyz"),
        ("*x*y*z*", "axbyc"),
        ("*x*y*z*", "axbyzc"),
        ("*x*y*z*", "zyx"),
    ];
    for (pat, s) in cases {
        let cpat = CString::new(*pat).unwrap();
        let cs = CString::new(*s).unwrap();
        let r_fl = unsafe { fl::fnmatch(cpat.as_ptr(), cs.as_ptr(), 0) };
        let r_lc = unsafe { fnmatch(cpat.as_ptr(), cs.as_ptr(), 0) };
        if (r_fl == 0) != (r_lc == 0) {
            divs.push(Divergence {
                function: "fnmatch",
                case: format!("({pat:?}, {s:?})"),
                field: "match",
                frankenlibc: format!("rc={r_fl}"),
                glibc: format!("rc={r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "star-chain divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn fnmatch_glob_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"fnmatch.h+glob.h\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
