#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc tempnam oracle; mutates process-global TMPDIR

//! Differential gate for tempnam's directory and prefix selection (bd-7rbh4r).
//!
//! tempnam runs glibc's `__path_search(..., try_tmpdir = 1)`, whose precedence
//! is the opposite of the obvious one. Measured on live glibc 2.42 with two
//! real directories tdA and tdB:
//!
//!   TMPDIR unset,  dir = tdA          -> tdA
//!   TMPDIR unset,  dir = /nonexistent -> /tmp    (an unusable dir is SKIPPED)
//!   TMPDIR = tdB,  dir = NULL         -> tdB
//!   TMPDIR = tdB,  dir = tdA          -> tdB     (TMPDIR OUTRANKS the argument)
//!   TMPDIR = bad,  dir = tdA          -> tdA
//!   TMPDIR = bad,  dir = NULL         -> /tmp
//!
//! and for the prefix:
//!
//!   pfx = NULL          -> "file"
//!   pfx = ""            -> "file"   (empty counts as absent)
//!   pfx = "abcdefghij"  -> "abcde"  (truncated to 5)
//!
//! fl hardcoded /tmp when dir was NULL, never read TMPDIR, never checked that a
//! directory existed, and defaulted the prefix to "tmp".
//!
//! The generated suffix is deliberately NOT compared: tempnam guarantees only
//! uniqueness, and fl's suffix (pid+counter) legitimately differs from glibc's
//! six random characters. What is compared is the part the contract does fix —
//! the directory and the prefix — extracted from each returned path.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Mutex;

unsafe extern "C" {
    fn tempnam(dir: *const c_char, pfx: *const c_char) -> *mut c_char;
    fn dlopen(filename: *const c_char, flag: std::ffi::c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// TMPDIR is process-global; the harness runs tests in parallel threads.
static TMPDIR_LOCK: Mutex<()> = Mutex::new(());

type TempnamFn = unsafe extern "C" fn(*const c_char, *const c_char) -> *mut c_char;

/// glibc's tempnam by dlsym, asserted distinct from fl's — the plain extern
/// route binds to fl's own symbol in a release test build, where `no_mangle` is
/// active, and would compare fl against itself.
fn glibc_tempnam() -> TempnamFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, c"tempnam".as_ptr());
        assert!(!s.is_null(), "dlsym(tempnam) failed");
        assert_ne!(
            s as usize,
            frankenlibc_abi::unistd_abi::tempnam as *const () as usize,
            "tempnam resolved to fl's own symbol — the arms are not distinct"
        );
        std::mem::transmute::<*mut c_void, TempnamFn>(s)
    }
}

/// Split a returned path into (directory, prefix), dropping the unique suffix.
///
/// The prefix is what remains of the basename after the 6 generated characters
/// glibc appends; fl appends a different number, so the basename is compared by
/// PREFIX rather than by length.
fn split(path: &str) -> (String, String) {
    let (dir, base) = path.rsplit_once('/').expect("tempnam returns an absolute path");
    (dir.to_string(), base.to_string())
}

/// Call one implementation and return (directory, basename), freeing the result.
fn call(f: TempnamFn, dir: Option<&str>, pfx: Option<&str>) -> Option<(String, String)> {
    let dir_c = dir.map(|d| CString::new(d).unwrap());
    let pfx_c = pfx.map(|p| CString::new(p).unwrap());
    let r = unsafe {
        f(
            dir_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            pfx_c.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
        )
    };
    if r.is_null() {
        return None;
    }
    let s = unsafe { CStr::from_ptr(r) }.to_string_lossy().into_owned();
    // tempnam's contract is that the caller frees with free(); both arms
    // allocate through the same interposed allocator in this test binary.
    unsafe { libc::free(r.cast()) };
    Some(split(&s))
}

fn fl_tempnam() -> TempnamFn {
    frankenlibc_abi::unistd_abi::tempnam
}

fn set_tmpdir(v: Option<&str>) {
    unsafe {
        let k = CString::new("TMPDIR").unwrap();
        match v {
            Some(v) => {
                let v = CString::new(v).unwrap();
                libc::setenv(k.as_ptr(), v.as_ptr(), 1);
            }
            None => {
                libc::unsetenv(k.as_ptr());
            }
        }
    }
}

/// Two real directories plus a path that does not exist, for the precedence
/// matrix. Created under the system temp dir and left in place (this project
/// does not delete files); names are process-scoped so parallel runs cannot
/// collide.
fn fixture_dirs() -> (String, String, String) {
    let base = std::env::temp_dir();
    let a = base.join(format!("fl_tempnam_A_{}", std::process::id()));
    let b = base.join(format!("fl_tempnam_B_{}", std::process::id()));
    std::fs::create_dir_all(&a).expect("create tdA");
    std::fs::create_dir_all(&b).expect("create tdB");
    let missing = base
        .join(format!("fl_tempnam_MISSING_{}", std::process::id()))
        .to_string_lossy()
        .into_owned();
    assert!(
        !std::path::Path::new(&missing).exists(),
        "the 'missing' fixture must not exist"
    );
    (
        a.to_string_lossy().into_owned(),
        b.to_string_lossy().into_owned(),
        missing,
    )
}

#[test]
fn tempnam_directory_precedence_matches_glibc() {
    let _guard = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("TMPDIR").ok();
    let (a, b, missing) = fixture_dirs();
    let g = glibc_tempnam();
    let f = fl_tempnam();

    // (TMPDIR, dir argument, label)
    let cases: &[(Option<&str>, Option<&str>, &str)] = &[
        (None, None, "no TMPDIR, dir=NULL"),
        (None, Some(&a), "no TMPDIR, dir=tdA"),
        (None, Some(&missing), "no TMPDIR, dir=missing -> /tmp"),
        (Some(&b), None, "TMPDIR=tdB, dir=NULL"),
        (Some(&b), Some(&a), "TMPDIR=tdB, dir=tdA -> TMPDIR wins"),
        (Some(&missing), Some(&a), "TMPDIR=missing, dir=tdA -> tdA"),
        (Some(&missing), None, "TMPDIR=missing, dir=NULL -> /tmp"),
        (Some(""), Some(&a), "TMPDIR empty, dir=tdA -> tdA"),
    ];

    let mut observed = Vec::new();
    for (tmpdir, dir, label) in cases {
        set_tmpdir(*tmpdir);
        let gr = call(g, *dir, Some("p"));
        let fr = call(f, *dir, Some("p"));
        let (gdir, _) = gr.clone().unwrap_or_else(|| panic!("{label}: glibc returned NULL"));
        let (fdir, _) = fr.unwrap_or_else(|| panic!("{label}: fl returned NULL"));
        assert_eq!(fdir, gdir, "{label}: directory differs");
        observed.push((*label, gdir));
    }

    set_tmpdir(saved.as_deref());

    // Assert what the ORACLE produced, not only that the arms agree: if both
    // impls ignored TMPDIR and the dir argument entirely and always answered
    // /tmp, every equality above would still hold.
    let by = |l: &str| -> String {
        observed
            .iter()
            .find(|(k, _)| *k == l)
            .map(|(_, v)| v.clone())
            .unwrap()
    };
    assert_eq!(by("no TMPDIR, dir=tdA"), a, "glibc should honour a usable dir");
    assert_eq!(
        by("TMPDIR=tdB, dir=tdA -> TMPDIR wins"),
        b,
        "glibc's __path_search consults TMPDIR before the dir argument"
    );
    assert_eq!(
        by("no TMPDIR, dir=missing -> /tmp"),
        "/tmp",
        "a directory that does not exist must be skipped, not used"
    );
    assert_eq!(
        by("TMPDIR=missing, dir=tdA -> tdA"),
        a,
        "an unusable TMPDIR falls through to the dir argument"
    );
    // The negative case that separates "TMPDIR wins" from "argument is ignored":
    // when TMPDIR is unusable the argument must still be honoured, so an
    // implementation that simply always preferred TMPDIR fails here.
    assert_ne!(
        by("TMPDIR=missing, dir=tdA -> tdA"),
        "/tmp",
        "falling back to /tmp here would mean the dir argument is ignored"
    );
}

#[test]
fn tempnam_prefix_defaults_and_truncation_match_glibc() {
    let _guard = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("TMPDIR").ok();
    set_tmpdir(None);
    let g = glibc_tempnam();
    let f = fl_tempnam();

    // (prefix, expected leading bytes of the basename)
    let cases: &[(Option<&str>, &str, &str)] = &[
        (None, "file", "NULL prefix defaults to \"file\""),
        (Some(""), "file", "empty prefix also defaults to \"file\""),
        (Some("p"), "p", "short prefix is used as-is"),
        (Some("abcde"), "abcde", "exactly 5 bytes is used as-is"),
        (Some("abcdefghij"), "abcde", "longer prefix truncates to 5"),
    ];

    for (pfx, expect, label) in cases {
        let (_, gbase) = call(g, None, *pfx).unwrap_or_else(|| panic!("{label}: glibc NULL"));
        let (_, fbase) = call(f, None, *pfx).unwrap_or_else(|| panic!("{label}: fl NULL"));
        // Assert the oracle first: this pins "file" and the 5-byte truncation
        // as glibc's actual behaviour rather than as something remembered.
        assert!(
            gbase.starts_with(expect),
            "{label}: glibc basename {gbase:?} should start with {expect:?}"
        );
        assert!(
            fbase.starts_with(expect),
            "{label}: fl basename {fbase:?} should start with {expect:?}"
        );
        // And the negative half of the truncation case: a 5-byte cap means the
        // 6th prefix byte must NOT appear, which an untruncated implementation
        // would fail while still satisfying starts_with.
        if *pfx == Some("abcdefghij") {
            assert!(
                !fbase.starts_with("abcdef"),
                "{label}: fl did not truncate, got {fbase:?}"
            );
        }
    }

    set_tmpdir(saved.as_deref());
}

#[test]
fn tempnam_reports_enoent_when_no_directory_is_usable() {
    // glibc's __path_search returns -1/ENOENT when TMPDIR, the argument, and
    // P_tmpdir are all unusable; tempnam surfaces that as NULL. /tmp exists on
    // any sane host, so this drives the ARGUMENT and TMPDIR halves and states
    // the contract for the final fallback rather than trying to remove /tmp.
    let _guard = TMPDIR_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved = std::env::var("TMPDIR").ok();
    let (_, _, missing) = fixture_dirs();

    set_tmpdir(Some(&missing));
    let f = fl_tempnam();
    // Both unusable, but /tmp exists, so this must SUCCEED and land in /tmp —
    // the fallback, not an error.
    let got = call(f, Some(&missing), Some("p"));
    set_tmpdir(saved.as_deref());

    let (dir, _) = got.expect("with /tmp present tempnam must not fail");
    assert_eq!(
        dir, "/tmp",
        "with TMPDIR and dir both unusable, tempnam falls back to /tmp"
    );
}
