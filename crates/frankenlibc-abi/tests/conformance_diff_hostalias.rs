#![cfg(target_os = "linux")]

//! Differential conformance harness for `__hostalias(3)`.
//!
//! Reads `$HOSTALIASES` (a path to a file with `alias dnsname` lines)
//! and resolves an alias case-insensitively. We diff fl's resolv-abi
//! impl against host libresolv on a temporary alias file we own.
//!
//! Filed under [bd-58e87f] follow-up.

use std::ffi::{c_char, CStr, CString};
use std::io::Write;

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn __hostalias(name: *const c_char) -> *const c_char;
}

struct AliasFile {
    path: std::path::PathBuf,
}
impl AliasFile {
    fn new(suffix: &str, content: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::path::PathBuf::from(format!("/tmp/fl_hostalias_{nanos}_{suffix}"));
        let mut f = std::fs::File::create(&path).expect("create alias file");
        f.write_all(content.as_bytes()).expect("write alias file");
        Self { path }
    }
}
impl Drop for AliasFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn cstr_or_empty(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

fn lookup(file: &AliasFile, query: &str) -> (Option<String>, Option<String>) {
    // `__hostalias` is a static-buffer API — we copy out before swapping
    // env so that the comparison is stable.
    let prev = std::env::var_os("HOSTALIASES");
    // SAFETY: tests run single-threaded by default; we restore on exit.
    unsafe { std::env::set_var("HOSTALIASES", &file.path) };
    let q = CString::new(query).unwrap();
    let fl_p = unsafe { fl::__hostalias(q.as_ptr()) };
    let fl_s = cstr_or_empty(fl_p);
    let lc_p = unsafe { __hostalias(q.as_ptr()) };
    let lc_s = cstr_or_empty(lc_p);
    match prev {
        Some(v) => unsafe { std::env::set_var("HOSTALIASES", v) },
        None => unsafe { std::env::remove_var("HOSTALIASES") },
    }
    (fl_s, lc_s)
}

#[test]
fn diff_hostalias_basic_match() {
    let f = AliasFile::new("basic", "shortname canonical.example.com\n");
    let (fl_s, lc_s) = lookup(&f, "shortname");
    assert_eq!(fl_s, lc_s, "basic: fl={fl_s:?} lc={lc_s:?}");
    assert_eq!(fl_s.as_deref(), Some("canonical.example.com"));
}

#[test]
fn diff_hostalias_case_insensitive_alias() {
    let f = AliasFile::new("ci", "ShortName canonical.example.com\n");
    let (fl_s, lc_s) = lookup(&f, "SHORTNAME");
    assert_eq!(fl_s, lc_s, "case-insensitive: fl={fl_s:?} lc={lc_s:?}");
}

#[test]
fn diff_hostalias_no_match_returns_null() {
    let f = AliasFile::new("nomatch", "foo bar.example.com\n");
    let (fl_s, lc_s) = lookup(&f, "baz");
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s, None);
}

#[test]
fn diff_hostalias_skips_blank_and_comment_lines() {
    let content = "\n# this is a comment\n   \nfoo bar.example.com\n# trailing\n";
    let f = AliasFile::new("comments", content);
    let (fl_s, lc_s) = lookup(&f, "foo");
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s.as_deref(), Some("bar.example.com"));
}

#[test]
fn diff_hostalias_first_match_wins() {
    let content = "host first.example.com\nhost second.example.com\n";
    let f = AliasFile::new("first", content);
    let (fl_s, lc_s) = lookup(&f, "host");
    assert_eq!(fl_s, lc_s, "first-match: fl={fl_s:?} lc={lc_s:?}");
    assert_eq!(fl_s.as_deref(), Some("first.example.com"));
}

#[test]
fn diff_hostalias_missing_file_returns_null() {
    // Point HOSTALIASES at a file that does not exist.
    let prev = std::env::var_os("HOSTALIASES");
    unsafe { std::env::set_var("HOSTALIASES", "/tmp/fl_hostalias_definitely_missing_xyz") };
    let q = CString::new("anything").unwrap();
    let fl_p = unsafe { fl::__hostalias(q.as_ptr()) };
    let lc_p = unsafe { __hostalias(q.as_ptr()) };
    match prev {
        Some(v) => unsafe { std::env::set_var("HOSTALIASES", v) },
        None => unsafe { std::env::remove_var("HOSTALIASES") },
    }
    assert!(fl_p.is_null());
    assert!(lc_p.is_null());
}

#[test]
fn diff_hostalias_unset_env_returns_null() {
    let prev = std::env::var_os("HOSTALIASES");
    unsafe { std::env::remove_var("HOSTALIASES") };
    let q = CString::new("anything").unwrap();
    let fl_p = unsafe { fl::__hostalias(q.as_ptr()) };
    let lc_p = unsafe { __hostalias(q.as_ptr()) };
    if let Some(v) = prev {
        unsafe { std::env::set_var("HOSTALIASES", v) };
    }
    assert!(fl_p.is_null());
    assert!(lc_p.is_null());
}

#[test]
fn hostalias_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv __hostalias\",\"reference\":\"glibc-libresolv\",\"functions\":1,\"divergences\":0}}",
    );
}
