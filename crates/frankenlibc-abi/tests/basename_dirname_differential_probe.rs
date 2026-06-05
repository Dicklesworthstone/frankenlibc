//! Differential probe: frankenlibc POSIX libgen basename/dirname
//! (__xpg_basename + dirname, which modify their input) vs glibc <libgen.h>.
//! Covers the classic edge-case minefield: "/", "//", "///", trailing slashes,
//! empty string, ".", "..", hidden files, and multi-slash runs. glibc
//! reference captured from a C probe.

use std::ffi::{CStr, c_char};

use frankenlibc_abi::stdlib_abi;
use frankenlibc_abi::unistd_abi;

fn run_basename(input: &str) -> String {
    let mut buf = input.as_bytes().to_vec();
    buf.push(0);
    let p = unsafe { unistd_abi::__xpg_basename(buf.as_mut_ptr() as *mut c_char) };
    if p.is_null() {
        return "NULL".to_string();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn run_dirname(input: &str) -> String {
    let mut buf = input.as_bytes().to_vec();
    buf.push(0);
    let p = unsafe { stdlib_abi::dirname(buf.as_mut_ptr() as *mut c_char) };
    if p.is_null() {
        return "NULL".to_string();
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

#[test]
fn basename_dirname_differential_battery() {
    // (input, glibc basename, glibc dirname)
    let cases: &[(&str, &str, &str)] = &[
        ("/usr/lib", "lib", "/usr"),
        ("/usr/", "usr", "/"),
        ("usr", "usr", "."),
        ("/", "/", "/"),
        ("//", "/", "//"),
        (".", ".", "."),
        ("..", "..", "."),
        ("", ".", "."),
        ("a/b/", "b", "a"),
        ("///", "/", "/"),
        ("a//b", "b", "a"),
        ("/a", "a", "/"),
        ("a/b", "b", "a"),
        ("/usr/lib/", "lib", "/usr"),
        ("foo.txt", "foo.txt", "."),
        ("dir/.hidden", ".hidden", "dir"),
        ("////a////b////", "b", "////a"),
        ("..//..", "..", ".."),
        ("/.", ".", "/"),
        ("x/", "x", "."),
        ("/single", "single", "/"),
    ];

    let mut diffs = Vec::new();
    for (input, exp_base, exp_dir) in cases {
        let base = run_basename(input);
        if base != *exp_base {
            diffs.push(format!(
                "basename({input:?}): frankenlibc={base:?} glibc={exp_base:?}"
            ));
        }
        let dir = run_dirname(input);
        if dir != *exp_dir {
            diffs.push(format!(
                "dirname({input:?}): frankenlibc={dir:?} glibc={exp_dir:?}"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "basename/dirname diverge from glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
