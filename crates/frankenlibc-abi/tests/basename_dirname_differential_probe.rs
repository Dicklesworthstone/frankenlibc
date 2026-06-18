//! Live differential probe: FrankenLibC POSIX libgen basename/dirname
//! (`__xpg_basename` + `dirname`, which may modify their input) vs host glibc
//! `<libgen.h>`.
//!
//! This used to compare against hand-copied glibc strings. The live harness
//! catches drift in both the returned component and the caller-buffer mutation
//! contract for classic edge cases: "/", "//", "///", trailing slashes, empty
//! string, ".", "..", hidden files, and multi-slash runs.

use std::ffi::{CStr, c_char};

use frankenlibc_abi::stdlib_abi;
use frankenlibc_abi::unistd_abi;

unsafe extern "C" {
    #[link_name = "__xpg_basename"]
    fn libc_xpg_basename(path: *mut c_char) -> *mut c_char;

    #[link_name = "dirname"]
    fn libc_dirname(path: *mut c_char) -> *mut c_char;
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PointerLocation {
    Static,
    Offset(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    result: Vec<u8>,
    location: PointerLocation,
    mutated_buffer: Vec<u8>,
}

fn pointer_location(base: *const u8, len: usize, ptr: *const c_char) -> PointerLocation {
    let start = base as usize;
    let end = start + len;
    let addr = ptr as usize;
    if (start..end).contains(&addr) {
        PointerLocation::Offset(addr - start)
    } else {
        PointerLocation::Static
    }
}

fn observe_with(
    input: &str,
    func: unsafe extern "C" fn(*mut c_char) -> *mut c_char,
) -> Observation {
    let mut buf = input.as_bytes().to_vec();
    buf.push(0);
    let base = buf.as_mut_ptr();
    // SAFETY: each case owns a fresh NUL-terminated mutable path buffer.
    let ptr = unsafe { func(base.cast::<c_char>()) };
    assert!(!ptr.is_null(), "libgen functions should not return NULL");
    Observation {
        // SAFETY: both implementations return valid NUL-terminated strings for
        // these valid path inputs.
        result: unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() },
        location: pointer_location(base, buf.len(), ptr),
        mutated_buffer: buf,
    }
}

fn run_basename(input: &str, host: bool) -> Observation {
    if host {
        observe_with(input, libc_xpg_basename)
    } else {
        observe_with(input, unistd_abi::__xpg_basename)
    }
}

fn run_dirname(input: &str, host: bool) -> Observation {
    if host {
        observe_with(input, libc_dirname)
    } else {
        observe_with(input, stdlib_abi::dirname)
    }
}

const PATH_CASES: &[&str] = &[
    "/usr/lib",
    "/usr/",
    "usr",
    "/",
    "//",
    ".",
    "..",
    "",
    "a/b/",
    "///",
    "a//b",
    "/a",
    "a/b",
    "/usr/lib/",
    "foo.txt",
    "dir/.hidden",
    "////a////b////",
    "..//..",
    "/.",
    "x/",
    "/single",
];

fn assert_live_match(function: &'static str, input: &str, fl: Observation, glibc: Observation) {
    assert_eq!(
        fl, glibc,
        "{function}({input:?}) diverged from live glibc\nfrankenlibc={fl:#?}\nglibc={glibc:#?}"
    );
}

#[test]
fn xpg_basename_matches_live_glibc_result_pointer_and_mutation() {
    for input in PATH_CASES {
        assert_live_match(
            "__xpg_basename",
            input,
            run_basename(input, false),
            run_basename(input, true),
        );
    }
}

#[test]
fn dirname_matches_live_glibc_result_pointer_and_mutation() {
    for input in PATH_CASES {
        assert_live_match(
            "dirname",
            input,
            run_dirname(input, false),
            run_dirname(input, true),
        );
    }
}

#[test]
fn basename_dirname_differential_battery() {
    let mut diffs = Vec::new();
    for input in PATH_CASES {
        let base = run_basename(input, false);
        let host_base = run_basename(input, true);
        if base != host_base {
            diffs.push(format!(
                "__xpg_basename({input:?}): frankenlibc={base:?} glibc={host_base:?}"
            ));
        }

        let dir = run_dirname(input, false);
        let host_dir = run_dirname(input, true);
        if dir != host_dir {
            diffs.push(format!(
                "dirname({input:?}): frankenlibc={dir:?} glibc={host_dir:?}"
            ));
        }
    }
    assert!(
        diffs.is_empty(),
        "basename/dirname diverge from live glibc in {} case(s):\n{}",
        diffs.len(),
        diffs.join("\n")
    );
}
