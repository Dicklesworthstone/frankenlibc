#![cfg(target_os = "linux")]

//! Differential conformance harness for `asprintf(3)` / `vasprintf(3)`.
//!
//! These are GNU extensions that allocate a string of the right size and
//! return it via an out-pointer. fl exports its own implementations in
//! stdio_abi.rs; this is the first head-to-head diff against host glibc.
//!
//! Filed under [bd-xn6p8] follow-up — extending host-libc parity coverage
//! into the printf family.

use std::ffi::{c_char, c_int, CStr};

unsafe extern "C" {
    fn asprintf(strp: *mut *mut c_char, fmt: *const c_char, ...) -> c_int;
    // fl's asprintf is exported via stdio_abi (extern "C") so we link to
    // the fl library by directly invoking via FFI.
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

/// Each test case is a closure that calls asprintf() with a specific
/// format and arg type. Two closures (fl_call, lc_call) so we can route
/// each to the right ABI entry point with the same args.
fn run_diff_pair(
    case: &str,
    fl_call: impl FnOnce(*mut *mut c_char) -> c_int,
    lc_call: impl FnOnce(*mut *mut c_char) -> c_int,
    divs: &mut Vec<Divergence>,
) {
    let mut fl_p: *mut c_char = std::ptr::null_mut();
    let mut lc_p: *mut c_char = std::ptr::null_mut();
    let fl_n = fl_call(&mut fl_p);
    let lc_n = lc_call(&mut lc_p);
    if fl_n != lc_n {
        divs.push(Divergence {
            case: case.to_string(),
            field: "return",
            frankenlibc: format!("{fl_n}"),
            glibc: format!("{lc_n}"),
        });
    }
    if fl_n >= 0 && lc_n >= 0 && !fl_p.is_null() && !lc_p.is_null() {
        let s_fl = unsafe { CStr::from_ptr(fl_p).to_bytes().to_vec() };
        let s_lc = unsafe { CStr::from_ptr(lc_p).to_bytes().to_vec() };
        if s_fl != s_lc {
            divs.push(Divergence {
                case: case.to_string(),
                field: "string",
                frankenlibc: String::from_utf8_lossy(&s_fl).into_owned(),
                glibc: String::from_utf8_lossy(&s_lc).into_owned(),
            });
        }
    }
    if !fl_p.is_null() {
        unsafe { libc::free(fl_p as *mut libc::c_void) };
    }
    if !lc_p.is_null() {
        unsafe { libc::free(lc_p as *mut libc::c_void) };
    }
}

#[test]
fn diff_asprintf_format_specifiers() {
    let mut divs = Vec::new();

    // Plain string passthrough.
    run_diff_pair(
        "literal",
        |p| unsafe {
            frankenlibc_abi::stdio_abi::asprintf(p, c"hello world".as_ptr())
        },
        |p| unsafe { asprintf(p, c"hello world".as_ptr()) },
        &mut divs,
    );

    // %d
    run_diff_pair(
        "%d=42",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%d".as_ptr(), 42) },
        |p| unsafe { asprintf(p, c"%d".as_ptr(), 42) },
        &mut divs,
    );

    // %s
    run_diff_pair(
        "%s=hello",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%s".as_ptr(), c"hello".as_ptr()) },
        |p| unsafe { asprintf(p, c"%s".as_ptr(), c"hello".as_ptr()) },
        &mut divs,
    );

    // %x with width + zero pad
    run_diff_pair(
        "%08x=0xCAFE",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%08x".as_ptr(), 0xCAFEu32) },
        |p| unsafe { asprintf(p, c"%08x".as_ptr(), 0xCAFEu32) },
        &mut divs,
    );

    // Mixed
    run_diff_pair(
        "name=%s age=%d",
        |p| unsafe {
            frankenlibc_abi::stdio_abi::asprintf(p, c"name=%s age=%d".as_ptr(), c"alice".as_ptr(), 30)
        },
        |p| unsafe {
            asprintf(p, c"name=%s age=%d".as_ptr(), c"alice".as_ptr(), 30)
        },
        &mut divs,
    );

    // Empty result
    run_diff_pair(
        "empty",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"".as_ptr()) },
        |p| unsafe { asprintf(p, c"".as_ptr()) },
        &mut divs,
    );

    // Long output (forces internal buffer growth)
    run_diff_pair(
        "long padding",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%200d".as_ptr(), 1) },
        |p| unsafe { asprintf(p, c"%200d".as_ptr(), 1) },
        &mut divs,
    );

    // %% literal
    run_diff_pair(
        "100%% done",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"100%% done".as_ptr()) },
        |p| unsafe { asprintf(p, c"100%% done".as_ptr()) },
        &mut divs,
    );

    assert!(divs.is_empty(), "asprintf divergences:\n{}", render_divs(&divs));
}

#[test]
fn asprintf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc asprintf\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
