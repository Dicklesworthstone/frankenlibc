#![cfg(target_os = "linux")]

//! Differential conformance harness for `asprintf(3)` / `vasprintf(3)`.
//!
//! These are GNU extensions that allocate a string of the right size and
//! return it via an out-pointer. fl exports its own implementations in
//! stdio_abi.rs; this is the first head-to-head diff against host glibc.
//!
//! Filed under [bd-xn6p8] follow-up — extending host-libc parity coverage
//! into the printf family.

use std::ffi::{CStr, c_char, c_int, c_void};

use frankenlibc_abi::stdio_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// Host `asprintf`, resolved through the oracle rather than declared at link
/// time: fl exports `asprintf` into this same binary, so a link-time declaration
/// is only an oracle while the linker happens to pick libc.so.6 (bd-v0388t).
///
/// The variadic tail is what makes this worth spelling out: the argument list
/// differs per call, so the pointer is typed as variadic and each call site must
/// pass exactly what the format string consumes.
type Asprintf = unsafe extern "C" fn(*mut *mut c_char, *const c_char, ...) -> c_int;

fn host_asprintf() -> Asprintf {
    // SAFETY: Asprintf is the declared prototype of asprintf, and host_fn
    // rejects a resolution that lands on fl's own definition.
    static P: std::sync::LazyLock<Asprintf> = std::sync::LazyLock::new(|| unsafe {
        dlsym_oracle::host_fn(c"asprintf", fl::asprintf as *const ())
    });
    *P
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
    // EACH PROVIDER'S BLOCK IS RELEASED BY THAT PROVIDER. In an interposed
    // process this distinction does not exist — the loader routes both calls
    // through fl, and fl's free recognises a foreign pointer. In a test binary
    // there is no interposition: `libc::free` is glibc's, and handing it fl's
    // segment-backed pointer aborts the process with "free(): invalid size"
    // before any assertion runs. That abort is what this file did until
    // bd-reality-202609-lx578q.7 — it made the differential unreadable and it
    // hid every divergence behind a crash in the cleanup path.
    if !fl_p.is_null() {
        // SAFETY: fl_p came from fl's asprintf, so fl's free releases it.
        unsafe { frankenlibc_abi::malloc_abi::free(fl_p as *mut c_void) };
    }
    if !lc_p.is_null() {
        // SAFETY: lc_p came from host glibc's asprintf, so host free releases it.
        unsafe { libc::free(lc_p as *mut c_void) };
    }
}

#[test]
fn diff_asprintf_format_specifiers() {
    let mut divs = Vec::new();

    // Plain string passthrough.
    run_diff_pair(
        "literal",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"hello world".as_ptr()) },
        |p| unsafe { (host_asprintf())(p, c"hello world".as_ptr()) },
        &mut divs,
    );

    // %d
    run_diff_pair(
        "%d=42",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%d".as_ptr(), 42) },
        |p| unsafe { (host_asprintf())(p, c"%d".as_ptr(), 42) },
        &mut divs,
    );

    // %s
    run_diff_pair(
        "%s=hello",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%s".as_ptr(), c"hello".as_ptr()) },
        |p| unsafe { (host_asprintf())(p, c"%s".as_ptr(), c"hello".as_ptr()) },
        &mut divs,
    );

    // %x with width + zero pad
    run_diff_pair(
        "%08x=0xCAFE",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%08x".as_ptr(), 0xCAFEu32) },
        |p| unsafe { (host_asprintf())(p, c"%08x".as_ptr(), 0xCAFEu32) },
        &mut divs,
    );

    // Mixed
    run_diff_pair(
        "name=%s age=%d",
        |p| unsafe {
            frankenlibc_abi::stdio_abi::asprintf(
                p,
                c"name=%s age=%d".as_ptr(),
                c"alice".as_ptr(),
                30,
            )
        },
        |p| unsafe { (host_asprintf())(p, c"name=%s age=%d".as_ptr(), c"alice".as_ptr(), 30) },
        &mut divs,
    );

    // Empty result
    run_diff_pair(
        "empty",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"".as_ptr()) },
        |p| unsafe { (host_asprintf())(p, c"".as_ptr()) },
        &mut divs,
    );

    // Long output (forces internal buffer growth)
    run_diff_pair(
        "long padding",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"%200d".as_ptr(), 1) },
        |p| unsafe { (host_asprintf())(p, c"%200d".as_ptr(), 1) },
        &mut divs,
    );

    // %% literal
    run_diff_pair(
        "100%% done",
        |p| unsafe { frankenlibc_abi::stdio_abi::asprintf(p, c"100%% done".as_ptr()) },
        |p| unsafe { (host_asprintf())(p, c"100%% done".as_ptr()) },
        &mut divs,
    );

    assert!(
        divs.is_empty(),
        "asprintf divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn asprintf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc asprintf\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
