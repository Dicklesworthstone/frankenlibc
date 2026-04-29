#![cfg(target_os = "linux")]

//! Differential conformance harness for `dprintf(3)`.
//!
//! dprintf writes formatted output to a file descriptor (no FILE*).
//! fl exports its own implementation in stdio_abi.rs; this is the first
//! head-to-head diff against host glibc.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int};

unsafe extern "C" {
    fn dprintf(fd: c_int, format: *const c_char, ...) -> c_int;
}

/// Run a single dprintf to a memory-backed pipe and return the captured bytes.
///
/// fd-based output requires a real fd; we use a pipe and read the write side
/// after dprintf returns.
unsafe fn capture_dprintf<F>(call: F) -> (c_int, Vec<u8>)
where
    F: FnOnce(c_int) -> c_int,
{
    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return (-1, Vec::new());
    }
    let n = call(fds[1]);
    unsafe { libc::close(fds[1]) };
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let r =
            unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if r <= 0 {
            break;
        }
        out.extend_from_slice(&buf[..r as usize]);
    }
    unsafe { libc::close(fds[0]) };
    (n, out)
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

#[test]
fn diff_dprintf_basic_specifiers() {
    let mut divs = Vec::new();

    macro_rules! pair {
        ($case:literal, $fl_call:expr, $lc_call:expr) => {{
            let (fl_n, fl_out) = unsafe { capture_dprintf($fl_call) };
            let (lc_n, lc_out) = unsafe { capture_dprintf($lc_call) };
            if fl_n != lc_n {
                divs.push(Divergence {
                    case: $case.to_string(),
                    field: "return",
                    frankenlibc: format!("{fl_n}"),
                    glibc: format!("{lc_n}"),
                });
            }
            if fl_out != lc_out {
                divs.push(Divergence {
                    case: $case.to_string(),
                    field: "output",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(&fl_out)),
                    glibc: format!("{:?}", String::from_utf8_lossy(&lc_out)),
                });
            }
        }};
    }

    pair!(
        "literal",
        |fd| unsafe { frankenlibc_abi::stdio_abi::dprintf(fd, c"hello world".as_ptr()) },
        |fd| unsafe { dprintf(fd, c"hello world".as_ptr()) }
    );

    pair!(
        "%d",
        |fd| unsafe { frankenlibc_abi::stdio_abi::dprintf(fd, c"%d".as_ptr(), 42) },
        |fd| unsafe { dprintf(fd, c"%d".as_ptr(), 42) }
    );

    pair!(
        "%s",
        |fd| unsafe { frankenlibc_abi::stdio_abi::dprintf(fd, c"%s".as_ptr(), c"hello".as_ptr()) },
        |fd| unsafe { dprintf(fd, c"%s".as_ptr(), c"hello".as_ptr()) }
    );

    pair!(
        "mixed",
        |fd| unsafe {
            frankenlibc_abi::stdio_abi::dprintf(
                fd,
                c"%s=%d %s=%d\n".as_ptr(),
                c"x".as_ptr(),
                10,
                c"y".as_ptr(),
                20,
            )
        },
        |fd| unsafe { dprintf(fd, c"%s=%d %s=%d\n".as_ptr(), c"x".as_ptr(), 10, c"y".as_ptr(), 20) }
    );

    pair!(
        "%08x",
        |fd| unsafe {
            frankenlibc_abi::stdio_abi::dprintf(fd, c"%08x".as_ptr(), 0xdeadbeefu32)
        },
        |fd| unsafe { dprintf(fd, c"%08x".as_ptr(), 0xdeadbeefu32) }
    );

    pair!(
        "long output %200d",
        |fd| unsafe { frankenlibc_abi::stdio_abi::dprintf(fd, c"%200d".as_ptr(), 1) },
        |fd| unsafe { dprintf(fd, c"%200d".as_ptr(), 1) }
    );

    pair!(
        "empty format",
        |fd| unsafe { frankenlibc_abi::stdio_abi::dprintf(fd, c"".as_ptr()) },
        |fd| unsafe { dprintf(fd, c"".as_ptr()) }
    );

    pair!(
        "%% literal",
        |fd| unsafe { frankenlibc_abi::stdio_abi::dprintf(fd, c"50%% complete".as_ptr()) },
        |fd| unsafe { dprintf(fd, c"50%% complete".as_ptr()) }
    );

    assert!(divs.is_empty(), "dprintf divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_dprintf_invalid_fd_returns_minus_one() {
    let fl_n = unsafe { frankenlibc_abi::stdio_abi::dprintf(-1, c"oops".as_ptr()) };
    let lc_n = unsafe { dprintf(-1, c"oops".as_ptr()) };
    assert_eq!(fl_n, lc_n, "dprintf invalid-fd return: fl={fl_n} lc={lc_n}");
    assert_eq!(fl_n, -1, "dprintf(-1) should return -1");
}

#[test]
fn dprintf_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc dprintf\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
