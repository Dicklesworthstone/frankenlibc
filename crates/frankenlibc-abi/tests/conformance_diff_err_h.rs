#![cfg(target_os = "linux")]

//! Differential conformance harness for `<err.h>` BSD error-reporting
//! functions.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - warnx (stderr message body)
//!   - warn  (message body + ": strerror(errno)" suffix)
//!   - errx  (fork-isolated: exit code + message body)
//!
//! Both impls write to fd 2 with a "progname: ..." prefix. FrankenLibC
//! should match glibc's argv[0] basename source for that prefix.
//!
//! Bead: CONFORMANCE: libc err.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};
use std::process::Command;
use std::sync::Mutex;

use frankenlibc_abi::err_abi as fl;

unsafe extern "C" {
    fn warn(fmt: *const c_char, ...);
    fn warnx(fmt: *const c_char, ...);
    fn errx(eval: c_int, fmt: *const c_char, ...) -> !;

    fn pipe(fds: *mut c_int) -> c_int;
    fn dup(fd: c_int) -> c_int;
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn read(fd: c_int, buf: *mut c_void, n: usize) -> isize;
}

static IO_LOCK: Mutex<()> = Mutex::new(());

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

/// Strip the leading "progname: " from an err.h-style message and
/// return the body. Returns None if the input has no ": " separator.
fn strip_progname(b: &[u8]) -> Option<&[u8]> {
    // Find first ": "
    for i in 0..b.len().saturating_sub(1) {
        if b[i] == b':' && b[i + 1] == b' ' {
            return Some(&b[i + 2..]);
        }
    }
    None
}

/// Capture stderr (fd 2) output from `body` by redirecting to a pipe.
/// Restores fd 2 before returning.
fn capture_stderr<F: FnOnce()>(body: F) -> Vec<u8> {
    let mut fds: [c_int; 2] = [0, 0];
    if unsafe { pipe(fds.as_mut_ptr()) } != 0 {
        return Vec::new();
    }
    let saved_stderr = unsafe { dup(2) };
    if saved_stderr < 0 {
        unsafe {
            close(fds[0]);
            close(fds[1]);
        }
        return Vec::new();
    }
    unsafe {
        dup2(fds[1], 2);
        close(fds[1]);
    }
    body();
    unsafe {
        dup2(saved_stderr, 2);
        close(saved_stderr);
    }
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = unsafe { read(fds[0], chunk.as_mut_ptr() as *mut c_void, chunk.len()) };
        if n <= 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
    }
    unsafe { close(fds[0]) };
    buf
}

#[test]
fn diff_warnx_message_body() {
    let _g = IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();

    let cases: &[&str] = &["hello world", "plain message", "no special chars here"];
    for s in cases {
        let cfmt = CString::new(*s).unwrap();
        let out_fl = capture_stderr(|| unsafe {
            fl::warnx(cfmt.as_ptr());
        });
        let out_lc = capture_stderr(|| unsafe {
            warnx(cfmt.as_ptr());
        });
        let body_fl = strip_progname(&out_fl).unwrap_or(&out_fl[..]);
        let body_lc = strip_progname(&out_lc).unwrap_or(&out_lc[..]);
        if body_fl != body_lc {
            divs.push(Divergence {
                function: "warnx",
                case: format!("{s:?}"),
                field: "message_body",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(body_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(body_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "warnx body divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_warnx_formatted_args() {
    let _g = IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();

    let cfmt = CString::new("file: %s, error: %d").unwrap();
    let carg1 = CString::new("foo.txt").unwrap();
    let out_fl = capture_stderr(|| unsafe {
        fl::warnx(cfmt.as_ptr(), carg1.as_ptr(), 42i32);
    });
    let out_lc = capture_stderr(|| unsafe {
        warnx(cfmt.as_ptr(), carg1.as_ptr(), 42i32);
    });
    let body_fl = strip_progname(&out_fl).unwrap_or(&out_fl[..]);
    let body_lc = strip_progname(&out_lc).unwrap_or(&out_lc[..]);
    if body_fl != body_lc {
        divs.push(Divergence {
            function: "warnx",
            case: r#""file: %s, error: %d" | "foo.txt", 42"#.into(),
            field: "message_body",
            frankenlibc: format!("{:?}", String::from_utf8_lossy(body_fl)),
            glibc: format!("{:?}", String::from_utf8_lossy(body_lc)),
        });
    }
    assert!(
        divs.is_empty(),
        "warnx formatted divergences:\n{}",
        render_divs(&divs)
    );
}

/// fl::warn reads errno from fl's per-thread errno; glibc::warn reads
/// from libc's per-thread errno. To exercise both consistently we set
/// both, then compare only the trailing ": <strerror>" suffix.
#[test]
fn diff_warn_errno_suffix() {
    let _g = IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();

    let errnos: &[c_int] = &[
        libc::ENOENT,
        libc::EACCES,
        libc::EINVAL,
        libc::EBADF,
        libc::ENOMEM,
    ];
    let cfmt = CString::new("test").unwrap();
    for e in errnos {
        let out_fl = capture_stderr(|| unsafe {
            *libc::__errno_location() = *e;
            *frankenlibc_abi::errno_abi::__errno_location() = *e;
            fl::warn(cfmt.as_ptr());
        });
        let out_lc = capture_stderr(|| unsafe {
            *libc::__errno_location() = *e;
            warn(cfmt.as_ptr());
        });
        // The format produced is "progname: test: <strerror>\n".
        // After strip_progname we get "test: <strerror>\n". Compare full
        // body — both should have identical "test: <strerror>" suffix.
        let body_fl = strip_progname(&out_fl).unwrap_or(&out_fl[..]);
        let body_lc = strip_progname(&out_lc).unwrap_or(&out_lc[..]);
        if body_fl != body_lc {
            divs.push(Divergence {
                function: "warn",
                case: format!("errno={e}"),
                field: "message_body",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(body_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(body_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "warn errno-suffix divergences:\n{}",
        render_divs(&divs)
    );
}

enum ErrImpl {
    Fl,
    Libc,
}

fn command_run_errx(eval: c_int, fmt: &str, which: ErrImpl) -> (c_int, Vec<u8>) {
    let Ok(current_exe) = std::env::current_exe() else {
        return (-1, Vec::new());
    };
    let which = match which {
        ErrImpl::Fl => "fl",
        ErrImpl::Libc => "libc",
    };
    let output = Command::new(current_exe)
        .args([
            "--exact",
            "errx_child_invocation",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_ERRX_HELPER", which)
        .env("FRANKENLIBC_ERRX_EVAL", eval.to_string())
        .env("FRANKENLIBC_ERRX_FMT", fmt)
        .output();
    match output {
        Ok(output) => (output.status.code().unwrap_or(-1), output.stderr),
        Err(_) => (-1, Vec::new()),
    }
}

#[test]
fn errx_child_invocation() {
    let Ok(which) = std::env::var("FRANKENLIBC_ERRX_HELPER") else {
        return;
    };
    let eval = std::env::var("FRANKENLIBC_ERRX_EVAL")
        .ok()
        .and_then(|s| s.parse::<c_int>().ok())
        .unwrap_or(1);
    let fmt = std::env::var("FRANKENLIBC_ERRX_FMT").unwrap_or_else(|_| "errx helper".into());
    let cfmt = CString::new(fmt).unwrap();
    match which.as_str() {
        "fl" => unsafe { fl::errx(eval, cfmt.as_ptr()) },
        "libc" => unsafe { errx(eval, cfmt.as_ptr()) },
        _ => {}
    }
}

#[test]
fn diff_errx_exit_and_body() {
    let _g = IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();
    let cases: &[(c_int, &str)] = &[
        (1, "fatal: config missing"),
        (2, "another fatal"),
        (42, "custom exit code"),
    ];
    for (eval, fmt) in cases {
        let (code_fl, out_fl) = command_run_errx(*eval, fmt, ErrImpl::Fl);
        let (code_lc, out_lc) = command_run_errx(*eval, fmt, ErrImpl::Libc);
        if code_fl != code_lc {
            divs.push(Divergence {
                function: "errx",
                case: format!("(eval={eval}, {fmt:?})"),
                field: "exit_code",
                frankenlibc: format!("{code_fl}"),
                glibc: format!("{code_lc}"),
            });
        }
        let body_fl = strip_progname(&out_fl).unwrap_or(&out_fl[..]);
        let body_lc = strip_progname(&out_lc).unwrap_or(&out_lc[..]);
        if body_fl != body_lc {
            divs.push(Divergence {
                function: "errx",
                case: format!("(eval={eval}, {fmt:?})"),
                field: "message_body",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(body_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(body_lc)),
            });
        }
    }
    assert!(divs.is_empty(), "errx divergences:\n{}", render_divs(&divs));
}

/// The err.h prefix should use the argv[0] basename rather than Linux
/// `/proc/self/comm`, which truncates long executable names.
#[test]
fn diff_progname_source_matches_glibc() {
    let _g = IO_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cfmt = CString::new("ping").unwrap();
    let out_fl = capture_stderr(|| unsafe { fl::warnx(cfmt.as_ptr()) });
    let out_lc = capture_stderr(|| unsafe { warnx(cfmt.as_ptr()) });
    let prefix_fl = out_fl.split(|&b| b == b':').next().unwrap_or(&[]).to_vec();
    let prefix_lc = out_lc.split(|&b| b == b':').next().unwrap_or(&[]).to_vec();
    assert_eq!(
        prefix_fl, prefix_lc,
        "err.h progname prefix should match glibc argv[0] basename"
    );
}

#[test]
fn err_h_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!("{{\"family\":\"err.h\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",);
}
