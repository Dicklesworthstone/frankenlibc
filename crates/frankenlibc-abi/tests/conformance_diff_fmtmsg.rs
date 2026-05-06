#![cfg(target_os = "linux")]

//! Differential conformance harness for XSI `fmtmsg(3)`.
//!
//! Host glibc is the oracle for stderr routing, severity names, null-field
//! formatting, and rejection of malformed labels/severities.

use std::ffi::{c_char, c_int};
use std::sync::Mutex;

use frankenlibc_abi::unistd_abi as fl;

const MM_PRINT: i64 = 0x100;
const MM_CONSOLE: i64 = 0x200;

unsafe extern "C" {
    fn fmtmsg(
        classification: libc::c_long,
        label: *const c_char,
        severity: c_int,
        text: *const c_char,
        action: *const c_char,
        tag: *const c_char,
    ) -> c_int;
}

static FMTMSG_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy)]
struct FmtmsgCase {
    name: &'static str,
    classification: i64,
    label: Option<&'static str>,
    severity: c_int,
    text: Option<&'static str>,
    action: Option<&'static str>,
    tag: Option<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
struct Captured {
    rc: c_int,
    stderr: Vec<u8>,
}

struct MsgverbGuard(Option<std::ffi::OsString>);

impl MsgverbGuard {
    fn clear() -> Self {
        let prior = std::env::var_os("MSGVERB");
        // SAFETY: fmtmsg differential cases run under FMTMSG_LOCK and do not
        // spawn threads, so this test owns MSGVERB for the duration.
        unsafe { std::env::remove_var("MSGVERB") };
        Self(prior)
    }
}

impl Drop for MsgverbGuard {
    fn drop(&mut self) {
        // SAFETY: see MsgverbGuard::clear; FMTMSG_LOCK is still held when the
        // guard is dropped at the end of each test.
        unsafe {
            if let Some(value) = &self.0 {
                std::env::set_var("MSGVERB", value);
            } else {
                std::env::remove_var("MSGVERB");
            }
        }
    }
}

fn with_case_args<T>(
    case: FmtmsgCase,
    body: impl FnOnce(*const c_char, *const c_char, *const c_char, *const c_char) -> T,
) -> T {
    let label = case.label.map(nul_terminated);
    let text = case.text.map(nul_terminated);
    let action = case.action.map(nul_terminated);
    let tag = case.tag.map(nul_terminated);

    body(
        label
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        text.as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        action
            .as_ref()
            .map_or(std::ptr::null(), |s| s.as_ptr().cast()),
        tag.as_ref().map_or(std::ptr::null(), |s| s.as_ptr().cast()),
    )
}

fn nul_terminated(s: &str) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(s.len() + 1);
    bytes.extend(s.as_bytes().iter().copied().filter(|b| *b != 0));
    bytes.push(0);
    bytes
}

fn capture_stderr(body: impl FnOnce() -> c_int) -> Captured {
    let mut fds = [-1; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let [read_fd, write_fd] = fds;
    let saved_stderr = unsafe { libc::dup(libc::STDERR_FILENO) };
    assert!(saved_stderr >= 0, "dup(stderr) failed");
    assert_eq!(
        unsafe { libc::dup2(write_fd, libc::STDERR_FILENO) },
        libc::STDERR_FILENO,
        "dup2(stderr) failed"
    );
    unsafe { libc::close(write_fd) };

    let rc = body();
    unsafe {
        libc::fflush(std::ptr::null_mut());
        libc::dup2(saved_stderr, libc::STDERR_FILENO);
        libc::close(saved_stderr);
    }

    let mut stderr = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(read_fd, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n <= 0 {
            break;
        }
        let Ok(n) = usize::try_from(n) else {
            break;
        };
        if let Some(bytes) = chunk.get(..n) {
            stderr.extend_from_slice(bytes);
        }
    }
    unsafe { libc::close(read_fd) };

    Captured { rc, stderr }
}

fn run_frankenlibc(case: FmtmsgCase) -> Captured {
    with_case_args(case, |label, text, action, tag| {
        capture_stderr(|| unsafe {
            fl::fmtmsg(case.classification, label, case.severity, text, action, tag)
        })
    })
}

fn run_glibc(case: FmtmsgCase) -> Captured {
    with_case_args(case, |label, text, action, tag| {
        capture_stderr(|| unsafe {
            fmtmsg(
                case.classification as libc::c_long,
                label,
                case.severity,
                text,
                action,
                tag,
            )
        })
    })
}

fn assert_matches_glibc(case: FmtmsgCase) {
    let fl = run_frankenlibc(case);
    let glibc = run_glibc(case);
    assert_eq!(
        fl, glibc,
        "{} diverged: frankenlibc={fl:?} glibc={glibc:?}",
        case.name
    );
}

#[test]
fn diff_fmtmsg_prints_glibc_message_shapes() {
    let _lock = FMTMSG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _msgverb = MsgverbGuard::clear();

    for case in [
        FmtmsgCase {
            name: "no severity",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: 0,
            text: Some("disk full"),
            action: Some("free space"),
            tag: Some("util:001"),
        },
        FmtmsgCase {
            name: "halt severity",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: 1,
            text: Some("halted"),
            action: Some("restart"),
            tag: Some("util:002"),
        },
        FmtmsgCase {
            name: "warning severity",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: 3,
            text: Some("low space"),
            action: Some("rotate logs"),
            tag: Some("util:003"),
        },
        FmtmsgCase {
            name: "null label",
            classification: MM_PRINT,
            label: None,
            severity: 2,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:004"),
        },
        FmtmsgCase {
            name: "null text keeps action on severity line",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: 2,
            text: None,
            action: Some("retry"),
            tag: Some("util:005"),
        },
        FmtmsgCase {
            name: "tag without action",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: 2,
            text: Some("failed"),
            action: None,
            tag: Some("util:006"),
        },
    ] {
        assert_matches_glibc(case);
    }
}

#[test]
fn diff_fmtmsg_non_stderr_routes_do_not_write_fd2() {
    let _lock = FMTMSG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _msgverb = MsgverbGuard::clear();

    for case in [
        FmtmsgCase {
            name: "null classification",
            classification: 0,
            label: Some("UX:app"),
            severity: 2,
            text: Some("hidden"),
            action: Some("ignore"),
            tag: Some("util:007"),
        },
        FmtmsgCase {
            name: "console only",
            classification: MM_CONSOLE,
            label: Some("UX:app"),
            severity: 2,
            text: Some("console"),
            action: Some("ignore"),
            tag: Some("util:008"),
        },
    ] {
        assert_matches_glibc(case);
    }
}

#[test]
fn diff_fmtmsg_rejects_invalid_label_and_severity() {
    let _lock = FMTMSG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _msgverb = MsgverbGuard::clear();

    for case in [
        FmtmsgCase {
            name: "label lacks component delimiter",
            classification: MM_PRINT,
            label: Some("app"),
            severity: 2,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:009"),
        },
        FmtmsgCase {
            name: "empty label",
            classification: MM_PRINT,
            label: Some(""),
            severity: 2,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:010"),
        },
        FmtmsgCase {
            name: "label first component too long",
            classification: MM_PRINT,
            label: Some("aaaaaaaaaaa:x"),
            severity: 2,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:011"),
        },
        FmtmsgCase {
            name: "label second component too long",
            classification: MM_PRINT,
            label: Some("aaaaaaaaaa:bbbbbbbbbbbbbbb"),
            severity: 2,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:012"),
        },
        FmtmsgCase {
            name: "negative severity",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: -1,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:013"),
        },
        FmtmsgCase {
            name: "too-large severity",
            classification: MM_PRINT,
            label: Some("UX:app"),
            severity: 5,
            text: Some("failed"),
            action: Some("retry"),
            tag: Some("util:014"),
        },
    ] {
        assert_matches_glibc(case);
    }
}
