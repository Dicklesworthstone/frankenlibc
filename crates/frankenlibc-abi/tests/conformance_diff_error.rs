#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc error() oracle; redirects process fd 2

//! Differential gate for glibc's error() (bd-xke0zv) — previously fl-internal
//! only. error(status, errnum, fmt, ...) prints "<progname>: <fmt>...
//! [: <strerror(errnum)>]\n" to stderr (and exit()s only when status != 0, so
//! every case here uses status 0). Both engines share the same
//! program_invocation_short_name, so the prefix matches. This captures stderr
//! and asserts byte-for-byte equality across: no-arg messages, printf
//! conversions (%s / %d), errnum == 0 (no strerror suffix), and several errno
//! values (EINVAL / ENOENT / EACCES). No mocks.

use std::ffi::{CString, c_char, c_int};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

unsafe extern "C" {
    fn error(status: c_int, errnum: c_int, fmt: *const c_char, ...);
}

static CAPTURE_LOCK: Mutex<()> = Mutex::new(());

fn capture<F: FnOnce()>(f: F) -> Vec<u8> {
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let saved = unsafe { libc::dup(2) };
    unsafe { libc::dup2(fds[1], 2) };
    f();
    unsafe { libc::fflush(std::ptr::null_mut()) };
    unsafe {
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::close(fds[1]);
    }
    let mut out = Vec::new();
    let mut file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _ = file.read_to_end(&mut out);
    out
}

macro_rules! both {
    ($desc:literal, $errnum:expr, $fmt:expr $(, $arg:expr)*) => {{
        let fmt = CString::new($fmt).unwrap();
        let g = capture(|| unsafe { error(0, $errnum, fmt.as_ptr() $(, $arg)*) });
        let f = capture(|| unsafe {
            frankenlibc_abi::stdlib_abi::error(0, $errnum, fmt.as_ptr() $(, $arg)*)
        });
        assert_eq!(
            f, g,
            "error(0, {}, {:?}) [{}]: fl={:?} glibc={:?}",
            $errnum, $fmt, $desc,
            String::from_utf8_lossy(&f), String::from_utf8_lossy(&g),
        );
    }};
}

#[test]
fn error_matches_glibc() {
    let foo = CString::new("foo.txt").unwrap();
    both!("plain, no errno", 0, "a plain message");
    both!("EINVAL suffix", libc::EINVAL, "operation failed");
    both!("ENOENT suffix", libc::ENOENT, "could not open");
    both!("EACCES suffix", libc::EACCES, "denied");
    both!("%s arg, no errno", 0, "cannot read %s", foo.as_ptr());
    both!(
        "%s arg + errno",
        libc::ENOENT,
        "cannot read %s",
        foo.as_ptr()
    );
    both!("%d arg", 0, "exit code %d", 42 as c_int);
    both!(
        "%s and %d",
        libc::EINVAL,
        "%s at line %d",
        foo.as_ptr(),
        7 as c_int
    );
    both!("empty fmt + errno", libc::EINVAL, "");
}
