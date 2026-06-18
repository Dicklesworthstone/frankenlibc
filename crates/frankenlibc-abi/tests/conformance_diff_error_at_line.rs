#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc error_at_line() oracle; redirects process fd 2

//! Differential gate for glibc's error_at_line() (bd-m70eq2) — previously
//! fl-internal only. error_at_line(status, errnum, file, line, fmt, ...) prints
//! "<progname>:<file>:<line>: <fmt>... [: <strerror(errnum)>]\n" to stderr
//! (exiting only when status != 0, so every case uses status 0). This captures
//! stderr and asserts byte-for-byte equality with glibc across the file:line
//! insertion, errnum == 0 (no suffix) vs set errno, and printf %s/%d args. The
//! consecutive-duplicate suppression (error_one_per_line) is left off (default
//! 0) so each call prints. No mocks.

use std::ffi::{c_char, c_int, c_uint, CString};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

unsafe extern "C" {
    fn error_at_line(status: c_int, errnum: c_int, file: *const c_char, line: c_uint, fmt: *const c_char, ...);
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
    ($desc:literal, $errnum:expr, $file:expr, $line:expr, $fmt:expr $(, $arg:expr)*) => {{
        let file = CString::new($file).unwrap();
        let fmt = CString::new($fmt).unwrap();
        let g = capture(|| unsafe { error_at_line(0, $errnum, file.as_ptr(), $line, fmt.as_ptr() $(, $arg)*) });
        let f = capture(|| unsafe {
            frankenlibc_abi::stdlib_abi::error_at_line(0, $errnum, file.as_ptr(), $line, fmt.as_ptr() $(, $arg)*)
        });
        assert_eq!(
            f, g,
            "error_at_line(0, {}, {:?}, {}, {:?}) [{}]: fl={:?} glibc={:?}",
            $errnum, $file, $line, $fmt, $desc,
            String::from_utf8_lossy(&f), String::from_utf8_lossy(&g),
        );
    }};
}

#[test]
fn error_at_line_matches_glibc() {
    let foo = CString::new("foo.txt").unwrap();
    both!("plain, no errno", 0, "parse.c", 12u32, "syntax error");
    both!("EINVAL suffix", libc::EINVAL, "io.c", 99u32, "bad value");
    both!("ENOENT suffix", libc::ENOENT, "open.c", 1u32, "missing");
    both!("%s arg", 0, "read.c", 256u32, "cannot read %s", foo.as_ptr());
    both!("%s + errno", libc::EACCES, "read.c", 257u32, "cannot read %s", foo.as_ptr());
    both!("%d arg + errno", libc::EINVAL, "x.c", 0u32, "code %d", 42 as c_int);
    both!("empty fmt + errno", libc::ENOENT, "y.c", 7u32, "");
}
