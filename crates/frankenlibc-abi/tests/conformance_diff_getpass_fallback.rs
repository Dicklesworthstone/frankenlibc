//! Differential gate for getpass's no-controlling-terminal fallback vs glibc.
//!
//! When `/dev/tty` cannot be opened (daemon / cron / setsid / container), glibc
//! getpass does NOT fail: it reads the password from stdin (fd 0) and writes the
//! prompt to stderr (fd 2), with no echo toggle, and returns the entered text.
//! fl previously returned NULL in this case.
//!
//! The golden expectation here was captured from a FRESH-process glibc oracle
//! (`echo "secret123" | setsid ./a.out`, a.out calling getpass("PW: ")): glibc
//! returns "secret123" and writes exactly "PW: " (no trailing newline) to
//! stderr. We can't run glibc in-process for the comparison because glibc's
//! buffered `stdin` FILE* (bound to the test process's original fd 0 at startup)
//! does not honor a post-fork `dup2` of a pipe onto fd 0, so an in-process glibc
//! getpass reads EOF — an artifact of fork+FILE buffering, not real behavior. fl
//! reads fd 0 with a raw `read(2)`, so the setsid-child harness exercises its
//! real fallback path.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::Read;

unsafe extern "C" {
    fn pipe(fds: *mut c_int) -> c_int;
    fn fork() -> c_int;
    fn setsid() -> c_int;
    fn dup2(oldfd: c_int, newfd: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn write(fd: c_int, buf: *const c_void, n: usize) -> isize;
    fn _exit(code: c_int) -> !;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
}

/// Run `body` in a child that has no controlling terminal (setsid), with stdin
/// fed `password` and stderr captured. Returns (password_returned, stderr_bytes).
/// `body` returns the C string pointer from the getpass under test.
fn run_in_setsid_child(password: &[u8], body: &dyn Fn() -> *mut c_char) -> (String, Vec<u8>) {
    // pipes: stdin (parent writes pw), stderr capture, result (child -> parent)
    let mut in_p = [0 as c_int; 2];
    let mut err_p = [0 as c_int; 2];
    let mut res_p = [0 as c_int; 2];
    assert_eq!(unsafe { pipe(in_p.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { pipe(err_p.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { pipe(res_p.as_mut_ptr()) }, 0);

    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // ---- child ----
        unsafe {
            setsid(); // drop controlling terminal so /dev/tty open fails
            dup2(in_p[0], 0);
            dup2(err_p[1], 2);
            close(in_p[0]);
            close(in_p[1]);
            close(err_p[0]);
            close(err_p[1]);
            close(res_p[0]);
            let p = body();
            let bytes: &[u8] = if p.is_null() {
                b"<NULL>"
            } else {
                CStr::from_ptr(p).to_bytes()
            };
            write(res_p[1], bytes.as_ptr() as *const c_void, bytes.len());
            close(res_p[1]);
            _exit(0);
        }
    }
    // ---- parent ----
    unsafe {
        close(in_p[0]);
        close(err_p[1]);
        close(res_p[1]);
        // feed the password
        write(in_p[1], password.as_ptr() as *const c_void, password.len());
        close(in_p[1]);
    }
    let mut res = Vec::new();
    let mut err = Vec::new();
    let mut rf = unsafe { fd_to_file(res_p[0]) };
    let mut ef = unsafe { fd_to_file(err_p[0]) };
    rf.read_to_end(&mut res).ok();
    ef.read_to_end(&mut err).ok();
    let mut status = 0;
    unsafe { waitpid(pid, &mut status, 0) };
    (String::from_utf8_lossy(&res).into_owned(), err)
}

unsafe fn fd_to_file(fd: c_int) -> std::fs::File {
    use std::os::unix::io::FromRawFd;
    unsafe { std::fs::File::from_raw_fd(fd) }
}

#[test]
fn getpass_no_tty_fallback_matches_glibc() {
    let pw = b"secret123\n";
    let fl_body = || unsafe { frankenlibc_abi::unistd_abi::getpass(c"PW: ".as_ptr()) };
    let (fl_res, fl_err) = run_in_setsid_child(pw, &fl_body);

    // Golden glibc behavior (fresh-process oracle): password returned from stdin,
    // prompt written to stderr with no trailing newline. fl previously returned
    // NULL (-> "<NULL>") here.
    assert_eq!(
        fl_res, "secret123",
        "getpass fallback should return the stdin password, got {fl_res:?}"
    );
    assert_eq!(
        fl_err,
        b"PW: ",
        "getpass fallback should write the prompt to stderr (no newline), got {:?}",
        String::from_utf8_lossy(&fl_err)
    );
}
