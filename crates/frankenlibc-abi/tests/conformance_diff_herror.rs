#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live host-glibc herror oracle; redirects process fd 2

//! Differential gate for herror (bd-88x0vd) — the obsolete DNS-error printer had
//! no differential gate. herror(s) writes "<s>: <hstrerror(h_errno)>\n" to
//! stderr (or just "<hstrerror(h_errno)>\n" when s is NULL/empty). fl and glibc
//! keep SEPARATE h_errno globals, so each is set via its own __h_errno_location
//! before the call; the captured stderr is compared byte-for-byte across the
//! NETDB_* codes and prefix variants. No mocks.

use std::ffi::{c_char, c_int, CString};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn herror(s: *const c_char);
        pub fn __h_errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::resolv_abi as flr;
use frankenlibc_abi::unistd_abi as flu;

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

fn assert_match(code: c_int, msg: Option<&str>) {
    let cmsg = msg.map(|m| CString::new(m).unwrap());
    let mptr = cmsg.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

    let g = capture(|| unsafe {
        *g::__h_errno_location() = code;
        g::herror(mptr);
    });
    let f = capture(|| unsafe {
        *flr::__h_errno_location() = code;
        flu::herror(mptr);
    });
    assert_eq!(
        f, g,
        "herror(h_errno={code}, {msg:?}): fl={:?} glibc={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&g),
    );
}

#[test]
fn herror_matches_glibc() {
    // NETDB_INTERNAL(-1), NETDB_SUCCESS(0), HOST_NOT_FOUND(1), TRY_AGAIN(2),
    // NO_RECOVERY(3), NO_DATA/NO_ADDRESS(4), plus an out-of-range code.
    let codes = [-1, 0, 1, 2, 3, 4, 99];
    let prefixes: [Option<&str>; 3] = [Some("resolver"), Some(""), None];
    for code in codes {
        for &p in &prefixes {
            assert_match(code, p);
        }
    }
}
