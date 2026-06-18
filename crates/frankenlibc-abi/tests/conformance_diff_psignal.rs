#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // live host-glibc psignal oracle; redirects process fd 2

//! Differential gate for psignal (bd-rfd32s). psignal(sig, msg) writes
//! "msg: <description>\n" (or just "<description>\n" when msg is NULL/empty) to
//! stderr — the same descriptions as strsignal. It had no differential gate
//! (only fl-internal). This captures both glibc's and fl's stderr for identical
//! (sig, msg) inputs and asserts byte-for-byte equality across standard signals,
//! prefix variants (NULL / empty / text), out-of-range "Unknown signal N", and
//! real-time signal naming. No mocks.

use std::ffi::{c_char, c_int, CString};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

unsafe extern "C" {
    fn psignal(sig: c_int, s: *const c_char);
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

fn assert_match(sig: c_int, msg: Option<&str>) {
    let cmsg = msg.map(|m| CString::new(m).unwrap());
    let mptr = cmsg.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

    let g = capture(|| unsafe { psignal(sig, mptr) });
    let f = capture(|| unsafe { frankenlibc_abi::string_abi::psignal(sig, mptr) });

    assert_eq!(
        f, g,
        "psignal({sig}, {msg:?}): fl={:?} glibc={:?}",
        String::from_utf8_lossy(&f),
        String::from_utf8_lossy(&g),
    );
}

#[test]
fn psignal_matches_glibc() {
    let sigs = [
        1, 2, 6, 8, 9, 11, 13, 15, 17, 19, 28, 31, // standard signals
        0, -1, 99, 128, // out-of-range -> "Unknown signal N"
        34, 35, 50, 64, // real-time signal range (SIGRTMIN..=SIGRTMAX)
    ];
    let prefixes: [Option<&str>; 3] = [Some("myprog"), Some(""), None];
    for &sig in &sigs {
        for &p in &prefixes {
            assert_match(sig, p);
        }
    }
}
