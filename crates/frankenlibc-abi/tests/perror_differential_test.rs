#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc perror oracle with fd-2 capture

//! Differential test for `perror` vs host glibc. perror writes
//! "[prefix: ]strerror(errno)\n" to stderr; this redirects fd 2 to a temp file,
//! runs each engine for a spread of errno values and prefix variants, and
//! compares the captured bytes. Covers errnos beyond the common set (EAGAIN,
//! high/socket codes) and unknown codes ("Unknown error <N>"), plus the
//! NULL / empty / non-empty prefix formatting.

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn perror(s: *const libc::c_char);
}

/// Capture what `call` writes to fd 2.
fn capture(tmp_fd: libc::c_int, call: impl FnOnce()) -> Vec<u8> {
    unsafe {
        let saved = libc::dup(2);
        libc::ftruncate(tmp_fd, 0);
        libc::lseek(tmp_fd, 0, libc::SEEK_SET);
        libc::dup2(tmp_fd, 2);
        call();
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::lseek(tmp_fd, 0, libc::SEEK_SET);
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = libc::read(tmp_fd, chunk.as_mut_ptr() as *mut libc::c_void, chunk.len());
            if n <= 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n as usize]);
        }
        buf
    }
}

fn set_fl_errno(e: i32) {
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = e };
}
fn set_glibc_errno(e: i32) {
    unsafe { *libc::__errno_location() = e };
}

#[test]
fn perror_matches_glibc() {
    let path = CString::new(format!("/tmp/fl_perror_{}", std::process::id())).unwrap();
    let tmp_fd =
        unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o600) };
    assert!(tmp_fd >= 0);

    let prefixes: &[Option<&str>] = &[None, Some(""), Some("prog"), Some("a/b")];
    // Spread: common, EAGAIN(11), high (40,75,95,131,133), unknown (200, 4095, -1, 0).
    let errnos = [1, 2, 11, 13, 22, 34, 40, 75, 95, 110, 131, 133, 200, 4095, -1, 0];

    let mut fails = Vec::new();
    for &e in &errnos {
        for &pfx in prefixes {
            let cpfx = pfx.map(|p| CString::new(p).unwrap());
            let fl_ptr = cpfx.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());

            let fl_out = capture(tmp_fd, || {
                set_fl_errno(e);
                unsafe { fl::perror(fl_ptr) };
            });
            let lc_out = capture(tmp_fd, || {
                set_glibc_errno(e);
                unsafe { perror(fl_ptr) };
            });
            if fl_out != lc_out {
                fails.push(format!(
                    "errno={e} prefix={pfx:?}: fl={:?} glibc={:?}",
                    String::from_utf8_lossy(&fl_out),
                    String::from_utf8_lossy(&lc_out),
                ));
            }
        }
    }

    unsafe {
        libc::close(tmp_fd);
        libc::unlink(path.as_ptr());
    }

    assert!(fails.is_empty(), "perror diverged from glibc:\n{}", fails.join("\n"));
}
