#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wprintf oracle with fd-1 capture

//! Differential test for `wprintf`'s RETURN VALUE vs host glibc. C specifies
//! wprintf returns the number of WIDE CHARACTERS transmitted — NOT the byte
//! length of the encoded output — so for any multibyte output (e.g. `%lc` of a
//! non-ASCII wide char) the two differ. fl previously returned the UTF-8 byte
//! count. This redirects fd 1 to a temp file, runs each format on both fl and
//! glibc, and asserts the return value AND the emitted bytes agree.

use std::ffi::CString;

use frankenlibc_abi::wchar_abi as fl;

unsafe extern "C" {
    fn wprintf(format: *const libc::wchar_t, ...) -> libc::c_int;
    fn fflush(stream: *mut libc::FILE) -> libc::c_int;
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
}

fn widen(s: &str) -> Vec<libc::wchar_t> {
    let mut v: Vec<libc::wchar_t> = s.chars().map(|c| c as libc::wchar_t).collect();
    v.push(0);
    v
}

/// Capture (return value, bytes written to fd 1) for a closure that emits to
/// stdout. `flush` controls whether glibc's buffered stdout is flushed after.
fn capture(tmp_fd: libc::c_int, flush: bool, call: impl FnOnce() -> libc::c_int) -> (i32, Vec<u8>) {
    unsafe {
        let saved = libc::dup(1);
        libc::ftruncate(tmp_fd, 0);
        libc::lseek(tmp_fd, 0, libc::SEEK_SET);
        libc::dup2(tmp_fd, 1);
        let ret = call();
        if flush {
            fflush(std::ptr::null_mut()); // flush ALL streams (incl glibc stdout)
        }
        libc::dup2(saved, 1);
        libc::close(saved);
        // Read everything written.
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
        (ret, buf)
    }
}

#[test]
fn wprintf_return_is_wide_count_not_bytes() {
    unsafe {
        let utf8 = CString::new("C.UTF-8").unwrap();
        setlocale(6 /* LC_ALL */, utf8.as_ptr());
    }
    let path = CString::new(format!("/tmp/fl_wprintf_cap_{}", std::process::id())).unwrap();
    let tmp_fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(tmp_fd >= 0, "could not open temp capture file");

    let mut fails: Vec<String> = Vec::new();

    macro_rules! check {
        ($label:expr, $fmt:expr $(, $arg:expr)*) => {{
            let fmt = widen($fmt);
            let (rf, bf) = capture(tmp_fd, false, || unsafe { fl::wprintf(fmt.as_ptr() $(, $arg)*) });
            let (rg, bg) = capture(tmp_fd, true, || unsafe { wprintf(fmt.as_ptr() $(, $arg)*) });
            if rf != rg || bf != bg {
                fails.push(format!(
                    "{}: fl=(ret={rf}, bytes={:x?}) glibc=(ret={rg}, bytes={:x?})",
                    $label, bf, bg
                ));
            }
        }};
    }

    check!("ascii", "hello");
    check!(
        "euro x3 via %lc",
        "%lc%lc%lc",
        0x20AC_i32,
        0x20AC_i32,
        0x20AC_i32
    );
    check!("mixed", "a%lcb", 0x20AC_i32);
    check!("int+wc", "%d%lc", 42_i32, 0xE9_i32);
    check!("emoji", "%lc!", 0x1F600_i32);
    let ws = widen("wörld");
    check!("wide %ls", "[%ls]", ws.as_ptr());

    unsafe {
        libc::close(tmp_fd);
        libc::unlink(path.as_ptr());
    }

    assert!(
        fails.is_empty(),
        "wprintf return/output diverged from glibc:\n{}",
        fails.join("\n")
    );
}
