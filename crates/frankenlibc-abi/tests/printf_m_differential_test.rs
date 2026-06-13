#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! Differential test for the glibc `%m` printf extension (prints
//! `strerror(errno)`, consumes no argument) vs host glibc. Compares fl's
//! rendered output against glibc's across a range of errno values and the
//! width / precision / flag modifiers, which `%m` honours like `%s`.

use std::ffi::CString;

use frankenlibc_abi::stdio_abi as fl;

unsafe extern "C" {
    fn snprintf(s: *mut libc::c_char, n: usize, fmt: *const libc::c_char, ...) -> libc::c_int;
}

fn set_errno(e: i32) {
    unsafe { *libc::__errno_location() = e };
}

fn render_fl(fmt: &str, errno: i32) -> (i32, Vec<u8>) {
    // fl's %m reads fl's OWN errno location (in a debug test binary that is a
    // separate symbol from glibc's), so set that one for the fl render.
    unsafe { *frankenlibc_abi::errno_abi::__errno_location() = errno };
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0u8; 256];
    let r = unsafe {
        fl::snprintf(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            cf.as_ptr(),
        )
    };
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    (r, buf[..n].to_vec())
}

fn render_glibc(fmt: &str, errno: i32) -> (i32, Vec<u8>) {
    set_errno(errno);
    let cf = CString::new(fmt).unwrap();
    let mut buf = vec![0u8; 256];
    let r = unsafe {
        snprintf(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            cf.as_ptr(),
        )
    };
    let n = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    (r, buf[..n].to_vec())
}

#[test]
fn printf_m_matches_glibc() {
    let fmts = [
        "%m", "[%m]", "x=%m=y", "[%20m]", "[%-20m]", "[%.3m]", "[%.0m]", "[%8.4m]", "%m %m",
    ];
    // A spread of errno values incl. 0 ("Success") and an unknown code.
    let errnos = [0, 1, 2, 11, 13, 22, 34, 110, 4095];
    let mut fails = Vec::new();
    for &e in &errnos {
        for fmt in fmts {
            let f = render_fl(fmt, e);
            let g = render_glibc(fmt, e);
            if f != g {
                fails.push(format!(
                    "fmt={fmt:?} errno={e}: fl=(ret={}, {:?}) glibc=(ret={}, {:?})",
                    f.0,
                    String::from_utf8_lossy(&f.1),
                    g.0,
                    String::from_utf8_lossy(&g.1),
                ));
            }
        }
    }
    assert!(
        fails.is_empty(),
        "printf %m diverged from glibc:\n{}",
        fails.join("\n")
    );
}
