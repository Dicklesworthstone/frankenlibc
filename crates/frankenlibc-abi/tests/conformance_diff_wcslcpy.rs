#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcslcpy/wcslcat oracle (glibc 2.38+)

//! Differential gate for the BSD-style bounded wide copy/concat wcslcpy /
//! wcslcat (bd-zke4ct) — both added in glibc 2.38 and had no differential gate
//! (only fl-internal). The return value is the length the call TRIED to produce
//! (independent of truncation), the destination is always NUL-terminated when
//! siz>0, and siz==0 writes nothing. fl must match glibc on both the return
//! value and the resulting buffer bytes across truncating / exact / oversized /
//! zero sizes. No mocks.

use libc::wchar_t;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

/// The host arm is resolved with `dlsym`, not declared at link time. fl exports
/// this symbol into this test binary, so a link-time reference can bind to fl
/// and leave BOTH arms as fl -- green while comparing nothing (bd-v0388t). That
/// matters especially here: this gate covers a hand-written SIMD kernel, whose
/// whole risk is diverging from the scalar contract at a vector boundary.

type WcslcpyFn = unsafe extern "C" fn(*mut wchar_t, *const wchar_t, usize) -> usize;

fn host_wcslcpy() -> WcslcpyFn {
    // SAFETY: signature matches BSD wcslcpy exactly.
    unsafe {
        dlsym_oracle::host_fn(c"wcslcpy", frankenlibc_abi::wchar_abi::wcslcpy as *const ())
    }
}

fn host_wcslcat() -> WcslcpyFn {
    // SAFETY: wcslcat shares wcslcpy's signature exactly.
    unsafe {
        dlsym_oracle::host_fn(c"wcslcat", frankenlibc_abi::wchar_abi::wcslcat as *const ())
    }
}

fn wstr(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

const FILL: wchar_t = 0x7e7e; // sentinel to detect over-writes

#[test]
fn wcslcpy_matches_glibc() {
    let src = wstr("hello");
    // siz: bigger than src, exact (+NUL), truncating, 1, 0
    for siz in [0usize, 1, 3, 5, 6, 10] {
        let mut gd = vec![FILL; 16];
        let mut fd = vec![FILL; 16];
        let g = unsafe { host_wcslcpy()(gd.as_mut_ptr(), src.as_ptr(), siz) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcslcpy(fd.as_mut_ptr(), src.as_ptr(), siz) };
        assert_eq!(f, g, "wcslcpy siz={siz} ret: fl={f} glibc={g}");
        assert_eq!(fd, gd, "wcslcpy siz={siz} buffer mismatch");
    }
}

#[test]
fn wcslcat_matches_glibc() {
    let src = wstr("world");
    for siz in [0usize, 1, 4, 6, 8, 11, 16] {
        // Both buffers start with the same "ab" prefix, then NUL, then FILL.
        let mut gd = vec![FILL; 16];
        let mut fd = vec![FILL; 16];
        for (i, &c) in wstr("ab").iter().enumerate() {
            gd[i] = c;
            fd[i] = c;
        }
        let g = unsafe { host_wcslcat()(gd.as_mut_ptr(), src.as_ptr(), siz) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcslcat(fd.as_mut_ptr(), src.as_ptr(), siz) };
        assert_eq!(f, g, "wcslcat siz={siz} ret: fl={f} glibc={g}");
        assert_eq!(fd, gd, "wcslcat siz={siz} buffer mismatch");
    }
}
