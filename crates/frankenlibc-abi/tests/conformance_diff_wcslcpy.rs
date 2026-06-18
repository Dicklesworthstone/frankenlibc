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

unsafe extern "C" {
    fn wcslcpy(dst: *mut wchar_t, src: *const wchar_t, siz: usize) -> usize;
    fn wcslcat(dst: *mut wchar_t, src: *const wchar_t, siz: usize) -> usize;
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
        let g = unsafe { wcslcpy(gd.as_mut_ptr(), src.as_ptr(), siz) };
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
        let g = unsafe { wcslcat(gd.as_mut_ptr(), src.as_ptr(), siz) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcslcat(fd.as_mut_ptr(), src.as_ptr(), siz) };
        assert_eq!(f, g, "wcslcat siz={siz} ret: fl={f} glibc={g}");
        assert_eq!(fd, gd, "wcslcat siz={siz} buffer mismatch");
    }
}
