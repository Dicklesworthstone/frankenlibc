#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc wcsnlen oracle

//! Differential gate for wcsnlen (bd-li039w) — previously uncovered. wcsnlen
//! returns min(wcslen(s), maxlen): it scans at most `maxlen` wide chars and
//! never reads past a NUL. fl must match host glibc across maxlen below/at/above
//! the string length, including 0 and no-NUL-within-bound. No mocks.

use libc::wchar_t;

unsafe extern "C" {
    fn wcsnlen(s: *const wchar_t, maxlen: usize) -> usize;
}

#[test]
fn wcsnlen_matches_glibc() {
    // "hello\0" plus trailing non-NUL filler to exercise the unbounded case.
    let mut buf: Vec<wchar_t> = "hello".chars().map(|c| c as wchar_t).collect();
    buf.push(0);
    buf.extend("WORLD".chars().map(|c| c as wchar_t)); // junk after the NUL

    for maxlen in [0usize, 1, 3, 5, 6, 10, 50] {
        let g = unsafe { wcsnlen(buf.as_ptr(), maxlen) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(buf.as_ptr(), maxlen) };
        assert_eq!(f, g, "wcsnlen(maxlen={maxlen}): fl={f} glibc={g}");
    }

    // A buffer with NO NUL within the bound: wcsnlen must stop at maxlen.
    let nonul: Vec<wchar_t> = "abcdefgh".chars().map(|c| c as wchar_t).collect();
    for maxlen in [0usize, 1, 4, 8] {
        let g = unsafe { wcsnlen(nonul.as_ptr(), maxlen) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(nonul.as_ptr(), maxlen) };
        assert_eq!(f, g, "wcsnlen(no NUL, maxlen={maxlen}): fl={f} glibc={g}");
        assert_eq!(f, maxlen, "wcsnlen must return maxlen when no NUL within bound");
    }

    // Empty string -> 0 regardless of maxlen.
    let empty: [wchar_t; 1] = [0];
    for maxlen in [0usize, 5] {
        let g = unsafe { wcsnlen(empty.as_ptr(), maxlen) };
        let f = unsafe { frankenlibc_abi::wchar_abi::wcsnlen(empty.as_ptr(), maxlen) };
        assert_eq!(f, g, "wcsnlen(empty, maxlen={maxlen})");
        assert_eq!(f, 0);
    }
}
