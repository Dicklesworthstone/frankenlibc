#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strxfrm_l/wcsxfrm_l oracle

//! Differential gate for the collation-transform _l variants strxfrm_l/
//! wcsxfrm_l (bd-4b4mpl) — previously uncovered. strxfrm_l transforms src into
//! dest (at most n units) for collation and returns the full transformed
//! length; in a "C" locale the transform is the identity copy. fl delegates to
//! strxfrm/wcsxfrm; it must match host glibc on the return length always, and
//! on the bytes written when the result fits (n > src len). When the return is
//! >= n the C standard leaves dest contents INDETERMINATE, so the buffer is not
//! compared in that case (only the length). No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

use libc::wchar_t;

unsafe extern "C" {
    fn strxfrm_l(dest: *mut c_char, src: *const c_char, n: usize, loc: *mut c_void) -> usize;
    fn wcsxfrm_l(dest: *mut wchar_t, src: *const wchar_t, n: usize, loc: *mut c_void) -> usize;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
}

const FILL: u8 = 0x7e;

#[test]
fn strxfrm_l_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());

    for s in ["abc", "hello world", "", "Z", "a longer collation string"] {
        let src = CString::new(s).unwrap();
        for n in [0usize, 1, 3, s.len(), s.len() + 1, 64] {
            let mut gd = vec![FILL; 80];
            let mut fd = vec![FILL; 80];
            let g = unsafe { strxfrm_l(gd.as_mut_ptr() as *mut c_char, src.as_ptr(), n, loc) };
            let f = unsafe {
                frankenlibc_abi::unistd_abi::strxfrm_l(
                    fd.as_mut_ptr() as *mut c_char,
                    src.as_ptr(),
                    n,
                    loc as *mut c_void,
                )
            };
            assert_eq!(f, g, "strxfrm_l({s:?}, n={n}) return");
            // Buffer is determinate exactly when the transform plus its NUL fit,
            // i.e. when the RETURN is < n (C17 7.24.4.5p3: if the return is >= n,
            // the contents of dest are indeterminate). Gate on the measured return
            // rather than on `n > s.len()`: those coincide only because this gate
            // runs in the "C" locale, where the transform is the identity copy and
            // the return happens to equal the source length. Keying on the return
            // is the standard's own condition and stays correct if this gate is
            // ever pointed at a locale whose transform expands or contracts.
            // bd-8omwj4.
            if g < n {
                assert_eq!(fd, gd, "strxfrm_l({s:?}, n={n}) buffer");
            }
        }
    }
    unsafe { freelocale(loc) };
}

#[test]
fn wcsxfrm_l_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());

    for s in ["abc", "wide str", ""] {
        let src: Vec<wchar_t> = s
            .chars()
            .map(|c| c as wchar_t)
            .chain(std::iter::once(0))
            .collect();
        for n in [0usize, 1, 3, s.len() + 1, 32] {
            let mut gd = vec![0x7e7e_i32 as wchar_t; 40];
            let mut fd = vec![0x7e7e_i32 as wchar_t; 40];
            let g = unsafe { wcsxfrm_l(gd.as_mut_ptr(), src.as_ptr(), n, loc) };
            let f = unsafe {
                frankenlibc_abi::wchar_abi::wcsxfrm_l(
                    fd.as_mut_ptr(),
                    src.as_ptr(),
                    n,
                    loc as *mut c_void,
                )
            };
            assert_eq!(f, g, "wcsxfrm_l({s:?}, n={n}) return");
            // Same determinacy rule as strxfrm_l above, keyed on the measured
            // return rather than a character count (bd-8omwj4). For the wide form
            // the proxy was doubly indirect: `s.chars().count()` is the number of
            // scalar values in the Rust source string, not the wide-transform
            // length the standard actually compares against n.
            if g < n {
                assert_eq!(fd, gd, "wcsxfrm_l({s:?}, n={n}) buffer");
            }
        }
    }
    unsafe { freelocale(loc) };
}
