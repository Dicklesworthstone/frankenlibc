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

// Host arms are resolved with `dlsym`, not declared at link time: fl exports
// all four of these into this binary, so link-time references can bind to fl
// and leave both arms as fl — green while proving nothing (bd-v0388t;
// conformance_diff_catopen was doing exactly that in a plain debug build and
// hiding a live errno defect).
//
// The locale is part of the same problem: this gate built ONE locale_t from the
// link-time `newlocale` and passed it to BOTH implementations, so whichever did
// not create it received a foreign handle, and freed it through whichever
// freelocale the linker picked. Each arm now builds and frees its own.
type StrxfrmLFn = unsafe extern "C" fn(*mut c_char, *const c_char, usize, *mut c_void) -> usize;
type WcsxfrmLFn = unsafe extern "C" fn(*mut wchar_t, *const wchar_t, usize, *mut c_void) -> usize;
type NewlocaleFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
type FreelocaleFn = unsafe extern "C" fn(*mut c_void);

fn host_symbol(name: &std::ffi::CStr, fl_addr: usize) -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: the handle came from dlopen; name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(!raw.is_null(), "dlsym {name:?}");
    assert_ne!(
        raw as usize, fl_addr,
        "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself"
    );
    raw
}

fn host_strxfrm_l() -> StrxfrmLFn {
    // SAFETY: resolved symbol has POSIX's documented strxfrm_l signature.
    unsafe {
        std::mem::transmute::<_, StrxfrmLFn>(host_symbol(
            c"strxfrm_l",
            frankenlibc_abi::unistd_abi::strxfrm_l as usize,
        ))
    }
}
fn host_wcsxfrm_l() -> WcsxfrmLFn {
    // SAFETY: resolved symbol has POSIX's documented wcsxfrm_l signature.
    unsafe {
        std::mem::transmute::<_, WcsxfrmLFn>(host_symbol(
            c"wcsxfrm_l",
            frankenlibc_abi::wchar_abi::wcsxfrm_l as usize,
        ))
    }
}
fn host_newlocale() -> NewlocaleFn {
    // SAFETY: resolved symbol has POSIX's documented newlocale signature.
    unsafe {
        std::mem::transmute::<_, NewlocaleFn>(host_symbol(
            c"newlocale",
            frankenlibc_abi::locale_abi::newlocale as usize,
        ))
    }
}
fn host_freelocale() -> FreelocaleFn {
    // SAFETY: paired with host_newlocale — freeing a glibc locale_t through fl's
    // freelocale would be a cross-implementation free, not a test.
    unsafe {
        std::mem::transmute::<_, FreelocaleFn>(host_symbol(
            c"freelocale",
            frankenlibc_abi::locale_abi::freelocale as usize,
        ))
    }
}

/// Build a C locale from each implementation. Returned as (host, fl).
fn c_locales() -> (*mut c_void, *mut c_void) {
    let cloc = CString::new("C").unwrap();
    let newlocale = host_newlocale();
    // SAFETY: LC_ALL_MASK with a valid name and no base locale.
    let host = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!host.is_null(), "host newlocale(C) failed");
    // SAFETY: as above, against fl.
    let fl = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            cloc.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!fl.is_null(), "fl newlocale(C) failed");
    (host, fl)
}

const FILL: u8 = 0x7e;

#[test]
fn strxfrm_l_matches_glibc() {
    let strxfrm_l = host_strxfrm_l();
    let freelocale = host_freelocale();
    let (loc, fl_loc) = c_locales();

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
                    fl_loc as *mut c_void,
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
    unsafe { frankenlibc_abi::locale_abi::freelocale(fl_loc) };
}

#[test]
fn wcsxfrm_l_matches_glibc() {
    let wcsxfrm_l = host_wcsxfrm_l();
    let freelocale = host_freelocale();
    let (loc, fl_loc) = c_locales();

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
                    fl_loc as *mut c_void,
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
    unsafe { frankenlibc_abi::locale_abi::freelocale(fl_loc) };
}
