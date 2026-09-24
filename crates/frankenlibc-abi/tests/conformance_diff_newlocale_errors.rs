#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc newlocale oracle

//! Differential gate for newlocale error errno (bd-h7oh9f), validating cod's
//! strict-error-path fix (bd-id0azv) against runtime glibc. For an invalid
//! category mask and an unsupported locale name, fl's newlocale must return
//! NULL with the same errno as host glibc; for "C" it must succeed (a non-NULL
//! locale_t, which is then freed). newlocale builds a fresh locale object and
//! does not touch the global locale, so this is side-effect-free. No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

// The host arms are resolved with `dlsym`, not declared at link time: fl
// exports its own newlocale/freelocale into this binary, and when those exports
// are live a link-time reference can bind locally, making both arms fl so the
// comparisons pass while proving nothing (bd-h95z6y found conformance_diff_fma
// doing exactly that). Whether it happens depends on the build profile, so a
// gate honest under `cargo test` can go hollow under `--release`. dlsym on an
// explicit libc.so.6 handle is correct in either profile.
type NewlocaleFn = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_void;
type FreelocaleFn = unsafe extern "C" fn(*mut c_void);

union NewlocaleSym {
    raw: *mut c_void,
    function: NewlocaleFn,
}
union FreelocaleSym {
    raw: *mut c_void,
    function: FreelocaleFn,
}

fn libc_handle() -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    handle
}

fn host_newlocale() -> NewlocaleFn {
    // SAFETY: the handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(libc_handle(), c"newlocale".as_ptr()) };
    assert!(!raw.is_null(), "dlsym newlocale");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::locale_abi::newlocale as usize,
        "the resolved oracle IS fl's newlocale — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has POSIX's documented newlocale signature.
    unsafe { NewlocaleSym { raw }.function }
}

fn host_freelocale() -> FreelocaleFn {
    // SAFETY: as above, for freelocale. Pairing the host's own deallocator with
    // the host's newlocale matters: freeing a glibc locale_t through fl's
    // freelocale would be a cross-allocator free, not a test.
    let raw = unsafe { libc::dlsym(libc_handle(), c"freelocale".as_ptr()) };
    assert!(!raw.is_null(), "dlsym freelocale");
    // SAFETY: the resolved symbol has POSIX's documented freelocale signature.
    unsafe { FreelocaleSym { raw }.function }
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

fn glibc_new(mask: c_int, name: &CString) -> (bool, c_int) {
    let newlocale = host_newlocale();
    unsafe { *__errno_location() = 0 };
    let r = unsafe { newlocale(mask, name.as_ptr(), std::ptr::null_mut()) };
    let e = errno();
    if !r.is_null() {
        let freelocale = host_freelocale();
        unsafe { freelocale(r) };
    }
    (r.is_null(), e)
}

fn fl_new(mask: c_int, name: &CString) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe {
        frankenlibc_abi::locale_abi::newlocale(mask, name.as_ptr(), std::ptr::null_mut())
    };
    let e = errno();
    if !r.is_null() {
        unsafe { frankenlibc_abi::locale_abi::freelocale(r) };
    }
    (r.is_null(), e)
}

#[test]
fn newlocale_invalid_mask_matches_glibc() {
    // A category-mask bit far outside the valid LC_*_MASK range.
    let bad_mask: c_int = 1 << 28;
    let c = CString::new("C").unwrap();
    let (gnull, ge) = glibc_new(bad_mask, &c);
    let (fnull, fe) = fl_new(bad_mask, &c);
    assert!(gnull, "glibc newlocale(invalid mask) should return NULL");
    assert_eq!(
        fnull, gnull,
        "newlocale(invalid mask) NULL-ness: fl={fnull} glibc={gnull}"
    );
    assert_eq!(fe, ge, "newlocale(invalid mask) errno: fl={fe} glibc={ge}");
}

#[test]
fn newlocale_unsupported_locale_matches_glibc() {
    let bogus = CString::new("fl_no_such_locale_zzqq.UTF-8").unwrap();
    let (gnull, ge) = glibc_new(libc::LC_ALL_MASK, &bogus);
    let (fnull, fe) = fl_new(libc::LC_ALL_MASK, &bogus);
    assert!(
        gnull,
        "glibc newlocale(LC_ALL_MASK, bogus) should return NULL"
    );
    assert_eq!(
        fnull, gnull,
        "newlocale(bogus) NULL-ness: fl={fnull} glibc={gnull}"
    );
    assert_eq!(fe, ge, "newlocale(bogus) errno: fl={fe} glibc={ge}");
}

#[test]
fn newlocale_c_succeeds_both() {
    let c = CString::new("C").unwrap();
    let (gnull, _) = glibc_new(libc::LC_ALL_MASK, &c);
    let (fnull, _) = fl_new(libc::LC_ALL_MASK, &c);
    assert!(!gnull, "glibc newlocale(LC_ALL_MASK, \"C\") should succeed");
    assert!(!fnull, "fl newlocale(LC_ALL_MASK, \"C\") should succeed");
}

/// The mask libstdc++ passes: exactly `1 << LC_ALL`. glibc normalizes it to
/// LC_ALL_MASK; only the LC_ALL bit combined with other bits is invalid. The
/// earlier gate covered just the combined form, so it stayed green while fl
/// rejected the exact form and every C++ program aborted at load
/// (bd-rc0923-epic-eeuy4f.2).
#[test]
fn newlocale_lc_all_bit_masks_match_glibc() {
    let exact: c_int = 1 << libc::LC_ALL;
    for (mask, label) in [
        (exact, "exact 1<<LC_ALL"),
        (libc::LC_ALL_MASK | exact, "LC_ALL_MASK|1<<LC_ALL"),
        (libc::LC_CTYPE_MASK | exact, "LC_CTYPE_MASK|1<<LC_ALL"),
        (0, "zero mask"),
        (libc::LC_NUMERIC_MASK, "LC_NUMERIC_MASK"),
    ] {
        for name in ["C", "POSIX", "C.UTF-8"] {
            let n = CString::new(name).unwrap();
            let (gnull, ge) = glibc_new(mask, &n);
            let (fnull, fe) = fl_new(mask, &n);
            assert_eq!(
                fnull, gnull,
                "newlocale({label}, {name}) NULL-ness: fl={fnull} glibc={gnull}"
            );
            if gnull {
                assert_eq!(fe, ge, "newlocale({label}, {name}) errno: fl={fe} glibc={ge}");
            }
        }
    }
}
