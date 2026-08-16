#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc catopen oracle

//! Differential gate for catopen error paths (bd-rp1e32), validating cod's
//! EINVAL fixes (bd-b7ks5s empty name, bd-jbujfo directory) against the
//! authoritative runtime glibc. For an empty name, an existing directory, and a
//! nonexistent catalog name, fl's catopen must FAIL exactly like glibc — same
//! "is it an error" outcome AND the same errno. NULL is not tested (glibc
//! dereferences it). No mocks.
//!
//! This is a cross-review gate: if cod's catopen returns EINVAL where glibc
//! returns ENOENT/EISDIR, this fails in the batch run and surfaces the bug; if
//! they agree, it confirms the fix.

use std::ffi::{CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

// The host arms are resolved with `dlsym`, not declared at link time: fl
// exports its own catopen/catclose into this binary, and when those exports are
// live a link-time reference can bind locally, making both arms fl so the
// comparisons pass while proving nothing (bd-h95z6y found conformance_diff_fma
// doing exactly that). Whether it happens depends on the build profile, so a
// gate honest under `cargo test` can go hollow under `--release`. dlsym on an
// explicit libc.so.6 handle is correct in either profile.
type CatopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void; // glibc nl_catd
type CatcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

union CatopenSym {
    raw: *mut c_void,
    function: CatopenFn,
}
union CatcloseSym {
    raw: *mut c_void,
    function: CatcloseFn,
}

fn libc_handle() -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    handle
}

fn host_catopen() -> CatopenFn {
    // SAFETY: the handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(libc_handle(), c"catopen".as_ptr()) };
    assert!(!raw.is_null(), "dlsym catopen");
    assert_ne!(
        raw as usize,
        frankenlibc_abi::locale_abi::catopen as usize,
        "the resolved oracle IS fl's catopen — this gate would compare fl to itself"
    );
    // SAFETY: the resolved symbol has POSIX's documented catopen signature.
    unsafe { CatopenSym { raw }.function }
}

fn host_catclose() -> CatcloseFn {
    // SAFETY: as above. The host's own catclose must close a host catd; closing
    // it through fl's would be a cross-implementation free, not a test.
    let raw = unsafe { libc::dlsym(libc_handle(), c"catclose".as_ptr()) };
    assert!(!raw.is_null(), "dlsym catclose");
    // SAFETY: the resolved symbol has POSIX's documented catclose signature.
    unsafe { CatcloseSym { raw }.function }
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

/// Returns (failed?, errno) for glibc catopen of `name`.
fn glibc_open(name: &CString) -> (bool, c_int) {
    let catopen = host_catopen();
    unsafe { *__errno_location() = 0 };
    let r = unsafe { catopen(name.as_ptr(), 0) };
    let e = errno();
    let failed = r as isize == -1;
    if !failed {
        let catclose = host_catclose();
        unsafe { catclose(r) };
    }
    (failed, e)
}

/// Returns (failed?, errno) for fl catopen of `name`.
fn fl_open(name: &CString) -> (bool, c_int) {
    unsafe { *__errno_location() = 0 };
    let r = unsafe { frankenlibc_abi::locale_abi::catopen(name.as_ptr(), 0) };
    let e = errno();
    let failed = r == -1;
    if !failed {
        unsafe { frankenlibc_abi::locale_abi::catclose(r) };
    }
    (failed, e)
}

#[test]
fn catopen_error_paths_match_glibc() {
    // Empty name, an existing directory, and a name that doesn't resolve.
    let cases = [
        CString::new("").unwrap(),
        CString::new("/tmp").unwrap(),
        CString::new("fl_no_such_catalog_zzqq").unwrap(),
    ];
    for name in &cases {
        let (gf, ge) = glibc_open(name);
        let (ff, fe) = fl_open(name);
        assert!(gf, "glibc catopen({name:?}) should fail (error-path test)");
        assert_eq!(
            ff, gf,
            "catopen({name:?}) failure-outcome: fl={ff} glibc={gf}"
        );
        assert_eq!(fe, ge, "catopen({name:?}) errno: fl={fe} glibc={ge}");
    }
}
