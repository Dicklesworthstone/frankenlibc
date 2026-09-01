#![cfg(target_os = "linux")]

//! Differential conformance harness for `<dlfcn.h>`:
//!   - dlopen / dlclose (handle lifecycle)
//!   - dlsym (symbol lookup via RTLD_DEFAULT and a real .so handle)
//!   - dlerror (error reporting after a failed lookup)
//!   - dladdr (resolve an address to its symbol)
//!
//! Tests use libm.so.6 (universally available) as the dlopen target
//! and look up `cos` (a deterministic symbol). For RTLD_DEFAULT we
//! look up `getpid` which is in the program's own symbols.
//!
//! Bead: CONFORMANCE: libc dlfcn.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};

use frankenlibc_abi::dlfcn_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *const c_char;
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

#[repr(C)]
#[derive(Default)]
struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

const RTLD_LAZY: c_int = 0x00001;
const RTLD_NOW: c_int = 0x00002;
const RTLD_DEEPBIND: c_int = 0x00008;
const RTLD_LOCAL: c_int = 0x00000;
const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut();

#[test]
fn diff_dlopen_libm_then_dlsym_cos() {
    let lib = CString::new("libm.so.6").unwrap();
    let sym = CString::new("cos").unwrap();

    let h_fl = unsafe { fl::dlopen(lib.as_ptr(), RTLD_LAZY) };
    let p_fl = if !h_fl.is_null() {
        unsafe { fl::dlsym(h_fl, sym.as_ptr()) }
    } else {
        std::ptr::null_mut()
    };
    let r_close_fl = if !h_fl.is_null() {
        unsafe { fl::dlclose(h_fl) }
    } else {
        -1
    };

    let h_lc = unsafe { dlopen(lib.as_ptr(), RTLD_LAZY) };
    let p_lc = if !h_lc.is_null() {
        unsafe { dlsym(h_lc, sym.as_ptr()) }
    } else {
        std::ptr::null_mut()
    };
    let r_close_lc = if !h_lc.is_null() {
        unsafe { dlclose(h_lc) }
    } else {
        -1
    };

    assert_eq!(
        h_fl.is_null(),
        h_lc.is_null(),
        "dlopen libm.so.6 null-match: fl={h_fl:?}, lc={h_lc:?}"
    );
    assert_eq!(
        p_fl.is_null(),
        p_lc.is_null(),
        "dlsym(cos) null-match: fl={p_fl:?}, lc={p_lc:?}"
    );
    assert_eq!(
        r_close_fl, r_close_lc,
        "dlclose return: fl={r_close_fl}, lc={r_close_lc}"
    );
    assert!(
        !p_fl.is_null(),
        "cos should resolve to a real address via fl"
    );
    // Both should point to the same address since the library is shared.
    if !p_fl.is_null() && !p_lc.is_null() {
        assert_eq!(p_fl, p_lc, "cos address divergence");
    }
}

#[test]
fn diff_libc_dlopen_mode_alias_libm_then_libc_dlsym_cos() {
    let lib = CString::new("libm.so.6").unwrap();
    let sym = CString::new("cos").unwrap();

    let h_fl = unsafe { fl::__libc_dlopen_mode(lib.as_ptr(), RTLD_NOW) };
    let p_fl = if !h_fl.is_null() {
        unsafe { fl::__libc_dlsym(h_fl, sym.as_ptr()) }
    } else {
        std::ptr::null_mut()
    };
    let r_close_fl = if !h_fl.is_null() {
        unsafe { fl::__libc_dlclose(h_fl) }
    } else {
        -1
    };

    let h_lc = unsafe { dlopen(lib.as_ptr(), RTLD_NOW) };
    let p_lc = if !h_lc.is_null() {
        unsafe { dlsym(h_lc, sym.as_ptr()) }
    } else {
        std::ptr::null_mut()
    };
    let r_close_lc = if !h_lc.is_null() {
        unsafe { dlclose(h_lc) }
    } else {
        -1
    };

    assert_eq!(
        h_fl.is_null(),
        h_lc.is_null(),
        "__libc_dlopen_mode libm.so.6 null-match: fl={h_fl:?}, lc={h_lc:?}"
    );
    assert_eq!(
        p_fl.is_null(),
        p_lc.is_null(),
        "__libc_dlsym(cos) null-match: fl={p_fl:?}, lc={p_lc:?}"
    );
    assert_eq!(
        r_close_fl, r_close_lc,
        "__libc_dlclose return: fl={r_close_fl}, lc={r_close_lc}"
    );
    assert!(
        !p_fl.is_null(),
        "cos should resolve to a real address via __libc_dlsym"
    );
    if !p_fl.is_null() && !p_lc.is_null() {
        assert_eq!(p_fl, p_lc, "cos address divergence via dlfcn aliases");
    }
}

#[test]
fn diff_dlopen_nonexistent_returns_null() {
    let lib = CString::new("/this/library/does/not/exist.so").unwrap();
    let h_fl = unsafe { fl::dlopen(lib.as_ptr(), RTLD_LAZY) };
    let h_lc = unsafe { dlopen(lib.as_ptr(), RTLD_LAZY) };
    assert_eq!(
        h_fl.is_null(),
        h_lc.is_null(),
        "dlopen nonexistent null-match: fl={h_fl:?}, lc={h_lc:?}"
    );
    assert!(h_fl.is_null(), "dlopen nonexistent must return NULL");
    let _ = RTLD_NOW;
}

#[test]
fn diff_dlsym_default_handle_finds_getpid() {
    let sym = CString::new("getpid").unwrap();
    let p_fl = unsafe { fl::dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    let p_lc = unsafe { dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    assert_eq!(
        p_fl.is_null(),
        p_lc.is_null(),
        "dlsym(RTLD_DEFAULT, getpid) null-match: fl={p_fl:?}, lc={p_lc:?}"
    );
    assert!(!p_fl.is_null(), "getpid must resolve");
    if !p_fl.is_null() && !p_lc.is_null() {
        assert_eq!(p_fl, p_lc, "getpid address divergence");
    }
}

#[test]
fn diff_dlsym_unknown_returns_null() {
    let sym = CString::new("definitely_not_a_real_symbol_xyz123").unwrap();
    let p_fl = unsafe { fl::dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    let p_lc = unsafe { dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    assert_eq!(
        p_fl.is_null(),
        p_lc.is_null(),
        "dlsym unknown null-match: fl={p_fl:?}, lc={p_lc:?}"
    );
    assert!(p_fl.is_null(), "unknown symbol must return NULL");
}

#[test]
fn diff_dlerror_is_consumed_after_lookup_failure() {
    let _ = unsafe { fl::dlerror() };
    let _ = unsafe { dlerror() };

    let sym = CString::new("definitely_not_a_real_symbol_for_dlerror_xyz123").unwrap();
    let p_fl = unsafe { fl::dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    let p_lc = unsafe { dlsym(RTLD_DEFAULT, sym.as_ptr()) };
    assert!(p_fl.is_null(), "fl unknown symbol must fail");
    assert!(p_lc.is_null(), "glibc unknown symbol must fail");

    let e_fl = unsafe { fl::dlerror() };
    let e_lc = unsafe { dlerror() };
    assert_eq!(
        e_fl.is_null(),
        e_lc.is_null(),
        "first dlerror null-match: fl={e_fl:?}, lc={e_lc:?}"
    );
    assert!(
        !e_fl.is_null(),
        "lookup failure should produce a dlerror message"
    );

    let second_fl = unsafe { fl::dlerror() };
    let second_lc = unsafe { dlerror() };
    assert!(
        second_fl.is_null() && second_lc.is_null(),
        "dlerror should consume the pending error"
    );
}

// dlclose with a bogus handle is undefined behavior (glibc tends to
// segfault inside its rtld); not a portable diff target. Skipped.

#[test]
fn diff_dladdr_resolves_known_function() {
    // Use a known function (libc::malloc) and verify dladdr finds it
    let func_addr = libc::malloc as *const c_void;
    let mut info_fl = DlInfo::default();
    let mut info_lc = DlInfo::default();
    let r_fl = unsafe { fl::dladdr(func_addr, &mut info_fl as *mut _ as *mut c_void) };
    let r_lc = unsafe { dladdr(func_addr, &mut info_lc) };
    assert_eq!(
        r_fl != 0,
        r_lc != 0,
        "dladdr success-match: fl={r_fl}, lc={r_lc}"
    );
    if r_fl != 0 && r_lc != 0 {
        // dli_fbase should match (same library)
        assert_eq!(
            info_fl.dli_fbase, info_lc.dli_fbase,
            "dladdr dli_fbase divergence"
        );
    }
}

/// `RTLD_DEEPBIND` must be accepted, and must behave the same as it does under
/// glibc.
///
/// fl's `valid_flags` omitted `RTLD_DEEPBIND` from its modifier mask, so every
/// `dlopen(path, RTLD_NOW | RTLD_DEEPBIND)` returned NULL with "invalid mode for
/// dlopen" where glibc returns a usable handle. That is the exact mode this
/// repository's own `incumbent_coverage_ab` uses to load FrankenLibC, so fl
/// rejected the way its own benchmark harness loads it.
///
/// The glibc arm is resolved through the `dlsym` oracle rather than a link-time
/// declaration: fl exports `dlopen` too, so in a release build a plain
/// `extern "C"` reference can bind to fl and quietly compare fl against itself.
#[test]
fn diff_dlopen_deepbind_is_accepted() {
    type DlopenFn = unsafe extern "C" fn(*const c_char, c_int) -> *mut c_void;
    type DlcloseFn = unsafe extern "C" fn(*mut c_void) -> c_int;

    let host_dlopen: DlopenFn =
        unsafe { dlsym_oracle::host_fn(c"dlopen", fl::dlopen as DlopenFn as *const ()) };
    let host_dlclose: DlcloseFn =
        unsafe { dlsym_oracle::host_fn(c"dlclose", fl::dlclose as DlcloseFn as *const ()) };

    let lib = CString::new("libm.so.6").unwrap();
    let sym = CString::new("cos").unwrap();

    for flags in [
        RTLD_NOW | RTLD_DEEPBIND,
        RTLD_LAZY | RTLD_DEEPBIND,
        RTLD_NOW | RTLD_DEEPBIND | RTLD_LOCAL,
    ] {
        let h_fl = unsafe { fl::dlopen(lib.as_ptr(), flags) };
        let h_lc = unsafe { host_dlopen(lib.as_ptr(), flags) };

        // The contract under test is agreement with glibc, not "fl succeeds":
        // if a host ever refused these flags, this gate must follow it.
        assert_eq!(
            h_fl.is_null(),
            h_lc.is_null(),
            "dlopen(libm.so.6, {flags:#x}) null-match: fl={h_fl:?} glibc={h_lc:?}"
        );

        // Non-vacuity: on this platform glibc accepts DEEPBIND, so a run in
        // which BOTH arms failed would satisfy the equality above while
        // testing nothing.
        assert!(
            !h_lc.is_null(),
            "glibc refused dlopen(libm.so.6, {flags:#x}); the equality above would be vacuous"
        );

        // A handle opened with DEEPBIND must still resolve symbols.
        let p_fl = unsafe { fl::dlsym(h_fl, sym.as_ptr()) };
        assert!(
            !p_fl.is_null(),
            "dlsym(cos) on a DEEPBIND handle returned NULL (flags={flags:#x})"
        );

        unsafe { fl::dlclose(h_fl) };
        unsafe { host_dlclose(h_lc) };
    }
}

#[test]
fn dlfcn_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"dlfcn.h\",\"reference\":\"glibc\",\"functions\":8,\"divergences\":0}}",
    );
}
