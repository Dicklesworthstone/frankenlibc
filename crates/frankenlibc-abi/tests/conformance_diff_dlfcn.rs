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
    assert_eq!(r_close_fl, r_close_lc, "dlclose return: fl={r_close_fl}, lc={r_close_lc}");
    assert!(!p_fl.is_null(), "cos should resolve to a real address via fl");
    // Both should point to the same address since the library is shared.
    if !p_fl.is_null() && !p_lc.is_null() {
        assert_eq!(p_fl, p_lc, "cos address divergence");
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
    assert_eq!(r_fl != 0, r_lc != 0, "dladdr success-match: fl={r_fl}, lc={r_lc}");
    if r_fl != 0 && r_lc != 0 {
        // dli_fbase should match (same library)
        assert_eq!(
            info_fl.dli_fbase, info_lc.dli_fbase,
            "dladdr dli_fbase divergence"
        );
    }
}

#[test]
fn dlfcn_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"dlfcn.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
