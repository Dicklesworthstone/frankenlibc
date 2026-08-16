#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strcasecmp_l oracle

//! Differential gate for strcasecmp_l/strncasecmp_l (bd-luyngu) — previously
//! uncovered. With a "C" locale these are ASCII case-insensitive compares; fl
//! ignores the locale and delegates to strcasecmp/strncasecmp, which matches
//! glibc for the C locale. Asserts fl's result sign matches host glibc across
//! case-folded, differing, and prefix cases (and the n bound for the bounded
//! form), using a real C locale_t. No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

// Host arms are resolved with `dlsym`, not declared at link time: fl exports
// all four of these into this binary, so link-time references can bind to fl
// and leave both arms as fl — green while proving nothing (bd-v0388t).
//
// The locale is part of the same problem. This gate built ONE locale_t from the
// link-time `newlocale` and passed it to BOTH implementations, so whichever did
// not create it received a foreign handle. Each arm now gets its own.
type CasecmpLFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> c_int;
type NcasecmpLFn = unsafe extern "C" fn(*const c_char, *const c_char, usize, *mut c_void) -> c_int;
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

fn host_strcasecmp_l() -> CasecmpLFn {
    // SAFETY: resolved symbol has POSIX's documented strcasecmp_l signature.
    unsafe {
        std::mem::transmute::<_, CasecmpLFn>(host_symbol(
            c"strcasecmp_l",
            frankenlibc_abi::string_abi::strcasecmp_l as usize,
        ))
    }
}
fn host_strncasecmp_l() -> NcasecmpLFn {
    // SAFETY: resolved symbol has POSIX's documented strncasecmp_l signature.
    unsafe {
        std::mem::transmute::<_, NcasecmpLFn>(host_symbol(
            c"strncasecmp_l",
            frankenlibc_abi::string_abi::strncasecmp_l as usize,
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

const PAIRS: &[(&str, &str)] = &[
    ("Hello", "hello"),
    ("HELLO", "hello"),
    ("abc", "abd"),
    ("abc", "ABD"),
    ("a", "B"),
    ("", ""),
    ("x", ""),
    ("Foo", "FooBar"),
    ("z", "a"),
];

#[test]
fn strcasecmp_l_matches_glibc() {
    let strcasecmp_l = host_strcasecmp_l();
    let strncasecmp_l = host_strncasecmp_l();
    let newlocale = host_newlocale();
    let freelocale = host_freelocale();
    let cloc_name = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc_name.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "host newlocale(C) failed");
    // One locale per implementation; a single shared handle would hand one of
    // them a locale_t it did not create.
    let fl_loc = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            cloc_name.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!fl_loc.is_null(), "fl newlocale(C) failed");

    for &(sa, sb) in PAIRS {
        let a = CString::new(sa).unwrap();
        let b = CString::new(sb).unwrap();
        let g = unsafe { strcasecmp_l(a.as_ptr(), b.as_ptr(), loc) };
        let f = unsafe {
            frankenlibc_abi::string_abi::strcasecmp_l(a.as_ptr(), b.as_ptr(), fl_loc as *mut c_void)
        };
        assert_eq!(
            f.signum(),
            g.signum(),
            "strcasecmp_l({sa:?},{sb:?}): fl={f} glibc={g}"
        );

        for n in [0usize, 1, 3, 10] {
            let gn = unsafe { strncasecmp_l(a.as_ptr(), b.as_ptr(), n, loc) };
            let fnr = unsafe {
                frankenlibc_abi::string_abi::strncasecmp_l(
                    a.as_ptr(),
                    b.as_ptr(),
                    n,
                    fl_loc as *mut c_void,
                )
            };
            assert_eq!(
                fnr.signum(),
                gn.signum(),
                "strncasecmp_l({sa:?},{sb:?},{n}): fl={fnr} glibc={gn}"
            );
        }
    }

    unsafe { freelocale(loc) };
    unsafe { frankenlibc_abi::locale_abi::freelocale(fl_loc) };
}
