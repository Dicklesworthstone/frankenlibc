#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strcoll_l/wcscoll_l oracle

//! Differential gate for the collation _l variants strcoll_l/wcscoll_l
//! (bd-2bjxh3) — previously uncovered. With a "C" locale these collate by byte
//! value; fl ignores the locale and delegates to strcoll/wcscoll, which matches
//! glibc for the C locale. Asserts fl's result sign matches host glibc across
//! equal/ordered/prefix pairs, using a real C locale_t. No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

use libc::wchar_t;

// Host arms are resolved with `dlsym`, not declared at link time. fl exports
// strcoll_l/wcscoll_l/newlocale/freelocale into this same test binary, so a
// link-time reference can bind to fl instead of libc and leave both arms as fl
// — green while proving nothing. Measured, not theoretical:
// conformance_diff_catopen was passing that way in a plain debug build and was
// hiding a live errno defect (bd-rp1e32, bd-v0388t).
//
// The locale matters as much as the functions here. This gate used to build ONE
// locale_t from the link-time `newlocale` and pass it to BOTH implementations,
// so whichever one did not create it received a foreign handle. Each arm now
// gets a locale from its own implementation, which is the only comparison that
// means anything.
type StrcollLFn = unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void) -> c_int;
type WcscollLFn = unsafe extern "C" fn(*const wchar_t, *const wchar_t, *mut c_void) -> c_int;
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

fn host_strcoll_l() -> StrcollLFn {
    // SAFETY: resolved symbol has POSIX's documented strcoll_l signature.
    unsafe {
        std::mem::transmute::<_, StrcollLFn>(host_symbol(
            c"strcoll_l",
            frankenlibc_abi::unistd_abi::strcoll_l as usize,
        ))
    }
}
fn host_wcscoll_l() -> WcscollLFn {
    // SAFETY: resolved symbol has POSIX's documented wcscoll_l signature.
    unsafe {
        std::mem::transmute::<_, WcscollLFn>(host_symbol(
            c"wcscoll_l",
            frankenlibc_abi::wchar_abi::wcscoll_l as usize,
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
    // SAFETY: resolved symbol has POSIX's documented freelocale signature.
    // Deliberately paired with host_newlocale: freeing a glibc locale_t through
    // fl's freelocale would be a cross-implementation free, not a test.
    unsafe {
        std::mem::transmute::<_, FreelocaleFn>(host_symbol(
            c"freelocale",
            frankenlibc_abi::locale_abi::freelocale as usize,
        ))
    }
}

const PAIRS: &[(&str, &str)] = &[
    ("abc", "abc"),
    ("abc", "abd"),
    ("abd", "abc"),
    ("Z", "a"),
    ("a", "Z"),
    ("", ""),
    ("x", ""),
    ("foo", "foobar"),
    ("9", "10"),
];

fn wide(s: &str) -> Vec<wchar_t> {
    let mut v: Vec<wchar_t> = s.chars().map(|c| c as wchar_t).collect();
    v.push(0);
    v
}

#[test]
fn strcoll_l_wcscoll_l_match_glibc() {
    let strcoll_l = host_strcoll_l();
    let wcscoll_l = host_wcscoll_l();
    let newlocale = host_newlocale();
    let freelocale = host_freelocale();

    let cloc = CString::new("C").unwrap();
    // One locale per implementation. Passing a single handle to both would hand
    // one of them a locale_t it did not create.
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "host newlocale(C) failed");
    let fl_loc = unsafe {
        frankenlibc_abi::locale_abi::newlocale(
            libc::LC_ALL_MASK,
            cloc.as_ptr(),
            std::ptr::null_mut(),
        )
    };
    assert!(!fl_loc.is_null(), "fl newlocale(C) failed");

    for &(sa, sb) in PAIRS {
        let a = CString::new(sa).unwrap();
        let b = CString::new(sb).unwrap();
        let g = unsafe { strcoll_l(a.as_ptr(), b.as_ptr(), loc) };
        let f = unsafe {
            frankenlibc_abi::unistd_abi::strcoll_l(a.as_ptr(), b.as_ptr(), fl_loc as *mut c_void)
        };
        assert_eq!(
            f.signum(),
            g.signum(),
            "strcoll_l({sa:?},{sb:?}): fl={f} glibc={g}"
        );

        let wa = wide(sa);
        let wb = wide(sb);
        let gw = unsafe { wcscoll_l(wa.as_ptr(), wb.as_ptr(), loc) };
        let fw = unsafe {
            frankenlibc_abi::wchar_abi::wcscoll_l(wa.as_ptr(), wb.as_ptr(), fl_loc as *mut c_void)
        };
        assert_eq!(
            fw.signum(),
            gw.signum(),
            "wcscoll_l({sa:?},{sb:?}): fl={fw} glibc={gw}"
        );
    }

    unsafe { freelocale(loc) };
    unsafe { frankenlibc_abi::locale_abi::freelocale(fl_loc) };
}
