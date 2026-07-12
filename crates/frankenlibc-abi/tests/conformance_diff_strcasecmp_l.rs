#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc strcasecmp_l oracle

//! Differential gate for strcasecmp_l/strncasecmp_l (bd-luyngu) — previously
//! uncovered. With a "C" locale these are ASCII case-insensitive compares; fl
//! ignores the locale and delegates to strcasecmp/strncasecmp, which matches
//! glibc for the C locale. Asserts fl's result sign matches host glibc across
//! case-folded, differing, and prefix cases (and the n bound for the bounded
//! form), using a real C locale_t. No mocks.

use std::ffi::{CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn strcasecmp_l(a: *const c_char, b: *const c_char, loc: *mut c_void) -> c_int;
    fn strncasecmp_l(a: *const c_char, b: *const c_char, n: usize, loc: *mut c_void) -> c_int;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
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
    let cloc_name = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc_name.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null(), "newlocale(C) failed");

    for &(sa, sb) in PAIRS {
        let a = CString::new(sa).unwrap();
        let b = CString::new(sb).unwrap();
        let g = unsafe { strcasecmp_l(a.as_ptr(), b.as_ptr(), loc) };
        let f = unsafe {
            frankenlibc_abi::string_abi::strcasecmp_l(a.as_ptr(), b.as_ptr(), loc as *mut c_void)
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
                    loc as *mut c_void,
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
}
