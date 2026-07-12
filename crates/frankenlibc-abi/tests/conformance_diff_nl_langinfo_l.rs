#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc nl_langinfo_l oracle

//! Differential gate for nl_langinfo_l (bd-lofdvp) — previously fl-internal
//! only. It delegates to nl_langinfo; this validates that the _l variant
//! returns the same string as glibc's nl_langinfo_l for the PUBLIC nl_item set
//! under a "C" locale_t. Restricted to documented public items (not raw 0..N)
//! to avoid glibc's internal _NL_* items that return non-string binary data.
//! Compares bytes (NULL vs empty distinguished). No mocks.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn nl_langinfo_l(item: c_int, loc: *mut c_void) -> *const c_char;
    fn newlocale(mask: c_int, name: *const c_char, base: *mut c_void) -> *mut c_void;
    fn freelocale(loc: *mut c_void);
}

unsafe fn val(p: *const c_char) -> Option<Vec<u8>> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
    }
}

fn items() -> Vec<(c_int, &'static str)> {
    use libc::*;
    let mut v: Vec<(c_int, &'static str)> = vec![
        (CODESET, "CODESET"),
        (D_T_FMT, "D_T_FMT"),
        (D_FMT, "D_FMT"),
        (T_FMT, "T_FMT"),
        (T_FMT_AMPM, "T_FMT_AMPM"),
        (AM_STR, "AM_STR"),
        (PM_STR, "PM_STR"),
        (RADIXCHAR, "RADIXCHAR"),
        (THOUSEP, "THOUSEP"),
        (YESEXPR, "YESEXPR"),
        (NOEXPR, "NOEXPR"),
        (CRNCYSTR, "CRNCYSTR"),
        (DAY_1, "DAY_1"),
        (DAY_7, "DAY_7"),
        (ABDAY_1, "ABDAY_1"),
        (ABDAY_7, "ABDAY_7"),
        (MON_1, "MON_1"),
        (MON_12, "MON_12"),
        (ABMON_1, "ABMON_1"),
        (ABMON_12, "ABMON_12"),
        (ERA, "ERA"),
        (ERA_D_FMT, "ERA_D_FMT"),
        (ALT_DIGITS, "ALT_DIGITS"),
    ];
    // Fill the contiguous day/month ranges too.
    for i in 0..7 {
        v.push((DAY_1 + i, "DAY_n"));
        v.push((ABDAY_1 + i, "ABDAY_n"));
    }
    for i in 0..12 {
        v.push((MON_1 + i, "MON_n"));
        v.push((ABMON_1 + i, "ABMON_n"));
    }
    v
}

#[test]
fn nl_langinfo_l_matches_glibc() {
    let cloc = CString::new("C").unwrap();
    let loc = unsafe { newlocale(libc::LC_ALL_MASK, cloc.as_ptr(), std::ptr::null_mut()) };
    assert!(!loc.is_null());

    for (code, name) in items() {
        let g = unsafe { val(nl_langinfo_l(code, loc)) };
        let f = unsafe {
            val(frankenlibc_abi::locale_abi::nl_langinfo_l(
                code,
                loc as *mut c_void,
            ))
        };
        assert_eq!(
            f,
            g,
            "nl_langinfo_l({name}={code}): fl={:?} glibc={:?}",
            f.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
            g.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
        );
    }
    unsafe { freelocale(loc) };
}
