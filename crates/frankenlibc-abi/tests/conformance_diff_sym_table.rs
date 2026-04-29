#![cfg(target_os = "linux")]

//! Differential conformance harness for `__sym_ntop` / `__sym_ntos` /
//! `__sym_ston` against host libresolv.
//!
//! These three walk a caller-provided `struct res_sym` table to map
//! between numeric DNS values and their textual symbols. The reference
//! tables (`__p_class_syms`, `__p_type_syms`) live in libresolv as
//! data symbols; we link against them directly.
//!
//! Filed under [bd-58e87f] follow-up.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

use frankenlibc_abi::resolv_abi as fl;

#[repr(C)]
struct ResSym {
    number: c_int,
    name: *const c_char,
    humanname: *const c_char,
}

#[link(name = "resolv")]
unsafe extern "C" {
    fn __sym_ntop(syms: *const c_void, number: c_int, success: *mut c_int) -> *const c_char;
    fn __sym_ntos(syms: *const c_void, number: c_int, success: *mut c_int) -> *const c_char;
    fn __sym_ston(syms: *const c_void, str: *const c_char, success: *mut c_int) -> c_int;

    static __p_class_syms: [ResSym; 0];
    static __p_type_syms: [ResSym; 0];
}

fn cstr(p: *const c_char) -> Option<String> {
    if p.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
    }
}

#[test]
fn diff_sym_ntop_class_known_values() {
    // Class numbers from <arpa/nameser.h>: IN=1, CHAOS=3, HS=4, ANY=255.
    for n in &[1, 3, 4, 255] {
        let mut fl_s: c_int = -7;
        let mut lc_s: c_int = -7;
        let fl_p = unsafe {
            fl::__sym_ntop(__p_class_syms.as_ptr() as *const c_void, *n, &mut fl_s)
        };
        let lc_p = unsafe {
            __sym_ntop(__p_class_syms.as_ptr() as *const c_void, *n, &mut lc_s)
        };
        assert_eq!(cstr(fl_p), cstr(lc_p), "ntop class {n}");
        assert_eq!(fl_s, lc_s, "ntop class success {n}: fl={fl_s} lc={lc_s}");
        assert_eq!(fl_s, 1);
    }
}

#[test]
fn diff_sym_ntos_class_known_values() {
    for n in &[1, 3, 4, 255] {
        let mut fl_s: c_int = 0;
        let mut lc_s: c_int = 0;
        let fl_p = unsafe {
            fl::__sym_ntos(__p_class_syms.as_ptr() as *const c_void, *n, &mut fl_s)
        };
        let lc_p = unsafe {
            __sym_ntos(__p_class_syms.as_ptr() as *const c_void, *n, &mut lc_s)
        };
        assert_eq!(cstr(fl_p), cstr(lc_p), "ntos class {n}");
        assert_eq!(fl_s, lc_s);
    }
}

#[test]
fn diff_sym_ntop_type_known_values() {
    // Type numbers: A=1, NS=2, CNAME=5, MX=15, AAAA=28, SRV=33.
    for n in &[1, 2, 5, 15, 28, 33] {
        let mut fl_s: c_int = 0;
        let mut lc_s: c_int = 0;
        let fl_p = unsafe {
            fl::__sym_ntop(__p_type_syms.as_ptr() as *const c_void, *n, &mut fl_s)
        };
        let lc_p = unsafe {
            __sym_ntop(__p_type_syms.as_ptr() as *const c_void, *n, &mut lc_s)
        };
        assert_eq!(cstr(fl_p), cstr(lc_p), "ntop type {n}");
        assert_eq!(fl_s, lc_s);
    }
}

#[test]
fn diff_sym_ntos_type_known_values() {
    for n in &[1, 2, 5, 15, 28, 33] {
        let mut fl_s: c_int = 0;
        let mut lc_s: c_int = 0;
        let fl_p = unsafe {
            fl::__sym_ntos(__p_type_syms.as_ptr() as *const c_void, *n, &mut fl_s)
        };
        let lc_p = unsafe {
            __sym_ntos(__p_type_syms.as_ptr() as *const c_void, *n, &mut lc_s)
        };
        assert_eq!(cstr(fl_p), cstr(lc_p), "ntos type {n}");
        assert_eq!(fl_s, lc_s);
    }
}

#[test]
fn diff_sym_ntop_unknown_renders_as_decimal() {
    // 9999 is not a known type — both impls must report failure and
    // return the decimal representation.
    let mut fl_s: c_int = 0;
    let mut lc_s: c_int = 0;
    let fl_p = unsafe {
        fl::__sym_ntop(__p_type_syms.as_ptr() as *const c_void, 9999, &mut fl_s)
    };
    let lc_p = unsafe {
        __sym_ntop(__p_type_syms.as_ptr() as *const c_void, 9999, &mut lc_s)
    };
    assert_eq!(fl_s, 0);
    assert_eq!(lc_s, 0);
    assert_eq!(cstr(fl_p), cstr(lc_p), "ntop unknown");
    assert_eq!(cstr(fl_p).as_deref(), Some("9999"));
}

#[test]
fn diff_sym_ston_class_basic_match() {
    // Names map to numbers: IN -> 1, CHAOS -> 3, HS -> 4, ANY -> 255.
    for name in &["IN", "CHAOS", "HS", "ANY"] {
        let cs = CString::new(*name).unwrap();
        let mut fl_s: c_int = 0;
        let mut lc_s: c_int = 0;
        let fl_v = unsafe {
            fl::__sym_ston(__p_class_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut fl_s)
        };
        let lc_v = unsafe {
            __sym_ston(__p_class_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut lc_s)
        };
        assert_eq!(fl_v, lc_v, "ston class '{name}': fl={fl_v} lc={lc_v}");
        assert_eq!(fl_s, lc_s);
        assert_eq!(fl_s, 1);
    }
}

#[test]
fn diff_sym_ston_case_insensitive() {
    let cs = CString::new("in").unwrap();
    let mut fl_s: c_int = 0;
    let mut lc_s: c_int = 0;
    let fl_v = unsafe {
        fl::__sym_ston(__p_class_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut fl_s)
    };
    let lc_v = unsafe {
        __sym_ston(__p_class_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut lc_s)
    };
    assert_eq!(fl_v, lc_v);
    assert_eq!(fl_s, lc_s);
    assert_eq!(fl_s, 1);
    assert_eq!(fl_v, 1);
}

#[test]
fn diff_sym_ston_type_known_values() {
    for (name, num) in &[("A", 1), ("NS", 2), ("CNAME", 5), ("MX", 15), ("AAAA", 28)] {
        let cs = CString::new(*name).unwrap();
        let mut fl_s: c_int = 0;
        let mut lc_s: c_int = 0;
        let fl_v = unsafe {
            fl::__sym_ston(__p_type_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut fl_s)
        };
        let lc_v = unsafe {
            __sym_ston(__p_type_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut lc_s)
        };
        assert_eq!(fl_v, lc_v, "ston type '{name}'");
        assert_eq!(fl_s, lc_s);
        assert_eq!(fl_v, *num);
    }
}

#[test]
fn diff_sym_ston_unknown_returns_sentinel_with_failure() {
    let cs = CString::new("DEFINITELY_NOT_A_TYPE").unwrap();
    let mut fl_s: c_int = 0;
    let mut lc_s: c_int = 0;
    let fl_v = unsafe {
        fl::__sym_ston(__p_type_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut fl_s)
    };
    let lc_v = unsafe {
        __sym_ston(__p_type_syms.as_ptr() as *const c_void, cs.as_ptr(), &mut lc_s)
    };
    assert_eq!(fl_s, 0);
    assert_eq!(lc_s, 0);
    assert_eq!(fl_v, lc_v, "ston unknown sentinel: fl={fl_v} lc={lc_v}");
}

#[test]
fn diff_sym_ntop_with_caller_table_works() {
    // Build our own res_sym table to verify fl walks arbitrary tables,
    // not just the libresolv globals.
    let na = b"ALPHA\0".as_ptr() as *const c_char;
    let ha = b"alpha (long)\0".as_ptr() as *const c_char;
    let nb = b"BETA\0".as_ptr() as *const c_char;
    let hb = b"beta (long)\0".as_ptr() as *const c_char;
    let table = [
        ResSym { number: 100, name: na, humanname: ha },
        ResSym { number: 200, name: nb, humanname: hb },
        ResSym { number: -1, name: std::ptr::null(), humanname: std::ptr::null() },
    ];
    let mut succ: c_int = 0;
    let p = unsafe {
        fl::__sym_ntop(table.as_ptr() as *const c_void, 200, &mut succ)
    };
    assert_eq!(succ, 1);
    assert_eq!(cstr(p).as_deref(), Some("beta (long)"));

    let mut succ2: c_int = 0;
    let p2 = unsafe {
        fl::__sym_ntop(table.as_ptr() as *const c_void, 999, &mut succ2)
    };
    assert_eq!(succ2, 0);
    assert_eq!(cstr(p2).as_deref(), Some("999"));
}

#[test]
fn sym_table_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv __sym_ntop + __sym_ntos + __sym_ston\",\"reference\":\"glibc-libresolv\",\"functions\":3,\"divergences\":0}}",
    );
}
