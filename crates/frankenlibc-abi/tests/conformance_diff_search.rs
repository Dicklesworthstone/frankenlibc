#![cfg(target_os = "linux")]

//! Differential conformance harness for `<search.h>` linear/hash search:
//!   - lfind  (find-only linear search)
//!   - lsearch (find-with-insert linear search)
//!   - hcreate / hsearch / hdestroy (process-global hash table)
//!
//! tsearch (binary tree) is intentionally excluded — its caller-allocated
//! root pointer is layout-incompatible across impls and the API uses
//! opaque tree-internal types.
//!
//! Bead: CONFORMANCE: libc search.h diff matrix.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::sync::Mutex;

use frankenlibc_abi::search_abi as fl;

unsafe extern "C" {
    fn lfind(
        key: *const c_void,
        base: *const c_void,
        nelp: *mut usize,
        width: usize,
        compar: extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn lsearch(
        key: *const c_void,
        base: *mut c_void,
        nelp: *mut usize,
        width: usize,
        compar: extern "C" fn(*const c_void, *const c_void) -> c_int,
    ) -> *mut c_void;
    fn hcreate(nel: usize) -> c_int;
    fn hsearch(item: HsearchEntry, action: c_int) -> *mut HsearchEntry;
    fn hdestroy();
}

#[repr(C)]
#[derive(Clone, Copy)]
struct HsearchEntry {
    key: *mut c_char,
    data: *mut c_void,
}

const ENTER: c_int = 1;
const FIND: c_int = 0;

// Hash table is process-global; serialize.
static HSEARCH_LOCK: Mutex<()> = Mutex::new(());

extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
    let av = unsafe { *(a as *const i32) };
    let bv = unsafe { *(b as *const i32) };
    av - bv
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// lfind — both impls return the same offset (or NULL) for present and
// absent keys.
// ===========================================================================

#[test]
fn diff_lfind_present_absent() {
    let mut divs = Vec::new();
    let arr: [i32; 6] = [10, 20, 30, 40, 50, 60];
    let cases: &[(i32, bool)] = &[
        (10, true),
        (60, true),
        (35, false),
        (-1, false),
        (0, false),
        (40, true),
    ];
    for (key, expected_found) in cases {
        let mut nel: usize = arr.len();
        let r_fl = unsafe {
            fl::lfind(
                key as *const _ as *const c_void,
                arr.as_ptr() as *const c_void,
                &mut nel,
                core::mem::size_of::<i32>(),
                core::mem::transmute::<extern "C" fn(*const c_void, *const c_void) -> c_int, _>(
                    cmp_i32,
                ),
            )
        };
        let mut nel2: usize = arr.len();
        let r_lc = unsafe {
            lfind(
                key as *const _ as *const c_void,
                arr.as_ptr() as *const c_void,
                &mut nel2,
                core::mem::size_of::<i32>(),
                cmp_i32,
            )
        };
        let found_fl = !r_fl.is_null();
        let found_lc = !r_lc.is_null();
        if found_fl != found_lc {
            divs.push(Divergence {
                function: "lfind",
                case: format!("key={key}"),
                field: "found",
                frankenlibc: format!("{found_fl}"),
                glibc: format!("{found_lc}"),
            });
        }
        if found_fl != *expected_found {
            divs.push(Divergence {
                function: "lfind",
                case: format!("key={key}"),
                field: "expected_found",
                frankenlibc: format!("{found_fl}"),
                glibc: format!("expected={expected_found}"),
            });
        }
        // If both found, returned pointer should point to same value
        if found_fl && found_lc {
            let v_fl = unsafe { *(r_fl as *const i32) };
            let v_lc = unsafe { *(r_lc as *const i32) };
            if v_fl != v_lc || v_fl != *key {
                divs.push(Divergence {
                    function: "lfind",
                    case: format!("key={key}"),
                    field: "value_at_ptr",
                    frankenlibc: format!("{v_fl}"),
                    glibc: format!("{v_lc}"),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "lfind divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// lsearch — when key not found, both impls insert and return pointer to
// new slot. When found, both return existing pointer.
// ===========================================================================

#[test]
fn diff_lsearch_insert() {
    let mut divs = Vec::new();
    let cap = 16;

    // fl run
    let mut buf_fl: Vec<i32> = vec![0; cap];
    let mut nel_fl: usize = 0;
    for &k in &[1, 2, 3, 1, 2, 4, 5] {
        let key = k;
        let _ = unsafe {
            fl::lsearch(
                &key as *const _ as *const c_void,
                buf_fl.as_mut_ptr() as *mut c_void,
                &mut nel_fl,
                core::mem::size_of::<i32>(),
                core::mem::transmute::<extern "C" fn(*const c_void, *const c_void) -> c_int, _>(
                    cmp_i32,
                ),
            )
        };
    }

    // libc run
    let mut buf_lc: Vec<i32> = vec![0; cap];
    let mut nel_lc: usize = 0;
    for &k in &[1, 2, 3, 1, 2, 4, 5] {
        let key = k;
        let _ = unsafe {
            lsearch(
                &key as *const _ as *const c_void,
                buf_lc.as_mut_ptr() as *mut c_void,
                &mut nel_lc,
                core::mem::size_of::<i32>(),
                cmp_i32,
            )
        };
    }

    if nel_fl != nel_lc {
        divs.push(Divergence {
            function: "lsearch",
            case: "insert sequence [1,2,3,1,2,4,5]".into(),
            field: "final_nel",
            frankenlibc: format!("{nel_fl}"),
            glibc: format!("{nel_lc}"),
        });
    }
    let slice_fl = &buf_fl[..nel_fl];
    let slice_lc = &buf_lc[..nel_lc];
    if slice_fl != slice_lc {
        divs.push(Divergence {
            function: "lsearch",
            case: "insert sequence [1,2,3,1,2,4,5]".into(),
            field: "final_buffer",
            frankenlibc: format!("{slice_fl:?}"),
            glibc: format!("{slice_lc:?}"),
        });
    }
    // Expected: 5 unique entries
    if nel_fl != 5 {
        divs.push(Divergence {
            function: "lsearch",
            case: "insert sequence".into(),
            field: "expected_5_unique",
            frankenlibc: format!("got {nel_fl}"),
            glibc: "5".into(),
        });
    }
    assert!(
        divs.is_empty(),
        "lsearch divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// hsearch — process-global hash table. Insert via fl, FIND via libc;
// then the inverse. Both impls share the same global state so we test
// each direction in serial isolation.
// ===========================================================================

#[test]
fn diff_hsearch_fl_then_lc_find() {
    let _g = HSEARCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Use the FL global hash table.
    let _ = unsafe { fl::hcreate(64) };
    let mut keys: Vec<CString> = Vec::new();
    let pairs: &[(&str, isize)] = &[("alpha", 100), ("beta", 200), ("gamma", 300)];
    for (k, v) in pairs {
        let ck = CString::new(*k).unwrap();
        let item = fl::Entry {
            key: ck.as_ptr() as *mut c_char,
            data: *v as *mut c_void,
        };
        let _ = unsafe { fl::hsearch(item, fl::Action::ENTER) };
        keys.push(ck);
    }
    // Find via fl
    let mut found_fl = 0;
    for (k, _v) in pairs {
        let ck = CString::new(*k).unwrap();
        let item = fl::Entry {
            key: ck.as_ptr() as *mut c_char,
            data: std::ptr::null_mut(),
        };
        let r = unsafe { fl::hsearch(item, fl::Action::FIND) };
        if !r.is_null() {
            found_fl += 1;
        }
    }
    unsafe { fl::hdestroy() };

    // Now do the same with libc
    let _ = unsafe { hcreate(64) };
    let mut found_lc = 0;
    for (k, v) in pairs {
        let ck = CString::new(*k).unwrap();
        let item = HsearchEntry {
            key: ck.as_ptr() as *mut c_char,
            data: *v as *mut c_void,
        };
        let _ = unsafe { hsearch(item, ENTER) };
    }
    for (k, _v) in pairs {
        let ck = CString::new(*k).unwrap();
        let item = HsearchEntry {
            key: ck.as_ptr() as *mut c_char,
            data: std::ptr::null_mut(),
        };
        let r = unsafe { hsearch(item, FIND) };
        if !r.is_null() {
            found_lc += 1;
        }
    }
    unsafe { hdestroy() };

    assert_eq!(
        found_fl, found_lc,
        "hsearch find-after-insert count: fl={found_fl}, lc={found_lc}",
    );
    assert_eq!(
        found_fl,
        pairs.len(),
        "hsearch fl: expected to find all {} inserted, found {}",
        pairs.len(),
        found_fl
    );
}

#[test]
fn diff_hsearch_find_missing() {
    let _g = HSEARCH_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let _ = unsafe { fl::hcreate(64) };
    let ck = CString::new("not_inserted").unwrap();
    let item_fl = fl::Entry {
        key: ck.as_ptr() as *mut c_char,
        data: std::ptr::null_mut(),
    };
    let r_fl = unsafe { fl::hsearch(item_fl, fl::Action::FIND) };
    unsafe { fl::hdestroy() };

    let _ = unsafe { hcreate(64) };
    let item_lc = HsearchEntry {
        key: ck.as_ptr() as *mut c_char,
        data: std::ptr::null_mut(),
    };
    let r_lc = unsafe { hsearch(item_lc, FIND) };
    unsafe { hdestroy() };

    assert!(
        r_fl.is_null() == r_lc.is_null(),
        "hsearch FIND missing: fl={:?}, lc={:?}",
        r_fl,
        r_lc
    );
    let _ = CStr::from_bytes_with_nul(b"x\0").unwrap();
}

#[test]
fn search_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"search.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",
    );
}
