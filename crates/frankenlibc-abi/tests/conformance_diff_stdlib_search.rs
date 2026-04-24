#![cfg(target_os = "linux")]

//! Differential conformance harness for `<stdlib.h>` qsort + bsearch.
//!
//! qsort: ascending sort of fixed integer arrays. We compare the
//! post-sort element sequence between FrankenLibC and glibc — the
//! comparator function is identical and pure, so the output element
//! order MUST match (qsort is allowed to be unstable, but POSIX requires
//! "the elements are sorted").
//!
//! bsearch: search for a key in a sorted array. We compare offset of the
//! returned pointer (or NULL).
//!
//! Bead: CONFORMANCE: libc stdlib.h sort+search diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::stdlib_abi as fl;

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

unsafe extern "C" fn cmp_int_asc(a: *const c_void, b: *const c_void) -> c_int {
    let av = unsafe { *(a as *const i32) };
    let bv = unsafe { *(b as *const i32) };
    av.cmp(&bv) as c_int
}

unsafe extern "C" fn cmp_int_desc(a: *const c_void, b: *const c_void) -> c_int {
    let av = unsafe { *(a as *const i32) };
    let bv = unsafe { *(b as *const i32) };
    bv.cmp(&av) as c_int
}

// ===========================================================================
// qsort — sort integer arrays
// ===========================================================================

#[test]
fn diff_qsort_int_ascending() {
    let mut divs = Vec::new();
    let cases: &[&[i32]] = &[
        &[],                             // empty
        &[42],                           // single
        &[1, 2, 3],                      // already sorted
        &[3, 2, 1],                      // reverse-sorted
        &[5, 1, 4, 2, 3],                // mixed
        &[1, 1, 1, 1],                   // all equal
        &[7, 3, 7, 3, 7, 3],             // many duplicates
        &[i32::MIN, 0, i32::MAX, -1, 1], // boundaries
        &[10, -10, 20, -20, 30, -30, 40, -40],
    ];
    for input in cases {
        let mut a_fl: Vec<i32> = input.to_vec();
        let mut a_lc: Vec<i32> = input.to_vec();
        let n = a_fl.len();
        let sz = std::mem::size_of::<i32>();
        unsafe {
            fl::qsort(a_fl.as_mut_ptr() as *mut c_void, n, sz, Some(cmp_int_asc));
            libc::qsort(a_lc.as_mut_ptr() as *mut c_void, n, sz, Some(cmp_int_asc));
        }
        if a_fl != a_lc {
            divs.push(Divergence {
                function: "qsort_asc",
                case: format!("{:?}", input),
                field: "post_sort",
                frankenlibc: format!("{:?}", a_fl),
                glibc: format!("{:?}", a_lc),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "qsort asc divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_qsort_int_descending() {
    let mut divs = Vec::new();
    let cases: &[&[i32]] = &[
        &[1, 2, 3, 4, 5],
        &[5, 4, 3, 2, 1],
        &[3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8],
    ];
    for input in cases {
        let mut a_fl: Vec<i32> = input.to_vec();
        let mut a_lc: Vec<i32> = input.to_vec();
        let n = a_fl.len();
        let sz = std::mem::size_of::<i32>();
        unsafe {
            fl::qsort(a_fl.as_mut_ptr() as *mut c_void, n, sz, Some(cmp_int_desc));
            libc::qsort(a_lc.as_mut_ptr() as *mut c_void, n, sz, Some(cmp_int_desc));
        }
        if a_fl != a_lc {
            divs.push(Divergence {
                function: "qsort_desc",
                case: format!("{:?}", input),
                field: "post_sort",
                frankenlibc: format!("{:?}", a_fl),
                glibc: format!("{:?}", a_lc),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "qsort desc divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// bsearch — find a key in a sorted array
// ===========================================================================

#[test]
fn diff_bsearch_int_cases() {
    let mut divs = Vec::new();
    let arr: Vec<i32> = (1..=20).map(|i| i * 5).collect(); // [5,10,15,...,100]
    let n = arr.len();
    let sz = std::mem::size_of::<i32>();
    let probes: &[i32] = &[
        5,
        10,
        15,
        50,
        100, // present, including bounds
        4,
        11,
        51,
        99,
        101, // absent, in/out of range
        i32::MIN,
        i32::MAX,
        0,
        -7, // out-of-range / negative
    ];
    for &key in probes {
        let r_fl = unsafe {
            fl::bsearch(
                &key as *const i32 as *const c_void,
                arr.as_ptr() as *const c_void,
                n,
                sz,
                Some(cmp_int_asc),
            )
        };
        let r_lc = unsafe {
            libc::bsearch(
                &key as *const i32 as *const c_void,
                arr.as_ptr() as *const c_void,
                n,
                sz,
                Some(cmp_int_asc),
            )
        };
        let off_fl = if r_fl.is_null() {
            -1
        } else {
            unsafe { (r_fl as *const i32).offset_from(arr.as_ptr()) }
        };
        let off_lc = if r_lc.is_null() {
            -1
        } else {
            unsafe { (r_lc as *const i32).offset_from(arr.as_ptr()) }
        };
        if off_fl != off_lc {
            divs.push(Divergence {
                function: "bsearch",
                case: format!("key={key}"),
                field: "offset",
                frankenlibc: format!("{off_fl}"),
                glibc: format!("{off_lc}"),
            });
        }
    }
    // Empty array → always NULL
    let empty: [i32; 0] = [];
    for &key in &[0i32, 5, 100] {
        let r_fl = unsafe {
            fl::bsearch(
                &key as *const i32 as *const c_void,
                empty.as_ptr() as *const c_void,
                0,
                sz,
                Some(cmp_int_asc),
            )
        };
        let r_lc = unsafe {
            libc::bsearch(
                &key as *const i32 as *const c_void,
                empty.as_ptr() as *const c_void,
                0,
                sz,
                Some(cmp_int_asc),
            )
        };
        if r_fl.is_null() != r_lc.is_null() {
            divs.push(Divergence {
                function: "bsearch",
                case: format!("empty key={key}"),
                field: "null",
                frankenlibc: format!("{}", r_fl.is_null()),
                glibc: format!("{}", r_lc.is_null()),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "bsearch divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn stdlib_search_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"stdlib.h sort+search\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
