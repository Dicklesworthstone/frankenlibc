#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc lsearch/lfind oracle + raw arrays

//! Differential + property gate for lsearch/lfind (bd-icwp4e). lfind does a
//! linear search and returns a pointer to the match (or NULL); lsearch does the
//! same but APPENDS the key at *nelp and increments *nelp when absent. For the
//! same inputs fl must agree with host glibc on the matched element offset, the
//! resulting count, and (for lsearch) the array contents after an append. No
//! mocks.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::search_abi::{lfind as fl_lfind, lsearch as fl_lsearch};

type Cmp = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

unsafe extern "C" {
    fn lfind(
        key: *const c_void,
        base: *const c_void,
        nelp: *mut usize,
        width: usize,
        c: Cmp,
    ) -> *mut c_void;
    fn lsearch(
        key: *const c_void,
        base: *mut c_void,
        nelp: *mut usize,
        width: usize,
        c: Cmp,
    ) -> *mut c_void;
}

unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
    let a = unsafe { *(a as *const i32) };
    let b = unsafe { *(b as *const i32) };
    (a > b) as c_int - (a < b) as c_int
}

/// Index of `ret` within the array starting at `base` (i32 elements), or -1 for NULL.
fn idx(ret: *mut c_void, base: *const i32) -> isize {
    if ret.is_null() {
        -1
    } else {
        (ret as isize - base as isize) / 4
    }
}

#[test]
fn lfind_matches_glibc() {
    let data = [10i32, 20, 30, 40, 50];
    for key in [10i32, 20, 30, 50, 0, 25, 99, 40] {
        let arr_f = data;
        let arr_g = data;
        let mut nf = data.len();
        let mut ng = data.len();
        let rf = unsafe {
            fl_lfind(
                &key as *const i32 as *const c_void,
                arr_f.as_ptr() as *const c_void,
                &mut nf,
                4,
                cmp_i32,
            )
        };
        let rg = unsafe {
            lfind(
                &key as *const i32 as *const c_void,
                arr_g.as_ptr() as *const c_void,
                &mut ng,
                4,
                cmp_i32,
            )
        };
        assert_eq!(
            idx(rf, arr_f.as_ptr()),
            idx(rg, arr_g.as_ptr()),
            "lfind key={key}"
        );
        assert_eq!(nf, ng, "lfind must not change count (key={key})");
        assert_eq!(nf, data.len(), "lfind count unchanged");
    }
}

#[test]
fn lsearch_appends_like_glibc() {
    // Backing capacity of 8, three live elements.
    let template = [10i32, 20, 30, 0, 0, 0, 0, 0];
    for key in [20i32 /* present */, 99 /* absent */, 10, 77] {
        let mut arr_f = template;
        let mut arr_g = template;
        let mut nf = 3usize;
        let mut ng = 3usize;
        let rf = unsafe {
            fl_lsearch(
                &key as *const i32 as *const c_void,
                arr_f.as_mut_ptr() as *mut c_void,
                &mut nf,
                4,
                cmp_i32,
            )
        };
        let rg = unsafe {
            lsearch(
                &key as *const i32 as *const c_void,
                arr_g.as_mut_ptr() as *mut c_void,
                &mut ng,
                4,
                cmp_i32,
            )
        };
        assert_eq!(nf, ng, "lsearch count agreement (key={key})");
        assert_eq!(
            idx(rf, arr_f.as_ptr()),
            idx(rg, arr_g.as_ptr()),
            "lsearch offset (key={key})"
        );
        assert_eq!(arr_f, arr_g, "lsearch array contents (key={key})");
        // Present keys leave count at 3; absent keys append and bump to 4.
        if key == 10 || key == 20 {
            assert_eq!(nf, 3, "present key must not append (key={key})");
        } else {
            assert_eq!(nf, 4, "absent key must append (key={key})");
            assert_eq!(arr_f[3], key, "absent key appended at index 3");
        }
    }
}

#[test]
fn lsearch_idempotent_after_append() {
    let mut arr = [1i32, 2, 3, 0, 0];
    let mut n = 3usize;
    let key = 42i32;
    // First lsearch appends.
    unsafe {
        fl_lsearch(
            &key as *const i32 as *const c_void,
            arr.as_mut_ptr() as *mut c_void,
            &mut n,
            4,
            cmp_i32,
        )
    };
    assert_eq!(n, 4);
    // Second lsearch for the same key finds it — no second append.
    unsafe {
        fl_lsearch(
            &key as *const i32 as *const c_void,
            arr.as_mut_ptr() as *mut c_void,
            &mut n,
            4,
            cmp_i32,
        )
    };
    assert_eq!(n, 4, "lsearch must not append a key it already inserted");
    assert_eq!(arr[3], 42);
    assert_eq!(arr[4], 0, "no spurious second append");
}
