#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc qsort_r oracle + raw arrays

//! Differential gate for qsort_r (bd-2dcvwl). qsort_r differs from qsort only in
//! that it threads a caller `arg` pointer through to every comparator call. This
//! gate uses a comparator that reads a sort-direction flag *from arg*, so a
//! wrong/NULL arg would flip or corrupt the ordering — proving the context is
//! actually delivered. fl must match host glibc's qsort_r for both directions,
//! and the result must be correctly sorted. No mocks.

use std::ffi::{c_int, c_void};

type CmpR = unsafe extern "C" fn(*const c_void, *const c_void, *mut c_void) -> c_int;

unsafe extern "C" {
    fn qsort_r(base: *mut c_void, nmemb: usize, size: usize, compar: CmpR, arg: *mut c_void);
}

/// Compares two i32 using the direction flag read from `arg` (1 = ascending,
/// -1 = descending). Reading `arg` is the whole point: it must be the pointer
/// the caller passed to qsort_r.
unsafe extern "C" fn cmp_dir(a: *const c_void, b: *const c_void, arg: *mut c_void) -> c_int {
    let a = unsafe { *(a as *const i32) };
    let b = unsafe { *(b as *const i32) };
    let dir = unsafe { *(arg as *const i32) };
    let ord = (a > b) as c_int - (a < b) as c_int;
    ord * dir
}

fn sorted(v: &[i32], dir: i32) -> bool {
    v.windows(2)
        .all(|w| if dir > 0 { w[0] <= w[1] } else { w[0] >= w[1] })
}

#[test]
fn qsort_r_threads_context_like_glibc() {
    let inputs: &[&[i32]] = &[
        &[3, 1, 2],
        &[5, 4, 3, 2, 1],
        &[1, 1, 1],
        &[],
        &[42],
        &[-3, 7, 0, -3, 7, 1, -100, 99],
    ];
    for &dir in &[1i32, -1i32] {
        let mut d = dir;
        for inp in inputs {
            let mut gf: Vec<i32> = inp.to_vec();
            let mut ff: Vec<i32> = inp.to_vec();
            unsafe {
                qsort_r(
                    gf.as_mut_ptr() as *mut c_void,
                    gf.len(),
                    4,
                    cmp_dir,
                    &mut d as *mut i32 as *mut c_void,
                );
                frankenlibc_abi::stdlib_abi::qsort_r(
                    ff.as_mut_ptr() as *mut c_void,
                    ff.len(),
                    4,
                    Some(cmp_dir),
                    &mut d as *mut i32 as *mut c_void,
                );
            }
            assert_eq!(ff, gf, "qsort_r(dir={dir}) input={inp:?}: fl != glibc");
            assert!(
                sorted(&ff, dir),
                "qsort_r(dir={dir}) result not sorted: {ff:?}"
            );
        }
    }
}

#[test]
fn qsort_r_arg_pointer_is_delivered_verbatim() {
    // The comparator records the arg pointer it observes; it must equal the
    // exact pointer handed to qsort_r (not NULL, not a copy of the value).
    use std::sync::atomic::{AtomicUsize, Ordering};
    static SEEN: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "C" fn rec(a: *const c_void, b: *const c_void, arg: *mut c_void) -> c_int {
        SEEN.store(arg as usize, Ordering::Relaxed);
        let a = unsafe { *(a as *const i32) };
        let b = unsafe { *(b as *const i32) };
        (a > b) as c_int - (a < b) as c_int
    }
    let mut ctx: u64 = 0xDEAD_BEEF;
    let ctx_ptr = &mut ctx as *mut u64 as *mut c_void;
    let mut arr = [9i32, 3, 7, 1];
    unsafe {
        frankenlibc_abi::stdlib_abi::qsort_r(
            arr.as_mut_ptr() as *mut c_void,
            arr.len(),
            4,
            Some(rec),
            ctx_ptr,
        );
    }
    assert_eq!(
        SEEN.load(Ordering::Relaxed),
        ctx_ptr as usize,
        "qsort_r must pass arg verbatim"
    );
    assert_eq!(arr, [1, 3, 7, 9]);
}
