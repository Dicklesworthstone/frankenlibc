#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc bsearch/lfind/lsearch oracle

//! Differential + property harness for the generic search family
//! (bd-pz9n58): bsearch / lfind / lsearch. These take a user comparator (not
//! SIMD) and had ZERO committed coverage. The SAME comparator and data are fed
//! to fl and to host glibc; results must agree, plus the documented contracts
//! hold as properties (found⟺present, correct element, lsearch appends on miss
//! and increments the count). No mocks.

use std::ffi::{c_int, c_void};

type Cmp = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn bsearch(
            key: *const c_void,
            base: *const c_void,
            nmemb: usize,
            size: usize,
            cmp: Cmp,
        ) -> *mut c_void;
        pub fn lfind(
            key: *const c_void,
            base: *const c_void,
            nelp: *const usize,
            width: usize,
            cmp: Cmp,
        ) -> *mut c_void;
        pub fn lsearch(
            key: *const c_void,
            base: *mut c_void,
            nelp: *mut usize,
            width: usize,
            cmp: Cmp,
        ) -> *mut c_void;
    }
}

use frankenlibc_abi::search_abi::{lfind as fl_lfind, lsearch as fl_lsearch};
use frankenlibc_abi::stdlib_abi::bsearch as fl_bsearch;

unsafe extern "C" fn cmp_i32(a: *const c_void, b: *const c_void) -> c_int {
    let x = unsafe { *(a as *const i32) };
    let y = unsafe { *(b as *const i32) };
    (x > y) as c_int - (x < y) as c_int
}

fn off(p: *const c_void, base: *const c_void) -> isize {
    if p.is_null() {
        -1
    } else {
        ((p as isize) - (base as isize)) / 4 // i32 elements
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
    fn i32v(&mut self, span: i32) -> i32 {
        (self.next() % (span as u64)) as i32
    }
}

#[test]
fn bsearch_matches_glibc() {
    let mut rng = Rng(0x6273_6561_7263_0000);
    for _ in 0..8000 {
        let n = rng.below(40);
        // Sorted array (bsearch requires sorted), small value span -> dups+hits.
        let mut arr: Vec<i32> = (0..n).map(|_| rng.i32v(30)).collect();
        arr.sort_unstable();
        let key: i32 = rng.i32v(34) - 2; // sometimes out of range
        let gr = unsafe { g::bsearch(&key as *const i32 as _, arr.as_ptr().cast(), n, 4, cmp_i32) };
        let fr = unsafe {
            fl_bsearch(
                &key as *const i32 as _,
                arr.as_ptr().cast(),
                n,
                4,
                Some(cmp_i32),
            )
        };
        // Both must agree on whether a match was found and that the element
        // equals the key (bsearch may return any equal element; assert equality
        // of the *pointed-to value*, not the offset, since ties are unspecified).
        let g_found = !gr.is_null();
        let f_found = !fr.is_null();
        assert_eq!(f_found, g_found, "bsearch found-ness key={key} arr={arr:?}");
        if f_found {
            assert_eq!(
                unsafe { *(fr as *const i32) },
                key,
                "bsearch fl element != key"
            );
            assert_eq!(
                unsafe { *(gr as *const i32) },
                key,
                "bsearch glibc element != key"
            );
        }
        // PROPERTY: found ⟺ key present in the array.
        assert_eq!(f_found, arr.contains(&key), "bsearch found ⟺ present");
    }
}

#[test]
fn lfind_matches_glibc() {
    let mut rng = Rng(0x6C66_696E_6400_0000);
    for _ in 0..8000 {
        let n = rng.below(40);
        let arr: Vec<i32> = (0..n).map(|_| rng.i32v(25)).collect(); // unsorted OK
        let key: i32 = rng.i32v(28);
        let mut nel = n;
        let gr = unsafe {
            g::lfind(
                &key as *const i32 as _,
                arr.as_ptr().cast(),
                &nel,
                4,
                cmp_i32,
            )
        };
        let fr = unsafe {
            fl_lfind(
                &key as *const i32 as _,
                arr.as_ptr().cast(),
                &mut nel,
                4,
                cmp_i32,
            )
        };
        // lfind returns the FIRST matching element — offset must match exactly.
        assert_eq!(
            off(fr, arr.as_ptr().cast()),
            off(gr, arr.as_ptr().cast()),
            "lfind offset key={key} arr={arr:?}"
        );
        // PROPERTY: returns first occurrence iff present.
        let expect = arr.iter().position(|&v| v == key);
        match expect {
            Some(i) => assert_eq!(off(fr, arr.as_ptr().cast()), i as isize, "lfind first occ"),
            None => assert!(fr.is_null(), "lfind absent -> NULL"),
        }
    }
}

#[test]
fn lsearch_matches_glibc_and_appends() {
    let mut rng = Rng(0x6C73_6561_7263_0000);
    for _ in 0..8000 {
        let n = rng.below(30);
        let arr: Vec<i32> = (0..n).map(|_| rng.i32v(20)).collect();
        let key: i32 = rng.i32v(24);
        let was_present = arr.contains(&key);

        // Each impl needs spare capacity for a possible append.
        let mk = || -> Vec<i32> {
            let mut v = arr.clone();
            v.push(0); // spare slot
            v
        };
        let mut gv = mk();
        let mut fv = mk();
        let mut gnel = n;
        let mut fnel = n;
        let gr = unsafe {
            g::lsearch(
                &key as *const i32 as _,
                gv.as_mut_ptr().cast(),
                &mut gnel,
                4,
                cmp_i32,
            )
        };
        let fr = unsafe {
            fl_lsearch(
                &key as *const i32 as _,
                fv.as_mut_ptr().cast(),
                &mut fnel,
                4,
                cmp_i32,
            )
        };
        // Resulting count, returned offset, and the live portion of the array
        // must all agree with glibc.
        assert_eq!(fnel, gnel, "lsearch nmemb key={key} arr={arr:?}");
        assert_eq!(
            off(fr, fv.as_ptr().cast()),
            off(gr, gv.as_ptr().cast()),
            "lsearch return offset key={key}"
        );
        assert_eq!(&fv[..fnel], &gv[..gnel], "lsearch live array key={key}");

        // PROPERTY: nmemb grows by 1 iff the key was absent; the returned
        // element equals the key; the key is present afterwards.
        if was_present {
            assert_eq!(fnel, n, "lsearch must not grow when present");
        } else {
            assert_eq!(fnel, n + 1, "lsearch must append when absent");
        }
        assert_eq!(
            unsafe { *(fr as *const i32) },
            key,
            "lsearch returns the key element"
        );
        assert!(fv[..fnel].contains(&key), "lsearch: key present after call");
    }
}

#[test]
fn edge_cases() {
    // Empty array: bsearch/lfind NULL; lsearch appends.
    let key: i32 = 7;
    let arr: Vec<i32> = vec![];
    let mut nel0 = 0usize;
    assert!(
        unsafe {
            fl_bsearch(
                &key as *const i32 as _,
                arr.as_ptr().cast(),
                0,
                4,
                Some(cmp_i32),
            )
        }
        .is_null()
    );
    assert!(
        unsafe {
            fl_lfind(
                &key as *const i32 as _,
                arr.as_ptr().cast(),
                &mut nel0,
                4,
                cmp_i32,
            )
        }
        .is_null()
    );
    // lsearch into an empty (capacity-1) buffer appends.
    let mut buf = vec![0i32; 1];
    let mut nel = 0usize;
    let r = unsafe {
        fl_lsearch(
            &key as *const i32 as _,
            buf.as_mut_ptr().cast(),
            &mut nel,
            4,
            cmp_i32,
        )
    };
    assert_eq!(nel, 1, "lsearch empty -> append");
    assert_eq!(unsafe { *(r as *const i32) }, key);
    // Single-element bsearch hit and miss.
    let one = [42i32];
    let hit: i32 = 42;
    let miss: i32 = 7;
    assert!(
        !unsafe {
            fl_bsearch(
                &hit as *const i32 as _,
                one.as_ptr().cast(),
                1,
                4,
                Some(cmp_i32),
            )
        }
        .is_null()
    );
    assert!(
        unsafe {
            fl_bsearch(
                &miss as *const i32 as _,
                one.as_ptr().cast(),
                1,
                4,
                Some(cmp_i32),
            )
        }
        .is_null()
    );
}
