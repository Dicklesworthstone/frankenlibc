#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc valloc/pvalloc oracle; real allocations

//! Differential gate for valloc/pvalloc page-alignment contract vs host glibc
//! (bd-8ytm7s) — previously fl-internal only. valloc returns a page-aligned
//! block; pvalloc returns a page-aligned block sized up to a whole number of
//! pages. Addresses differ between impls, so this compares the CONTRACT, not
//! values: page-alignment of the returned pointer, non-null for reasonable
//! sizes, the pvalloc(0) edge (glibc still returns a usable page), and usable
//! memory. Each impl's block is freed with its own allocator (no cross-allocator
//! free). No mocks.

use std::ffi::c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn valloc(size: usize) -> *mut c_void;
        pub fn pvalloc(size: usize) -> *mut c_void;
        pub fn free(p: *mut c_void);
    }
}
use frankenlibc_abi::malloc_abi as fl;

fn pagesize() -> usize {
    (unsafe { libc::sysconf(libc::_SC_PAGESIZE) }) as usize
}

#[test]
fn valloc_pvalloc_alignment_matches_glibc_contract() {
    let ps = pagesize();
    assert!(ps.is_power_of_two() && ps >= 4096);

    for &size in &[1usize, 8, 100, 4096, 4097, 100_000] {
        // valloc
        let gp = unsafe { g::valloc(size) };
        let fp = unsafe { fl::valloc(size) };
        assert!(!gp.is_null() && !fp.is_null(), "valloc({size}) null");
        assert_eq!(gp as usize % ps, 0, "glibc valloc({size}) page-aligned");
        assert_eq!(fp as usize % ps, 0, "fl valloc({size}) page-aligned");
        // both usable: write first + last byte
        unsafe {
            *(fp as *mut u8) = 0xAB;
            *((fp as *mut u8).add(size - 1)) = 0xCD;
            g::free(gp);
            fl::free(fp);
        }

        // pvalloc
        let gpp = unsafe { g::pvalloc(size) };
        let fpp = unsafe { fl::pvalloc(size) };
        assert!(!gpp.is_null() && !fpp.is_null(), "pvalloc({size}) null");
        assert_eq!(gpp as usize % ps, 0, "glibc pvalloc({size}) page-aligned");
        assert_eq!(fpp as usize % ps, 0, "fl pvalloc({size}) page-aligned");
        // pvalloc rounds the usable size up to a whole page: the rounded size is
        // writable. Write across the rounded-up region.
        let rounded = size.div_ceil(ps) * ps;
        unsafe {
            *((fpp as *mut u8).add(rounded - 1)) = 0xEF;
            g::free(gpp);
            fl::free(fpp);
        }
    }
}

#[test]
fn pvalloc_zero_edge_matches_glibc() {
    let ps = pagesize();
    // glibc pvalloc(0) returns a usable, page-aligned 1-page block (not NULL).
    let gp = unsafe { g::pvalloc(0) };
    let fp = unsafe { fl::pvalloc(0) };
    assert_eq!(
        fp.is_null(),
        gp.is_null(),
        "pvalloc(0) null-ness: fl={} glibc={}",
        fp.is_null(),
        gp.is_null()
    );
    if !gp.is_null() {
        assert_eq!(gp as usize % ps, 0, "glibc pvalloc(0) page-aligned");
        assert_eq!(fp as usize % ps, 0, "fl pvalloc(0) page-aligned");
        unsafe {
            *(fp as *mut u8) = 1;
            g::free(gp);
            fl::free(fp);
        }
    }
}
