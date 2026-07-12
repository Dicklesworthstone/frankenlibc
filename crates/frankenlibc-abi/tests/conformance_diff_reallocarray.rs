#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc reallocarray/malloc_usable_size oracle; real allocations

//! Differential gate for reallocarray overflow detection and malloc_usable_size
//! contract vs host glibc (bd-ij9mvq) — both previously fl-internal only.
//! Addresses are allocator-specific, so this compares the CONTRACT:
//!   reallocarray(p, nmemb, size): when nmemb*size overflows size_t it returns
//!     NULL + errno ENOMEM and leaves the original block intact; otherwise it
//!     behaves like realloc(p, nmemb*size) and returns usable memory.
//!   malloc_usable_size(NULL) == 0; malloc_usable_size(malloc(n)) >= n.
//! Each impl's blocks are freed with its own allocator. No mocks.

use std::ffi::c_int;
use std::ffi::c_void;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn reallocarray(p: *mut c_void, nmemb: usize, size: usize) -> *mut c_void;
        pub fn malloc(n: usize) -> *mut c_void;
        pub fn malloc_usable_size(p: *mut c_void) -> usize;
        pub fn free(p: *mut c_void);
        pub fn __errno_location() -> *mut c_int;
    }
}
use frankenlibc_abi::{malloc_abi as flm, stdlib_abi as fls};

const ENOMEM: c_int = 12;

#[test]
fn reallocarray_overflow_matches_glibc() {
    // Cases that overflow size_t (nmemb*size) -> must fail with ENOMEM.
    let overflow: &[(usize, usize)] = &[
        (usize::MAX, 2),
        (2, usize::MAX),
        (usize::MAX / 2 + 1, 2),
        (1 << 33, 1 << 33), // 2^66 overflows on 64-bit
    ];
    for &(n, s) in overflow {
        unsafe { *g::__errno_location() = 0 };
        let gp = unsafe { g::reallocarray(std::ptr::null_mut(), n, s) };
        let ge = unsafe { *g::__errno_location() };
        // fl's reallocarray uses set_abi_errno, which mirrors to the host errno
        // slot in non-standalone builds, so the bare read observes fl's ENOMEM.
        unsafe { *g::__errno_location() = 0 };
        let fp = unsafe { fls::reallocarray(std::ptr::null_mut(), n, s) };
        let fe = unsafe { *g::__errno_location() };
        assert!(
            gp.is_null(),
            "glibc reallocarray({n},{s}) must fail on overflow"
        );
        assert_eq!(
            fp.is_null(),
            gp.is_null(),
            "reallocarray({n},{s}) null-ness: fl={} glibc={}",
            fp.is_null(),
            gp.is_null()
        );
        assert_eq!(fe, ge, "reallocarray({n},{s}) errno: fl={fe} glibc={ge}");
        assert_eq!(ge, ENOMEM, "glibc overflow errno should be ENOMEM");
    }
}

#[test]
fn reallocarray_success_returns_usable_memory() {
    for &(n, s) in &[(4usize, 8usize), (16, 16), (1, 1), (100, 7)] {
        let fp = unsafe { fls::reallocarray(std::ptr::null_mut(), n, s) };
        assert!(!fp.is_null(), "fl reallocarray({n},{s}) should succeed");
        // usable across the whole requested region
        unsafe {
            let bytes = n * s;
            for i in 0..bytes {
                *((fp as *mut u8).add(i)) = (i & 0xFF) as u8;
            }
            assert!(
                flm::malloc_usable_size(fp) >= bytes,
                "usable_size >= requested"
            );
            flm::free(fp);
        }
        let gp = unsafe { g::reallocarray(std::ptr::null_mut(), n, s) };
        assert!(!gp.is_null(), "glibc reallocarray({n},{s}) should succeed");
        unsafe { g::free(gp) };
    }
}

#[test]
fn malloc_usable_size_contract_matches_glibc() {
    // NULL -> 0 (both)
    assert_eq!(
        unsafe { flm::malloc_usable_size(std::ptr::null_mut()) },
        0,
        "fl usable_size(NULL)"
    );
    assert_eq!(
        unsafe { g::malloc_usable_size(std::ptr::null_mut()) },
        0,
        "glibc usable_size(NULL)"
    );
    // usable >= requested (both); exact value is allocator-specific so not compared
    for &n in &[1usize, 24, 1000, 65536] {
        let fp = unsafe { flm::malloc(n) };
        assert!(!fp.is_null());
        assert!(
            unsafe { flm::malloc_usable_size(fp) } >= n,
            "fl usable_size({n}) >= n"
        );
        unsafe { flm::free(fp) };
        let gp = unsafe { g::malloc(n) };
        assert!(!gp.is_null());
        assert!(
            unsafe { g::malloc_usable_size(gp) } >= n,
            "glibc usable_size({n}) >= n"
        );
        unsafe { g::free(gp) };
    }
}
