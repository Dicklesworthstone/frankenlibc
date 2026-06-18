#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc getresuid/getresgid oracle

//! Differential gate for getresuid / getresgid (bd-qvveya) — no differential
//! gate existed. They report the calling process's real/effective/saved
//! uid (resp. gid); both impls query the same process so the resolved triples
//! must match, with return 0. Also checks the EFAULT/-1 contract on a NULL
//! out-pointer. No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn getresuid(r: *mut u32, e: *mut u32, s: *mut u32) -> c_int;
    fn getresgid(r: *mut u32, e: *mut u32, s: *mut u32) -> c_int;
    fn __errno_location() -> *mut c_int;
}

#[test]
fn getresuid_matches_glibc() {
    let g = unsafe {
        let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
        let rc = getresuid(&mut r, &mut e, &mut s);
        (rc, r, e, s)
    };
    let f = unsafe {
        let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
        let rc = frankenlibc_abi::unistd_abi::getresuid(&mut r, &mut e, &mut s);
        (rc, r, e, s)
    };
    assert_eq!(f, g, "getresuid: fl={f:?} glibc={g:?}");
    assert_eq!(g.0, 0, "getresuid should succeed");
}

#[test]
fn getresgid_matches_glibc() {
    let g = unsafe {
        let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
        let rc = getresgid(&mut r, &mut e, &mut s);
        (rc, r, e, s)
    };
    let f = unsafe {
        let (mut r, mut e, mut s) = (0u32, 0u32, 0u32);
        let rc = frankenlibc_abi::unistd_abi::getresgid(&mut r, &mut e, &mut s);
        (rc, r, e, s)
    };
    assert_eq!(f, g, "getresgid: fl={f:?} glibc={g:?}");
    assert_eq!(g.0, 0, "getresgid should succeed");
}

#[test]
fn getresuid_null_pointer_matches_glibc() {
    let g = unsafe {
        *__errno_location() = 0;
        let rc = getresuid(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
        (rc, *__errno_location())
    };
    let f = unsafe {
        *__errno_location() = 0;
        let rc = frankenlibc_abi::unistd_abi::getresuid(std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut());
        (rc, *__errno_location())
    };
    assert_eq!(f, g, "getresuid(NULL,NULL,NULL): fl={f:?} glibc={g:?}");
    assert_eq!((g.0, g.1), (-1, libc::EFAULT), "glibc: -1/EFAULT on NULL out-pointer");
}
