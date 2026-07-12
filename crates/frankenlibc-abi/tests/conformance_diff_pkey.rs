#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)]

//! Differential coverage for x86_64 pkey invalid-argument handling.
//!
//! Invalid pkey IDs, rights masks, allocation flags, and mprotect keys must
//! fail before touching PKRU or consuming protection keys. This keeps the error
//! path deterministic even on hosts where valid pkey operations are unavailable
//! or would mutate process-local access state.

use std::ffi::{c_int, c_uint, c_void};

use frankenlibc_abi::{errno_abi, unistd_abi as fl};

unsafe extern "C" {
    fn pkey_alloc(flags: c_uint, access_rights: c_uint) -> c_int;
    fn pkey_free(pkey: c_int) -> c_int;
    fn pkey_get(pkey: c_int) -> c_int;
    fn pkey_mprotect(addr: *mut c_void, len: usize, prot: c_int, pkey: c_int) -> c_int;
    fn pkey_set(pkey: c_int, rights: c_int) -> c_int;
}

#[derive(Clone, Copy, Debug)]
enum PkeyCall {
    Get { pkey: c_int },
    Set { pkey: c_int, rights: c_int },
}

impl PkeyCall {
    fn name(self) -> &'static str {
        match self {
            Self::Get { .. } => "pkey_get",
            Self::Set { .. } => "pkey_set",
        }
    }
}

fn clear_errnos() {
    unsafe {
        *errno_abi::__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

fn fl_errno() -> c_int {
    unsafe { *errno_abi::__errno_location() }
}

fn host_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn run_fl(call: PkeyCall) -> (c_int, c_int) {
    clear_errnos();
    let ret = match call {
        PkeyCall::Get { pkey } => unsafe { fl::pkey_get(pkey) },
        PkeyCall::Set { pkey, rights } => unsafe { fl::pkey_set(pkey, rights) },
    };
    (ret, fl_errno())
}

fn run_glibc(call: PkeyCall) -> (c_int, c_int) {
    clear_errnos();
    let ret = match call {
        PkeyCall::Get { pkey } => unsafe { pkey_get(pkey) },
        PkeyCall::Set { pkey, rights } => unsafe { pkey_set(pkey, rights) },
    };
    (ret, host_errno())
}

#[test]
fn pkey_invalid_arguments_match_glibc_einval() {
    let cases = [
        PkeyCall::Get { pkey: -1 },
        PkeyCall::Get { pkey: 16 },
        PkeyCall::Set {
            pkey: -1,
            rights: 0,
        },
        PkeyCall::Set {
            pkey: 16,
            rights: 0,
        },
        PkeyCall::Set { pkey: 0, rights: 4 },
        PkeyCall::Set {
            pkey: 0,
            rights: -1,
        },
    ];

    for case in cases {
        let (fl_ret, fl_err) = run_fl(case);
        let (glibc_ret, glibc_err) = run_glibc(case);
        assert_eq!(fl_ret, -1, "{}({case:?}) should fail", case.name());
        assert_eq!(
            glibc_ret,
            -1,
            "host glibc {}({case:?}) should fail",
            case.name()
        );
        assert_eq!(
            fl_err,
            glibc_err,
            "{}({case:?}) errno mismatch: fl={fl_err} glibc={glibc_err}",
            case.name()
        );
        assert_eq!(
            fl_err,
            libc::EINVAL,
            "{}({case:?}) should set EINVAL",
            case.name()
        );
    }
}

#[test]
fn pkey_alloc_free_mprotect_invalid_arguments_match_glibc() {
    clear_errnos();
    let glibc_ret = unsafe { pkey_alloc(1, 0) };
    let glibc_err = host_errno();
    clear_errnos();
    let fl_ret = unsafe { fl::pkey_alloc(1, 0) };
    let fl_err = fl_errno();
    assert_eq!(fl_ret, -1, "pkey_alloc(invalid flags) should fail");
    assert_eq!(glibc_ret, -1, "host pkey_alloc(invalid flags) should fail");
    assert_eq!(
        (fl_ret, fl_err),
        (glibc_ret, glibc_err),
        "pkey_alloc(invalid flags): fl=({fl_ret}, {fl_err}) \
         glibc=({glibc_ret}, {glibc_err})"
    );

    clear_errnos();
    let glibc_ret = unsafe { pkey_free(-1) };
    let glibc_err = host_errno();
    clear_errnos();
    let fl_ret = unsafe { fl::pkey_free(-1) };
    let fl_err = fl_errno();
    assert_eq!(fl_ret, -1, "pkey_free(-1) should fail");
    assert_eq!(glibc_ret, -1, "host pkey_free(-1) should fail");
    assert_eq!(
        (fl_ret, fl_err),
        (glibc_ret, glibc_err),
        "pkey_free(-1): fl=({fl_ret}, {fl_err}) glibc=({glibc_ret}, {glibc_err})"
    );

    clear_errnos();
    let glibc_ret = unsafe { pkey_mprotect(std::ptr::null_mut(), 4096, libc::PROT_READ, -1) };
    let glibc_err = host_errno();
    clear_errnos();
    let fl_ret = unsafe { fl::pkey_mprotect(std::ptr::null_mut(), 4096, libc::PROT_READ, -1) };
    let fl_err = fl_errno();
    assert_eq!(fl_ret, -1, "pkey_mprotect(NULL, invalid pkey) should fail");
    assert_eq!(
        glibc_ret, -1,
        "host pkey_mprotect(NULL, invalid pkey) should fail"
    );
    assert_eq!(
        (fl_ret, fl_err),
        (glibc_ret, glibc_err),
        "pkey_mprotect(NULL, invalid pkey): fl=({fl_ret}, {fl_err}) \
         glibc=({glibc_ret}, {glibc_err})"
    );
}
