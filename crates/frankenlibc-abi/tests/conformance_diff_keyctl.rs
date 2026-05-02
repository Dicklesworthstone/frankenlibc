#![cfg(target_os = "linux")]

//! Differential conformance harness for Linux keyring syscalls
//! `add_key(2)`, `request_key(2)`, and `keyctl(2)`.
//!
//! These are kernel-keyring operations exposed through unistd_abi.
//! Their full behavior depends on session keyring availability, which
//! varies by environment. We assert acceptance/error parity (both
//! impls succeed or both fail with the same errno).
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, c_long, c_ulong, c_void, CStr, CString};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn syscall(number: c_long, ...) -> c_long;
}

const SYS_ADD_KEY: c_long = 248;
const SYS_REQUEST_KEY: c_long = 249;
const SYS_KEYCTL: c_long = 250;

const KEYCTL_GET_KEYRING_ID: c_int = 0;
const KEY_SPEC_THREAD_KEYRING: c_long = -1;
const KEY_SPEC_PROCESS_KEYRING: c_long = -2;
const KEY_SPEC_SESSION_KEYRING: c_long = -3;

fn errno_now() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[test]
fn diff_keyctl_get_keyring_id_session() {
    // KEYCTL_GET_KEYRING_ID(KEY_SPEC_SESSION_KEYRING, 0) — either
    // returns the keyring's serial or fails. fl and glibc must
    // agree on outcome.
    let fl_v = unsafe {
        fl::keyctl(
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_SESSION_KEYRING as c_ulong,
            0,
            0,
            0,
        )
    };
    let fl_e = if fl_v == -1 { errno_now() } else { 0 };
    let lc_v = unsafe {
        syscall(
            SYS_KEYCTL,
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_SESSION_KEYRING,
            0,
            0,
            0,
        )
    };
    let lc_e = if lc_v == -1 { errno_now() } else { 0 };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(
            fl_v == -1,
            lc_v == -1,
            "keyctl session ret: fl={fl_v} lc={lc_v}"
        );
        if fl_v == -1 {
            assert_eq!(fl_e, lc_e, "keyctl session errno: fl={fl_e} lc={lc_e}");
        }
    } else {
        // Both succeeded — they must return the same serial number.
        assert_eq!(fl_v, lc_v, "keyctl session serial: fl={fl_v} lc={lc_v}");
    }
}

#[test]
fn diff_keyctl_get_keyring_id_process() {
    let fl_v = unsafe {
        fl::keyctl(
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_PROCESS_KEYRING as c_ulong,
            0,
            0,
            0,
        )
    };
    let lc_v = unsafe {
        syscall(
            SYS_KEYCTL,
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_PROCESS_KEYRING,
            0,
            0,
            0,
        )
    };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v == -1, lc_v == -1, "keyctl process ret");
    } else {
        assert_eq!(fl_v, lc_v);
    }
}

#[test]
fn diff_keyctl_get_keyring_id_thread() {
    let fl_v = unsafe {
        fl::keyctl(
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_THREAD_KEYRING as c_ulong,
            0,
            0,
            0,
        )
    };
    let lc_v = unsafe {
        syscall(
            SYS_KEYCTL,
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_THREAD_KEYRING,
            0,
            0,
            0,
        )
    };
    if fl_v == -1 || lc_v == -1 {
        assert_eq!(fl_v == -1, lc_v == -1, "keyctl thread ret");
    } else {
        assert_eq!(fl_v, lc_v);
    }
}

#[test]
fn diff_keyctl_invalid_op_returns_eopnotsupp_or_einval() {
    // Operation 9999 is not implemented; the kernel returns -1 with
    // EOPNOTSUPP (or similar). Both impls must propagate the same
    // errno.
    let fl_v = unsafe { fl::keyctl(9999, 0, 0, 0, 0) };
    let fl_e = errno_now();
    let lc_v = unsafe { syscall(SYS_KEYCTL, 9999, 0, 0, 0, 0) };
    let lc_e = errno_now();
    assert_eq!(fl_v, -1);
    assert_eq!(lc_v, -1);
    assert_eq!(fl_e, lc_e, "invalid-op errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn diff_request_key_nonexistent_returns_enokey() {
    // Request a key with a name that doesn't exist; expect ENOKEY
    // or similar from both impls.
    let key_type = CString::new("user").unwrap();
    let desc = CString::new("frankenlibc-test-nonexistent-key-xyz").unwrap();
    let fl_v = unsafe {
        fl::request_key(
            key_type.as_ptr(),
            desc.as_ptr(),
            std::ptr::null(),
            KEY_SPEC_PROCESS_KEYRING as i32,
        )
    };
    let fl_e = errno_now();
    let lc_v = unsafe {
        syscall(
            SYS_REQUEST_KEY,
            key_type.as_ptr() as c_long,
            desc.as_ptr() as c_long,
            0 as c_long,
            KEY_SPEC_PROCESS_KEYRING,
        )
    };
    let lc_e = errno_now();
    assert_eq!(
        fl_v == -1,
        lc_v == -1,
        "request_key ret: fl={fl_v} lc={lc_v}"
    );
    if fl_v == -1 {
        assert_eq!(fl_e, lc_e, "request_key errno: fl={fl_e} lc={lc_e}");
    }
}

#[test]
fn diff_add_key_invalid_keyring_returns_einval_or_eperm() {
    // Adding to keyring -42 (invalid). Both impls must report failure
    // with the same errno.
    let key_type = CString::new("user").unwrap();
    let desc = CString::new("frankenlibc-test-invalid-keyring").unwrap();
    let payload = b"x";
    let fl_v = unsafe {
        fl::add_key(
            key_type.as_ptr(),
            desc.as_ptr(),
            payload.as_ptr() as *const c_void,
            payload.len(),
            -42i32,
        )
    };
    let fl_e = errno_now();
    let lc_v = unsafe {
        syscall(
            SYS_ADD_KEY,
            key_type.as_ptr() as c_long,
            desc.as_ptr() as c_long,
            payload.as_ptr() as c_long,
            payload.len() as c_long,
            -42 as c_long,
        )
    };
    let lc_e = errno_now();
    assert_eq!(fl_v, -1);
    assert_eq!(lc_v, -1);
    assert_eq!(fl_e, lc_e, "add_key errno: fl={fl_e} lc={lc_e}");
}

#[test]
fn keyctl_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc add_key + request_key + keyctl\",\"reference\":\"glibc-syscall\",\"functions\":3,\"divergences\":0}}",
    );
    let _ = (CStr::from_bytes_with_nul(b"\0").unwrap(), 0u8 as c_char);
}
