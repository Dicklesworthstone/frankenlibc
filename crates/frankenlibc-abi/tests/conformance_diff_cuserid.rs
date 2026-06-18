#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cuserid oracle

//! Differential coverage for deprecated `cuserid(3)`.
//!
//! FrankenLibC resolves the current uid through the passwd backend and supports
//! both the static-buffer and caller-buffer forms. This gate compares both
//! contracts against the live host glibc implementation for the same process.

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

type CuseridFn = unsafe extern "C" fn(*mut c_char) -> *mut c_char;

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

fn host_cuserid() -> CuseridFn {
    unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen(libc.so.6) failed");
        let symbol = dlsym(lib, c"cuserid".as_ptr());
        assert!(!symbol.is_null(), "dlsym(cuserid) failed");
        std::mem::transmute(symbol)
    }
}

fn bytes(ptr: *const c_char) -> Vec<u8> {
    assert!(!ptr.is_null(), "cuserid returned NULL");
    unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() }
}

struct EnvGuard {
    key: &'static str,
    old: Option<String>,
}

impl EnvGuard {
    fn unset(key: &'static str) -> Self {
        let old = std::env::var(key).ok();
        unsafe { std::env::remove_var(key) };
        Self { key, old }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match &self.old {
            Some(value) => unsafe { std::env::set_var(self.key, value) },
            None => unsafe { std::env::remove_var(self.key) },
        }
    }
}

#[test]
fn cuserid_static_and_caller_buffer_match_host() {
    let _env = EnvGuard::unset("FRANKENLIBC_PASSWD_PATH");
    let host = host_cuserid();

    let host_static = unsafe { host(std::ptr::null_mut()) };
    let fl_static = unsafe { fl::cuserid(std::ptr::null_mut()) };
    assert_eq!(bytes(fl_static), bytes(host_static), "cuserid(NULL)");

    let second_fl_static = unsafe { fl::cuserid(std::ptr::null_mut()) };
    assert_eq!(
        second_fl_static, fl_static,
        "FrankenLibC should reuse per-thread cuserid static storage"
    );

    let mut host_buf = [0 as c_char; 64];
    let mut fl_buf = [0 as c_char; 64];
    let host_out = unsafe { host(host_buf.as_mut_ptr()) };
    let fl_out = unsafe { fl::cuserid(fl_buf.as_mut_ptr()) };

    assert_eq!(
        host_out,
        host_buf.as_mut_ptr(),
        "host cuserid should return caller buffer"
    );
    assert_eq!(
        fl_out,
        fl_buf.as_mut_ptr(),
        "FrankenLibC cuserid should return caller buffer"
    );
    assert_eq!(
        bytes(fl_buf.as_ptr()),
        bytes(host_buf.as_ptr()),
        "cuserid(caller buffer)"
    );
    assert_eq!(
        bytes(fl_buf.as_ptr()),
        bytes(fl_static),
        "caller-buffer and static-buffer values should agree"
    );
}
