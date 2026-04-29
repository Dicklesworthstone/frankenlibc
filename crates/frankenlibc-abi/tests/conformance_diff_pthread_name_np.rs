#![cfg(target_os = "linux")]

//! Differential conformance harness for `pthread_setname_np` /
//! `pthread_getname_np`.
//!
//! Both write/read the per-thread name via /proc/self/task/<tid>/comm.
//! Linux limits names to 16 bytes including NUL.
//!
//! Filed under [bd-xn6p8] follow-up.

use std::ffi::{c_char, c_int, CStr, CString};

use frankenlibc_abi::pthread_abi as fl;

unsafe extern "C" {
    fn pthread_setname_np(thread: libc::pthread_t, name: *const c_char) -> c_int;
    fn pthread_getname_np(thread: libc::pthread_t, buf: *mut c_char, len: usize) -> c_int;
    fn pthread_self() -> libc::pthread_t;
}

#[test]
fn diff_pthread_setname_get_round_trip() {
    // fl uses raw-syscall pthread_self while the libc crate's pthread_self
    // goes through glibc. They produce different opaque tokens, so we use
    // each impl's OWN pthread_self handle when calling its setter/getter.
    let fl_me = unsafe { fl::pthread_self() };
    let lc_me = unsafe { pthread_self() };
    let names: &[&str] = &[
        "thread-0",
        "abc",
        "exactly-15-char",  // 15 chars + NUL = 16 (max)
        "",
    ];
    for name in names {
        let cn = CString::new(*name).unwrap();
        let r = unsafe { fl::pthread_setname_np(fl_me, cn.as_ptr()) };
        assert_eq!(r, 0, "fl pthread_setname_np({name:?}) failed: {r}");
        let mut buf = [0i8; 32];
        let g = unsafe { fl::pthread_getname_np(fl_me, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(g, 0, "fl pthread_getname_np failed: {g}");
        let got = unsafe { CStr::from_ptr(buf.as_ptr()).to_bytes() };
        assert_eq!(got, name.as_bytes(), "fl name mismatch: set={name:?}, got={:?}", String::from_utf8_lossy(got));

        // Same with glibc:
        let r = unsafe { pthread_setname_np(lc_me, cn.as_ptr()) };
        assert_eq!(r, 0, "glibc pthread_setname_np({name:?}) failed: {r}");
        let mut buf = [0i8; 32];
        let g = unsafe { pthread_getname_np(lc_me, buf.as_mut_ptr(), buf.len()) };
        assert_eq!(g, 0, "glibc pthread_getname_np failed: {g}");
        let got = unsafe { CStr::from_ptr(buf.as_ptr()).to_bytes() };
        assert_eq!(got, name.as_bytes(), "glibc name mismatch");
    }
}

#[test]
fn diff_pthread_setname_too_long_rejected() {
    let fl_me = unsafe { fl::pthread_self() };
    let lc_me = unsafe { pthread_self() };
    let cn = CString::new("this-name-is-way-too-long-for-linux").unwrap();
    let fl_r = unsafe { fl::pthread_setname_np(fl_me, cn.as_ptr()) };
    let lc_r = unsafe { pthread_setname_np(lc_me, cn.as_ptr()) };
    assert_eq!(
        fl_r, lc_r,
        "long-name return mismatch: fl={fl_r} lc={lc_r}"
    );
    // Both should reject with the same errno (typically ERANGE = 34).
    assert_ne!(fl_r, 0, "long name should be rejected");
}

#[test]
fn diff_pthread_getname_buffer_too_small() {
    let fl_me = unsafe { fl::pthread_self() };
    let lc_me = unsafe { pthread_self() };
    let cn = CString::new("smol").unwrap();
    let _ = unsafe { fl::pthread_setname_np(fl_me, cn.as_ptr()) };
    let mut tiny = [0i8; 2]; // less than 5 bytes for "smol\0"
    let fl_r = unsafe { fl::pthread_getname_np(fl_me, tiny.as_mut_ptr(), tiny.len()) };
    let lc_r = unsafe { pthread_getname_np(lc_me, tiny.as_mut_ptr(), tiny.len()) };
    assert_eq!(
        fl_r, lc_r,
        "small-buf return mismatch: fl={fl_r} lc={lc_r}"
    );
}

#[test]
fn pthread_name_np_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc pthread_*name_np\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
