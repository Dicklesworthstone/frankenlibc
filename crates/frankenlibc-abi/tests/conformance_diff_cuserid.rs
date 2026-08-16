#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cuserid oracle
//! Differential gate for `cuserid` (bd-l1xxt3).
//!
//! `cuserid` returns the login name associated with the effective user. It has
//! two shapes: with a NULL argument it fills a static buffer and returns a
//! pointer to it, and with a caller buffer it fills that (at least `L_cuserid`
//! bytes) and returns it. Both are compared against the live host here.
//!
//! `cuserid` is compat-only in modern glibc, so the host symbol is resolved with
//! `dlvsym` — a link-time declaration or a plain `dlsym` finds nothing and the
//! target would go silent rather than red (bd-86hcwh).

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_void};

const GLIBC_2_2_5: &std::ffi::CStr = c"GLIBC_2.2.5";
type CuseridFn = unsafe extern "C" fn(*mut c_char) -> *mut c_char;

union CuseridSymbol {
    raw: *mut c_void,
    function: CuseridFn,
}

fn host_cuserid() -> CuseridFn {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: handle came from dlopen; both names are NUL-terminated constants.
    let raw = unsafe { libc::dlvsym(handle, c"cuserid".as_ptr(), GLIBC_2_2_5.as_ptr()) };
    assert!(
        !raw.is_null(),
        "dlvsym cuserid@GLIBC_2.2.5 — compat-only symbols need dlvsym, not dlsym"
    );
    // SAFETY: the resolved symbol has glibc's documented cuserid signature.
    unsafe { CuseridSymbol { raw }.function }
}

/// `L_cuserid` is 9 in glibc; give both implementations more room than that so a
/// short-buffer difference cannot be mistaken for a name difference.
const BUF: usize = 64;

#[test]
fn cuserid_matches_glibc_for_caller_buffer_and_static_storage() {
    let host = host_cuserid();

    // Caller-supplied buffer. Prefill with a sentinel so a short write leaves
    // evidence rather than looking like a correct short name.
    let mut host_buf = [0xAAu8; BUF];
    let mut fl_buf = [0xAAu8; BUF];
    // SAFETY: both buffers are far larger than L_cuserid.
    let host_ret = unsafe { host(host_buf.as_mut_ptr().cast::<c_char>()) };
    // SAFETY: as above, against fl's implementation.
    let fl_ret = unsafe { fl::cuserid(fl_buf.as_mut_ptr().cast::<c_char>()) };

    assert_eq!(
        host_ret.is_null(),
        fl_ret.is_null(),
        "one implementation returned NULL for the caller-buffer form and the other did not"
    );

    if !host_ret.is_null() {
        // glibc returns the caller's buffer, not private storage.
        assert_eq!(
            host_ret.cast::<u8>(),
            host_buf.as_mut_ptr(),
            "oracle: cuserid(buf) should return buf itself"
        );
        assert_eq!(
            fl_ret.cast::<u8>(),
            fl_buf.as_mut_ptr(),
            "fl should return the caller's buffer, not private storage"
        );
        // SAFETY: both calls NUL-terminated their buffers.
        let host_name = unsafe { CStr::from_ptr(host_ret) }.to_bytes().to_vec();
        // SAFETY: as above.
        let fl_name = unsafe { CStr::from_ptr(fl_ret) }.to_bytes().to_vec();
        assert_eq!(
            fl_name,
            host_name,
            "cuserid(buf) name diverged: fl={:?} glibc={:?}",
            String::from_utf8_lossy(&fl_name),
            String::from_utf8_lossy(&host_name)
        );
        // Nothing may be written past the NUL either implementation placed.
        let end = host_name.len() + 1;
        assert!(
            fl_buf[end..].iter().all(|&b| b == 0xAA),
            "fl wrote past the terminating NUL in the caller's buffer"
        );
    }

    // NULL argument: static storage. Compare the CONTENTS, not the pointers —
    // the two implementations legitimately own different static buffers.
    // SAFETY: the NULL form is cuserid's documented static-storage shape.
    let host_static = unsafe { host(std::ptr::null_mut()) };
    // SAFETY: as above.
    let fl_static = unsafe { fl::cuserid(std::ptr::null_mut()) };
    assert_eq!(
        host_static.is_null(),
        fl_static.is_null(),
        "one implementation returned NULL for the static-storage form and the other did not"
    );
    if !host_static.is_null() {
        // SAFETY: both pointers are NUL-terminated static storage.
        let host_name = unsafe { CStr::from_ptr(host_static) }.to_bytes().to_vec();
        // SAFETY: as above.
        let fl_name = unsafe { CStr::from_ptr(fl_static) }.to_bytes().to_vec();
        assert_eq!(
            fl_name,
            host_name,
            "cuserid(NULL) name diverged: fl={:?} glibc={:?}",
            String::from_utf8_lossy(&fl_name),
            String::from_utf8_lossy(&host_name)
        );
        // The two shapes must agree with each other as well, or a caller that
        // switches forms sees a different user.
        // SAFETY: filled by the caller-buffer call above.
        let fl_buf_name = unsafe { CStr::from_ptr(fl_buf.as_ptr().cast::<c_char>()) }
            .to_bytes()
            .to_vec();
        assert_eq!(
            fl_name, fl_buf_name,
            "fl's NULL and caller-buffer forms disagree with each other"
        );
    }
}
