#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc regerror oracle

//! `regerror` message-string parity vs host glibc (bd-2g7oyh.NEW).
//!
//! fl's regex error table had drifted from glibc's `__re_error_msgid`: four
//! messages were paraphrased (REG_ECOLLATE, REG_EBRACK, REG_EPAREN, REG_EBRACE)
//! and three GNU codes (REG_EEND/ESIZE/ERPAREN = 14/15/16) fell through to
//! "Unknown error". This gate compares the message text and the returned needed
//! length for every error code against the live host.

use frankenlibc_abi::string_abi as fl;

unsafe extern "C" {
    fn regerror(e: i32, p: *const libc::regex_t, b: *mut i8, n: usize) -> usize;
}

fn render(eng: u8, code: i32) -> (usize, String) {
    let mut buf = [0i8; 128];
    let n = if eng == 0 {
        unsafe { fl::regerror(code, std::ptr::null(), buf.as_mut_ptr(), buf.len()) }
    } else {
        unsafe { regerror(code, std::ptr::null(), buf.as_mut_ptr(), buf.len()) }
    };
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();
    (n, s)
}

#[test]
fn regerror_messages_match_glibc() {
    // 0..=16 covers REG_NOERROR through the GNU REG_ERPAREN.
    for code in 0..=16 {
        let a = render(0, code);
        let b = render(1, code);
        assert_eq!(a, b, "regerror({code}) diverged: fl={a:?} glibc={b:?}");
    }

    // Truncation: a small buffer still NUL-terminates and reports the full
    // needed length, matching glibc.
    let mut small = [0i8; 5];
    let needed_fl = unsafe { fl::regerror(2, std::ptr::null(), small.as_mut_ptr(), small.len()) };
    let fl_s = unsafe { std::ffi::CStr::from_ptr(small.as_ptr()) }.to_string_lossy().into_owned();
    let mut small_g = [0i8; 5];
    let needed_gl = unsafe { regerror(2, std::ptr::null(), small_g.as_mut_ptr(), small_g.len()) };
    let gl_s = unsafe { std::ffi::CStr::from_ptr(small_g.as_ptr()) }.to_string_lossy().into_owned();
    assert_eq!((needed_fl, fl_s), (needed_gl, gl_s), "regerror truncation diverged");
}
