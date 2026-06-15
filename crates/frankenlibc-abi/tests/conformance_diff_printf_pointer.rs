#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc snprintf oracle

//! `printf %p` flag parity vs host glibc (bd-2g7oyh.NEW).
//!
//! glibc renders a non-NULL pointer like `%#x` of its value — honouring the
//! `0` (zero-pad), `#`, precision and width flags — and additionally applies
//! the `+`/space sign flags (which a real `%x` ignores). A NULL pointer prints
//! "(nil)" as a string (width / left-justify only). fl previously honoured only
//! width and left-justify. This gate compares the rendered string for a flag
//! matrix over several pointer values, including NULL.

use frankenlibc_abi::stdio_abi as fl;
use std::ffi::{CString, c_char, c_void};

unsafe extern "C" {
    fn snprintf(b: *mut c_char, s: usize, f: *const c_char, ...) -> i32;
}

fn render(eng: u8, fmt: &str, p: *const c_void) -> String {
    let cf = CString::new(fmt).unwrap();
    let mut b = [0u8; 96];
    let n = if eng == 0 {
        unsafe { fl::snprintf(b.as_mut_ptr() as *mut c_char, 96, cf.as_ptr(), p) }
    } else {
        unsafe { snprintf(b.as_mut_ptr() as *mut c_char, 96, cf.as_ptr(), p) }
    };
    String::from_utf8_lossy(&b[..n.max(0) as usize]).into_owned()
}

#[test]
fn printf_pointer_flags_match_glibc() {
    let ptrs: &[*const c_void] = &[
        std::ptr::null(),
        std::ptr::dangling::<c_void>(),
        0x1234 as *const c_void,
        0xdead_beef_usize as *const c_void,
        0xffff_ffff_ffff_ffff_usize as *const c_void,
    ];
    let fmts = [
        "%p", "%20p", "%-20p|", "%020p", "[%5p]", "%+p", "% p", "%#p", "%#020p", "%+020p",
        "% 020p", "%-+20p|", "%.10p", "%.0p", "%015p", "% .8p", "%+.5p", "%+-25p|", "%025p", "%1p",
    ];
    for fmt in fmts {
        for &p in ptrs {
            let a = render(0, fmt, p);
            let b = render(1, fmt, p);
            assert_eq!(a, b, "snprintf({fmt:?}, {p:?}): fl={a:?} glibc={b:?}");
        }
    }
}
