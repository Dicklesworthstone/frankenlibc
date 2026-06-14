//! Conformance gate: the glibc-2.42 arbitrary-baud termios family
//! (cfsetbaud/cfsetibaud/cfsetobaud + cfgetibaud/cfgetobaud) vs host glibc.
//!
//! Pins the ABI ARITY of cfsetbaud: glibc is `int cfsetbaud(struct termios *,
//! baud_t baud)` — ONE baud argument that sets BOTH input and output. fl
//! previously declared a 3-argument (ibaud, obaud) form, so a caller passing the
//! documented 2 arguments left fl reading a garbage register. This gate calls
//! cfsetbaud with the correct 2-argument signature and checks the user-observable
//! round-trip (cfget*baud returns the baud just set) matches host glibc.
//!
//! NOTE: the raw c_cflag CBAUD/CIBAUD encoding is intentionally NOT asserted —
//! glibc 2.42 maps standard bauds to their Bxxx codes while fl uses the BOTHER
//! marker + c_ospeed/c_ispeed consistently; both read back identically via the
//! cfget*baud accessors (the documented interface).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
use std::os::raw::{c_int, c_uint, c_void};

unsafe extern "C" {
    #[link_name = "cfsetbaud"]
    fn h_setbaud(t: *mut c_void, b: c_uint) -> c_int;
    #[link_name = "cfsetibaud"]
    fn h_setibaud(t: *mut c_void, b: c_uint) -> c_int;
    #[link_name = "cfsetobaud"]
    fn h_setobaud(t: *mut c_void, b: c_uint) -> c_int;
    #[link_name = "cfgetibaud"]
    fn h_getibaud(t: *const c_void) -> c_uint;
    #[link_name = "cfgetobaud"]
    fn h_getobaud(t: *const c_void) -> c_uint;
}
use frankenlibc_abi::glibc_internal_abi as fl;

fn zt() -> libc::termios {
    unsafe { std::mem::zeroed() }
}

const BAUDS: &[c_uint] = &[
    0, 50, 110, 300, 1200, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600, 1000000,
    1500000, 4000000,
];

#[test]
fn cfsetbaud_sets_both_like_glibc() {
    for &b in BAUDS {
        let (mut ht, mut ft) = (zt(), zt());
        let hr = unsafe { h_setbaud((&mut ht) as *mut _ as *mut c_void, b) };
        let fr = unsafe { fl::cfsetbaud((&mut ft) as *mut _ as *mut c_void, b) };
        assert_eq!(hr, fr, "cfsetbaud({b}) return value");
        let hi = unsafe { h_getibaud((&ht) as *const _ as *const c_void) };
        let ho = unsafe { h_getobaud((&ht) as *const _ as *const c_void) };
        let fi = unsafe { fl::cfgetibaud((&ft) as *const _ as *const c_void) };
        let fo = unsafe { fl::cfgetobaud((&ft) as *const _ as *const c_void) };
        assert_eq!((fi, fo), (hi, ho), "cfsetbaud({b}) -> (ibaud,obaud)");
        // cfsetbaud sets BOTH to the same value.
        assert_eq!(
            (fi, fo),
            (b, b),
            "cfsetbaud({b}) sets both input and output"
        );
    }
}

#[test]
fn cfsetibaud_cfsetobaud_independent_like_glibc() {
    for &b in BAUDS {
        // input only
        let (mut ht, mut ft) = (zt(), zt());
        unsafe {
            h_setibaud((&mut ht) as *mut _ as *mut c_void, b);
            fl::cfsetibaud((&mut ft) as *mut _ as *mut c_void, b);
        }
        let hi = unsafe { h_getibaud((&ht) as *const _ as *const c_void) };
        let fi = unsafe { fl::cfgetibaud((&ft) as *const _ as *const c_void) };
        assert_eq!(fi, hi, "cfsetibaud({b}) -> ibaud");
        assert_eq!(fi, b, "cfsetibaud({b}) round-trips");

        // output only
        let (mut ht, mut ft) = (zt(), zt());
        unsafe {
            h_setobaud((&mut ht) as *mut _ as *mut c_void, b);
            fl::cfsetobaud((&mut ft) as *mut _ as *mut c_void, b);
        }
        let ho = unsafe { h_getobaud((&ht) as *const _ as *const c_void) };
        let fo = unsafe { fl::cfgetobaud((&ft) as *const _ as *const c_void) };
        assert_eq!(fo, ho, "cfsetobaud({b}) -> obaud");
        assert_eq!(fo, b, "cfsetobaud({b}) round-trips");
    }
}
