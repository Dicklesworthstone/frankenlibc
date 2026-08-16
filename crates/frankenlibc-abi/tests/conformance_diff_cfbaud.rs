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

// Host arms resolved with `dlsym`, not `#[link_name]`.
//
// The previous form abbreviated the Rust names to `h_setbaud` and friends while
// `#[link_name]` pointed at the real symbols, which fl also exports. That binds
// like any plain extern — to whichever definition the linker picks — and the
// abbreviation hides it: nothing in the name `h_setbaud` tells a reader whether
// the arm is the host's or fl's. This is the renamed-import variant of
// bd-v0388t; the `assert_ne!` below is what actually settles it.
type SetBaudFn = unsafe extern "C" fn(*mut c_void, c_uint) -> c_int;
type GetBaudFn = unsafe extern "C" fn(*const c_void) -> c_uint;

fn host_symbol(name: &std::ffi::CStr, fl_addr: usize) -> *mut c_void {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: handle came from dlopen; name is NUL-terminated.
    let raw = unsafe { libc::dlsym(handle, name.as_ptr()) };
    assert!(
        !raw.is_null(),
        "dlsym {name:?} — these are glibc extensions; if the host lacks them the \
         gate must skip rather than compare against nothing"
    );
    assert_ne!(
        raw as usize, fl_addr,
        "the resolved oracle IS fl's {name:?} — this gate would compare fl to itself"
    );
    raw
}

fn h_setbaud_fn() -> SetBaudFn {
    // SAFETY: resolved symbol has glibc's documented cfsetbaud signature.
    unsafe {
        std::mem::transmute::<_, SetBaudFn>(host_symbol(c"cfsetbaud", fl::cfsetbaud as usize))
    }
}
fn h_setibaud_fn() -> SetBaudFn {
    // SAFETY: as above, for cfsetibaud.
    unsafe {
        std::mem::transmute::<_, SetBaudFn>(host_symbol(c"cfsetibaud", fl::cfsetibaud as usize))
    }
}
fn h_setobaud_fn() -> SetBaudFn {
    // SAFETY: as above, for cfsetobaud.
    unsafe {
        std::mem::transmute::<_, SetBaudFn>(host_symbol(c"cfsetobaud", fl::cfsetobaud as usize))
    }
}
fn h_getibaud_fn() -> GetBaudFn {
    // SAFETY: as above, for cfgetibaud.
    unsafe {
        std::mem::transmute::<_, GetBaudFn>(host_symbol(c"cfgetibaud", fl::cfgetibaud as usize))
    }
}
fn h_getobaud_fn() -> GetBaudFn {
    // SAFETY: as above, for cfgetobaud.
    unsafe {
        std::mem::transmute::<_, GetBaudFn>(host_symbol(c"cfgetobaud", fl::cfgetobaud as usize))
    }
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
        let hr = unsafe { h_setbaud_fn()((&mut ht) as *mut _ as *mut c_void, b) };
        let fr = unsafe { fl::cfsetbaud((&mut ft) as *mut _ as *mut c_void, b) };
        assert_eq!(hr, fr, "cfsetbaud({b}) return value");
        let hi = unsafe { h_getibaud_fn()((&ht) as *const _ as *const c_void) };
        let ho = unsafe { h_getobaud_fn()((&ht) as *const _ as *const c_void) };
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
            h_setibaud_fn()((&mut ht) as *mut _ as *mut c_void, b);
            fl::cfsetibaud((&mut ft) as *mut _ as *mut c_void, b);
        }
        let hi = unsafe { h_getibaud_fn()((&ht) as *const _ as *const c_void) };
        let fi = unsafe { fl::cfgetibaud((&ft) as *const _ as *const c_void) };
        assert_eq!(fi, hi, "cfsetibaud({b}) -> ibaud");
        assert_eq!(fi, b, "cfsetibaud({b}) round-trips");

        // output only
        let (mut ht, mut ft) = (zt(), zt());
        unsafe {
            h_setobaud_fn()((&mut ht) as *mut _ as *mut c_void, b);
            fl::cfsetobaud((&mut ft) as *mut _ as *mut c_void, b);
        }
        let ho = unsafe { h_getobaud_fn()((&ht) as *const _ as *const c_void) };
        let fo = unsafe { fl::cfgetobaud((&ft) as *const _ as *const c_void) };
        assert_eq!(fo, ho, "cfsetobaud({b}) -> obaud");
        assert_eq!(fo, b, "cfsetobaud({b}) round-trips");
    }
}
