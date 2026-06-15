//! Differential gate for getnetbyaddr address-type matching vs glibc.
//!
//! glibc's files backend matches a /etc/networks entry only when BOTH
//! `n_net == net` AND `n_addrtype == type`. Every entry parsed from
//! /etc/networks carries `n_addrtype == AF_INET`, so a query with any
//! other address family (AF_INET6, an arbitrary integer, 0) finds
//! nothing and returns NULL. fl previously ignored the `type` argument
//! entirely, so it returned a match for every type.
//!
//! Both fl and glibc read the same fixed `/etc/networks`, so this gate
//! compares fl's getnetbyaddr directly against the live host glibc
//! (reached via dlsym to bypass fl's no_mangle interposition) across a
//! (net, type) matrix built from the host's real entries plus a
//! synthetic absent net. Agreement is required name-for-name.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_uint, c_void};

const RTLD_NOW: c_int = 2;
const AF_INET: c_int = 2;
const AF_INET6: c_int = 10;

#[repr(C)]
struct NetEnt {
    n_name: *mut c_char,
    n_aliases: *mut *mut c_char,
    n_addrtype: c_int,
    n_net: u32,
}

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type GetByAddrFn = extern "C" fn(c_uint, c_int) -> *mut NetEnt;
type GetEntFn = extern "C" fn() -> *mut NetEnt;
type SetEntFn = extern "C" fn(c_int);
type EndEntFn = extern "C" fn();

unsafe fn sym(lib: *mut c_void, name: &CStr) -> *mut c_void {
    let p = unsafe { dlsym(lib, name.as_ptr()) };
    assert!(!p.is_null(), "dlsym {name:?} failed");
    p
}

fn name_of(p: *mut NetEnt) -> Option<Vec<u8>> {
    if p.is_null() {
        return None;
    }
    let n = unsafe { (*p).n_name };
    if n.is_null() {
        return Some(Vec::new());
    }
    Some(unsafe { CStr::from_ptr(n) }.to_bytes().to_vec())
}

#[test]
fn getnetbyaddr_type_matches_glibc() {
    let lib = unsafe { dlopen(c"libc.so.6".as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen libc.so.6 failed");
    let g_getbyaddr: GetByAddrFn =
        unsafe { std::mem::transmute(sym(lib, c"getnetbyaddr")) };
    let g_getent: GetEntFn = unsafe { std::mem::transmute(sym(lib, c"getnetent")) };
    let g_setent: SetEntFn = unsafe { std::mem::transmute(sym(lib, c"setnetent")) };
    let g_endent: EndEntFn = unsafe { std::mem::transmute(sym(lib, c"endnetent")) };

    // Enumerate the host's real /etc/networks nets via glibc.
    let mut nets: Vec<u32> = Vec::new();
    g_setent(1);
    loop {
        let e = g_getent();
        if e.is_null() {
            break;
        }
        nets.push(unsafe { (*e).n_net });
        if nets.len() > 256 {
            break;
        }
    }
    g_endent();
    // Always include a synthetic almost-certainly-absent net.
    nets.push(0xDEAD_BEEF);

    let types = [AF_INET, AF_INET6, 99, 0];

    let mut mismatches = Vec::new();
    for &net in &nets {
        for &ty in &types {
            let g = name_of(g_getbyaddr(net, ty));
            let f = name_of(unsafe { fl::getnetbyaddr(net, ty).cast::<NetEnt>() });
            if g != f {
                mismatches.push(format!(
                    "net=0x{net:08x} type={ty}: glibc={g:?} fl={f:?}"
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "getnetbyaddr diverged from glibc:\n{}",
        mismatches.join("\n")
    );
}
