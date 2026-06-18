//! Differential gate: gethostent() /etc/hosts iteration vs live host glibc.
//!
//! Both engines read the same /etc/hosts (the "files" source). We iterate each
//! and compare the full `struct hostent` per entry — h_name, h_aliases,
//! h_addrtype, h_length, h_addr_list — catching alias-dropping, wrong family,
//! or address mishandling (the bug class the netdb vein found in
//! getservent/getprotoent/getnetent). glibc reached via dlsym.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type EntFn = unsafe extern "C" fn() -> *mut c_void;
type VoidFn = unsafe extern "C" fn();

struct Glibc {
    gethostent: EntFn,
    sethostent: unsafe extern "C" fn(c_int),
    endhostent: VoidFn,
}
fn glibc() -> Glibc {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        Glibc {
            gethostent: std::mem::transmute(dlsym(h, c"gethostent".as_ptr())),
            sethostent: std::mem::transmute(dlsym(h, c"sethostent".as_ptr())),
            endhostent: std::mem::transmute(dlsym(h, c"endhostent".as_ptr())),
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
struct Host {
    name: Vec<u8>,
    aliases: Vec<Vec<u8>>,
    addrtype: i32,
    length: i32,
    addrs: Vec<Vec<u8>>,
}

/// Decode a `struct hostent*` into a comparable owned value.
unsafe fn decode(p: *const u8) -> Host {
    unsafe {
        let h_name = *(p as *const *const c_char);
        let h_aliases = *(p.add(8) as *const *const *const c_char);
        let h_addrtype = *(p.add(16) as *const i32);
        let h_length = *(p.add(20) as *const i32);
        let h_addr_list = *(p.add(24) as *const *const *const u8);
        let name = CStr::from_ptr(h_name).to_bytes().to_vec();
        let mut aliases = Vec::new();
        if !h_aliases.is_null() {
            let mut i = 0;
            loop {
                let a = *h_aliases.add(i);
                if a.is_null() {
                    break;
                }
                aliases.push(CStr::from_ptr(a).to_bytes().to_vec());
                i += 1;
            }
        }
        let mut addrs = Vec::new();
        if !h_addr_list.is_null() {
            let mut i = 0;
            loop {
                let a = *h_addr_list.add(i);
                if a.is_null() {
                    break;
                }
                addrs.push(std::slice::from_raw_parts(a, h_length.max(0) as usize).to_vec());
                i += 1;
            }
        }
        Host {
            name,
            aliases,
            addrtype: h_addrtype,
            length: h_length,
            addrs,
        }
    }
}

#[test]
fn gethostent_iteration_matches_glibc() {
    let g = glibc();
    // Collect glibc's full sequence first (its iteration state is independent).
    let mut gseq = Vec::new();
    unsafe {
        (g.sethostent)(1);
        loop {
            let p = (g.gethostent)();
            if p.is_null() {
                break;
            }
            gseq.push(decode(p as *const u8));
            if gseq.len() > 4096 {
                break;
            }
        }
        (g.endhostent)();
    }
    // Now fl's sequence.
    let mut fseq = Vec::new();
    unsafe {
        fl::sethostent(1);
        loop {
            let p = fl::gethostent();
            if p.is_null() {
                break;
            }
            fseq.push(decode(p as *const u8));
            if fseq.len() > 4096 {
                break;
            }
        }
        fl::endhostent();
    }
    assert_eq!(
        gseq.len(),
        fseq.len(),
        "entry count: glibc={} fl={}",
        gseq.len(),
        fseq.len()
    );
    let mut mism = Vec::new();
    for (i, (gh, fh)) in gseq.iter().zip(fseq.iter()).enumerate() {
        if gh != fh {
            mism.push(format!("entry {i}:\n  glibc={gh:x?}\n  fl   ={fh:x?}"));
        }
    }
    assert!(
        mism.is_empty(),
        "gethostent diverged ({}):\n{}",
        mism.len(),
        mism.join("\n")
    );
}
