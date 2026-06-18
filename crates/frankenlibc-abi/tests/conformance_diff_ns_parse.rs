#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc ns_* parser oracle; opaque ns_msg/ns_rr buffers

//! Differential gate for the DNS message parse+format pipeline (bd-yrwdqn):
//! ns_initparse -> ns_parserr -> ns_sprintrr. Driven by a hand-crafted, valid
//! A-record response for "example.com". ns_msg/ns_rr are opaque and stay within
//! each implementation (generous byte buffers back them); only the final
//! formatted RR text (and each step's return code) is compared cross-impl. No
//! mocks.

use std::ffi::{c_char, c_int, c_void, CStr};

const NS_S_AN: c_int = 1; // answer section

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn ns_initparse(msg: *const u8, msglen: c_int, handle: *mut c_void) -> c_int;
        pub fn ns_parserr(handle: *mut c_void, section: c_int, rrnum: c_int, rr: *mut c_void) -> c_int;
        pub fn ns_sprintrr(handle: *const c_void, rr: *const c_void, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, buflen: usize) -> c_int;
    }
}
use frankenlibc_abi::resolv_abi as fl;

// A valid DNS A-record response for example.com -> 93.184.216.34.
fn response() -> Vec<u8> {
    vec![
        0x12, 0x34, // ID
        0x81, 0x80, // flags: response, RD, RA
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // question: example.com, A, IN
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        0x00, 0x01, 0x00, 0x01,
        // answer: ptr->12, A, IN, TTL=300, RDLEN=4, 93.184.216.34
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04,
        93, 184, 216, 34,
    ]
}

/// (initparse_rc, parserr_rc, sprintrr_rc, formatted_text)
fn run(
    initparse: unsafe extern "C" fn(*const u8, c_int, *mut c_void) -> c_int,
    parserr: unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int,
    sprintrr: unsafe extern "C" fn(*const c_void, *const c_void, *const c_char, *const c_char, *mut c_char, usize) -> c_int,
) -> (c_int, c_int, c_int, String) {
    let msg = response();
    // Generous opaque backing buffers (ns_msg ~80B, ns_rr ~1.1KB on glibc/fl).
    let mut handle = vec![0u8; 4096];
    let mut rr = vec![0u8; 4096];
    let mut out = vec![0u8; 1024];
    unsafe {
        let ip = initparse(msg.as_ptr(), msg.len() as c_int, handle.as_mut_ptr() as *mut c_void);
        if ip != 0 {
            return (ip, -99, -99, String::new());
        }
        let pr = parserr(handle.as_mut_ptr() as *mut c_void, NS_S_AN, 0, rr.as_mut_ptr() as *mut c_void);
        if pr != 0 {
            return (ip, pr, -99, String::new());
        }
        let sr = sprintrr(
            handle.as_ptr() as *const c_void,
            rr.as_ptr() as *const c_void,
            std::ptr::null(),
            std::ptr::null(),
            out.as_mut_ptr() as *mut c_char,
            out.len(),
        );
        let text = if sr >= 0 {
            CStr::from_ptr(out.as_ptr() as *const c_char).to_string_lossy().into_owned()
        } else {
            String::new()
        };
        (ip, pr, sr, text)
    }
}

#[test]
fn ns_parse_pipeline_matches_glibc() {
    let gres = run(g::ns_initparse, g::ns_parserr, g::ns_sprintrr);
    // fl's ns_* take typed CNsMsg*/CNsRr* pointers; the pointer ABI is identical
    // to *mut c_void, so transmute the fn pointers for the shared driver.
    type InitFn = unsafe extern "C" fn(*const u8, c_int, *mut c_void) -> c_int;
    type ParseFn = unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int;
    type SprintFn = unsafe extern "C" fn(*const c_void, *const c_void, *const c_char, *const c_char, *mut c_char, usize) -> c_int;
    let f_init: InitFn = unsafe { std::mem::transmute(fl::ns_initparse as *const ()) };
    let f_parse: ParseFn = unsafe { std::mem::transmute(fl::ns_parserr as *const ()) };
    let f_sprint: SprintFn = unsafe { std::mem::transmute(fl::ns_sprintrr as *const ()) };
    let fres = run(f_init, f_parse, f_sprint);
    assert_eq!(gres.0, 0, "glibc ns_initparse should accept the crafted response");
    assert_eq!(gres.1, 0, "glibc ns_parserr should parse the answer RR");
    assert!(gres.2 >= 0, "glibc ns_sprintrr should succeed");
    assert_eq!(
        (fres.0, fres.1, fres.3.clone()),
        (gres.0, gres.1, gres.3.clone()),
        "ns parse pipeline: fl=({},{},{:?}) glibc=({},{},{:?})",
        fres.0, fres.1, fres.3, gres.0, gres.1, gres.3
    );
}
