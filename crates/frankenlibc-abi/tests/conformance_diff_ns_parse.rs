#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc ns_* parser oracle; opaque ns_msg/ns_rr buffers

//! Differential gate for the DNS message parse+format pipeline (bd-yrwdqn):
//! ns_initparse -> ns_parserr -> ns_sprintrr. Driven by a hand-crafted, valid
//! A-record response for "example.com". ns_msg/ns_rr are opaque and stay within
//! each implementation (generous byte buffers back them); only the final
//! formatted RR text (and each step's return code) is compared cross-impl. No
//! mocks.

use std::ffi::{CStr, c_char, c_int, c_void};

const NS_S_AN: c_int = 1; // answer section

mod g {
    use super::*;
    // The ns_* parser lives in libresolv, NOT libc: nm -D libresolv.so.2 shows
    // ns_initparse@@GLIBC_2.9, ns_parserr@@GLIBC_2.9, ns_sprintrr@@GLIBC_2.9, and libc.so.6
    // exports none of them. Without this the target does not link, and an unlinkable target is
    // silent rather than green — this one never compiled once, so bd-yrwdqn could not have been
    // observed. It also aborted the whole `cargo test -p frankenlibc-abi` run. bd-5wckql.
    #[link(name = "resolv")]
    unsafe extern "C" {
        pub fn ns_initparse(msg: *const u8, msglen: c_int, handle: *mut c_void) -> c_int;
        pub fn ns_parserr(
            handle: *mut c_void,
            section: c_int,
            rrnum: c_int,
            rr: *mut c_void,
        ) -> c_int;
        pub fn ns_sprintrr(
            handle: *const c_void,
            rr: *const c_void,
            name_ctx: *const c_char,
            origin: *const c_char,
            buf: *mut c_char,
            buflen: usize,
        ) -> c_int;
        #[allow(clippy::too_many_arguments)]
        pub fn ns_sprintrrf(
            msg: *const u8,
            msglen: usize,
            name: *const c_char,
            class: u16,
            ty: u16,
            ttl: u32,
            rdata: *const u8,
            rdlen: usize,
            name_ctx: *const c_char,
            origin: *const c_char,
            buf: *mut c_char,
            buflen: usize,
        ) -> c_int;
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
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01,
        // answer: ptr->12, A, IN, TTL=300, RDLEN=4, 93.184.216.34
        0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 93, 184, 216, 34,
    ]
}

/// (initparse_rc, parserr_rc, sprintrr_rc, formatted_text)
fn run(
    initparse: unsafe extern "C" fn(*const u8, c_int, *mut c_void) -> c_int,
    parserr: unsafe extern "C" fn(*mut c_void, c_int, c_int, *mut c_void) -> c_int,
    sprintrr: unsafe extern "C" fn(
        *const c_void,
        *const c_void,
        *const c_char,
        *const c_char,
        *mut c_char,
        usize,
    ) -> c_int,
) -> (c_int, c_int, c_int, String) {
    let msg = response();
    // Generous opaque backing buffers (ns_msg ~80B, ns_rr ~1.1KB on glibc/fl).
    let mut handle = vec![0u8; 4096];
    let mut rr = vec![0u8; 4096];
    let mut out = vec![0u8; 1024];
    unsafe {
        let ip = initparse(
            msg.as_ptr(),
            msg.len() as c_int,
            handle.as_mut_ptr() as *mut c_void,
        );
        if ip != 0 {
            return (ip, -99, -99, String::new());
        }
        let pr = parserr(
            handle.as_mut_ptr() as *mut c_void,
            NS_S_AN,
            0,
            rr.as_mut_ptr() as *mut c_void,
        );
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
            CStr::from_ptr(out.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned()
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
    type SprintFn = unsafe extern "C" fn(
        *const c_void,
        *const c_void,
        *const c_char,
        *const c_char,
        *mut c_char,
        usize,
    ) -> c_int;
    let f_init: InitFn = unsafe { std::mem::transmute(fl::ns_initparse as *const ()) };
    let f_parse: ParseFn = unsafe { std::mem::transmute(fl::ns_parserr as *const ()) };
    let f_sprint: SprintFn = unsafe { std::mem::transmute(fl::ns_sprintrr as *const ()) };
    let fres = run(f_init, f_parse, f_sprint);
    assert_eq!(
        gres.0, 0,
        "glibc ns_initparse should accept the crafted response"
    );
    assert_eq!(gres.1, 0, "glibc ns_parserr should parse the answer RR");
    assert!(gres.2 >= 0, "glibc ns_sprintrr should succeed");
    assert_eq!(
        (fres.0, fres.1, fres.3.clone()),
        (gres.0, gres.1, gres.3.clone()),
        "ns parse pipeline: fl=({},{},{:?}) glibc=({},{},{:?})",
        fres.0,
        fres.1,
        fres.3,
        gres.0,
        gres.1,
        gres.3
    );
}

/// Pin the master-file PADDING LAW against live glibc, not one sample.
///
/// glibc pads the owner name to column 24 and the rdata to column 40 with 8-column tab stops,
/// falls back to two spaces once the column is within one of the target, and — the part no
/// single row can reveal — makes that fallback STICKY for the rest of the line. A long TTL
/// alone therefore changes the rdata separator while the name separator stays tabs.
///
/// Sweeping every owner-name length across the 22/23 tab-to-space boundary and TTLs from 1s to
/// u32::MAX is what makes this a law rather than a fitted constant.
#[test]
fn ns_sprintrrf_padding_matches_glibc_across_lengths_and_ttls() {
    const RDATA: [u8; 4] = [93, 184, 216, 34];
    let mut checked = 0usize;

    for name_len in 1..=30usize {
        for ttl in [1u32, 300, 86_400, 604_800, i32::MAX as u32, u32::MAX] {
            let name = "x".repeat(name_len);
            let name_c = std::ffi::CString::new(name.as_str()).expect("no interior NUL");

            let mut fl_buf = [0i8; 1024];
            let fl_rc = unsafe {
                fl::ns_sprintrrf(
                    std::ptr::null(),
                    0,
                    name_c.as_ptr(),
                    1,
                    1,
                    ttl,
                    RDATA.as_ptr(),
                    RDATA.len(),
                    std::ptr::null(),
                    std::ptr::null(),
                    fl_buf.as_mut_ptr(),
                    fl_buf.len(),
                )
            };
            let mut g_buf = [0i8; 1024];
            let g_rc = unsafe {
                g::ns_sprintrrf(
                    std::ptr::null(),
                    0,
                    name_c.as_ptr(),
                    1,
                    1,
                    ttl,
                    RDATA.as_ptr(),
                    RDATA.len(),
                    std::ptr::null(),
                    std::ptr::null(),
                    g_buf.as_mut_ptr(),
                    g_buf.len(),
                )
            };
            assert!(
                g_rc >= 0,
                "glibc ns_sprintrrf failed for len={name_len} ttl={ttl}"
            );

            let fl_txt = unsafe { CStr::from_ptr(fl_buf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            let g_txt = unsafe { CStr::from_ptr(g_buf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            assert_eq!(
                (fl_rc, fl_txt.as_str()),
                (g_rc, g_txt.as_str()),
                "ns_sprintrrf name_len={name_len} ttl={ttl}: fl={fl_txt:?} glibc={g_txt:?}"
            );
            checked += 1;
        }
    }

    // The sweep must actually have crossed the boundary that makes this a law: with the root dot
    // appended, name_len 22 pads with a tab and 23 with two spaces.
    assert_eq!(checked, 30 * 6, "sweep did not run every case");
}
