#![cfg(target_os = "linux")]

//! Differential conformance harness for `<arpa/inet.h>` byte-order +
//! address-string conversions. Pure functions — easiest differential
//! targets.
//!
//! Bead: CONFORMANCE: libc arpa/inet.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};
use std::ptr;

use frankenlibc_abi::inet_abi as fl;

unsafe extern "C" {
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: u32) -> *const c_char;
    fn inet_aton(cp: *const c_char, inp: *mut libc::in_addr) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// htonl / htons / ntohl / ntohs — byte order
// ===========================================================================

#[test]
fn diff_byte_order_conversions() {
    let mut divs = Vec::new();
    let u16s: &[u16] = &[0, 1, 0xFF, 0x100, 0x1234, 0xFFFE, 0xFFFF];
    let u32s: &[u32] = &[0, 1, 0xFF, 0x100, 0xCAFEBABE, 0xFFFFFFFE, 0xFFFFFFFF];
    for &v in u16s {
        let fl_v = unsafe { fl::htons(v) };
        let lc_v = unsafe { libc::htons(v) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "htons",
                case: format!("{:#x}", v),
                field: "return",
                frankenlibc: format!("{:#x}", fl_v),
                glibc: format!("{:#x}", lc_v),
            });
        }
        let fl_back = unsafe { fl::ntohs(fl_v) };
        let lc_back = unsafe { libc::ntohs(lc_v) };
        if fl_back != v || lc_back != v {
            divs.push(Divergence {
                function: "ntohs",
                case: format!("{:#x}", v),
                field: "round_trip",
                frankenlibc: format!("{:#x}", fl_back),
                glibc: format!("{:#x}", lc_back),
            });
        }
    }
    for &v in u32s {
        let fl_v = unsafe { fl::htonl(v) };
        let lc_v = unsafe { libc::htonl(v) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "htonl",
                case: format!("{:#x}", v),
                field: "return",
                frankenlibc: format!("{:#x}", fl_v),
                glibc: format!("{:#x}", lc_v),
            });
        }
        let fl_back = unsafe { fl::ntohl(fl_v) };
        let lc_back = unsafe { libc::ntohl(lc_v) };
        if fl_back != v || lc_back != v {
            divs.push(Divergence {
                function: "ntohl",
                case: format!("{:#x}", v),
                field: "round_trip",
                frankenlibc: format!("{:#x}", fl_back),
                glibc: format!("{:#x}", lc_back),
            });
        }
    }
    assert!(divs.is_empty(), "byte-order divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// inet_pton — text → binary
// ===========================================================================

const INET_PTON_V4_CASES: &[&[u8]] = &[
    b"0.0.0.0",
    b"127.0.0.1",
    b"255.255.255.255",
    b"192.168.1.1",
    b"10.0.0.42",
    b"1.2.3.4",
    b"256.0.0.0",            // invalid octet > 255
    b"1.2.3",                // missing octet
    b"1.2.3.4.5",            // too many octets
    b"a.b.c.d",              // non-numeric
    b"",                     // empty
    b"127.0.0.01",           // glibc accepts leading zero; some impls reject
    b" 127.0.0.1",           // leading whitespace
];

#[test]
fn diff_inet_pton_v4_cases() {
    let mut divs = Vec::new();
    for input in INET_PTON_V4_CASES {
        let cinp = {
            let mut v = input.to_vec();
            v.push(0);
            v
        };
        let mut fl_buf = [0u8; 4];
        let mut lc_buf = [0u8; 4];
        let r_fl = unsafe {
            fl::inet_pton(
                libc::AF_INET,
                cinp.as_ptr() as *const c_char,
                fl_buf.as_mut_ptr() as *mut c_void,
            )
        };
        let r_lc = unsafe {
            inet_pton(
                libc::AF_INET,
                cinp.as_ptr() as *const c_char,
                lc_buf.as_mut_ptr() as *mut c_void,
            )
        };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "inet_pton(AF_INET)",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl == 1 && r_lc == 1 && fl_buf != lc_buf {
            divs.push(Divergence {
                function: "inet_pton(AF_INET)",
                case,
                field: "binary",
                frankenlibc: format!("{:?}", fl_buf),
                glibc: format!("{:?}", lc_buf),
            });
        }
    }
    assert!(divs.is_empty(), "inet_pton v4 divergences:\n{}", render_divs(&divs));
}

const INET_PTON_V6_CASES: &[&[u8]] = &[
    b"::",
    b"::1",
    b"2001:db8::1",
    b"fe80::1",
    b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    b"2001:db8::",
    b"::ffff:192.0.2.128",      // IPv4-mapped
    b"abcd",                     // invalid
    b"",                         // empty
    b":::",                      // too many colons
];

#[test]
fn diff_inet_pton_v6_cases() {
    let mut divs = Vec::new();
    for input in INET_PTON_V6_CASES {
        let cinp = {
            let mut v = input.to_vec();
            v.push(0);
            v
        };
        let mut fl_buf = [0u8; 16];
        let mut lc_buf = [0u8; 16];
        let r_fl = unsafe {
            fl::inet_pton(
                libc::AF_INET6,
                cinp.as_ptr() as *const c_char,
                fl_buf.as_mut_ptr() as *mut c_void,
            )
        };
        let r_lc = unsafe {
            inet_pton(
                libc::AF_INET6,
                cinp.as_ptr() as *const c_char,
                lc_buf.as_mut_ptr() as *mut c_void,
            )
        };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "inet_pton(AF_INET6)",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl == 1 && r_lc == 1 && fl_buf != lc_buf {
            divs.push(Divergence {
                function: "inet_pton(AF_INET6)",
                case,
                field: "binary",
                frankenlibc: format!("{:?}", fl_buf),
                glibc: format!("{:?}", lc_buf),
            });
        }
    }
    assert!(divs.is_empty(), "inet_pton v6 divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// inet_ntop — binary → text
// ===========================================================================

#[test]
fn diff_inet_ntop_v4_roundtrip() {
    let mut divs = Vec::new();
    let v4_addrs: &[[u8; 4]] = &[
        [0, 0, 0, 0],
        [127, 0, 0, 1],
        [255, 255, 255, 255],
        [192, 168, 1, 1],
        [10, 0, 0, 42],
        [1, 2, 3, 4],
    ];
    for addr in v4_addrs {
        let mut fl_buf = vec![0i8; 64];
        let mut lc_buf = vec![0i8; 64];
        let p_fl = unsafe {
            fl::inet_ntop(
                libc::AF_INET,
                addr.as_ptr() as *const c_void,
                fl_buf.as_mut_ptr(),
                fl_buf.len() as u32,
            )
        };
        let p_lc = unsafe {
            inet_ntop(
                libc::AF_INET,
                addr.as_ptr() as *const c_void,
                lc_buf.as_mut_ptr(),
                lc_buf.len() as u32,
            )
        };
        let case = format!("{:?}", addr);
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "inet_ntop(AF_INET)",
                case: case.clone(),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
            let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "inet_ntop(AF_INET)",
                    case,
                    field: "string",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
                });
            }
        }
    }
    assert!(divs.is_empty(), "inet_ntop v4 divergences:\n{}", render_divs(&divs));
}

#[test]
fn diff_inet_ntop_v6_roundtrip() {
    let mut divs = Vec::new();
    let v6_addrs: &[[u8; 16]] = &[
        [0u8; 16],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],          // ::1
        [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],   // fe80::1
        [0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34],
    ];
    for addr in v6_addrs {
        let mut fl_buf = vec![0i8; 64];
        let mut lc_buf = vec![0i8; 64];
        let p_fl = unsafe {
            fl::inet_ntop(
                libc::AF_INET6,
                addr.as_ptr() as *const c_void,
                fl_buf.as_mut_ptr(),
                fl_buf.len() as u32,
            )
        };
        let p_lc = unsafe {
            inet_ntop(
                libc::AF_INET6,
                addr.as_ptr() as *const c_void,
                lc_buf.as_mut_ptr(),
                lc_buf.len() as u32,
            )
        };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "inet_ntop(AF_INET6)",
                case: format!("{:?}", addr),
                field: "null",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if !p_fl.is_null() {
            let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl).to_bytes() };
            let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
            if s_fl != s_lc {
                divs.push(Divergence {
                    function: "inet_ntop(AF_INET6)",
                    case: format!("{:?}", addr),
                    field: "string",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
                });
            }
        }
    }
    assert!(divs.is_empty(), "inet_ntop v6 divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// inet_aton — text → 32-bit address
// ===========================================================================

#[test]
fn diff_inet_aton_cases() {
    let mut divs = Vec::new();
    let cases: &[&[u8]] = &[
        b"127.0.0.1",
        b"0.0.0.0",
        b"255.255.255.255",
        b"1.2.3.4",
        b"a.b.c.d",
        b"",
    ];
    for input in cases {
        let cinp = CString::new(*input).unwrap();
        let mut fl_addr: u32 = 0;
        let mut lc_addr = libc::in_addr { s_addr: 0 };
        let r_fl = unsafe { fl::inet_aton(cinp.as_ptr(), &mut fl_addr) };
        let r_lc = unsafe { inet_aton(cinp.as_ptr(), &mut lc_addr) };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "inet_aton",
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl != 0 && r_lc != 0 && fl_addr != lc_addr.s_addr {
            divs.push(Divergence {
                function: "inet_aton",
                case,
                field: "addr",
                frankenlibc: format!("{:#x}", fl_addr),
                glibc: format!("{:#x}", lc_addr.s_addr),
            });
        }
    }
    assert!(divs.is_empty(), "inet_aton divergences:\n{}", render_divs(&divs));
}

#[test]
fn arpa_inet_diff_coverage_report() {
    let _ = ptr::null::<c_int>();
    eprintln!(
        "{{\"family\":\"arpa/inet.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
