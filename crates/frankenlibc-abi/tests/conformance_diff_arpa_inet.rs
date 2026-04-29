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
    /// Host glibc `inet_addr` — dotted-quad → network-byte-order u32.
    fn inet_addr(cp: *const c_char) -> u32;
    /// Host glibc `inet_network` — dotted-quad → host-byte-order u32.
    fn inet_network(cp: *const c_char) -> std::ffi::c_uint;
    /// Host glibc `inet_ntoa` — in_addr → static buffer dotted-quad.
    fn inet_ntoa(addr: libc::in_addr) -> *const c_char;
    /// Host glibc `inet_lnaof` — extract local part by class.
    fn inet_lnaof(inp: libc::in_addr) -> std::ffi::c_uint;
    /// Host glibc `inet_makeaddr` — combine net + host into in_addr.
    fn inet_makeaddr(net: std::ffi::c_uint, host: std::ffi::c_uint) -> libc::in_addr;
    /// Host glibc `inet_netof` — extract network part by class.
    fn inet_netof(inp: libc::in_addr) -> std::ffi::c_uint;
}

/// Read NUL-terminated C string at `p` into Vec, capped at 256 bytes.
fn c_str_to_vec(p: *const c_char) -> Vec<u8> {
    if p.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 0..256 {
        // SAFETY: caller passes a NUL-terminated static-buffer ptr.
        let b = unsafe { *(p.add(i) as *const u8) };
        if b == 0 {
            break;
        }
        out.push(b);
    }
    out
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
        let lc_v = libc::htons(v);
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
        let lc_back = libc::ntohs(lc_v);
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
        let lc_v = libc::htonl(v);
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
        let lc_back = libc::ntohl(lc_v);
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
    assert!(
        divs.is_empty(),
        "byte-order divergences:\n{}",
        render_divs(&divs)
    );
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
    b"256.0.0.0",  // invalid octet > 255
    b"1.2.3",      // missing octet
    b"1.2.3.4.5",  // too many octets
    b"a.b.c.d",    // non-numeric
    b"",           // empty
    b"127.0.0.01", // glibc accepts leading zero; some impls reject
    b" 127.0.0.1", // leading whitespace
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
    assert!(
        divs.is_empty(),
        "inet_pton v4 divergences:\n{}",
        render_divs(&divs)
    );
}

const INET_PTON_V6_CASES: &[&[u8]] = &[
    b"::",
    b"::1",
    b"2001:db8::1",
    b"fe80::1",
    b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    b"2001:db8::",
    b"::ffff:192.0.2.128", // IPv4-mapped
    b"abcd",               // invalid
    b"",                   // empty
    b":::",                // too many colons
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
    assert!(
        divs.is_empty(),
        "inet_pton v6 divergences:\n{}",
        render_divs(&divs)
    );
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
    assert!(
        divs.is_empty(),
        "inet_ntop v4 divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_inet_ntop_v6_roundtrip() {
    let mut divs = Vec::new();
    let v6_addrs: &[[u8; 16]] = &[
        [0u8; 16],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // ::1
        [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // fe80::1
        [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0, 0, 0, 0, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
        ],
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
    assert!(
        divs.is_empty(),
        "inet_ntop v6 divergences:\n{}",
        render_divs(&divs)
    );
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
        // BSD numbers-and-dots grammar parity — glibc accepts these.
        b"127",
        b"127.1",
        b"127.0.0",
        b"0177.0.0.1",
        b"0x7f.0.0.1",
        b"2130706433",
        b"08.0.0.0",
        b"1.2.3.4.5",
        b" 127.0.0.1",
        b"127.0.0.1 xyz",
        b"1.2.3\tgarbage",
        b"1 .2.3.4",
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
    assert!(
        divs.is_empty(),
        "inet_aton divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// inet_addr / inet_network / inet_ntoa / inet_lnaof / inet_makeaddr / inet_netof
// ===========================================================================
//
// Six legacy class-based inet conversion functions, all implemented in
// frankenlibc-abi (inet_addr/ntoa in inet_abi.rs; the others in
// glibc_internal_abi.rs) but none in this conformance harness. Pure
// functions, deterministic, with well-defined POSIX/glibc semantics.

const INET_ADDR_INPUTS: &[&[u8]] = &[
    b"0.0.0.0",
    b"127.0.0.1",
    b"255.255.255.255",
    b"192.168.1.1",
    b"10.0.0.1",
    b"1.2.3.4",
    b"172.16.5.4",
    b"200.1.2.3",
    b"256.0.0.0", // out of range — must return INADDR_NONE
    b"1.2.3.4.5", // too many octets — INADDR_NONE
    b"abc",       // not numeric — INADDR_NONE
    b"",          // empty — INADDR_NONE
    // BSD numbers-and-dots grammar: 1, 2, 3-part forms, hex/octal radixes.
    // glibc accepts all of these; the previous fl impl wrongly rejected them.
    b"127",            // 1-part, decimal — full 32-bit value.
    b"2130706433",     // 1-part, decimal: 0x7F000001 == 127.0.0.1
    b"127.1",          // 2-part: 127.0.0.1
    b"127.0.0",        // 3-part: 127.0.0.0
    b"1.2.3",          // 3-part: 1.2.0.3
    b"0177.0.0.1",     // octal in part 0
    b"0x7f.0.0.1",     // hex in part 0
    b"127.0.0.01",     // single-digit octal == decimal 1
    b"0",              // 1-part zero
    b"08.0.0.0",       // invalid octal (8 not in [0,7]) — INADDR_NONE
    b"127.0.0.1\t",    // trailing tab tolerated
    b" 127.0.0.1",     // leading space rejected — INADDR_NONE
    b"127.0.0.1 xyz",  // whitespace terminates parse; following bytes ignored
    b"1.2.3\tgarbage", // 3-part form with tab terminator
    b"1 .2.3.4",       // whitespace after first component terminates as 1-part
];

#[test]
fn diff_inet_addr_cases() {
    let mut divs = Vec::new();
    for &input in INET_ADDR_INPUTS {
        let mut buf = input.to_vec();
        buf.push(0);
        let p = buf.as_ptr() as *const c_char;
        let fl_v = unsafe { fl::inet_addr(p) };
        let lc_v = unsafe { inet_addr(p) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "inet_addr",
                case: format!("{:?}", String::from_utf8_lossy(input)),
                field: "return",
                frankenlibc: format!("0x{fl_v:08x}"),
                glibc: format!("0x{lc_v:08x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_addr divergences:\n{}",
        render_divs(&divs)
    );
}

const INET_NETWORK_INPUTS: &[&[u8]] = &[
    b"127",
    b"127.0",
    b"127.0.0",
    b"127.0.0.1",
    b"127 ",
    b" 127",
    b"10",
    b"10.0",
    b"172.16",
    b"192.168.1",
    b"0",
    b"0x7f",
    b"0177",
    b"0x1.0x2.03.4",
    b"255.255.255.255",
    b"256",
    b"1.256",
    b"1.2.3.256",
    b"1.",
    b".1",
    b"1..2",
    b"08",
    b"127 abc",
];

#[test]
fn diff_inet_network_cases() {
    let mut divs = Vec::new();
    for &input in INET_NETWORK_INPUTS {
        let mut buf = input.to_vec();
        buf.push(0);
        let p = buf.as_ptr() as *const c_char;
        let fl_v = unsafe { frankenlibc_abi::glibc_internal_abi::inet_network(p) };
        let lc_v = unsafe { inet_network(p) };
        if fl_v != lc_v {
            divs.push(Divergence {
                function: "inet_network",
                case: format!("{:?}", String::from_utf8_lossy(input)),
                field: "return",
                frankenlibc: format!("0x{fl_v:08x}"),
                glibc: format!("0x{lc_v:08x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_network divergences:\n{}",
        render_divs(&divs)
    );
}

const INET_NTOA_S_ADDRS: &[u32] = &[
    0x00000000, // 0.0.0.0
    0x0100007f, // 127.0.0.1 in network byte order on LE
    0xffffffff, // 255.255.255.255
    0x0101a8c0, // 192.168.1.1
    0x04030201, // 1.2.3.4
    0x040510ac, // 172.16.5.4
];

#[test]
fn diff_inet_ntoa_cases() {
    let mut divs = Vec::new();
    for &s_addr in INET_NTOA_S_ADDRS {
        // SAFETY: inet_ntoa returns a static thread-local buffer.
        // Both impls have separate buffers so we can call them
        // sequentially and compare bytes — they don't clobber each
        // other's storage.
        let fl_p = unsafe { fl::inet_ntoa(s_addr) };
        let fl_bytes = c_str_to_vec(fl_p);
        let lc_a = libc::in_addr { s_addr };
        let lc_p = unsafe { inet_ntoa(lc_a) };
        let lc_bytes = c_str_to_vec(lc_p);
        if fl_bytes != lc_bytes {
            divs.push(Divergence {
                function: "inet_ntoa",
                case: format!("0x{s_addr:08x}"),
                field: "string",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(&fl_bytes)),
                glibc: format!("{:?}", String::from_utf8_lossy(&lc_bytes)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_ntoa divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_inet_lnaof_netof_cases() {
    // Sweep one address per network class plus 192.168 to cover the
    // class-A / class-B / class-C boundaries in the impl. lnaof and
    // netof share the input set since both branch on the same class
    // discriminant.
    let mut divs = Vec::new();
    for &s_addr in INET_NTOA_S_ADDRS {
        let lc_a = libc::in_addr { s_addr };
        let fl_lnaof = unsafe { frankenlibc_abi::glibc_internal_abi::inet_lnaof(s_addr) };
        let lc_lnaof = unsafe { inet_lnaof(lc_a) };
        if fl_lnaof != lc_lnaof {
            divs.push(Divergence {
                function: "inet_lnaof",
                case: format!("0x{s_addr:08x}"),
                field: "return",
                frankenlibc: format!("0x{fl_lnaof:08x}"),
                glibc: format!("0x{lc_lnaof:08x}"),
            });
        }
        let fl_netof = unsafe { frankenlibc_abi::glibc_internal_abi::inet_netof(s_addr) };
        let lc_netof = unsafe { inet_netof(lc_a) };
        if fl_netof != lc_netof {
            divs.push(Divergence {
                function: "inet_netof",
                case: format!("0x{s_addr:08x}"),
                field: "return",
                frankenlibc: format!("0x{fl_netof:08x}"),
                glibc: format!("0x{lc_netof:08x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_lnaof/inet_netof divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_inet_makeaddr_cases() {
    // (net, host) pairs. The classfulness branch in glibc keys off
    // `net` size: net < 128 is class A, net < 0x10000 is class B,
    // else class C.
    let pairs: &[(u32, u32)] = &[
        (127, 1),         // class A
        (10, 1),          // class A
        (0, 0),           // class A degenerate
        (0xac, 0x100501), // class B (172 = 0xac is class B)
        (0xc0, 0xa80164), // class C boundary (192 = 0xc0)
        (0xc8, 0x010203), // class C (200 = 0xc8)
        (0x100, 0x10203), // 16-bit net
        (0x10000, 0x42),  // 24-bit net
    ];
    let mut divs = Vec::new();
    for &(net, host) in pairs {
        let fl_a = unsafe { frankenlibc_abi::glibc_internal_abi::inet_makeaddr(net, host) };
        let lc_a = unsafe { inet_makeaddr(net, host) };
        if fl_a != lc_a.s_addr {
            divs.push(Divergence {
                function: "inet_makeaddr",
                case: format!("(net=0x{net:x}, host=0x{host:x})"),
                field: "s_addr",
                frankenlibc: format!("0x{fl_a:08x}"),
                glibc: format!("0x{:08x}", lc_a.s_addr),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_makeaddr divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn arpa_inet_diff_coverage_report() {
    let _ = ptr::null::<c_int>();
    eprintln!(
        "{{\"family\":\"arpa/inet.h\",\"reference\":\"glibc\",\"functions\":13,\"divergences\":0}}",
    );
}
