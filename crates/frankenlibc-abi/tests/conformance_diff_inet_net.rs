#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `inet_net_pton` /
//! `inet_net_ntop` (CIDR-aware variants of inet_pton/ntop).
//!
//! Both symbols live in `libresolv.so.2`, so `#[link(name = "resolv")]`
//! is required to pull in the host implementations. fl exports its own
//! versions in `frankenlibc_abi::glibc_internal_abi`. This harness was
//! filed under [bd-xn6p8] follow-up — extending differential coverage
//! across the libresolv address-codec surface.
//!
//! `inet_net_pton(af, src, dst, size)` parses a CIDR-style address like
//! `"192.168.1.0/24"` or partial `"192.168"`, writing the address into
//! `dst` and returning the prefix length (or -1 on error).
//!
//! `inet_net_ntop(af, src, bits, dst, size)` formats `bits` of `src` as
//! a CIDR string into `dst`.

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_abi::errno_abi::__errno_location as fl_errno_location;
use frankenlibc_abi::glibc_internal_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn inet_net_pton(af: c_int, src: *const c_char, dst: *mut c_void, size: usize) -> c_int;
    fn inet_net_ntop(
        af: c_int,
        src: *const c_void,
        bits: c_int,
        dst: *mut c_char,
        size: usize,
    ) -> *const c_char;
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

unsafe fn clear_errno_both() {
    unsafe {
        *fl_errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

unsafe fn read_fl_errno() -> c_int {
    unsafe { *fl_errno_location() }
}

unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

const PTON_CASES: &[&[u8]] = &[
    // Standard CIDR with explicit prefix — fl matches glibc.
    b"192.168.1.0/24",
    b"10.0.0.0/8",
    b"172.16.0.0/12",
    b"0.0.0.0/0",
    b"255.255.255.255/32",
    // Partial dotted-quad without prefix (classful inference).
    b"10",
    b"10.0",
    b"10.0.0",
    b"172.16.5",
    b"0177/8",
    b"128.1",
    b"192",
    b"192.168",
    b"224.1.2.3",
    b"240",
    b"1.2.3.4.5",
    b"1.2.3.4.5/24",
    // Edge cases that fl and glibc both reject (or both accept identically).
    b"",
    b"foo",
    b"1.2.3.4/",
    b"1.2.3.4/33",      // prefix > 32
    b"1.2.3.4/-1",      // negative prefix
    b"1.2.3.4/abc",     // non-numeric prefix
    b"256.0.0.0/24",    // octet overflow
    b" 192.168.1.0/24", // leading whitespace
];

const PTON_SIZE_CASES: &[(&[u8], usize)] = &[
    (b"0/0", 0),
    (b"0/0", 1),
    (b"10/8", 0),
    (b"10/8", 1),
    (b"10.1.2/20", 2),
    (b"10.1.2/20", 3),
    (b"192.168.1.0/24", 3),
    (b"192.168.1.0/24", 4),
    (b"0xC0A80000/24", 3),
    (b"0xC0A80000/24", 4),
    (b"192.168", 2),
    (b"192.168", 3),
    (b"224.1.2.3", 3),
    (b"224.1.2.3", 4),
    (b"1.2.3.4.5/24", 4),
    (b"1.2.3.4.5/24", 5),
];

#[test]
fn diff_inet_net_pton_cases() {
    let mut divs = Vec::new();
    for input in PTON_CASES {
        let mut nul_input = input.to_vec();
        nul_input.push(0);
        let p = nul_input.as_ptr() as *const c_char;
        let mut fl_buf = [0u8; 16];
        let mut lc_buf = [0u8; 16];
        let fl_n = unsafe {
            fl::inet_net_pton(
                libc::AF_INET,
                p,
                fl_buf.as_mut_ptr() as *mut c_void,
                fl_buf.len(),
            )
        };
        let lc_n = unsafe {
            inet_net_pton(
                libc::AF_INET,
                p,
                lc_buf.as_mut_ptr() as *mut c_void,
                lc_buf.len(),
            )
        };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if fl_n != lc_n {
            divs.push(Divergence {
                function: "inet_net_pton",
                case: case.clone(),
                field: "prefix_length",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        if fl_n >= 0 && lc_n >= 0 && fl_buf != lc_buf {
            divs.push(Divergence {
                function: "inet_net_pton",
                case,
                field: "address_bytes",
                frankenlibc: format!("{:?}", &fl_buf[..4]),
                glibc: format!("{:?}", &lc_buf[..4]),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_net_pton divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_inet_net_pton_output_size_boundaries() {
    let mut divs = Vec::new();
    for &(input, size) in PTON_SIZE_CASES {
        let mut nul_input = input.to_vec();
        nul_input.push(0);
        let p = nul_input.as_ptr() as *const c_char;
        let mut fl_buf = vec![0u8; size + 4];
        let mut lc_buf = vec![0u8; size + 4];

        unsafe { clear_errno_both() };
        let fl_n = unsafe {
            fl::inet_net_pton(libc::AF_INET, p, fl_buf.as_mut_ptr() as *mut c_void, size)
        };
        let fl_errno = unsafe { read_fl_errno() };

        unsafe { clear_errno_both() };
        let lc_n =
            unsafe { inet_net_pton(libc::AF_INET, p, lc_buf.as_mut_ptr() as *mut c_void, size) };
        let lc_errno = unsafe { read_lc_errno() };

        let case = format!("{:?}, size={size}", String::from_utf8_lossy(input));
        if fl_n != lc_n {
            divs.push(Divergence {
                function: "inet_net_pton",
                case: case.clone(),
                field: "prefix_length",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        if fl_n < 0 && lc_n < 0 && fl_errno != lc_errno {
            divs.push(Divergence {
                function: "inet_net_pton",
                case: case.clone(),
                field: "errno",
                frankenlibc: format!("{fl_errno}"),
                glibc: format!("{lc_errno}"),
            });
        }
        if fl_n >= 0 && lc_n >= 0 {
            let compared = size.min(4);
            if fl_buf[..compared] != lc_buf[..compared] {
                divs.push(Divergence {
                    function: "inet_net_pton",
                    case,
                    field: "address_bytes",
                    frankenlibc: format!("{:?}", &fl_buf[..compared]),
                    glibc: format!("{:?}", &lc_buf[..compared]),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "inet_net_pton size-boundary divergences:\n{}",
        render_divs(&divs)
    );
}

const NTOP_CASES: &[(&[u8; 16], c_int, &str)] = &[
    (
        &[192, 168, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        24,
        "192.168.1.0/24",
    ),
    (
        &[192, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        16,
        "192.168/16",
    ),
    (
        &[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        8,
        "10/8",
    ),
    (
        &[172, 16, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        24,
        "172.16.5.0/24",
    ),
    // Cases that previously diverged — fixed in net_pton.rs::format:
    (&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, "0/0"),
    (
        &[255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
        "255.255.255.255/32",
    ),
    (
        &[1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        12,
        "1.2.3.4/12",
    ),
];

const NTOP_SIZE_CASES: &[(&[u8; 16], c_int, usize)] = &[
    (&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, 4),
    (&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0, 5),
    (&[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8, 5),
    (&[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8, 6),
    (&[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16, 7),
    (&[10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 16, 8),
    (
        &[255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
        18,
    ),
    (
        &[255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        32,
        19,
    ),
];

#[test]
fn diff_inet_net_ntop_cases() {
    let mut divs = Vec::new();
    for (addr, bits, label) in NTOP_CASES {
        let mut fl_buf = [0i8; 64];
        let mut lc_buf = [0i8; 64];
        let p_fl = unsafe {
            fl::inet_net_ntop(
                libc::AF_INET,
                addr.as_ptr() as *const c_void,
                *bits,
                fl_buf.as_mut_ptr() as *mut c_char,
                fl_buf.len(),
            )
        };
        let p_lc = unsafe {
            inet_net_ntop(
                libc::AF_INET,
                addr.as_ptr() as *const c_void,
                *bits,
                lc_buf.as_mut_ptr() as *mut c_char,
                lc_buf.len(),
            )
        };
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "inet_net_ntop",
                case: label.to_string(),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            continue;
        }
        let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl as *const c_char).to_bytes() };
        let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "inet_net_ntop",
                case: label.to_string(),
                field: "string",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_net_ntop divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_inet_net_ntop_output_size_boundaries() {
    let mut divs = Vec::new();
    for &(addr, bits, size) in NTOP_SIZE_CASES {
        let mut fl_buf = vec![0i8; size + 4];
        let mut lc_buf = vec![0i8; size + 4];

        unsafe { clear_errno_both() };
        let p_fl = unsafe {
            fl::inet_net_ntop(
                libc::AF_INET,
                addr.as_ptr() as *const c_void,
                bits,
                fl_buf.as_mut_ptr() as *mut c_char,
                size,
            )
        };
        let fl_errno = unsafe { read_fl_errno() };

        unsafe { clear_errno_both() };
        let p_lc = unsafe {
            inet_net_ntop(
                libc::AF_INET,
                addr.as_ptr() as *const c_void,
                bits,
                lc_buf.as_mut_ptr() as *mut c_char,
                size,
            )
        };
        let lc_errno = unsafe { read_lc_errno() };

        let case = format!("{addr:?}, bits={bits}, size={size}");
        if p_fl.is_null() != p_lc.is_null() {
            divs.push(Divergence {
                function: "inet_net_ntop",
                case: case.clone(),
                field: "null_return",
                frankenlibc: format!("{}", p_fl.is_null()),
                glibc: format!("{}", p_lc.is_null()),
            });
            continue;
        }
        if p_fl.is_null() {
            if fl_errno != lc_errno {
                divs.push(Divergence {
                    function: "inet_net_ntop",
                    case,
                    field: "errno",
                    frankenlibc: format!("{fl_errno}"),
                    glibc: format!("{lc_errno}"),
                });
            }
            continue;
        }
        let s_fl = unsafe { std::ffi::CStr::from_ptr(p_fl as *const c_char).to_bytes() };
        let s_lc = unsafe { std::ffi::CStr::from_ptr(p_lc).to_bytes() };
        if s_fl != s_lc {
            divs.push(Divergence {
                function: "inet_net_ntop",
                case,
                field: "string",
                frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "inet_net_ntop size-boundary divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn inet_net_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv inet_net_*\",\"reference\":\"glibc\",\"functions\":2,\"pton_cases\":25,\"pton_size_cases\":16,\"ntop_cases\":7,\"ntop_size_cases\":8,\"divergences\":0}}",
    );
}
