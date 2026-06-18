#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc res_mkquery oracle

//! Differential gate for res_mkquery (bd-t09766) — the DNS query-packet builder
//! had no differential gate. It is pure (no network): it formats a DNS query
//! message (12-byte header + question section) into the caller's buffer. The
//! 2-byte ID at offset 0 is randomized, so the packet is compared from offset 2
//! onward (flags + QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT + the encoded QNAME/QTYPE/
//! QCLASS) vs glibc, along with the returned length. Each impl uses its own
//! res_init/_res state. No mocks.

use std::ffi::{c_char, c_int, c_void, CString};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn res_init() -> c_int;
        pub fn res_mkquery(
            op: c_int, dname: *const c_char, class: c_int, typ: c_int,
            data: *const c_void, datalen: c_int, newrr: *const c_void,
            buf: *mut c_void, buflen: c_int,
        ) -> c_int;
    }
}
use frankenlibc_abi::{glibc_internal_abi as flg, unistd_abi as flu};

const NS_O_QUERY: c_int = 0;
const NS_C_IN: c_int = 1;

fn glibc_q(name: &str, typ: c_int) -> (c_int, Vec<u8>) {
    let dn = CString::new(name).unwrap();
    let mut buf = vec![0u8; 512];
    unsafe {
        g::res_init();
        let n = g::res_mkquery(NS_O_QUERY, dn.as_ptr(), NS_C_IN, typ, std::ptr::null(), 0, std::ptr::null(), buf.as_mut_ptr() as *mut c_void, 512);
        (n, if n > 2 { buf[2..n as usize].to_vec() } else { Vec::new() })
    }
}
fn fl_q(name: &str, typ: c_int) -> (c_int, Vec<u8>) {
    let dn = CString::new(name).unwrap();
    let mut buf = vec![0u8; 512];
    unsafe {
        flu::res_init();
        let n = flg::res_mkquery(NS_O_QUERY, dn.as_ptr(), NS_C_IN, typ, std::ptr::null(), 0, std::ptr::null(), buf.as_mut_ptr() as *mut c_void, 512);
        (n, if n > 2 { buf[2..n as usize].to_vec() } else { Vec::new() })
    }
}

#[test]
fn res_mkquery_matches_glibc() {
    // (name, qtype): A=1, NS=2, CNAME=5, MX=15, AAAA=28, TXT=16.
    let cases: &[(&str, c_int)] = &[
        ("example.com", 1),
        ("www.example.org", 1),
        ("example.com", 28),
        ("mail.example.com", 15),
        ("a.b.c.d.example.net", 2),
        ("x", 16),
        ("", 1), // root
    ];
    for &(name, typ) in cases {
        let g = glibc_q(name, typ);
        let f = fl_q(name, typ);
        assert_eq!(f.0, g.0, "res_mkquery({name:?}, {typ}) len: fl={} glibc={}", f.0, g.0);
        assert_eq!(
            f.1, g.1,
            "res_mkquery({name:?}, {typ}) packet[2..]: fl={:02x?} glibc={:02x?}",
            f.1, g.1
        );
    }
}
