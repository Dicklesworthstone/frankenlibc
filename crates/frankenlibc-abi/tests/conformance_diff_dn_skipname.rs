#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc dn_skipname oracle

//! Differential gate for dn_skipname (bd-oos0nz) — skips a (possibly
//! compressed) domain name in a DNS message and returns its on-the-wire byte
//! length, or -1 on error. Pure (no network). Compares fl's return vs glibc's
//! across an uncompressed name, a name ending in a compression pointer, the
//! root name, a bare pointer, and truncated/malformed inputs (which must error
//! identically). No mocks.

use std::ffi::{c_int, c_uchar};

unsafe extern "C" {
    fn dn_skipname(comp_dn: *const c_uchar, eom: *const c_uchar) -> c_int;
}

fn glibc(msg: &[u8]) -> c_int {
    unsafe { dn_skipname(msg.as_ptr(), msg.as_ptr().add(msg.len())) }
}
fn fl(msg: &[u8]) -> c_int {
    unsafe { frankenlibc_abi::unistd_abi::dn_skipname(msg.as_ptr(), msg.as_ptr().add(msg.len())) }
}

#[test]
fn dn_skipname_matches_glibc() {
    let cases: Vec<Vec<u8>> = vec![
        // "example.com" uncompressed: 7 'example' 3 'com' 0  -> 13
        vec![
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ],
        // root name (single 0 byte) -> 1
        vec![0],
        // bare compression pointer 0xC00C -> 2
        vec![0xC0, 0x0C],
        // label then pointer: 3 'foo' <ptr> -> 4 + 2 = 6
        vec![3, b'f', b'o', b'o', 0xC0, 0x0C],
        // single short label: 1 'x' 0 -> 3
        vec![1, b'x', 0],
        // truncated: label length exceeds remaining bytes -> error (-1)
        vec![7, b'a', b'b'],
        // truncated: name with no terminator / runs off end -> error
        vec![3, b'f', b'o', b'o'],
        // empty buffer -> error
        vec![],
        // dangling pointer first byte (0xC0 with no second byte) -> error
        vec![0xC0],
    ];
    for (i, msg) in cases.iter().enumerate() {
        let g = glibc(msg);
        let f = fl(msg);
        assert_eq!(f, g, "dn_skipname case {i} ({msg:02x?}): fl={f} glibc={g}");
    }
}
