//! Differential gate: dn_expand must match glibc, including compression
//! pointers and the bytes-consumed return value.
//!
//! dn_expand reads a (possibly compressed) wire-format name from a DNS message
//! and renders the dotted text, returning the number of bytes consumed from
//! the *original* position (NOT following pointers for the count). fl
//! implements the full RFC1035 pointer-following reader; this pins it against
//! the live host glibc (via dlsym) over uncompressed, pointer-compressed, and
//! root cases.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type DnExpandFn = extern "C" fn(*const u8, *const u8, *const u8, *mut c_char, c_int) -> c_int;

fn cstr_text(buf: &[u8]) -> Vec<u8> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf[..end].to_vec()
}

#[test]
fn dn_expand_matches_glibc() {
    let g: DnExpandFn = unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen libc.so.6 failed");
        let s = dlsym(lib, c"dn_expand".as_ptr());
        assert!(!s.is_null(), "dlsym dn_expand failed");
        std::mem::transmute::<*mut c_void, DnExpandFn>(s)
    };

    // (message bytes, offset of the name to expand within the message)
    let www_example_com: Vec<u8> = vec![
        3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];

    // A message with a compression pointer: "mail" + ptr->offset 0 (the
    // www.example.com name above lives at offset 0 of this message).
    let mut compressed = www_example_com.clone();
    let ptr_to_0 = compressed.len(); // offset where the second name starts
    compressed.extend_from_slice(&[4, b'm', b'a', b'i', b'l', 0xC0, 0x00]);

    // Pointer that jumps to the "example.com" suffix (offset 4) of the first name.
    let mut suffix = www_example_com.clone();
    let ptr_to_4 = suffix.len();
    suffix.extend_from_slice(&[2, b'n', b's', 0xC0, 0x04]);

    let root: Vec<u8> = vec![0];

    let cases: &[(&[u8], usize, &str)] = &[
        (&www_example_com, 0, "uncompressed www.example.com"),
        (&compressed, ptr_to_0, "pointer to full name"),
        (&suffix, ptr_to_4, "pointer to example.com suffix"),
        (&root, 0, "root"),
    ];

    let mut mismatches = Vec::new();
    for &(msg, off, label) in cases {
        let eom = unsafe { msg.as_ptr().add(msg.len()) };
        let comp = unsafe { msg.as_ptr().add(off) };

        let mut gt = [0u8; 1024];
        let grc = g(
            msg.as_ptr(),
            eom,
            comp,
            gt.as_mut_ptr() as *mut c_char,
            gt.len() as c_int,
        );

        let mut ft = [0u8; 1024];
        let frc = unsafe {
            flu::dn_expand(
                msg.as_ptr(),
                eom,
                comp,
                ft.as_mut_ptr() as *mut c_char,
                ft.len() as c_int,
            )
        };

        if grc != frc {
            mismatches.push(format!("{label}: rc glibc={grc} fl={frc}"));
        }
        if grc >= 0 && frc >= 0 {
            let gs = cstr_text(&gt);
            let fs = cstr_text(&ft);
            if gs != fs {
                mismatches.push(format!(
                    "{label}: text glibc={:?} fl={:?}",
                    String::from_utf8_lossy(&gs),
                    String::from_utf8_lossy(&fs)
                ));
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "dn_expand diverged from glibc:\n{}",
        mismatches.join("\n")
    );
}
