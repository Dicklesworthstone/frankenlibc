//! Differential gate: ns_name_pton / ns_name_ntop must match glibc, including
//! the return-value contracts.
//!
//! Both functions are file-independent BIND/RFC1035 converters, so they can be
//! compared directly against the live host glibc (reached via dlsym to bypass
//! fl's no_mangle interposition). Two return-value contracts are pinned here:
//!   * ns_name_pton returns -1 on error, 1 if the name is fully qualified
//!     (unescaped trailing dot), 0 otherwise — NOT the wire byte count.
//!   * ns_name_ntop returns the text length INCLUDING the NUL terminator.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type PtonFn = extern "C" fn(*const c_char, *mut u8, usize) -> c_int;
type NtopFn = extern "C" fn(*const u8, *mut c_char, usize) -> c_int;

#[test]
fn ns_name_pton_ntop_match_glibc() {
    let (g_pton, g_ntop): (PtonFn, NtopFn) = unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen libc.so.6 failed");
        let p = dlsym(lib, c"ns_name_pton".as_ptr());
        let n = dlsym(lib, c"ns_name_ntop".as_ptr());
        assert!(!p.is_null() && !n.is_null(), "dlsym ns_name_* failed");
        (
            std::mem::transmute::<*mut c_void, PtonFn>(p),
            std::mem::transmute::<*mut c_void, NtopFn>(n),
        )
    };

    let names: &[&str] = &[
        "www.example.com",
        "example.com.",
        "a.b",
        "a.b.",
        ".",
        "com.",
        "single",
        "single.",
        "foo\\046bar.com", // \DDD escape for '.'
        "host\\255.net",   // \DDD non-printable
        "x\\.",            // escaped trailing dot -> not FQDN
        "x\\\\.",          // escaped backslash then real dot -> FQDN
        "sub.domain.example.org",
        "a.very.long.multi.label.name.example.test.",
        "UPPER.Case.Domain",
    ];

    let mut mismatches = Vec::new();

    for &name in names {
        let cn = CString::new(name).unwrap();

        // ---- pton: compare rc and the wire bytes written.
        let mut gw = [0u8; 256];
        let mut fw = [0u8; 256];
        let grc = g_pton(cn.as_ptr(), gw.as_mut_ptr(), gw.len());
        let frc =
            unsafe { fl::ns_name_pton(cn.as_ptr(), fw.as_mut_ptr() as *mut c_void, fw.len()) };
        if grc != frc {
            mismatches.push(format!("ns_name_pton({name:?}) rc: glibc={grc} fl={frc}"));
        }
        if grc >= 0 && frc >= 0 && gw != fw {
            mismatches.push(format!(
                "ns_name_pton({name:?}) wire differs:\n  glibc={:02x?}\n  fl   ={:02x?}",
                &gw[..wire_len(&gw)],
                &fw[..wire_len(&fw)]
            ));
        }

        // ---- ntop: feed glibc's wire encoding to both and compare rc + text.
        if grc >= 0 {
            let mut gt = [0u8; 1024];
            let mut ft = [0u8; 1024];
            let grc2 = g_ntop(gw.as_ptr(), gt.as_mut_ptr() as *mut c_char, gt.len());
            let frc2 = unsafe {
                fl::ns_name_ntop(
                    gw.as_ptr() as *const c_void,
                    ft.as_mut_ptr() as *mut c_char,
                    ft.len(),
                )
            };
            if grc2 != frc2 {
                mismatches.push(format!("ns_name_ntop({name:?}) rc: glibc={grc2} fl={frc2}"));
            }
            if grc2 >= 0 && frc2 >= 0 {
                let gs = cstr_text(&gt);
                let fs = cstr_text(&ft);
                if gs != fs {
                    mismatches.push(format!(
                        "ns_name_ntop({name:?}) text: glibc={:?} fl={:?}",
                        String::from_utf8_lossy(&gs),
                        String::from_utf8_lossy(&fs)
                    ));
                }
            }
        }
    }

    assert!(
        mismatches.is_empty(),
        "ns_name_pton/ntop diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

// Length of an uncompressed wire name (through and including the root 0 byte).
fn wire_len(w: &[u8]) -> usize {
    let mut i = 0;
    while i < w.len() {
        let l = w[i] as usize;
        if l == 0 {
            return i + 1;
        }
        i += 1 + l;
    }
    w.len()
}

fn cstr_text(buf: &[u8]) -> Vec<u8> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf[..end].to_vec()
}
