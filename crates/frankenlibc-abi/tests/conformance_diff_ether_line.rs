//! Differential gate: ether_line must match glibc byte-for-byte.
//!
//! ether_line parses one /etc/ethers-format line into a 6-byte address plus a
//! hostname and is fully file-independent, so it can be compared directly
//! against the live host glibc (reached via dlsym to bypass fl's no_mangle
//! interposition).
//!
//! fl previously diverged on two realistic cases: it skipped leading
//! whitespace (glibc rejects such a line) and it did not honor inline '#'
//! comments in the hostname field (glibc terminates the hostname at '#' and
//! rejects a comment-only hostname).
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as flu;
use std::ffi::{CString, c_char, c_int, c_void};

const RTLD_NOW: c_int = 2;

unsafe extern "C" {
    fn dlopen(filename: *const c_char, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}
type EtherLineFn = extern "C" fn(*const c_char, *mut u8, *mut c_char) -> c_int;

#[test]
fn ether_line_matches_glibc() {
    let g_ether_line: EtherLineFn = unsafe {
        let lib = dlopen(c"libc.so.6".as_ptr(), RTLD_NOW);
        assert!(!lib.is_null(), "dlopen libc.so.6 failed");
        let sym = dlsym(lib, c"ether_line".as_ptr());
        assert!(!sym.is_null(), "dlsym ether_line failed");
        std::mem::transmute::<*mut c_void, EtherLineFn>(sym)
    };

    let cases: &[&str] = &[
        "1:2:3:4:5:6 host",
        "01:23:45:67:89:ab myhost",
        "  08:00:20:0a:8c:6d leading-ws",
        "\t08:00:20:0a:8c:6d tab-leading",
        "08:00:20:0a:8c:6d\thosttab",
        "08:00:20:0a:8c:6d host # comment",
        "08:00:20:0a:8c:6d host#nocomment",
        "08:00:20:0a:8c:6d #onlycomment",
        "08:00:20:0a:8c:6d\t#tabcomment",
        "08:00:20:0a:8c:6d   manyspaces",
        "08:00:20:0a:8c:6d",
        "08:00:20:0a:8c:6d   ",
        "0:0:0:0:0:0 zero",
        "aa:bb:cc:dd:ee:ff UPPER",
        "Aa:bB:Cc:dD:eE:fF mixedcase",
        "# full comment line",
        "08:00:20:0a:8c host5only",
        "08-00-20-0a-8c-6d dashsep",
        "01:23:45:67:89:ab host with spaces",
        "01:23:45:67:89:ab host\twith\ttabs",
        "",
        "   ",
        "not-a-mac host",
        "1:2:3:4:5:6g host",
        "01:23:45:67:89:ab host.example.com",
        "ff:ff:ff:ff:ff:ff broadcast",
    ];

    let mut mismatches = Vec::new();
    for &case in cases {
        let cl = CString::new(case).unwrap();

        let mut g_addr = [0u8; 6];
        let mut g_host = [0u8; 256];
        let g_rc = g_ether_line(cl.as_ptr(), g_addr.as_mut_ptr(), g_host.as_mut_ptr() as *mut c_char);

        let mut f_addr = [0u8; 6];
        let mut f_host = [0u8; 256];
        let f_rc = unsafe {
            flu::ether_line(
                cl.as_ptr(),
                f_addr.as_mut_ptr() as *mut c_void,
                f_host.as_mut_ptr() as *mut c_char,
            )
        };

        // On failure, only the return code is contractually defined; the
        // address/hostname buffers are scratch. On success, compare fully.
        let g_norm = (g_rc, if g_rc == 0 { g_addr } else { [0; 6] }, if g_rc == 0 { hostname(&g_host) } else { Vec::new() });
        let f_norm = (f_rc.signum(), if f_rc == 0 { f_addr } else { [0; 6] }, if f_rc == 0 { hostname(&f_host) } else { Vec::new() });
        // glibc returns -1; fl returns -1 too — normalize glibc rc sign as well.
        let g_norm = (g_norm.0.signum(), g_norm.1, g_norm.2);

        if g_norm != f_norm {
            mismatches.push(format!(
                "{case:?}: glibc=(rc={},addr={:x?},host={:?}) fl=(rc={},addr={:x?},host={:?})",
                g_rc, g_norm.1, String::from_utf8_lossy(&g_norm.2),
                f_rc, f_norm.1, String::from_utf8_lossy(&f_norm.2),
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "ether_line diverged from glibc ({} cases):\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}

fn hostname(buf: &[u8]) -> Vec<u8> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    buf[..end].to_vec()
}
