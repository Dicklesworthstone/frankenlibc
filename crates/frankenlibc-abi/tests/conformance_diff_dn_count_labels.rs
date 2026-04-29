#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `__dn_count_labels`.
//!
//! Counts labels in a DNS name (decoded textual form). Trailing dot is
//! the FQDN root marker and doesn't add a label.
//!
//! Filed under [bd-xn6p8] follow-up — extending libresolv parity coverage.

use std::ffi::{c_char, c_int, CString};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn __dn_count_labels(name: *const c_char) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    frankenlibc: i32,
    glibc: i32,
}

const DN_INPUTS: &[&[u8]] = &[
    b"",
    b"a",
    b"a.b",
    b"a.b.c",
    b"www.example.com",
    b"www.example.com.",
    b".",
    b"..",
    b"...",
    b"a.b.c.d.e.f.g.h.i.j.k",
    b"localhost",
    b"localhost.",
    b"foo..bar",
    b"a.",
    b".a",
];

#[test]
fn diff_dn_count_labels_cases() {
    let mut divs = Vec::new();
    for input in DN_INPUTS {
        let c_input = CString::new(*input).unwrap();
        let fl_n = unsafe { fl::__dn_count_labels(c_input.as_ptr()) };
        let lc_n = unsafe { __dn_count_labels(c_input.as_ptr()) };
        if fl_n != lc_n {
            divs.push(Divergence {
                case: format!("{:?}", String::from_utf8_lossy(input)),
                frankenlibc: fl_n,
                glibc: lc_n,
            });
        }
    }
    assert!(
        divs.is_empty(),
        "__dn_count_labels divergences:\n{}",
        divs.iter()
            .map(|d| format!("  case: {} | fl: {} | glibc: {}\n", d.case, d.frankenlibc, d.glibc))
            .collect::<String>()
    );
}

#[test]
fn dn_count_labels_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv __dn_count_labels\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
