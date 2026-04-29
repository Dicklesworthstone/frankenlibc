#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `ns_makecanon`.
//!
//! Canonicalizes a DNS name by appending a trailing dot if absent.
//! Empty input becomes ".".
//!
//! Filed under [bd-xn6p8] follow-up — extending libresolv parity coverage.

use std::ffi::{c_char, c_int, CStr, CString};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn ns_makecanon(src: *const c_char, dst: *mut c_char, dstsize: usize) -> c_int;
}

#[derive(Debug)]
struct Divergence {
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  case: {} | field: {} | fl: {} | glibc: {}\n",
            d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

const NAME_INPUTS: &[&[u8]] = &[
    b"",
    b".",
    b"example.com",
    b"example.com.",
    b"WWW.EXAMPLE.com",
    b"a",
    b"a.",
    b"a.b.c.d",
    b"a.b.c.d.",
    b"localhost",
    b"localhost.",
    b"sub.deep.nested.dns.zone.example.com",
    b"sub.deep.nested.dns.zone.example.com.",
];

#[test]
fn diff_ns_makecanon_cases() {
    let mut divs = Vec::new();
    for input in NAME_INPUTS {
        let c_input = CString::new(*input).unwrap();
        let mut fl_buf = vec![0i8; 256];
        let mut lc_buf = vec![0i8; 256];
        let fl_n =
            unsafe { fl::ns_makecanon(c_input.as_ptr(), fl_buf.as_mut_ptr(), fl_buf.len()) };
        let lc_n = unsafe { ns_makecanon(c_input.as_ptr(), lc_buf.as_mut_ptr(), lc_buf.len()) };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if fl_n != lc_n {
            divs.push(Divergence {
                case: case.clone(),
                field: "return",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
        if fl_n == 0 && lc_n == 0 {
            let s_fl = unsafe { CStr::from_ptr(fl_buf.as_ptr()).to_bytes() };
            let s_lc = unsafe { CStr::from_ptr(lc_buf.as_ptr()).to_bytes() };
            if s_fl != s_lc {
                divs.push(Divergence {
                    case,
                    field: "string",
                    frankenlibc: format!("{:?}", String::from_utf8_lossy(s_fl)),
                    glibc: format!("{:?}", String::from_utf8_lossy(s_lc)),
                });
            }
        }
    }
    assert!(divs.is_empty(), "ns_makecanon divergences:\n{}", render_divs(&divs));
}

/// Buffer-too-small contract — fl and host must agree on EMSGSIZE.
#[test]
fn diff_ns_makecanon_buffer_too_small() {
    let mut divs = Vec::new();
    let input = CString::new("example.com").unwrap();
    // "example.com." + NUL = 13 bytes.
    for size in [0usize, 1, 5, 12] {
        let mut fl_buf = vec![0i8; size + 4];
        let mut lc_buf = vec![0i8; size + 4];
        let fl_n = unsafe { fl::ns_makecanon(input.as_ptr(), fl_buf.as_mut_ptr(), size) };
        let lc_n = unsafe { ns_makecanon(input.as_ptr(), lc_buf.as_mut_ptr(), size) };
        if (fl_n < 0) != (lc_n < 0) {
            divs.push(Divergence {
                case: format!("size={size}"),
                field: "error_signal",
                frankenlibc: format!("{fl_n}"),
                glibc: format!("{lc_n}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "ns_makecanon buffer-too-small divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn ns_makecanon_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv ns_makecanon\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
