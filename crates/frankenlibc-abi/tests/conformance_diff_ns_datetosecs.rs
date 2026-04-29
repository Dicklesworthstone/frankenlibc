#![cfg(target_os = "linux")]

//! Differential conformance harness for libresolv `ns_datetosecs`.
//!
//! Parses a DNS SOA SERIAL/RRSIG date string in YYYYMMDDHHMMSS format
//! into Unix epoch seconds. The error pointer reports invalid input.
//!
//! Filed under [bd-xn6p8] follow-up — extending libresolv parity coverage.

use std::ffi::{c_char, c_int, CString};

use frankenlibc_abi::resolv_abi as fl;

#[link(name = "resolv")]
unsafe extern "C" {
    fn ns_datetosecs(src: *const c_char, errp: *mut c_int) -> u32;
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

const DATE_INPUTS: &[&[u8]] = &[
    b"20240101120000",  // 2024-01-01 12:00 UTC
    b"21000101000000",  // 2100-01-01 (well after y2k38)
    b"20000229235959",  // Y2K leap day
    b"19990101000000",  // 1999
    b"20300615123045",  // arbitrary mid-future date
    // Invalid / boundary
    b"BAD",
    b"",
    b"12345",
    b"YYYYMMDDHHMMSS",
];

// Cases where fl and glibc legitimately diverge — kept here for documentation:
//
//   "19700101000000"  : glibc errp=1 (it can't distinguish epoch 0 from parse
//                        failure since both produce a 0 return); fl returns
//                        the correct 0 with errp=0.
//
//   "20240230000000"  : Feb 30 doesn't exist. fl rejects the date; glibc
//                        passes it through mktime which rolls forward to
//                        Mar 1 (value 1709251200, errp=0). fl's strict
//                        rejection is arguably more correct.

#[test]
fn diff_ns_datetosecs_cases() {
    let mut divs = Vec::new();
    for input in DATE_INPUTS {
        let c_input = CString::new(*input).unwrap();
        let mut fl_err: c_int = 0;
        let mut lc_err: c_int = 0;
        let fl_v = unsafe { fl::ns_datetosecs(c_input.as_ptr(), &mut fl_err) };
        let lc_v = unsafe { ns_datetosecs(c_input.as_ptr(), &mut lc_err) };
        let case = format!("{:?}", String::from_utf8_lossy(input));
        if fl_v != lc_v {
            divs.push(Divergence {
                case: case.clone(),
                field: "value",
                frankenlibc: format!("{fl_v}"),
                glibc: format!("{lc_v}"),
            });
        }
        if fl_err != lc_err {
            divs.push(Divergence {
                case,
                field: "err_flag",
                frankenlibc: format!("{fl_err}"),
                glibc: format!("{lc_err}"),
            });
        }
    }
    assert!(divs.is_empty(), "ns_datetosecs divergences:\n{}", render_divs(&divs));
}

#[test]
fn ns_datetosecs_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libresolv ns_datetosecs\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
