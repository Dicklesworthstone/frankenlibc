#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Live host-glibc differential coverage for DNS label predicates.
//!
//! These predicates are consumed before resolver queries are assembled, so
//! boundary labels must follow the host contract exactly rather than merely
//! accepting the common alphanumeric cases.

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

unsafe extern "C" {
    fn res_dnok(name: *const c_char) -> c_int;
    fn res_hnok(name: *const c_char) -> c_int;
}

#[test]
fn resolver_label_boundaries_match_glibc() {
    for raw in [
        "",
        "-bad.example",
        "bad-.example",
        "example.com.",
        "two..dots",
        "_service._tcp.example",
    ] {
        let name = CString::new(raw).unwrap();
        let fl_hnok = unsafe { fl::res_hnok(name.as_ptr()) };
        let host_hnok = unsafe { res_hnok(name.as_ptr()) };
        let fl_dnok = unsafe { fl::res_dnok(name.as_ptr()) };
        let host_dnok = unsafe { res_dnok(name.as_ptr()) };
        assert_eq!(fl_hnok, host_hnok, "res_hnok({raw:?})");
        assert_eq!(fl_dnok, host_dnok, "res_dnok({raw:?})");
    }
}
