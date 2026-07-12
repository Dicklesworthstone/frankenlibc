#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc gettext oracle

//! Differential coverage for gettext passthrough on unknown domains.
//!
//! With no catalog for the domain, glibc returns the original msgid/msgid_plural
//! pointers. FrankenLibC intentionally implements the same untranslated
//! fallback for these ABI exports.

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{CStr, c_char, c_int, c_ulong};

unsafe extern "C" {
    fn dcgettext(domainname: *const c_char, msgid: *const c_char, category: c_int) -> *mut c_char;
    fn dcngettext(
        domainname: *const c_char,
        msgid: *const c_char,
        msgid_plural: *const c_char,
        n: c_ulong,
        category: c_int,
    ) -> *mut c_char;
    fn dngettext(
        domainname: *const c_char,
        msgid: *const c_char,
        msgid_plural: *const c_char,
        n: c_ulong,
    ) -> *mut c_char;
}

fn text(ptr: *const c_char) -> Vec<u8> {
    assert!(!ptr.is_null(), "gettext function returned NULL");
    unsafe { CStr::from_ptr(ptr).to_bytes().to_vec() }
}

#[test]
fn gettext_unknown_domain_matches_host_passthrough() {
    let domain = c"frankenlibc-missing-domain-for-diff";
    let singular = c"frankenlibc singular sentinel";
    let plural = c"frankenlibc plural sentinel";

    let host_dc = unsafe { dcgettext(domain.as_ptr(), singular.as_ptr(), libc::LC_MESSAGES) };
    let fl_dc = unsafe { fl::dcgettext(domain.as_ptr(), singular.as_ptr(), libc::LC_MESSAGES) };
    assert_eq!(text(fl_dc), text(host_dc), "dcgettext unknown domain");
    assert_eq!(text(fl_dc), singular.to_bytes());

    let host_dcn_one = unsafe {
        dcngettext(
            domain.as_ptr(),
            singular.as_ptr(),
            plural.as_ptr(),
            1,
            libc::LC_MESSAGES,
        )
    };
    let fl_dcn_one = unsafe {
        fl::dcngettext(
            domain.as_ptr(),
            singular.as_ptr(),
            plural.as_ptr(),
            1,
            libc::LC_MESSAGES,
        )
    };
    assert_eq!(text(fl_dcn_one), text(host_dcn_one), "dcngettext n=1");
    assert_eq!(text(fl_dcn_one), singular.to_bytes());

    let host_dcn_many = unsafe {
        dcngettext(
            domain.as_ptr(),
            singular.as_ptr(),
            plural.as_ptr(),
            2,
            libc::LC_MESSAGES,
        )
    };
    let fl_dcn_many = unsafe {
        fl::dcngettext(
            domain.as_ptr(),
            singular.as_ptr(),
            plural.as_ptr(),
            2,
            libc::LC_MESSAGES,
        )
    };
    assert_eq!(text(fl_dcn_many), text(host_dcn_many), "dcngettext n=2");
    assert_eq!(text(fl_dcn_many), plural.to_bytes());

    let host_dn_one = unsafe { dngettext(domain.as_ptr(), singular.as_ptr(), plural.as_ptr(), 1) };
    let fl_dn_one =
        unsafe { fl::dngettext(domain.as_ptr(), singular.as_ptr(), plural.as_ptr(), 1) };
    assert_eq!(text(fl_dn_one), text(host_dn_one), "dngettext n=1");
    assert_eq!(text(fl_dn_one), singular.to_bytes());

    let host_dn_many = unsafe { dngettext(domain.as_ptr(), singular.as_ptr(), plural.as_ptr(), 2) };
    let fl_dn_many =
        unsafe { fl::dngettext(domain.as_ptr(), singular.as_ptr(), plural.as_ptr(), 2) };
    assert_eq!(text(fl_dn_many), text(host_dn_many), "dngettext n=2");
    assert_eq!(text(fl_dn_many), plural.to_bytes());
}
