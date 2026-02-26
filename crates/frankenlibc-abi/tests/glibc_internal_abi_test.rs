#![cfg(target_os = "linux")]

//! Integration tests for glibc_internal_abi entrypoints.

use frankenlibc_abi::glibc_internal_abi::{
    iruserok, iruserok_af, parse_printf_format, rcmd, rcmd_af, rexec, rexec_af, res_dnok,
    res_hnok, res_mailok, res_ownok, ruserok, ruserok_af, ruserpass,
};
use std::ffi::CString;
use std::ptr;

// ===========================================================================
// DNS name validators
// ===========================================================================

#[test]
fn res_hnok_accepts_valid_hostnames() {
    let valid = CString::new("example.com").unwrap();
    assert_eq!(unsafe { res_hnok(valid.as_ptr()) }, 1);

    let with_hyphen = CString::new("my-host.example.com").unwrap();
    assert_eq!(unsafe { res_hnok(with_hyphen.as_ptr()) }, 1);

    let single = CString::new("localhost").unwrap();
    assert_eq!(unsafe { res_hnok(single.as_ptr()) }, 1);
}

#[test]
fn res_hnok_rejects_invalid_hostnames() {
    let underscore = CString::new("bad_host.com").unwrap();
    assert_eq!(unsafe { res_hnok(underscore.as_ptr()) }, 0);

    let space = CString::new("bad host").unwrap();
    assert_eq!(unsafe { res_hnok(space.as_ptr()) }, 0);

    assert_eq!(unsafe { res_hnok(ptr::null()) }, 0);
}

#[test]
fn res_dnok_accepts_underscores() {
    let with_underscore = CString::new("_sip._tcp.example.com").unwrap();
    assert_eq!(unsafe { res_dnok(with_underscore.as_ptr()) }, 1);

    let normal = CString::new("example.com").unwrap();
    assert_eq!(unsafe { res_dnok(normal.as_ptr()) }, 1);
}

#[test]
fn res_mailok_accepts_mailbox_label() {
    // res_mailok allows more chars in first label (mailbox part) but NOT '@'
    // In DNS mail notation, user.example.com represents user@example.com
    let maildom = CString::new("user.example.com").unwrap();
    assert_eq!(unsafe { res_mailok(maildom.as_ptr()) }, 1);

    // First label can contain chars that hostnames can't (like +, etc.)
    let plus = CString::new("user+tag.example.com").unwrap();
    assert_eq!(unsafe { res_mailok(plus.as_ptr()) }, 1);
}

#[test]
fn res_ownok_delegates_to_dnok() {
    let valid = CString::new("_srv.example.com").unwrap();
    assert_eq!(unsafe { res_ownok(valid.as_ptr()) }, 1);

    let invalid = CString::new("bad name").unwrap();
    assert_eq!(unsafe { res_ownok(invalid.as_ptr()) }, 0);
}

// ===========================================================================
// parse_printf_format
// ===========================================================================

const PA_INT: i32 = 1;
const PA_CHAR: i32 = 2;
const PA_STRING: i32 = 4;
const PA_POINTER: i32 = 6;
const PA_DOUBLE: i32 = 8;
const PA_FLAG_LONG: i32 = 0x100;
const PA_FLAG_LONG_LONG: i32 = 0x200;

#[test]
fn parse_printf_format_simple_types() {
    let fmt = CString::new("%d %s %f %p").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    assert_eq!(count, 4);
    assert_eq!(types[0], PA_INT);
    assert_eq!(types[1], PA_STRING);
    assert_eq!(types[2], PA_DOUBLE);
    assert_eq!(types[3], PA_POINTER);
}

#[test]
fn parse_printf_format_length_modifiers() {
    let fmt = CString::new("%ld %lld %hd %c").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    assert_eq!(count, 4);
    assert_eq!(types[0], PA_INT | PA_FLAG_LONG);
    assert_eq!(types[1], PA_INT | PA_FLAG_LONG_LONG);
    assert_eq!(types[2], PA_INT | 0x400); // PA_FLAG_SHORT
    assert_eq!(types[3], PA_CHAR);
}

#[test]
fn parse_printf_format_star_width_and_precision() {
    let fmt = CString::new("%*.*f").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    // star width → int, star precision → int, then double
    assert_eq!(count, 3);
    assert_eq!(types[0], PA_INT);
    assert_eq!(types[1], PA_INT);
    assert_eq!(types[2], PA_DOUBLE);
}

#[test]
fn parse_printf_format_percent_literal_not_counted() {
    let fmt = CString::new("100%% done %d").unwrap();
    let mut types = [0i32; 8];
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 8, types.as_mut_ptr()) };
    assert_eq!(count, 1);
    assert_eq!(types[0], PA_INT);
}

#[test]
fn parse_printf_format_null_argtypes_just_counts() {
    let fmt = CString::new("%d %s %f").unwrap();
    let count = unsafe { parse_printf_format(fmt.as_ptr(), 0, ptr::null_mut()) };
    assert_eq!(count, 3);
}

#[test]
fn parse_printf_format_null_fmt_returns_zero() {
    let count = unsafe { parse_printf_format(ptr::null(), 0, ptr::null_mut()) };
    assert_eq!(count, 0);
}

// ===========================================================================
// Security deny stubs: rcmd/rexec/ruserok/iruserok/ruserpass
// ===========================================================================

#[test]
fn iruserok_always_denies() {
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let result = unsafe { iruserok(0x7f000001, 0, ruser.as_ptr(), user.as_ptr()) };
    assert_eq!(result, -1, "iruserok should deny all .rhosts auth");
}

#[test]
fn iruserok_af_always_denies() {
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let addr: u32 = 0x7f000001;
    let result = unsafe {
        iruserok_af(
            &addr as *const u32 as *const std::ffi::c_void,
            0,
            ruser.as_ptr(),
            user.as_ptr(),
            libc::AF_INET,
        )
    };
    assert_eq!(result, -1);
}

#[test]
fn ruserok_always_denies() {
    let host = CString::new("attacker.example.com").unwrap();
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let result = unsafe { ruserok(host.as_ptr(), 0, ruser.as_ptr(), user.as_ptr()) };
    assert_eq!(result, -1);
}

#[test]
fn ruserok_af_always_denies() {
    let host = CString::new("attacker.example.com").unwrap();
    let user = CString::new("root").unwrap();
    let ruser = CString::new("attacker").unwrap();
    let result = unsafe { ruserok_af(host.as_ptr(), 0, ruser.as_ptr(), user.as_ptr(), libc::AF_INET) };
    assert_eq!(result, -1);
}

#[test]
fn rcmd_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe { rcmd(&mut host_ptr, 514, user.as_ptr(), user.as_ptr(), cmd.as_ptr(), ptr::null_mut()) };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
}

#[test]
fn rcmd_af_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe {
        rcmd_af(&mut host_ptr, 514, user.as_ptr(), user.as_ptr(), cmd.as_ptr(), ptr::null_mut(), libc::AF_INET)
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
}

#[test]
fn rexec_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let pass = CString::new("pass").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe { rexec(&mut host_ptr, 512, user.as_ptr(), pass.as_ptr(), cmd.as_ptr(), ptr::null_mut()) };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
}

#[test]
fn rexec_af_returns_enosys() {
    let host = CString::new("target.example.com").unwrap();
    let mut host_ptr = host.as_ptr() as *mut libc::c_char;
    let user = CString::new("user").unwrap();
    let pass = CString::new("pass").unwrap();
    let cmd = CString::new("id").unwrap();
    let result = unsafe {
        rexec_af(&mut host_ptr, 512, user.as_ptr(), pass.as_ptr(), cmd.as_ptr(), ptr::null_mut(), libc::AF_INET)
    };
    assert_eq!(result, -1);
    assert_eq!(unsafe { *libc::__errno_location() }, libc::ENOSYS);
}

#[test]
fn ruserpass_returns_error_with_null_credentials() {
    let host = CString::new("example.com").unwrap();
    let mut name_ptr: *const libc::c_char = ptr::null();
    let mut pass_ptr: *const libc::c_char = ptr::null();
    let result = unsafe { ruserpass(host.as_ptr(), &mut name_ptr, &mut pass_ptr) };
    assert_eq!(result, -1);
    assert!(name_ptr.is_null(), "ruserpass should not set name");
    assert!(pass_ptr.is_null(), "ruserpass should not set pass");
}

