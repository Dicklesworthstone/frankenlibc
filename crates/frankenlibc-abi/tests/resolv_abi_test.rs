use std::ffi::CString;
use std::ptr;

use frankenlibc_abi::inet_abi;
use frankenlibc_abi::resolv_abi;

const NO_RECOVERY_ERRNO: i32 = 3;
const HOST_NOT_FOUND_ERRNO: i32 = 1;

#[test]
fn gethostbyname_numeric_ipv4_returns_hostent() {
    let query = CString::new("127.0.0.1").expect("query should be valid C string");
    let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
    assert!(!ptr.is_null());

    let hostent = unsafe { &*(ptr as *const libc::hostent) };
    assert_eq!(hostent.h_addrtype, libc::AF_INET);
    assert_eq!(hostent.h_length, 4);
    assert!(!hostent.h_addr_list.is_null());

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    assert!(!first_addr_ptr.is_null());
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [127, 0, 0, 1]);
}

#[test]
fn gethostbyname_unknown_host_returns_null() {
    let query = CString::new("missing.example.invalid").expect("query should be valid C string");
    let ptr = unsafe { resolv_abi::gethostbyname(query.as_ptr()) };
    assert!(ptr.is_null());
}

#[test]
fn gethostbyname_r_numeric_ipv4_populates_result() {
    let query = CString::new("10.20.30.40").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
    let mut scratch = [0i8; 256];
    let mut result_ptr: *mut libc::c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<libc::c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, 0);
    assert_eq!(h_errno, 0);
    assert_eq!(
        result_ptr,
        (&mut hostent as *mut libc::hostent).cast::<libc::c_void>()
    );
    assert_eq!(hostent.h_addrtype, libc::AF_INET);
    assert_eq!(hostent.h_length, 4);
    assert!(!hostent.h_addr_list.is_null());

    let first_addr_ptr = unsafe { *hostent.h_addr_list };
    assert!(!first_addr_ptr.is_null());
    let octets = unsafe { std::slice::from_raw_parts(first_addr_ptr.cast::<u8>(), 4) };
    assert_eq!(octets, [10, 20, 30, 40]);
}

#[test]
fn gethostbyname_r_small_buffer_returns_erange() {
    let query = CString::new("127.0.0.1").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
    let mut scratch = [0i8; 4];
    let mut result_ptr: *mut libc::c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<libc::c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::ERANGE);
    assert!(result_ptr.is_null());
    assert_eq!(h_errno, NO_RECOVERY_ERRNO);
}

#[test]
fn gethostbyname_r_unknown_host_returns_enoent() {
    let query = CString::new("missing.example.invalid").expect("query should be valid C string");
    let mut hostent: libc::hostent = unsafe { std::mem::zeroed() };
    let mut scratch = [0i8; 256];
    let mut result_ptr: *mut libc::c_void = ptr::null_mut();
    let mut h_errno = -1;

    let rc = unsafe {
        inet_abi::gethostbyname_r(
            query.as_ptr(),
            (&mut hostent as *mut libc::hostent).cast::<libc::c_void>(),
            scratch.as_mut_ptr(),
            scratch.len(),
            &mut result_ptr,
            &mut h_errno,
        )
    };
    assert_eq!(rc, libc::ENOENT);
    assert!(result_ptr.is_null());
    assert_eq!(h_errno, HOST_NOT_FOUND_ERRNO);
}
