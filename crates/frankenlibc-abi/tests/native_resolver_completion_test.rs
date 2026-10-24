//! Direct calls to FrankenLibC's Rust ABI implementation, not host libresolv.
//! The C probes separately check exported-symbol ownership and caller buffers.

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::resolv_abi::{CNsMsg, CNsRr, ns_initparse, ns_parserr};
use std::ffi::CStr;
use std::ptr;

fn message(answers: u16) -> Vec<u8> {
    let mut bytes = vec![0x12, 0x34, 0x81, 0x80, 0, 1];
    bytes.extend_from_slice(&answers.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(b"\x04host\x04test\0\0\x01\0\x01");
    for index in 0..answers {
        bytes.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        bytes.extend_from_slice(&(60 + u32::from(index)).to_be_bytes());
        bytes.extend_from_slice(&[0, 4, 192, 0, 2, index as u8]);
    }
    bytes
}

fn handle(bytes: &[u8]) -> CNsMsg {
    // SAFETY: all-zero integers/pointers are valid in this C-compatible struct.
    let mut handle: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { ns_initparse(bytes.as_ptr(), bytes.len() as i32, &mut handle) }, 0);
    assert_eq!((handle._sect, handle._rrnum), (4, -1));
    assert!(handle._msg_ptr.is_null());
    handle
}

fn record() -> CNsRr {
    CNsRr {
        name: [0; 1025],
        _type: 0,
        rr_class: 0,
        ttl: 0,
        rdlength: 0,
        rdata: ptr::null(),
    }
}

fn cursor(handle: &CNsMsg) -> (i32, i32, *const u8) {
    (handle._sect, handle._rrnum, handle._msg_ptr)
}

fn answer(handle: &mut CNsMsg, requested: i32, expected: i32) {
    let mut rr = record();
    assert_eq!(unsafe { ns_parserr(handle, 1, requested, &mut rr) }, 0);
    assert_eq!(unsafe { CStr::from_ptr(rr.name.as_ptr()) }.to_bytes(), b"host.test");
    assert_eq!((rr._type, rr.rr_class, rr.ttl, rr.rdlength), (1, 1, 60 + expected as u32, 4));
    assert_eq!(unsafe { std::slice::from_raw_parts(rr.rdata, 4) }, [192, 0, 2, expected as u8]);
    assert_eq!((handle._sect, handle._rrnum), (1, expected + 1));
    assert_eq!(handle._msg_ptr, unsafe { rr.rdata.add(4) });
}

#[test]
fn sequential_iteration_and_indexed_seeks_share_next_record_cursor() {
    let bytes = message(4);
    let mut h = handle(&bytes);
    answer(&mut h, -1, 0);
    answer(&mut h, -1, 1);
    answer(&mut h, 0, 0);
    answer(&mut h, -1, 1);
    answer(&mut h, 3, 3);
    answer(&mut h, 2, 2);
    answer(&mut h, -1, 3);
}

#[test]
fn changing_sections_restarts_iteration_and_question_has_no_rdata() {
    let bytes = message(2);
    let mut h = handle(&bytes);
    answer(&mut h, 1, 1);
    let mut rr = record();
    assert_eq!(unsafe { ns_parserr(&mut h, 0, -1, &mut rr) }, 0);
    assert_eq!((rr._type, rr.rr_class, rr.ttl, rr.rdlength), (1, 1, 0, 0));
    assert!(rr.rdata.is_null());
    assert_eq!(h._msg_ptr, h._sections[1]);
    answer(&mut h, -1, 0);
    assert!(h._sections[2].is_null());
    assert!(h._sections[3].is_null());
}

#[test]
fn exhausted_and_full_width_invalid_indices_fail_without_losing_cursor() {
    let bytes = message(1);
    let mut h = handle(&bytes);
    answer(&mut h, -1, 0);
    let saved = cursor(&h);
    let mut rr = record();
    for (section, index) in [(1, -1), (1, 1), (1, 65536), (1, i32::MAX),
        (1, -2), (1, i32::MIN), (4, 0), (-1, 0), (2, -1)] {
        unsafe { *__errno_location() = 0 };
        assert_eq!(unsafe { ns_parserr(&mut h, section, index, &mut rr) }, -1);
        assert_eq!(unsafe { *__errno_location() }, libc::ENODEV);
        assert_eq!(cursor(&h), saved);
    }
    answer(&mut h, 0, 0);
}

#[test]
fn truncated_frames_and_trailing_bytes_never_publish_a_handle() {
    let mut bytes = message(3);
    for length in 0..bytes.len() {
        let mut h: CNsMsg = unsafe { std::mem::zeroed() };
        h._id = 0xbeef;
        assert_eq!(unsafe { ns_initparse(bytes.as_ptr(), length as i32, &mut h) }, -1);
        assert_eq!(unsafe { *__errno_location() }, libc::EMSGSIZE);
        assert_eq!(h._id, 0xbeef);
        assert!(h._msg.is_null());
    }
    bytes.push(0);
    let mut h: CNsMsg = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { ns_initparse(bytes.as_ptr(), bytes.len() as i32, &mut h) }, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EMSGSIZE);
    assert!(h._msg.is_null());
}

#[test]
fn malformed_compressed_owner_does_not_publish_a_partial_record() {
    let mut bytes = message(2);
    let mut h = handle(&bytes);
    answer(&mut h, -1, 0);
    let offset = h._msg_ptr as usize - bytes.as_ptr() as usize;
    bytes[offset] = 0xc0 | (offset >> 8) as u8;
    bytes[offset + 1] = offset as u8; // A self-referential compression pointer.
    let saved = cursor(&h);
    let mut rr = record();
    rr.name.fill(42);
    rr.ttl = 0xdeadbeef;
    rr.rdlength = 123;
    assert_eq!(unsafe { ns_parserr(&mut h, 1, -1, &mut rr) }, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EMSGSIZE);
    assert!(rr.name.iter().all(|&value| value == 42));
    assert_eq!((rr.ttl, rr.rdlength), (0xdeadbeef, 123));
    assert!(rr.rdata.is_null());
    assert_eq!(cursor(&h), saved);
    bytes[offset] = 0xc0;
    bytes[offset + 1] = 12;
    answer(&mut h, -1, 1);
}

#[test]
fn payload_bounds_are_rechecked_after_initialization() {
    let mut bytes = message(1);
    let mut h = handle(&bytes);
    let start = h._sections[1] as usize - bytes.as_ptr() as usize;
    bytes[start + 10..start + 12].copy_from_slice(&u16::MAX.to_be_bytes());
    let saved = cursor(&h);
    let mut rr = record();
    rr.ttl = 77;
    assert_eq!(unsafe { ns_parserr(&mut h, 1, 0, &mut rr) }, -1);
    assert_eq!(unsafe { *__errno_location() }, libc::EMSGSIZE);
    assert_eq!(rr.ttl, 77);
    assert_eq!(cursor(&h), saved);
}

#[test]
fn separate_handles_keep_independent_iteration_state() {
    let bytes = message(3);
    let mut first = handle(&bytes);
    let mut second = handle(&bytes);
    answer(&mut first, -1, 0);
    answer(&mut first, -1, 1);
    answer(&mut second, -1, 0);
    answer(&mut first, -1, 2);
    answer(&mut second, -1, 1);
}

#[test]
fn large_sections_support_both_sequential_and_explicit_iteration() {
    let bytes = message(2048);
    let mut h = handle(&bytes);
    for index in 0..2048 {
        answer(&mut h, -1, index);
    }
    for index in 0..2048 {
        answer(&mut h, index, index);
    }
}
