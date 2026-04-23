#![cfg(target_os = "linux")]
#![allow(non_camel_case_types)]

//! Integration tests for the 68 native XDR symbols in rpc_abi.rs.
//!
//! Tests cover:
//! - Memory stream creation and encode/decode round-trips
//! - Primitive type serializers (int, uint, bool, char, short, long, hyper, float, double, enum)
//! - Fixed-width type serializers (int8_t, uint8_t, int16_t, uint16_t, int32_t, uint32_t, int64_t, uint64_t)
//! - 64-bit aliases (longlong_t, u_longlong_t, quad_t, u_quad_t)
//! - Composite serializers (opaque, bytes, string, wrapstring, array, vector, pointer, reference, netobj)
//! - Utility functions (xdr_void, xdr_free, xdr_sizeof)
//! - Stream backends (xdrrec_create, xdrstdio_create)
//! - RPC type serializers (opaque_auth, pmap, des_block, keybuf, keystatus)

use std::ffi::{c_char, c_int, c_uint, c_void};

type c_ulong = u64;
type c_long = i64;

use frankenlibc_abi::rpc_abi::*;

// XDR operation constants
const XDR_ENCODE: c_int = 0;
const XDR_DECODE: c_int = 1;
const XDR_FREE: c_int = 2;

// Size of struct Xdr on LP64 (x86_64):
// x_op(4) + pad(4) + x_ops(8) + x_public(8) + x_private(8) + x_base(8) + x_handy(4) + pad(4)
// = 48 bytes. Must be 8-byte aligned for pointer fields.
const XDR_SIZE: usize = 48;

/// 8-byte-aligned XDR handle storage. The struct Xdr contains pointer fields
/// that require proper alignment on LP64.
#[repr(C, align(8))]
struct XdrHandle {
    data: [u8; XDR_SIZE],
}

impl XdrHandle {
    fn new() -> Self {
        Self {
            data: [0u8; XDR_SIZE],
        }
    }

    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.data.as_mut_ptr().cast()
    }

    /// Read the x_op field (offset 0, c_int).
    fn x_op(&self) -> c_int {
        i32::from_ne_bytes(self.data[0..4].try_into().unwrap())
    }

    /// Read the x_ops pointer field (offset 8, 8 bytes on LP64).
    fn x_ops_raw(&self) -> usize {
        usize::from_ne_bytes(self.data[8..16].try_into().unwrap())
    }

    /// Read the x_private pointer field (offset 24, 8 bytes on LP64).
    /// Layout: x_op(0..4) + pad(4..8) + x_ops(8..16) + x_public(16..24) + x_private(24..32)
    fn x_private_raw(&self) -> usize {
        usize::from_ne_bytes(self.data[24..32].try_into().unwrap())
    }
}

/// Helper: create a memory XDR stream in encode mode over the given buffer.
fn xdr_encode(xdr: &mut XdrHandle, buf: &mut [u8]) {
    unsafe {
        xdrmem_create(
            xdr.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len() as c_uint,
            XDR_ENCODE,
        );
    }
}

/// Helper: create a memory XDR stream in decode mode over the given buffer.
fn xdr_decode(xdr: &mut XdrHandle, buf: &mut [u8]) {
    unsafe {
        xdrmem_create(
            xdr.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len() as c_uint,
            XDR_DECODE,
        );
    }
}

// ===========================================================================
// 1. Memory stream basics
// ===========================================================================

#[test]
fn xdrmem_create_initializes_handle() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();
    xdr_encode(&mut xdr, &mut buf);

    // x_op at offset 0 should be XDR_ENCODE (0)
    let op = xdr.x_op();
    assert_eq!(op, XDR_ENCODE);
}

#[test]
fn xdrmem_create_decode_mode() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();
    xdr_decode(&mut xdr, &mut buf);

    let op = xdr.x_op();
    assert_eq!(op, XDR_DECODE);
}

// ===========================================================================
// 2. Primitive types: 32-bit round-trips
// ===========================================================================

#[test]
fn xdr_int_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    // Encode
    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 42;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut val) }, 1);

    // Decode
    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 0;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 42);
}

#[test]
fn xdr_int_negative() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = -12345;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 0;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -12345);
}

#[test]
fn xdr_int_boundary_values() {
    for &val in &[0i32, 1, -1, i32::MAX, i32::MIN] {
        let mut buf = [0u8; 128];
        let mut xdr = XdrHandle::new();

        xdr_encode(&mut xdr, &mut buf);
        let mut v = val;
        assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut v) }, 1);

        xdr_decode(&mut xdr, &mut buf);
        let mut out: c_int = 0;
        assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut out) }, 1);
        assert_eq!(out, val, "xdr_int round-trip failed for {val}");
    }
}

#[test]
fn xdr_u_int_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_uint = 0xDEADBEEF;
    assert_eq!(unsafe { xdr_u_int(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_uint = 0;
    assert_eq!(unsafe { xdr_u_int(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0xDEADBEEF);
}

#[test]
fn xdr_int32_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i32 = -999999;
    assert_eq!(unsafe { xdr_int32_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i32 = 0;
    assert_eq!(unsafe { xdr_int32_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -999999);
}

#[test]
fn xdr_uint32_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u32 = u32::MAX;
    assert_eq!(unsafe { xdr_uint32_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u32 = 0;
    assert_eq!(unsafe { xdr_uint32_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, u32::MAX);
}

#[test]
fn xdr_enum_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 7; // arbitrary enum value
    assert_eq!(unsafe { xdr_enum(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 0;
    assert_eq!(unsafe { xdr_enum(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 7);
}

// ===========================================================================
// 3. Bool
// ===========================================================================

#[test]
fn xdr_bool_true_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 1;
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 99;
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 1);
}

#[test]
fn xdr_bool_false_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 0;
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 99;
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0);
}

#[test]
fn xdr_bool_normalizes_nonzero_to_one() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    // Encoding a non-zero value should normalize to 1
    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 42; // non-zero but not 1
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 99;
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 1, "Non-zero booleans should decode as 1");
}

// ===========================================================================
// 4. Narrowing types (char, short, int8/16/uint8/16)
// ===========================================================================

#[test]
fn xdr_char_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_char = b'A' as c_char;
    assert_eq!(unsafe { xdr_char(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_char = 0;
    assert_eq!(unsafe { xdr_char(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, b'A' as c_char);
}

#[test]
fn xdr_short_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i16 = -32000;
    assert_eq!(unsafe { xdr_short(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i16 = 0;
    assert_eq!(unsafe { xdr_short(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -32000);
}

#[test]
fn xdr_u_short_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u16 = 65535;
    assert_eq!(unsafe { xdr_u_short(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u16 = 0;
    assert_eq!(unsafe { xdr_u_short(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 65535);
}

#[test]
fn xdr_u_char_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u8 = 0xFF;
    assert_eq!(unsafe { xdr_u_char(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u8 = 0;
    assert_eq!(unsafe { xdr_u_char(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0xFF);
}

#[test]
fn xdr_int8_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i8 = -128;
    assert_eq!(unsafe { xdr_int8_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i8 = 0;
    assert_eq!(unsafe { xdr_int8_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -128);
}

#[test]
fn xdr_uint8_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u8 = 200;
    assert_eq!(unsafe { xdr_uint8_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u8 = 0;
    assert_eq!(unsafe { xdr_uint8_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 200);
}

#[test]
fn xdr_int16_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i16 = i16::MIN;
    assert_eq!(unsafe { xdr_int16_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i16 = 0;
    assert_eq!(unsafe { xdr_int16_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, i16::MIN);
}

#[test]
fn xdr_uint16_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u16 = 12345;
    assert_eq!(unsafe { xdr_uint16_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u16 = 0;
    assert_eq!(unsafe { xdr_uint16_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 12345);
}

// ===========================================================================
// 5. Long types (64-bit C long -> 32-bit XDR)
// ===========================================================================

#[test]
fn xdr_long_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_long = 123456;
    assert_eq!(unsafe { xdr_long(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_long = 0;
    assert_eq!(unsafe { xdr_long(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 123456);
}

#[test]
fn xdr_u_long_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_ulong = 0xCAFEBABE;
    assert_eq!(unsafe { xdr_u_long(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_ulong = 0;
    assert_eq!(unsafe { xdr_u_long(xdr.as_mut_ptr(), &mut out) }, 1);
    // Note: xdr_u_long truncates to 32 bits on wire
    assert_eq!(out as u32, 0xCAFEBABE_u32);
}

// ===========================================================================
// 6. 64-bit types (hyper, u_hyper, int64_t, uint64_t, aliases)
// ===========================================================================

#[test]
fn xdr_hyper_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = 0x0123456789ABCDEF_i64;
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i64 = 0;
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0x0123456789ABCDEF_i64);
}

#[test]
fn xdr_hyper_negative() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = -0x7FFFFFFFFFFFFFFF;
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i64 = 0;
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -0x7FFFFFFFFFFFFFFF);
}

#[test]
fn xdr_u_hyper_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u64 = u64::MAX;
    assert_eq!(unsafe { xdr_u_hyper(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u64 = 0;
    assert_eq!(unsafe { xdr_u_hyper(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, u64::MAX);
}

#[test]
fn xdr_int64_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = i64::MIN;
    assert_eq!(unsafe { xdr_int64_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i64 = 0;
    assert_eq!(unsafe { xdr_int64_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, i64::MIN);
}

#[test]
fn xdr_uint64_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u64 = 0xFEDCBA9876543210;
    assert_eq!(unsafe { xdr_uint64_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u64 = 0;
    assert_eq!(unsafe { xdr_uint64_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0xFEDCBA9876543210);
}

#[test]
fn xdr_longlong_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = -9999999999;
    assert_eq!(unsafe { xdr_longlong_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i64 = 0;
    assert_eq!(unsafe { xdr_longlong_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -9999999999);
}

#[test]
fn xdr_quad_aliases_roundtrip() {
    // quad_t and u_quad_t are aliases for hyper/u_hyper
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = 0x1122334455667788;
    assert_eq!(unsafe { xdr_quad_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: i64 = 0;
    assert_eq!(unsafe { xdr_quad_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0x1122334455667788);
}

// ===========================================================================
// 7. Float and double (IEEE 754 via XDR)
// ===========================================================================

#[test]
fn xdr_float_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: f32 = 1.5;
    assert_eq!(unsafe { xdr_float(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: f32 = 0.0;
    assert_eq!(unsafe { xdr_float(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 1.5);
}

#[test]
fn xdr_float_negative() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: f32 = -123.456;
    assert_eq!(unsafe { xdr_float(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: f32 = 0.0;
    assert_eq!(unsafe { xdr_float(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, -123.456_f32);
}

#[test]
fn xdr_double_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: f64 = std::f64::consts::E;
    assert_eq!(unsafe { xdr_double(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: f64 = 0.0;
    assert_eq!(unsafe { xdr_double(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, std::f64::consts::E);
}

#[test]
fn xdr_double_large() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: f64 = f64::MAX;
    assert_eq!(unsafe { xdr_double(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: f64 = 0.0;
    assert_eq!(unsafe { xdr_double(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, f64::MAX);
}

// ===========================================================================
// 8. Multiple values in sequence
// ===========================================================================

#[test]
fn xdr_multiple_values_sequence() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // Encode: int, bool, short, hyper
    xdr_encode(&mut xdr, &mut buf);
    let mut i_val: c_int = 100;
    let mut b_val: c_int = 1;
    let mut s_val: i16 = -500;
    let mut h_val: i64 = 0xDEADCAFE12345678_u64 as i64;

    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut i_val) }, 1);
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut b_val) }, 1);
    assert_eq!(unsafe { xdr_short(xdr.as_mut_ptr(), &mut s_val) }, 1);
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut h_val) }, 1);

    // Decode all in same order
    xdr_decode(&mut xdr, &mut buf);
    let mut io: c_int = 0;
    let mut bo: c_int = 0;
    let mut so: i16 = 0;
    let mut ho: i64 = 0;

    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut io) }, 1);
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut bo) }, 1);
    assert_eq!(unsafe { xdr_short(xdr.as_mut_ptr(), &mut so) }, 1);
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut ho) }, 1);

    assert_eq!(io, 100);
    assert_eq!(bo, 1);
    assert_eq!(so, -500);
    assert_eq!(ho, 0xDEADCAFE12345678_u64 as i64);
}

// ===========================================================================
// 9. Buffer overflow protection
// ===========================================================================

#[test]
fn xdr_int_fails_on_insufficient_buffer() {
    let mut buf = [0u8; 2]; // only 2 bytes, need 4
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 42;
    let rc = unsafe { xdr_int(xdr.as_mut_ptr(), &mut val) };
    assert_eq!(rc, 0, "Should fail with insufficient buffer");
}

#[test]
fn xdr_hyper_fails_on_insufficient_buffer() {
    let mut buf = [0u8; 4]; // only 4 bytes, need 8
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = 42;
    let rc = unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut val) };
    assert_eq!(rc, 0, "Should fail with insufficient buffer for hyper");
}

// ===========================================================================
// 10. Big-endian wire format verification
// ===========================================================================

#[test]
fn xdr_int_big_endian_wire_format() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: c_int = 0x01020304;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut val) }, 1);

    // XDR is big-endian: MSB first
    assert_eq!(buf[0], 0x01);
    assert_eq!(buf[1], 0x02);
    assert_eq!(buf[2], 0x03);
    assert_eq!(buf[3], 0x04);
}

#[test]
fn xdr_hyper_big_endian_wire_format() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: i64 = 0x0102030405060708_i64;
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut val) }, 1);

    // High word first, then low word, each in big-endian
    assert_eq!(buf[0], 0x01);
    assert_eq!(buf[1], 0x02);
    assert_eq!(buf[2], 0x03);
    assert_eq!(buf[3], 0x04);
    assert_eq!(buf[4], 0x05);
    assert_eq!(buf[5], 0x06);
    assert_eq!(buf[6], 0x07);
    assert_eq!(buf[7], 0x08);
}

// ===========================================================================
// 11. Composite types: xdr_opaque
// ===========================================================================

#[test]
fn xdr_opaque_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    let data = b"Hello!"; // 6 bytes -> padded to 8

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), data.as_ptr() as *mut c_char, 6,) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = [0u8; 6];
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), out.as_mut_ptr().cast(), 6,) },
        1
    );
    assert_eq!(&out, b"Hello!");
}

#[test]
fn xdr_opaque_empty() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), std::ptr::null_mut(), 0) },
        1
    );
}

#[test]
fn xdr_opaque_padding_is_zero() {
    let mut buf = [0xFFu8; 128]; // fill with 0xFF to detect zero padding
    let mut xdr = XdrHandle::new();

    let data = [0xAA_u8; 5]; // 5 bytes -> 3 bytes padding to reach 8

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), data.as_ptr() as *mut c_char, 5,) },
        1
    );

    // Bytes 5, 6, 7 should be zero-padded
    assert_eq!(buf[5], 0);
    assert_eq!(buf[6], 0);
    assert_eq!(buf[7], 0);
}

// ===========================================================================
// 12. Composite types: xdr_bytes
// ===========================================================================

#[test]
fn xdr_bytes_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // Encode
    let src = b"Test data";
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;
    let mut len: c_uint = 9;

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_bytes(xdr.as_mut_ptr(), &mut src_ptr, &mut len, 256,) },
        1
    );

    // Decode
    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    let mut out_len: c_uint = 0;
    assert_eq!(
        unsafe { xdr_bytes(xdr.as_mut_ptr(), &mut out_ptr, &mut out_len, 256,) },
        1
    );
    assert_eq!(out_len, 9);
    assert!(!out_ptr.is_null());

    let decoded = unsafe { std::slice::from_raw_parts(out_ptr as *const u8, out_len as usize) };
    assert_eq!(decoded, b"Test data");

    // Free the allocated buffer
    unsafe { libc::free(out_ptr.cast()) };
}

#[test]
fn xdr_bytes_exceeds_max_returns_false() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let src = b"data";
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;
    let mut len: c_uint = 4;

    xdr_encode(&mut xdr, &mut buf);
    // maxsize = 2, but we're encoding 4 bytes
    let rc = unsafe { xdr_bytes(xdr.as_mut_ptr(), &mut src_ptr, &mut len, 2) };
    assert_eq!(rc, 0, "Should fail when len > maxsize");
}

// ===========================================================================
// 13. Composite types: xdr_string / xdr_wrapstring
// ===========================================================================

#[test]
fn xdr_string_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let src = std::ffi::CString::new("hello world").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_string(xdr.as_mut_ptr(), &mut src_ptr, 256) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe { xdr_string(xdr.as_mut_ptr(), &mut out_ptr, 256) },
        1
    );
    assert!(!out_ptr.is_null());

    let decoded = unsafe { std::ffi::CStr::from_ptr(out_ptr) }
        .to_str()
        .unwrap();
    assert_eq!(decoded, "hello world");

    unsafe { libc::free(out_ptr.cast()) };
}

#[test]
fn xdr_wrapstring_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let src = std::ffi::CString::new("wraptest").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(unsafe { xdr_wrapstring(xdr.as_mut_ptr(), &mut src_ptr) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    assert_eq!(unsafe { xdr_wrapstring(xdr.as_mut_ptr(), &mut out_ptr) }, 1);
    assert!(!out_ptr.is_null());

    let decoded = unsafe { std::ffi::CStr::from_ptr(out_ptr) }
        .to_str()
        .unwrap();
    assert_eq!(decoded, "wraptest");

    unsafe { libc::free(out_ptr.cast()) };
}

#[test]
fn xdr_string_exceeds_max() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let src = std::ffi::CString::new("toolong").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    // maxsize=3, but "toolong" is 7 characters
    let rc = unsafe { xdr_string(xdr.as_mut_ptr(), &mut src_ptr, 3) };
    assert_eq!(rc, 0, "String exceeding maxsize should fail");
}

// ===========================================================================
// 14. Composite types: xdr_vector (fixed-length array)
// ===========================================================================

#[test]
fn xdr_vector_int_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let mut arr: [c_int; 4] = [10, 20, 30, 40];

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe {
            xdr_vector(
                xdr.as_mut_ptr(),
                arr.as_mut_ptr().cast(),
                4,
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out: [c_int; 4] = [0; 4];
    assert_eq!(
        unsafe {
            xdr_vector(
                xdr.as_mut_ptr(),
                out.as_mut_ptr().cast(),
                4,
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );
    assert_eq!(out, [10, 20, 30, 40]);
}

// ===========================================================================
// 15. Composite types: xdr_array (variable-length array)
// ===========================================================================

#[test]
fn xdr_array_int_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let mut arr: [c_int; 3] = [100, 200, 300];
    let mut arr_ptr: *mut c_char = arr.as_mut_ptr().cast();
    let mut count: c_uint = 3;

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe {
            xdr_array(
                xdr.as_mut_ptr(),
                &mut arr_ptr,
                &mut count,
                10, // maxsize
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );

    // Decode into a freshly allocated array
    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    let mut out_count: c_uint = 0;
    assert_eq!(
        unsafe {
            xdr_array(
                xdr.as_mut_ptr(),
                &mut out_ptr,
                &mut out_count,
                10,
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );
    assert_eq!(out_count, 3);
    assert!(!out_ptr.is_null());

    let decoded = unsafe { std::slice::from_raw_parts(out_ptr as *const c_int, 3) };
    assert_eq!(decoded, &[100, 200, 300]);

    unsafe { libc::free(out_ptr.cast()) };
}

// ===========================================================================
// 16. Composite types: xdr_pointer / xdr_reference
// ===========================================================================

#[test]
fn xdr_pointer_present_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let mut val: c_int = 42;
    let mut ptr: *mut c_char = (&mut val as *mut c_int).cast();

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe {
            xdr_pointer(
                xdr.as_mut_ptr(),
                (&mut ptr as *mut *mut c_char).cast(),
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );

    // Decode
    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            xdr_pointer(
                xdr.as_mut_ptr(),
                (&mut out_ptr as *mut *mut c_char).cast(),
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );
    assert!(!out_ptr.is_null());

    let decoded = unsafe { *(out_ptr as *const c_int) };
    assert_eq!(decoded, 42);

    unsafe { libc::free(out_ptr.cast()) };
}

#[test]
fn xdr_pointer_null_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let mut ptr: *mut c_char = std::ptr::null_mut();

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe {
            xdr_pointer(
                xdr.as_mut_ptr(),
                (&mut ptr as *mut *mut c_char).cast(),
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );

    // Decode: should get null back
    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::dangling_mut::<c_char>(); // non-null sentinel
    assert_eq!(
        unsafe {
            xdr_pointer(
                xdr.as_mut_ptr(),
                (&mut out_ptr as *mut *mut c_char).cast(),
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );
    assert!(out_ptr.is_null(), "Null pointer should decode as null");
}

#[test]
fn xdr_reference_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let mut val: c_int = 77;
    let mut ptr: *mut c_char = (&mut val as *mut c_int).cast();

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe {
            xdr_reference(
                xdr.as_mut_ptr(),
                &mut ptr,
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            xdr_reference(
                xdr.as_mut_ptr(),
                &mut out_ptr,
                std::mem::size_of::<c_int>() as c_uint,
                xdr_int as *mut c_void,
            )
        },
        1
    );
    assert!(!out_ptr.is_null());

    let decoded = unsafe { *(out_ptr as *const c_int) };
    assert_eq!(decoded, 77);

    unsafe { libc::free(out_ptr.cast()) };
}

// ===========================================================================
// 17. Composite types: xdr_netobj
// ===========================================================================

#[test]
fn xdr_netobj_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // netobj layout on LP64: { u32 n_len; [4 pad]; char *n_bytes; } = 16 bytes
    #[repr(C)]
    struct NetObj {
        n_len: c_uint,
        _pad: c_uint,
        n_bytes: *mut c_char,
    }

    let data = b"netobj_data";
    let mut src = NetObj {
        n_len: 11,
        _pad: 0,
        n_bytes: data.as_ptr() as *mut c_char,
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_netobj(xdr.as_mut_ptr(), (&mut src as *mut NetObj).cast(),) },
        1
    );

    // Decode
    xdr_decode(&mut xdr, &mut buf);
    let mut out = NetObj {
        n_len: 0,
        _pad: 0,
        n_bytes: std::ptr::null_mut(),
    };
    assert_eq!(
        unsafe { xdr_netobj(xdr.as_mut_ptr(), (&mut out as *mut NetObj).cast(),) },
        1
    );

    assert_eq!(out.n_len, 11);
    assert!(!out.n_bytes.is_null());

    let decoded = unsafe { std::slice::from_raw_parts(out.n_bytes as *const u8, 11) };
    assert_eq!(decoded, b"netobj_data");

    unsafe { libc::free(out.n_bytes.cast()) };
}

// ===========================================================================
// 18. Utilities: xdr_void, xdr_free, xdr_sizeof
// ===========================================================================

#[test]
fn xdr_void_always_true() {
    assert_eq!(unsafe { xdr_void() }, 1);
}

#[test]
fn xdr_free_on_string() {
    // Encode a string, decode to get allocated memory, then free with xdr_free
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let src_str = std::ffi::CString::new("free_test").unwrap();
    let mut str_ptr: *mut c_char = src_str.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    unsafe {
        xdr_wrapstring(xdr.as_mut_ptr(), &mut str_ptr);
    }

    xdr_decode(&mut xdr, &mut buf);
    let mut decoded_ptr: *mut c_char = std::ptr::null_mut();
    unsafe {
        xdr_wrapstring(xdr.as_mut_ptr(), &mut decoded_ptr);
    }
    assert!(!decoded_ptr.is_null());

    // xdr_free calls the proc in FREE mode, which should free decoded_ptr
    // Note: xdr_free takes (proc, objp) where objp points to the *mut c_char
    unsafe {
        xdr_free(
            xdr_wrapstring as *mut c_void,
            (&mut decoded_ptr as *mut *mut c_char).cast(),
        );
    }
    // After free, the pointer should be set to null by xdr_string in FREE mode
    assert!(
        decoded_ptr.is_null(),
        "xdr_free should null out the pointer"
    );
}

#[test]
fn xdr_sizeof_int() {
    let mut val: c_int = 42;
    let size = unsafe { xdr_sizeof(xdr_int as *mut c_void, (&mut val as *mut c_int).cast()) };
    assert_eq!(size, 4, "xdr_sizeof(xdr_int) should be 4");
}

#[test]
fn xdr_sizeof_hyper() {
    let mut val: i64 = 42;
    let size = unsafe { xdr_sizeof(xdr_hyper as *mut c_void, (&mut val as *mut i64).cast()) };
    assert_eq!(size, 8, "xdr_sizeof(xdr_hyper) should be 8");
}

#[test]
fn xdr_sizeof_bool() {
    let mut val: c_int = 1;
    let size = unsafe { xdr_sizeof(xdr_bool as *mut c_void, (&mut val as *mut c_int).cast()) };
    assert_eq!(size, 4, "xdr_sizeof(xdr_bool) should be 4");
}

// ===========================================================================
// 19. Stream backends: xdrstdio_create (basic smoke test)
// ===========================================================================

#[test]
fn xdrstdio_create_initializes_handle() {
    let mut xdr = XdrHandle::new();

    // Create a tmpfile for the stdio stream
    let f = unsafe { libc::tmpfile() };
    assert!(!f.is_null(), "tmpfile failed");

    // Create stdio XDR stream in ENCODE mode
    unsafe {
        xdrstdio_create(xdr.as_mut_ptr(), f.cast(), XDR_ENCODE);
    }

    // x_op at offset 0 should be XDR_ENCODE (0)
    let op = xdr.x_op();
    assert_eq!(op, XDR_ENCODE);

    // Encode an int
    let mut val: c_int = 99;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut val) }, 1);

    // Rewind and decode
    unsafe {
        libc::fseek(f.cast(), 0, libc::SEEK_SET);
        xdrstdio_create(xdr.as_mut_ptr(), f.cast(), XDR_DECODE);
    }

    let mut out: c_int = 0;
    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 99);

    unsafe {
        libc::fclose(f.cast());
    }
}

// ===========================================================================
// 20. Stream backends: xdrrec_create (basic smoke test)
// ===========================================================================

#[test]
fn xdrrec_create_initializes_handle() {
    let mut xdr = XdrHandle::new();

    // Create with null I/O callbacks (just verify initialization)
    unsafe {
        xdrrec_create(
            xdr.as_mut_ptr(),
            0, // sendsize (0 = default 4096)
            0, // recvsize (0 = default 4096)
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }

    // x_ops should be non-null (pointing to XDRREC_OPS)
    let ops_ptr = xdr.x_ops_raw();
    assert_ne!(ops_ptr, 0, "x_ops should be set after xdrrec_create");

    // Clean up: the record stream allocates buffers via malloc
    // x_private at offset 16 points to RecStream
    let private_ptr = xdr.x_private_raw();
    assert_ne!(private_ptr, 0, "x_private should be set (RecStream)");

    // We can't easily destroy without the destroy function pointer, but the
    // Xdr handle has a vtable. Let's just verify it was created successfully.
    // The destroy function will be called by Drop of the test, or we can
    // manually call it through the vtable.
}

// ===========================================================================
// 21. RPC type serializers: xdr_opaque_auth
// ===========================================================================

#[test]
fn xdr_opaque_auth_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    // OpaqueAuth layout: { oa_flavor: c_int, [4pad], oa_base: *mut c_char, oa_length: c_uint, [4pad] }
    #[repr(C)]
    struct OpaqueAuth {
        oa_flavor: c_int,
        _pad: c_int,
        oa_base: *mut c_char,
        oa_length: c_uint,
        _pad2: c_uint,
    }

    let auth_data = b"auth";
    let mut auth = OpaqueAuth {
        oa_flavor: 1, // AUTH_UNIX
        _pad: 0,
        oa_base: auth_data.as_ptr() as *mut c_char,
        oa_length: 4,
        _pad2: 0,
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_opaque_auth(xdr.as_mut_ptr(), (&mut auth as *mut OpaqueAuth).cast(),) },
        1
    );

    // Decode into fresh struct
    xdr_decode(&mut xdr, &mut buf);
    let mut out_auth = OpaqueAuth {
        oa_flavor: 0,
        _pad: 0,
        oa_base: std::ptr::null_mut(),
        oa_length: 0,
        _pad2: 0,
    };
    assert_eq!(
        unsafe { xdr_opaque_auth(xdr.as_mut_ptr(), (&mut out_auth as *mut OpaqueAuth).cast(),) },
        1
    );

    assert_eq!(out_auth.oa_flavor, 1);
    assert_eq!(out_auth.oa_length, 4);
    assert!(!out_auth.oa_base.is_null());

    let decoded = unsafe { std::slice::from_raw_parts(out_auth.oa_base as *const u8, 4) };
    assert_eq!(decoded, b"auth");

    unsafe { libc::free(out_auth.oa_base.cast()) };
}

// ===========================================================================
// 22. RPC type serializers: xdr_pmap
// ===========================================================================

#[test]
fn xdr_pmap_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // Pmap: { pm_prog: c_ulong, pm_vers: c_ulong, pm_prot: c_ulong, pm_port: c_ulong }
    // = 32 bytes on LP64
    #[repr(C)]
    struct Pmap {
        pm_prog: c_ulong,
        pm_vers: c_ulong,
        pm_prot: c_ulong,
        pm_port: c_ulong,
    }

    let mut pmap = Pmap {
        pm_prog: 100000, // portmapper
        pm_vers: 2,
        pm_prot: 17, // UDP
        pm_port: 111,
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_pmap(xdr.as_mut_ptr(), (&mut pmap as *mut Pmap).cast(),) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = Pmap {
        pm_prog: 0,
        pm_vers: 0,
        pm_prot: 0,
        pm_port: 0,
    };
    assert_eq!(
        unsafe { xdr_pmap(xdr.as_mut_ptr(), (&mut out as *mut Pmap).cast(),) },
        1
    );
    // Note: xdr_u_long truncates to 32 bits, so we compare the lower 32 bits
    assert_eq!(out.pm_prog as u32, 100000);
    assert_eq!(out.pm_vers as u32, 2);
    assert_eq!(out.pm_prot as u32, 17);
    assert_eq!(out.pm_port as u32, 111);
}

// ===========================================================================
// 23. RPC type serializers: xdr_des_block
// ===========================================================================

#[test]
fn xdr_des_block_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    let mut block = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_des_block(xdr.as_mut_ptr(), block.as_mut_ptr().cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = [0u8; 8];
    assert_eq!(
        unsafe { xdr_des_block(xdr.as_mut_ptr(), out.as_mut_ptr().cast()) },
        1
    );
    assert_eq!(out, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
}

// ===========================================================================
// 24. RPC type serializers: xdr_keybuf
// ===========================================================================

#[test]
fn xdr_keybuf_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // HEXKEYBYTES = 144
    let mut keybuf = [0xABu8; 144];

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_keybuf(xdr.as_mut_ptr(), keybuf.as_mut_ptr().cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = [0u8; 144];
    assert_eq!(
        unsafe { xdr_keybuf(xdr.as_mut_ptr(), out.as_mut_ptr().cast()) },
        1
    );
    assert_eq!(out, [0xAB; 144]);
}

// ===========================================================================
// 25. RPC type serializers: xdr_keystatus
// ===========================================================================

#[test]
fn xdr_keystatus_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    let mut status: c_int = 3; // KEY_SYSTEMERR or similar

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_keystatus(xdr.as_mut_ptr(), (&mut status as *mut c_int).cast(),) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out: c_int = 0;
    assert_eq!(
        unsafe { xdr_keystatus(xdr.as_mut_ptr(), (&mut out as *mut c_int).cast(),) },
        1
    );
    assert_eq!(out, 3);
}

// ===========================================================================
// 26. xdr_authdes_verf round-trip
// ===========================================================================

#[test]
fn xdr_authdes_verf_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    // DES verifier: timestamp(8 bytes) + nickname(4 bytes) = 12 bytes
    let mut verf = [0u8; 12];
    verf[0..4].copy_from_slice(&1000_u32.to_ne_bytes()); // timestamp_sec
    verf[4..8].copy_from_slice(&500_u32.to_ne_bytes()); // timestamp_usec
    verf[8..12].copy_from_slice(&42_u32.to_ne_bytes()); // nickname

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_authdes_verf(xdr.as_mut_ptr(), verf.as_mut_ptr().cast(),) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = [0u8; 12];
    assert_eq!(
        unsafe { xdr_authdes_verf(xdr.as_mut_ptr(), out.as_mut_ptr().cast(),) },
        1
    );
    assert_eq!(out, verf);
}

// ===========================================================================
// 27. FREE mode tests
// ===========================================================================

#[test]
fn xdr_int_free_mode_is_noop() {
    let mut xdr = XdrHandle::new();
    let mut buf = [0u8; 16];

    // Create a FREE-mode XDR handle
    unsafe {
        xdrmem_create(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 16, XDR_FREE);
    }

    let mut val: c_int = 42;
    // FREE mode should return TRUE without modifying anything
    let rc = unsafe { xdr_int(xdr.as_mut_ptr(), &mut val) };
    assert_eq!(rc, 1, "xdr_int in FREE mode should return TRUE");
    assert_eq!(val, 42, "Value should be unchanged in FREE mode");
}

#[test]
fn xdr_string_free_mode_frees_memory() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // Encode a string
    let src = std::ffi::CString::new("free_me_string").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    unsafe {
        xdr_wrapstring(xdr.as_mut_ptr(), &mut src_ptr);
    }

    // Decode to get allocated memory
    xdr_decode(&mut xdr, &mut buf);
    let mut alloc_ptr: *mut c_char = std::ptr::null_mut();
    unsafe {
        xdr_wrapstring(xdr.as_mut_ptr(), &mut alloc_ptr);
    }
    assert!(!alloc_ptr.is_null());

    // Now free via xdr_string in FREE mode
    unsafe {
        xdrmem_create(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 256, XDR_FREE);
        xdr_wrapstring(xdr.as_mut_ptr(), &mut alloc_ptr);
    }
    assert!(
        alloc_ptr.is_null(),
        "xdr_string FREE should null out the pointer"
    );
}

// ===========================================================================
// 28. Stdio stream encode/decode multiple values
// ===========================================================================

#[test]
fn xdrstdio_multiple_values() {
    let mut xdr = XdrHandle::new();
    let f = unsafe { libc::tmpfile() };
    assert!(!f.is_null());

    // Encode multiple types
    unsafe {
        xdrstdio_create(xdr.as_mut_ptr(), f.cast(), XDR_ENCODE);
    }

    let mut i_val: c_int = 12345;
    let mut h_val: i64 = 0xAAAABBBBCCCCDDDD_u64 as i64;
    let mut b_val: c_int = 1;

    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut i_val) }, 1);
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut h_val) }, 1);
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut b_val) }, 1);

    // Rewind and decode
    unsafe {
        libc::fseek(f.cast(), 0, libc::SEEK_SET);
        xdrstdio_create(xdr.as_mut_ptr(), f.cast(), XDR_DECODE);
    }

    let mut io: c_int = 0;
    let mut ho: i64 = 0;
    let mut bo: c_int = 0;

    assert_eq!(unsafe { xdr_int(xdr.as_mut_ptr(), &mut io) }, 1);
    assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut ho) }, 1);
    assert_eq!(unsafe { xdr_bool(xdr.as_mut_ptr(), &mut bo) }, 1);

    assert_eq!(io, 12345);
    assert_eq!(ho, 0xAAAABBBBCCCCDDDD_u64 as i64);
    assert_eq!(bo, 1);

    unsafe {
        libc::fclose(f.cast());
    }
}

// ===========================================================================
// 29. xdr_sizeof for composite types
// ===========================================================================

#[test]
fn xdr_sizeof_opaque() {
    // xdr_opaque encodes `cnt` bytes with padding to 4-byte boundary
    // 5 bytes -> 5 + 3 pad = 8 bytes on wire
    // But xdr_sizeof works with the counting backend that just tracks putbytes/putint32
    // xdr_opaque writes: putbytes(cnt) + putbytes(pad)
    // For xdr_sizeof, we need a function that takes (xdrs, data) and calls xdr_opaque.
    // Since xdr_opaque takes (xdrs, cp, cnt) which doesn't match XdrProc, we
    // test with xdr_des_block which takes (xdrs, blkp) -> xdr_opaque(xdrs, blkp, 8)
    let mut block = [0u8; 8];
    let size = unsafe { xdr_sizeof(xdr_des_block as *mut c_void, block.as_mut_ptr().cast()) };
    assert_eq!(size, 8, "xdr_sizeof(xdr_des_block) should be 8");
}

// ===========================================================================
// 30. xdr_u_longlong_t and xdr_u_quad_t aliases
// ===========================================================================

#[test]
fn xdr_u_longlong_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u64 = 0x1234567890ABCDEF;
    assert_eq!(unsafe { xdr_u_longlong_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u64 = 0;
    assert_eq!(unsafe { xdr_u_longlong_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0x1234567890ABCDEF);
}

#[test]
fn xdr_u_quad_t_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: u64 = 0xFEDCBA9876543210;
    assert_eq!(unsafe { xdr_u_quad_t(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: u64 = 0;
    assert_eq!(unsafe { xdr_u_quad_t(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0xFEDCBA9876543210);
}

// ===========================================================================
// 31. xdr_unixcred round-trip
// ===========================================================================

#[test]
fn xdr_unixcred_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // UnixCred layout: { uid: u32, gid: u32, gidlen: i16, [6pad], gids: *mut u32 }
    // On x86_64 this is ~24 bytes due to pointer alignment.
    // For encoding with gidlen=0, no gids array needed.
    #[repr(C)]
    struct UnixCred {
        uid: u32,
        gid: u32,
        gidlen: i16,
        _pad: [u8; 6],
        gids: *mut u32,
    }

    let mut cred = UnixCred {
        uid: 1000,
        gid: 1000,
        gidlen: 0,
        _pad: [0; 6],
        gids: std::ptr::null_mut(),
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_unixcred(xdr.as_mut_ptr(), (&mut cred as *mut UnixCred).cast(),) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = UnixCred {
        uid: 0,
        gid: 0,
        gidlen: 0,
        _pad: [0; 6],
        gids: std::ptr::null_mut(),
    };
    assert_eq!(
        unsafe { xdr_unixcred(xdr.as_mut_ptr(), (&mut out as *mut UnixCred).cast(),) },
        1
    );
    assert_eq!(out.uid, 1000);
    assert_eq!(out.gid, 1000);
    assert_eq!(out.gidlen, 0);
}

// ===========================================================================
// 32. xdr_netnamestr round-trip
// ===========================================================================

#[test]
fn xdr_netnamestr_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let src = std::ffi::CString::new("unix.1000@localhost").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_netnamestr(xdr.as_mut_ptr(), (&mut src_ptr as *mut *mut c_char).cast(),) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe { xdr_netnamestr(xdr.as_mut_ptr(), (&mut out_ptr as *mut *mut c_char).cast(),) },
        1
    );
    assert!(!out_ptr.is_null());

    let decoded = unsafe { std::ffi::CStr::from_ptr(out_ptr) }
        .to_str()
        .unwrap();
    assert_eq!(decoded, "unix.1000@localhost");

    unsafe { libc::free(out_ptr.cast()) };
}

// ===========================================================================
// 33. xdr_cryptkeyres round-trip
// ===========================================================================

#[test]
fn xdr_cryptkeyres_roundtrip() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    // cryptkeyres layout: { status: c_int (4), deskey: [u8; 8] }
    #[repr(C, align(4))]
    struct CryptKeyRes {
        status: c_int,
        deskey: [u8; 8],
    }

    let mut res = CryptKeyRes {
        status: 0, // KEY_SUCCESS
        deskey: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22],
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_cryptkeyres(xdr.as_mut_ptr(), (&mut res as *mut CryptKeyRes).cast(),) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = CryptKeyRes {
        status: -1,
        deskey: [0; 8],
    };
    assert_eq!(
        unsafe { xdr_cryptkeyres(xdr.as_mut_ptr(), (&mut out as *mut CryptKeyRes).cast(),) },
        1
    );

    assert_eq!(out.status, 0);
    assert_eq!(out.deskey, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]);
}

// ===========================================================================
// 34. XDR record stream encode/decode (functional test with pipe)
// ===========================================================================

// Callback for xdrrec_create that writes to a pipe fd
unsafe extern "C" fn pipe_write(handle: *mut c_void, buf: *mut c_void, len: c_int) -> c_int {
    let fd = handle as usize as c_int;
    unsafe { libc::write(fd, buf, len as usize) as c_int }
}

// Callback for xdrrec_create that reads from a pipe fd
unsafe extern "C" fn pipe_read(handle: *mut c_void, buf: *mut c_void, len: c_int) -> c_int {
    let fd = handle as usize as c_int;
    unsafe { libc::read(fd, buf, len as usize) as c_int }
}

#[test]
fn xdrrec_encode_decode_via_pipe() {
    let mut fds: [c_int; 2] = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let read_fd = fds[0];
    let write_fd = fds[1];

    // Set up encoder
    let mut enc_xdr = XdrHandle::new();
    unsafe {
        xdrrec_create(
            enc_xdr.as_mut_ptr(),
            0,
            0,
            write_fd as usize as *mut c_void,
            std::ptr::null_mut(),
            pipe_write as *mut c_void,
        );
        // Set to ENCODE mode
        *(enc_xdr.as_mut_ptr() as *mut c_int) = XDR_ENCODE;
    }

    // Encode an int value
    let mut val: c_int = 12345;
    assert_eq!(unsafe { xdr_int(enc_xdr.as_mut_ptr(), &mut val) }, 1);

    // Flush the record
    assert_eq!(unsafe { xdrrec_endofrecord(enc_xdr.as_mut_ptr(), 1) }, 1);

    // Close write end so read side can detect EOF
    unsafe {
        libc::close(write_fd);
    }

    // Set up decoder
    let mut dec_xdr = XdrHandle::new();
    unsafe {
        xdrrec_create(
            dec_xdr.as_mut_ptr(),
            0,
            0,
            read_fd as usize as *mut c_void,
            pipe_read as *mut c_void,
            std::ptr::null_mut(),
        );
        // Set to DECODE mode
        *(dec_xdr.as_mut_ptr() as *mut c_int) = XDR_DECODE;
    }

    // Skip record header (xdrrec_skiprecord resets to next record)
    // First we need to feed the fragment header
    let mut out: c_int = 0;
    let rc = unsafe { xdr_int(dec_xdr.as_mut_ptr(), &mut out) };
    assert_eq!(rc, 1, "Should decode int from record stream");
    assert_eq!(out, 12345);

    unsafe {
        libc::close(read_fd);
    }
}

// ===========================================================================
// 35. xdr_bytes FREE mode
// ===========================================================================

#[test]
fn xdr_bytes_free_mode() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // Encode some bytes
    let data = b"to_free";
    let mut data_ptr: *mut c_char = data.as_ptr() as *mut c_char;
    let mut len: c_uint = 7;

    xdr_encode(&mut xdr, &mut buf);
    unsafe {
        xdr_bytes(xdr.as_mut_ptr(), &mut data_ptr, &mut len, 256);
    }

    // Decode to get allocated memory
    xdr_decode(&mut xdr, &mut buf);
    let mut alloc_ptr: *mut c_char = std::ptr::null_mut();
    let mut out_len: c_uint = 0;
    unsafe {
        xdr_bytes(xdr.as_mut_ptr(), &mut alloc_ptr, &mut out_len, 256);
    }
    assert!(!alloc_ptr.is_null());

    // Free via xdr_bytes in FREE mode
    unsafe {
        xdrmem_create(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 256, XDR_FREE);
        xdr_bytes(xdr.as_mut_ptr(), &mut alloc_ptr, &mut out_len, 256);
    }
    assert!(
        alloc_ptr.is_null(),
        "xdr_bytes FREE should null out pointer"
    );
}

// ===========================================================================
// 36. Empty string encoding
// ===========================================================================

#[test]
fn xdr_string_empty() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    let src = std::ffi::CString::new("").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_string(xdr.as_mut_ptr(), &mut src_ptr, 256) },
        1
    );

    // Wire format: length(4 bytes) = 0, no data bytes
    let wire_len = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    assert_eq!(wire_len, 0);

    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    assert_eq!(
        unsafe { xdr_string(xdr.as_mut_ptr(), &mut out_ptr, 256) },
        1
    );
    assert!(!out_ptr.is_null());

    let decoded = unsafe { std::ffi::CStr::from_ptr(out_ptr) }
        .to_str()
        .unwrap();
    assert_eq!(decoded, "");

    unsafe { libc::free(out_ptr.cast()) };
}

// ===========================================================================
// 37. Float special values
// ===========================================================================

#[test]
fn xdr_float_zero() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: f32 = 0.0;
    assert_eq!(unsafe { xdr_float(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: f32 = 1.0;
    assert_eq!(unsafe { xdr_float(xdr.as_mut_ptr(), &mut out) }, 1);
    assert_eq!(out, 0.0);
}

#[test]
fn xdr_double_negative_zero() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    xdr_encode(&mut xdr, &mut buf);
    let mut val: f64 = -0.0;
    assert_eq!(unsafe { xdr_double(xdr.as_mut_ptr(), &mut val) }, 1);

    xdr_decode(&mut xdr, &mut buf);
    let mut out: f64 = 1.0;
    assert_eq!(unsafe { xdr_double(xdr.as_mut_ptr(), &mut out) }, 1);
    // Check it's negative zero
    assert_eq!(out.to_bits(), (-0.0_f64).to_bits());
}

// ===========================================================================
// 38. xdr_sizeof for string
// ===========================================================================

#[test]
fn xdr_sizeof_wrapstring() {
    let src = std::ffi::CString::new("test").unwrap();
    let mut src_ptr: *mut c_char = src.as_ptr() as *mut c_char;

    let size = unsafe {
        xdr_sizeof(
            xdr_wrapstring as *mut c_void,
            (&mut src_ptr as *mut *mut c_char).cast(),
        )
    };
    // "test" = 4 chars, length prefix = 4 bytes, data = 4 bytes (aligned)
    // Total = 8 bytes
    assert_eq!(size, 8, "xdr_sizeof for 'test' should be 8");
}

// ===========================================================================
// 39. Multiple hypers in sequence
// ===========================================================================

#[test]
fn xdr_multiple_hypers() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    let values: [i64; 4] = [i64::MIN, -1, 0, i64::MAX];

    xdr_encode(&mut xdr, &mut buf);
    for v in &values {
        let mut val = *v;
        assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut val) }, 1);
    }

    xdr_decode(&mut xdr, &mut buf);
    for &expected in &values {
        let mut out: i64 = 0;
        assert_eq!(unsafe { xdr_hyper(xdr.as_mut_ptr(), &mut out) }, 1);
        assert_eq!(out, expected);
    }
}

// ===========================================================================
// 40. xdr_opaque alignment edge cases
// ===========================================================================

#[test]
fn xdr_opaque_1_byte() {
    let mut buf = [0u8; 128];
    let mut xdr = XdrHandle::new();

    let mut data = [0x42u8];

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), data.as_mut_ptr().cast(), 1,) },
        1
    );
    // 1 byte data + 3 bytes padding = 4 bytes consumed
    assert_eq!(buf[0], 0x42);
    assert_eq!(buf[1], 0); // padding
    assert_eq!(buf[2], 0);
    assert_eq!(buf[3], 0);

    xdr_decode(&mut xdr, &mut buf);
    let mut out = [0u8; 1];
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), out.as_mut_ptr().cast(), 1,) },
        1
    );
    assert_eq!(out[0], 0x42);
}

#[test]
fn xdr_opaque_4_bytes_no_padding() {
    let mut buf = [0xFFu8; 128];
    let mut xdr = XdrHandle::new();

    let mut data = [0x11u8, 0x22, 0x33, 0x44];

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_opaque(xdr.as_mut_ptr(), data.as_mut_ptr().cast(), 4,) },
        1
    );

    // Exactly 4 bytes, no padding needed
    assert_eq!(buf[0], 0x11);
    assert_eq!(buf[1], 0x22);
    assert_eq!(buf[2], 0x33);
    assert_eq!(buf[3], 0x44);
    // Next byte should still be original 0xFF (untouched)
    assert_eq!(buf[4], 0xFF);
}

// ===========================================================================
// 41. xdr_array with maxsize exceeded on decode
// ===========================================================================

#[test]
fn xdr_array_exceeds_maxsize_on_decode() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    // Manually encode count=100 into the buffer
    let count_be = 100_u32.to_be_bytes();
    buf[0..4].copy_from_slice(&count_be);

    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    let mut out_count: c_uint = 0;
    let rc = unsafe {
        xdr_array(
            xdr.as_mut_ptr(),
            &mut out_ptr,
            &mut out_count,
            10, // maxsize = 10, but encoded count = 100
            4,
            xdr_int as *mut c_void,
        )
    };
    assert_eq!(rc, 0, "Should fail when count exceeds maxsize");
}

// ===========================================================================
// 42. xdr_short with positive and negative boundary values
// ===========================================================================

#[test]
fn xdr_short_boundaries() {
    for &val in &[i16::MIN, -1, 0, 1, i16::MAX] {
        let mut buf = [0u8; 128];
        let mut xdr = XdrHandle::new();

        xdr_encode(&mut xdr, &mut buf);
        let mut v = val;
        assert_eq!(unsafe { xdr_short(xdr.as_mut_ptr(), &mut v) }, 1);

        xdr_decode(&mut xdr, &mut buf);
        let mut out: i16 = 0;
        assert_eq!(unsafe { xdr_short(xdr.as_mut_ptr(), &mut out) }, 1);
        assert_eq!(out, val, "xdr_short round-trip failed for {val}");
    }
}

// ===========================================================================
// 87. bd-bhqcn regression: wire-length vs stream-bound pre-malloc check
// ===========================================================================
//
// An attacker-supplied length in the wire must not cause xdr_string /
// xdr_bytes / xdr_array to allocate gigabytes before discovering the
// stream is actually short. Crafted wires here declare u32::MAX or a
// few-GiB length across a 16-byte stream; the parser must refuse
// without ever calling malloc for the fraudulent length.

#[test]
fn xdr_wrapstring_rejects_oversized_wire_length_without_oom() {
    // Stream: first 4 bytes = length of 0xFD000000 (~4.24 GiB) in
    // big-endian, rest zeros. Stream size is 16 bytes total.
    let mut buf = [0u8; 16];
    buf[0] = 0xFD;

    let mut xdr = XdrHandle::new();
    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    let rc = unsafe { xdr_wrapstring(xdr.as_mut_ptr(), &mut out_ptr) };
    // Must refuse — not crash/OOM. Pointer stays NULL so we do not
    // attempt to free anything fictional.
    assert_eq!(
        rc, 0,
        "xdr_wrapstring must refuse 4 GiB length from 16-byte stream"
    );
    assert!(
        out_ptr.is_null(),
        "xdr_wrapstring must not allocate on refusal"
    );
}

#[test]
fn xdr_bytes_rejects_oversized_wire_length_without_oom() {
    // Same primitive as above, but through xdr_bytes with a large
    // caller-supplied maxsize (the case where maxsize itself doesn't
    // save us).
    let mut buf = [0u8; 16];
    buf[0] = 0x40; // 0x40000000 = 1 GiB

    let mut xdr = XdrHandle::new();
    xdr_decode(&mut xdr, &mut buf);
    let mut out_ptr: *mut c_char = std::ptr::null_mut();
    let mut out_len: c_uint = 0;
    let rc = unsafe {
        xdr_bytes(
            xdr.as_mut_ptr(),
            &mut out_ptr,
            &mut out_len,
            c_uint::MAX, // maxsize cap saturated
        )
    };
    assert_eq!(
        rc, 0,
        "xdr_bytes must refuse 1 GiB length from 16-byte stream"
    );
    assert!(out_ptr.is_null(), "xdr_bytes must not allocate on refusal");
}

// ===========================================================================
// 88. bd-bhqcn regression: xdr_array(elsize=0) heap-buffer-overflow
// ===========================================================================
//
// xdr_array(elsize=0) with a non-zero count used to:
// (1) skip the `c > u32::MAX / elsize` overflow guard (short-circuit
//     on `elsize > 0`),
// (2) compute `total_bytes = c * 0 = 0`,
// (3) libc::malloc(0) → 1-byte allocation,
// (4) call the per-element xdrproc on each of the `count` elements,
// (5) each xdrproc (e.g. xdr_u_int) writes 4 bytes into the
//     1-byte slot → heap-buffer-overflow.
//
// Fix: reject elsize=0 with non-zero count.

#[test]
fn xdr_array_rejects_elsize_zero_with_nonzero_count() {
    let mut buf = [0u8; 16];
    // First 4 bytes = count = 1 (big-endian).
    buf[3] = 1;

    let mut xdr = XdrHandle::new();
    xdr_decode(&mut xdr, &mut buf);

    let mut arrp: *mut c_char = std::ptr::null_mut();
    let mut size: c_uint = 0;
    unsafe extern "C" fn dummy_int_proc(xdrs: *mut c_void, objp: *mut c_void) -> c_int {
        unsafe { xdr_int(xdrs, objp as *mut c_int) }
    }
    let rc = unsafe {
        xdr_array(
            xdr.as_mut_ptr(),
            &mut arrp,
            &mut size,
            16,
            0, // elsize = 0
            dummy_int_proc as *mut c_void,
        )
    };
    assert_eq!(rc, 0, "xdr_array must refuse elsize=0 with count>0");
    assert!(
        arrp.is_null(),
        "xdr_array must not allocate when refusing elsize=0"
    );
}

// ===========================================================================
// 86. xdr_pmaplist deep-stream regression (bd-lc5ss)
// ===========================================================================
//
// xdr_pmaplist used to recurse via xdr_pointer chasing — a malicious
// wire stream of N "more=1" flags would consume N stack frames and
// SIGSEGV the process. Iterative implementation must handle a stream
// far larger than any plausible thread-stack budget without
// overflowing.
#[test]
fn xdr_pmaplist_deep_stream_does_not_overflow_stack() {
    // 50_000 entries: each PmapList is 5 u32s on the wire (more=1
    // + pm_prog + pm_vers + pm_prot + pm_port) = 20 bytes. The
    // recursive impl would have eaten ~hundreds of bytes per level
    // for ~10 MiB of stack at this depth — well past the default
    // 8 MiB and certainly past CI worker defaults. Iterative impl
    // uses one stack frame total.
    const ENTRIES: usize = 50_000;
    let bytes_per_entry = 4 * 5; // more flag + 4 Pmap fields
    let total = bytes_per_entry * ENTRIES + 4; // + trailing more=0
    let mut buf = vec![0u8; total];

    // Hand-encode: ENTRIES copies of (more=1, prog, vers, prot, port)
    // followed by more=0. Big-endian u32s.
    for i in 0..ENTRIES {
        let off = i * bytes_per_entry;
        buf[off..off + 4].copy_from_slice(&1u32.to_be_bytes()); // more=1
        buf[off + 4..off + 8].copy_from_slice(&100000u32.to_be_bytes()); // pm_prog
        buf[off + 8..off + 12].copy_from_slice(&2u32.to_be_bytes()); // pm_vers
        buf[off + 12..off + 16].copy_from_slice(&17u32.to_be_bytes()); // pm_prot
        buf[off + 16..off + 20].copy_from_slice(&111u32.to_be_bytes()); // pm_port
    }
    // trailing more=0
    let tail = ENTRIES * bytes_per_entry;
    buf[tail..tail + 4].copy_from_slice(&0u32.to_be_bytes());

    let mut xdr = XdrHandle::new();
    xdr_decode(&mut xdr, &mut buf);

    // *rp starts NULL; the iterative parser walks forward, mallocs
    // each entry, and links them. We just verify it doesn't crash —
    // no oracle on the linked list contents (would require freeing
    // it, which would also need iterative free, which we test by
    // not crashing).
    let mut head: *mut c_void = std::ptr::null_mut();
    let rc = unsafe { xdr_pmaplist(xdr.as_mut_ptr(), &mut head as *mut *mut c_void as *mut c_void) };
    assert_eq!(rc, 1, "xdr_pmaplist failed on deep stream");

    // Free via xdr_pmaplist with XDR_FREE op — also must be iterative.
    let mut free_xdr = XdrHandle::new();
    unsafe {
        xdrmem_create(
            free_xdr.as_mut_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len() as c_uint,
            XDR_FREE,
        );
    }
    let rc_free =
        unsafe { xdr_pmaplist(free_xdr.as_mut_ptr(), &mut head as *mut *mut c_void as *mut c_void) };
    assert_eq!(rc_free, 1, "xdr_pmaplist free failed on deep list");
}
