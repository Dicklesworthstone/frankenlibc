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
    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
}

mod array_regressions {
    use super::*;
    use std::ffi::CStr;

    type ArrayFn = unsafe extern "C" fn(
        *mut c_void,
        *mut *mut c_char,
        *mut c_uint,
        c_uint,
        c_uint,
        *mut c_void,
    ) -> c_int;

    #[derive(Clone, Copy)]
    struct Provider {
        name: &'static str,
        array: ArrayFn,
        element: *mut c_void,
    }

    impl Provider {
        unsafe fn run(
            self,
            operation: c_int,
            wire: &mut [u8],
            data: &mut *mut c_char,
            count: &mut c_uint,
            stride: usize,
        ) -> c_int {
            let mut stream = XdrHandle::new();
            // SAFETY: each test supplies matching object/serializer layouts;
            // the initialized public XDR handle and wire remain live here.
            unsafe {
                xdrmem_create(
                    stream.as_mut_ptr(),
                    wire.as_mut_ptr().cast(),
                    wire.len() as c_uint,
                    operation,
                );
                (self.array)(
                    stream.as_mut_ptr(),
                    data,
                    count,
                    32,
                    stride as c_uint,
                    self.element,
                )
            }
        }

        fn roundtrip<T: Copy + std::fmt::Debug + PartialEq>(self, values: &[T], expected: &[u8]) {
            assert!(!values.is_empty());
            let mut input = values.to_vec();
            let mut data = input.as_mut_ptr().cast();
            let mut count = values.len() as c_uint;
            let mut wire = vec![0; expected.len()];
            let stride = std::mem::size_of::<T>();
            // SAFETY: the selected codec matches T and the input is live.
            assert_eq!(
                unsafe { self.run(XDR_ENCODE, &mut wire, &mut data, &mut count, stride) },
                1,
                "{} encode",
                self.name
            );
            assert_eq!(wire, expected, "{} exact wire", self.name);
            data = std::ptr::null_mut();
            count = 0;
            // SAFETY: a null destination requests an allocation from this provider.
            assert_eq!(
                unsafe { self.run(XDR_DECODE, &mut wire, &mut data, &mut count, stride) },
                1,
                "{} decode",
                self.name
            );
            assert_eq!(count as usize, values.len());
            assert!(!data.is_null());
            // SAFETY: successful decode initialized count elements of T.
            assert_eq!(
                unsafe { std::slice::from_raw_parts(data.cast::<T>(), count as usize) },
                values,
                "{} values",
                self.name
            );
            // SAFETY: the same provider owns this decoded array.
            assert_eq!(
                unsafe { self.run(XDR_FREE, &mut [], &mut data, &mut count, stride) },
                1
            );
            assert!(data.is_null());
        }
    }

    fn providers(element: *mut c_void, name: Option<&CStr>) -> Vec<Provider> {
        let native = Provider {
            name: "native",
            array: xdr_array,
            element,
        };
        #[cfg(target_env = "gnu")]
        {
            static GNU: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
            let handle = *GNU.get_or_init(|| {
                // SAFETY: retain the host handle for all independently resolved codecs.
                let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW) };
                assert!(
                    !handle.is_null(),
                    "GNU XDR oracle is required on GNU targets"
                );
                handle as usize
            });
            let resolve = |name: &CStr, candidate: *mut c_void| {
                let mut symbol = std::ptr::null_mut();
                for version in [c"GLIBC_2.2.5", c"GLIBC_2.17"] {
                    // SAFETY: the process-lifetime handle and names are live.
                    symbol = unsafe {
                        libc::dlvsym(handle as *mut c_void, name.as_ptr(), version.as_ptr())
                    };
                    if !symbol.is_null() {
                        break;
                    }
                }
                assert!(!symbol.is_null(), "missing GNU XDR oracle: {name:?}");
                assert_ne!(symbol, candidate, "oracle resolved to candidate: {name:?}");
                symbol
            };
            let array = resolve(c"xdr_array", xdr_array as *mut c_void);
            vec![
                native,
                Provider {
                    name: "GNU",
                    // SAFETY: xdr_array has the public ArrayFn signature.
                    array: unsafe { std::mem::transmute::<*mut c_void, ArrayFn>(array) },
                    element: name.map_or(element, |name| resolve(name, element)),
                },
            ]
        }
        #[cfg(not(target_env = "gnu"))]
        {
            let _ = name;
            vec![native]
        }
    }

    #[test]
    fn xdr_array_longs_use_wire_width_not_lp64_stride() {
        let values = [i32::MIN as c_long, -1, 0, i32::MAX as c_long];
        let wire = [
            0, 0, 0, 4, 0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff,
        ];
        for provider in providers(xdr_long as *mut c_void, Some(c"xdr_long")) {
            provider.roundtrip(&values, &wire);
        }
    }

    #[test]
    fn xdr_array_unsigned_longs_preserve_high_wire_bits() {
        let values: [c_ulong; 4] = [0, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff];
        let wire = [
            0, 0, 0, 4, 0, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0x80, 0, 0, 0, 0xff, 0xff, 0xff, 0xff,
        ];
        for provider in providers(xdr_u_long as *mut c_void, Some(c"xdr_u_long")) {
            provider.roundtrip(&values, &wire);
        }
    }

    #[test]
    fn xdr_array_custom_padded_elements_have_independent_wire_layout() {
        #[repr(C)]
        #[derive(Clone, Copy, Debug, PartialEq)]
        struct Element {
            tag: u8,
            value: c_ulong,
        }
        unsafe extern "C" fn codec(stream: *mut c_void, object: *mut c_void) -> c_int {
            // SAFETY: this callback is used only with Element storage.
            let element = unsafe { &mut *object.cast::<Element>() };
            // SAFETY: both fields match their serializers and the live stream.
            unsafe {
                if xdr_u_char(stream, &mut element.tag) == 0 {
                    return 0;
                }
                xdr_u_long(stream, &mut element.value)
            }
        }
        let values = [Element { tag: 7, value: 19 }, Element { tag: 8, value: 23 }];
        let wire = [0, 0, 0, 2, 0, 0, 0, 7, 0, 0, 0, 19, 0, 0, 0, 8, 0, 0, 0, 23];
        for provider in providers(codec as *mut c_void, None) {
            provider.roundtrip(&values, &wire);
        }
    }

    #[test]
    fn xdr_array_custom_elements_can_consume_no_wire_bytes() {
        unsafe extern "C" fn codec(stream: *mut c_void, object: *mut c_void) -> c_int {
            // SAFETY: the stream starts with x_op; the object is a live u64 slot.
            unsafe {
                if *stream.cast::<c_int>() == XDR_DECODE {
                    *object.cast::<u64>() = 77;
                }
            }
            1
        }
        for provider in providers(codec as *mut c_void, None) {
            provider.roundtrip(&[77u64; 3], &[0, 0, 0, 3]);
        }
    }

    #[test]
    fn xdr_array_empty_strings_decode_into_initialized_pointer_slots() {
        for provider in providers(xdr_wrapstring as *mut c_void, Some(c"xdr_wrapstring")) {
            let mut wire = [0u8; 16];
            wire[3] = 3;
            let mut data = std::ptr::null_mut();
            let mut count = 0;
            let stride = std::mem::size_of::<*mut c_char>();
            // SAFETY: the wire is a three-element array of empty strings.
            assert_eq!(
                unsafe { provider.run(XDR_DECODE, &mut wire, &mut data, &mut count, stride) },
                1,
                "{} empty strings",
                provider.name
            );
            assert_eq!(count, 3);
            assert!(!data.is_null());
            // SAFETY: successful decode initialized three string pointers.
            for &string in unsafe { std::slice::from_raw_parts(data.cast::<*mut c_char>(), 3) } {
                assert!(!string.is_null());
                // SAFETY: each successful string decode includes its terminator.
                assert_eq!(unsafe { CStr::from_ptr(string) }.to_bytes(), b"");
            }
            // SAFETY: this provider owns the array and all nested strings.
            assert_eq!(
                unsafe { provider.run(XDR_FREE, &mut [], &mut data, &mut count, stride) },
                1
            );
            assert!(data.is_null());
        }
    }

    #[test]
    fn xdr_array_partial_nested_decode_leaves_unvisited_slots_safe_to_free() {
        for provider in providers(xdr_wrapstring as *mut c_void, Some(c"xdr_wrapstring")) {
            // Sixteen payload bytes satisfy the three-element minimum of twelve.
            // The second string then claims eight bytes with only four available.
            let mut wire = [
                0, 0, 0, 3, 0, 0, 0, 3, b'a', b'b', b'c', 0, 0, 0, 0, 8, b'x', b'x', b'x', b'x',
            ];
            let mut data = std::ptr::null_mut();
            let mut count = 0;
            let stride = std::mem::size_of::<*mut c_char>();
            // SAFETY: the valid outer count requests storage for three strings.
            assert_eq!(
                unsafe { provider.run(XDR_DECODE, &mut wire, &mut data, &mut count, stride) },
                0
            );
            assert_eq!(count, 3);
            assert!(
                !data.is_null(),
                "{} must reach element decoding",
                provider.name
            );
            // SAFETY: array allocation initializes the complete published count.
            let strings = unsafe { std::slice::from_raw_parts(data.cast::<*mut c_char>(), 3) };
            assert!(!strings[0].is_null());
            // SAFETY: the first string completed decoding before the later failure.
            assert_eq!(unsafe { CStr::from_ptr(strings[0]) }.to_bytes(), b"abc");
            assert!(strings[2].is_null(), "{} unvisited slot", provider.name);
            // SAFETY: FREE must handle both partial and unvisited elements.
            assert_eq!(
                unsafe { provider.run(XDR_FREE, &mut [], &mut data, &mut count, stride) },
                1
            );
            assert!(data.is_null());
        }
    }

    unsafe extern "C" fn failing_element(_: *mut c_void, _: *mut c_void) -> c_int {
        0
    }

    #[test]
    fn xdr_array_free_null_with_nonzero_count_does_not_call_serializer() {
        for provider in providers(failing_element as *mut c_void, None) {
            let mut data = std::ptr::null_mut();
            let mut count = 3;
            // SAFETY: a null result is valid after an earlier decode failure.
            assert_eq!(
                unsafe { provider.run(XDR_FREE, &mut [], &mut data, &mut count, 4) },
                1
            );
            assert!(data.is_null());
        }
    }

    #[test]
    fn xdr_array_free_releases_empty_existing_storage() {
        for provider in providers(xdr_int as *mut c_void, Some(c"xdr_int")) {
            let mut wire = [0, 0, 0, 1, 0, 0, 0, 42];
            let mut data = std::ptr::null_mut();
            let mut count = 0;
            // SAFETY: decode one int using the provider that will release it.
            assert_eq!(
                unsafe { provider.run(XDR_DECODE, &mut wire, &mut data, &mut count, 4) },
                1
            );
            assert!(!data.is_null());
            count = 0;
            let provider = Provider {
                element: std::ptr::null_mut(),
                ..provider
            };
            // SAFETY: an empty array has no callback invocations, even with storage.
            assert_eq!(
                unsafe { provider.run(XDR_FREE, &mut [], &mut data, &mut count, 4) },
                1
            );
            assert!(data.is_null());
        }
    }

    #[test]
    fn xdr_array_free_releases_outer_storage_after_element_failure() {
        for provider in providers(xdr_int as *mut c_void, Some(c"xdr_int")) {
            let mut wire = [0, 0, 0, 1, 0, 0, 0, 42];
            let mut data = std::ptr::null_mut();
            let mut count = 0;
            // SAFETY: decode scalar storage with no nested allocations to leak.
            assert_eq!(
                unsafe { provider.run(XDR_DECODE, &mut wire, &mut data, &mut count, 4) },
                1
            );
            assert!(!data.is_null());
            let provider = Provider {
                element: failing_element as *mut c_void,
                ..provider
            };
            // SAFETY: the callback reports failure without changing array ownership.
            assert_eq!(
                unsafe { provider.run(XDR_FREE, &mut [], &mut data, &mut count, 4) },
                0
            );
            assert!(data.is_null());
        }
    }
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
}

#[test]
fn xdr_reference_free_null_matches_gnu_without_leaking_depth() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    type ReferenceFn =
        unsafe extern "C" fn(*mut c_void, *mut *mut c_char, c_uint, *mut c_void) -> c_int;
    static CALLBACKS: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "C" fn decode_or_fail(stream: *mut c_void, object: *mut c_void) -> c_int {
        CALLBACKS.fetch_add(1, Ordering::SeqCst);
        // SAFETY: the public XDR operation is the first c_int. A decode call
        // supplies provider-owned storage for one complete integer.
        if unsafe { *stream.cast::<c_int>() } == XDR_DECODE {
            unsafe { *object.cast::<c_int>() = 77 };
            1
        } else {
            0
        }
    }

    let native = ("native", xdr_reference as ReferenceFn);
    let providers = {
        #[cfg(target_env = "gnu")]
        {
            // SAFETY: keep the GNU handle live through all oracle calls.
            let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW) };
            assert!(!handle.is_null(), "GNU XDR oracle is required");
            let mut symbol = std::ptr::null_mut();
            for version in [c"GLIBC_2.2.5", c"GLIBC_2.17"] {
                // SAFETY: these terminated names select the public host ABI.
                symbol =
                    unsafe { libc::dlvsym(handle, c"xdr_reference".as_ptr(), version.as_ptr()) };
                if !symbol.is_null() {
                    break;
                }
            }
            assert!(!symbol.is_null(), "GNU xdr_reference oracle is required");
            assert_ne!(symbol, xdr_reference as *mut c_void);
            // SAFETY: the independently resolved symbol has the public signature.
            let host = unsafe { std::mem::transmute::<*mut c_void, ReferenceFn>(symbol) };
            vec![native, ("GNU", host)]
        }
        #[cfg(not(target_env = "gnu"))]
        {
            vec![native]
        }
    };

    for (name, reference) in providers {
        CALLBACKS.store(0, Ordering::SeqCst);
        let mut stream = XdrHandle::new();
        stream.data[..4].copy_from_slice(&XDR_FREE.to_ne_bytes());
        let mut object = std::ptr::null_mut();
        // The callback performs no wire I/O, so the public operation field is
        // sufficient; neither provider shares the other's memory backend.
        for _ in 0..1024 {
            // SAFETY: no object is owned. FREE must not invoke this failing
            // callback, and repeated no-ops must release the native depth slot.
            assert_eq!(
                unsafe {
                    reference(
                        stream.as_mut_ptr(),
                        &mut object,
                        4,
                        decode_or_fail as *mut c_void,
                    )
                },
                1,
                "{name} null FREE"
            );
        }
        assert!(object.is_null());
        assert_eq!(
            CALLBACKS.load(Ordering::SeqCst),
            0,
            "{name} null callback count"
        );
        // SAFETY: null FREE must not construct an unused null function pointer.
        assert_eq!(
            unsafe { reference(stream.as_mut_ptr(), &mut object, 4, std::ptr::null_mut()) },
            1,
            "{name} null FREE without serializer"
        );

        stream.data[..4].copy_from_slice(&XDR_DECODE.to_ne_bytes());
        // SAFETY: null decode requests provider-owned storage of the declared size.
        assert_eq!(
            unsafe {
                reference(
                    stream.as_mut_ptr(),
                    &mut object,
                    4,
                    decode_or_fail as *mut c_void,
                )
            },
            1,
            "{name} decode after repeated FREE"
        );
        assert!(!object.is_null());
        assert_eq!(unsafe { *object.cast::<c_int>() }, 77);
        assert_eq!(CALLBACKS.load(Ordering::SeqCst), 1);
        stream.data[..4].copy_from_slice(&XDR_FREE.to_ne_bytes());
        // SAFETY: the same provider owns this object; a failed callback must
        // still release and null the outer reference while preserving FALSE.
        assert_eq!(
            unsafe {
                reference(
                    stream.as_mut_ptr(),
                    &mut object,
                    4,
                    decode_or_fail as *mut c_void,
                )
            },
            0,
            "{name} failed serializer status"
        );
        assert!(
            object.is_null(),
            "{name} releases reference after callback failure"
        );
        assert_eq!(CALLBACKS.load(Ordering::SeqCst), 2);
        // SAFETY: the completed cleanup leaves an empty reference to free again.
        assert_eq!(
            unsafe {
                reference(
                    stream.as_mut_ptr(),
                    &mut object,
                    4,
                    decode_or_fail as *mut c_void,
                )
            },
            1,
            "{name} repeated cleanup"
        );
        assert_eq!(CALLBACKS.load(Ordering::SeqCst), 2);
    }

    // Preserve the native policy that encoding a required null reference fails
    // before entering a user serializer; only FREE gained the empty no-op case.
    CALLBACKS.store(0, Ordering::SeqCst);
    let mut stream = XdrHandle::new();
    stream.data[..4].copy_from_slice(&XDR_ENCODE.to_ne_bytes());
    let mut object = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            xdr_reference(
                stream.as_mut_ptr(),
                &mut object,
                4,
                decode_or_fail as *mut c_void,
            )
        },
        0
    );
    assert_eq!(CALLBACKS.load(Ordering::SeqCst), 0);
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

    unsafe { frankenlibc_abi::malloc_abi::free(out.n_bytes.cast()) };
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_auth.oa_base.cast()) };
}

// ===========================================================================
// 22. RPC type serializers: reply and call message composites
// ===========================================================================

#[test]
fn xdr_accepted_reply_prog_mismatch_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    #[repr(C)]
    struct OpaqueAuth {
        oa_flavor: c_int,
        _pad: c_int,
        oa_base: *mut c_char,
        oa_length: c_uint,
        _pad2: c_uint,
    }

    #[repr(C)]
    struct AcceptedReply {
        ar_verf: OpaqueAuth,
        ar_stat: c_int,
        _pad: c_int,
        ar_u1: c_ulong,
        ar_u2: c_ulong,
    }

    let mut reply = AcceptedReply {
        ar_verf: OpaqueAuth {
            oa_flavor: 0,
            _pad: 0,
            oa_base: std::ptr::null_mut(),
            oa_length: 0,
            _pad2: 0,
        },
        ar_stat: 2,
        _pad: 0,
        ar_u1: 2,
        ar_u2: 4,
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_accepted_reply(xdr.as_mut_ptr(), (&mut reply as *mut AcceptedReply).cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = AcceptedReply {
        ar_verf: OpaqueAuth {
            oa_flavor: -1,
            _pad: 0,
            oa_base: std::ptr::null_mut(),
            oa_length: 0,
            _pad2: 0,
        },
        ar_stat: 0,
        _pad: 0,
        ar_u1: 0,
        ar_u2: 0,
    };
    assert_eq!(
        unsafe { xdr_accepted_reply(xdr.as_mut_ptr(), (&mut out as *mut AcceptedReply).cast()) },
        1
    );

    assert_eq!(out.ar_verf.oa_flavor, 0);
    assert_eq!(out.ar_verf.oa_length, 0);
    assert_eq!(out.ar_stat, 2);
    assert_eq!(out.ar_u1 as u32, 2);
    assert_eq!(out.ar_u2 as u32, 4);
}

#[test]
fn xdr_replymsg_accepted_mismatch_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    #[repr(C, align(8))]
    struct ReplyMsg {
        bytes: [u8; 80],
    }

    let mut msg = ReplyMsg { bytes: [0; 80] };
    unsafe {
        *(msg.bytes.as_mut_ptr().add(0) as *mut c_ulong) = 0xAABBCCDD;
        *(msg.bytes.as_mut_ptr().add(8) as *mut c_int) = 1;
        *(msg.bytes.as_mut_ptr().add(16) as *mut c_int) = 0;
        *(msg.bytes.as_mut_ptr().add(24) as *mut c_int) = 0;
        *(msg.bytes.as_mut_ptr().add(40) as *mut c_uint) = 0;
        *(msg.bytes.as_mut_ptr().add(48) as *mut c_int) = 2;
        *(msg.bytes.as_mut_ptr().add(56) as *mut c_ulong) = 2;
        *(msg.bytes.as_mut_ptr().add(64) as *mut c_ulong) = 4;
    }

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_replymsg(xdr.as_mut_ptr(), msg.bytes.as_mut_ptr().cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = ReplyMsg { bytes: [0; 80] };
    assert_eq!(
        unsafe { xdr_replymsg(xdr.as_mut_ptr(), out.bytes.as_mut_ptr().cast()) },
        1
    );

    unsafe {
        assert_eq!(
            *(out.bytes.as_ptr().add(0) as *const c_ulong) as u32,
            0xAABBCCDD
        );
        assert_eq!(*(out.bytes.as_ptr().add(8) as *const c_int), 1);
        assert_eq!(*(out.bytes.as_ptr().add(16) as *const c_int), 0);
        assert_eq!(*(out.bytes.as_ptr().add(24) as *const c_int), 0);
        assert_eq!(*(out.bytes.as_ptr().add(40) as *const c_uint), 0);
        assert_eq!(*(out.bytes.as_ptr().add(48) as *const c_int), 2);
        assert_eq!(*(out.bytes.as_ptr().add(56) as *const c_ulong) as u32, 2);
        assert_eq!(*(out.bytes.as_ptr().add(64) as *const c_ulong) as u32, 4);
    }
}

#[test]
fn xdr_callmsg_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    #[repr(C, align(8))]
    struct CallMsg {
        bytes: [u8; 104],
    }

    let mut msg = CallMsg { bytes: [0; 104] };
    unsafe {
        *(msg.bytes.as_mut_ptr().add(0) as *mut c_ulong) = 0x01020304;
        *(msg.bytes.as_mut_ptr().add(24) as *mut c_ulong) = 100000;
        *(msg.bytes.as_mut_ptr().add(32) as *mut c_ulong) = 2;
        *(msg.bytes.as_mut_ptr().add(40) as *mut c_ulong) = 3;
        *(msg.bytes.as_mut_ptr().add(48) as *mut c_int) = 0;
        *(msg.bytes.as_mut_ptr().add(64) as *mut c_uint) = 0;
        *(msg.bytes.as_mut_ptr().add(72) as *mut c_int) = 0;
        *(msg.bytes.as_mut_ptr().add(88) as *mut c_uint) = 0;
    }

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_callmsg(xdr.as_mut_ptr(), msg.bytes.as_mut_ptr().cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = CallMsg { bytes: [0; 104] };
    assert_eq!(
        unsafe { xdr_callmsg(xdr.as_mut_ptr(), out.bytes.as_mut_ptr().cast()) },
        1
    );

    unsafe {
        assert_eq!(
            *(out.bytes.as_ptr().add(0) as *const c_ulong) as u32,
            0x01020304
        );
        assert_eq!(*(out.bytes.as_ptr().add(8) as *const c_int), 0);
        assert_eq!(*(out.bytes.as_ptr().add(16) as *const c_ulong) as u32, 2);
        assert_eq!(
            *(out.bytes.as_ptr().add(24) as *const c_ulong) as u32,
            100000
        );
        assert_eq!(*(out.bytes.as_ptr().add(32) as *const c_ulong) as u32, 2);
        assert_eq!(*(out.bytes.as_ptr().add(40) as *const c_ulong) as u32, 3);
        assert_eq!(*(out.bytes.as_ptr().add(48) as *const c_int), 0);
        assert_eq!(*(out.bytes.as_ptr().add(64) as *const c_uint), 0);
        assert_eq!(*(out.bytes.as_ptr().add(72) as *const c_int), 0);
        assert_eq!(*(out.bytes.as_ptr().add(88) as *const c_uint), 0);
    }
}

#[test]
fn xdr_authunix_parms_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    #[repr(C)]
    struct AuthUnixParms {
        aup_time: c_ulong,
        aup_machname: *mut c_char,
        aup_uid: u32,
        aup_gid: u32,
        aup_len: c_uint,
        _pad: c_uint,
        aup_gids: *mut u32,
    }

    let machname = std::ffi::CString::new("host").unwrap();
    let mut gids = [10_u32, 20_u32];
    let mut parms = AuthUnixParms {
        aup_time: 12345,
        aup_machname: machname.as_ptr() as *mut c_char,
        aup_uid: 1000,
        aup_gid: 100,
        aup_len: gids.len() as c_uint,
        _pad: 0,
        aup_gids: gids.as_mut_ptr(),
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_authunix_parms(xdr.as_mut_ptr(), (&mut parms as *mut AuthUnixParms).cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = AuthUnixParms {
        aup_time: 0,
        aup_machname: std::ptr::null_mut(),
        aup_uid: 0,
        aup_gid: 0,
        aup_len: 0,
        _pad: 0,
        aup_gids: std::ptr::null_mut(),
    };
    assert_eq!(
        unsafe { xdr_authunix_parms(xdr.as_mut_ptr(), (&mut out as *mut AuthUnixParms).cast()) },
        1
    );

    assert_eq!(out.aup_time as u32, 12345);
    assert_eq!(out.aup_uid, 1000);
    assert_eq!(out.aup_gid, 100);
    assert_eq!(out.aup_len, 2);
    let decoded_host = unsafe { std::ffi::CStr::from_ptr(out.aup_machname) }
        .to_str()
        .unwrap();
    assert_eq!(decoded_host, "host");
    let decoded_gids = unsafe { std::slice::from_raw_parts(out.aup_gids, out.aup_len as usize) };
    assert_eq!(decoded_gids, &[10, 20]);

    unsafe {
        frankenlibc_abi::malloc_abi::free(out.aup_machname.cast());
        frankenlibc_abi::malloc_abi::free(out.aup_gids.cast());
    }
}

// ===========================================================================
// 23. RPC type serializers: xdr_pmap
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
    // Public rpcsvc/key_prot.h defines HEXKEYBYTES as 48. A keybuf is
    // fixed opaque data: it has no length word and no trailing string byte.
    #[repr(C)]
    struct GuardedKey {
        key: [u8; 48],
        guard: [u8; 8],
    }

    for (name, memory, codec, _) in key_protocol_providers(xdr_keybuf, c"xdr_keybuf") {
        let mut buf = [0u8; 48];
        let mut xdr = XdrHandle::new();
        let mut keybuf = [0xABu8; 48];
        // SAFETY: both providers receive the public fixed-width key buffer and
        // their own memory stream, with exactly the required wire capacity.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 48, XDR_ENCODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), keybuf.as_mut_ptr().cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(buf, [0xAB; 48], "{name}: exact keybuf wire");

        let mut out = GuardedKey {
            key: [0; 48],
            guard: [0x5A; 8],
        };
        // SAFETY: the destination owns the exact public keybuf plus a guard.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 48, XDR_DECODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), out.key.as_mut_ptr().cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(out.key, [0xAB; 48], "{name}");
        assert_eq!(out.guard, [0x5A; 8], "{name}: decode exceeded keybuf");
    }
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
    // The public unixcred has unsigned uid/gid and an unsigned XDR array
    // count. The short* parameter of authdes_getucred is a different API.
    #[repr(C)]
    struct UnixCred {
        uid: c_uint,
        gid: c_uint,
        gidlen: c_uint,
        gids: *mut c_uint,
    }

    let expected: Vec<u8> = [1000u32, 1001, 3, 10, 20, 0xFEDC_BA98]
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect();
    for (name, memory, codec, release) in key_protocol_providers(xdr_unixcred, c"xdr_unixcred") {
        let mut buf = [0u8; 24];
        let mut xdr = XdrHandle::new();
        let mut groups = [10u32, 20, 0xFEDC_BA98];
        let mut cred = UnixCred {
            uid: 1000,
            gid: 1001,
            gidlen: groups.len() as c_uint,
            gids: groups.as_mut_ptr(),
        };
        // SAFETY: the public C layout and its borrowed group array remain live
        // throughout ENCODE; the selected provider owns its memory stream.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 24, XDR_ENCODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), (&mut cred as *mut UnixCred).cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(buf.as_slice(), expected, "{name}: exact unixcred wire");
        let mut out = UnixCred {
            uid: 0,
            gid: 0,
            gidlen: 0,
            gids: std::ptr::null_mut(),
        };
        // SAFETY: a null array destination asks the provider to allocate it.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 24, XDR_DECODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), (&mut out as *mut UnixCred).cast()),
                1,
                "{name}"
            );
        }
        assert_eq!((out.uid, out.gid, out.gidlen), (1000, 1001, 3), "{name}");
        assert!(!out.gids.is_null(), "{name}");
        // SAFETY: successful decode initialized the three declared groups.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(out.gids, 3) },
            groups,
            "{name}"
        );
        // SAFETY: the same provider frees only its decoded array; the input
        // points to borrowed stack storage and is never passed to XDR_FREE.
        unsafe { release(codec as *mut c_void, (&mut out as *mut UnixCred).cast()) };
        assert!(out.gids.is_null(), "{name}: decoded group ownership");
    }
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
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
// 34. Secure RPC/keyserv composite serializers
// ===========================================================================

#[test]
fn xdr_authdes_cred_fullname_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    #[repr(C)]
    struct AuthDesCred {
        namekind: c_int,
        _pad: c_int,
        name: *mut c_char,
        key: [u8; 8],
        window: [u8; 4],
    }

    let name = std::ffi::CString::new("unix.1000@host").unwrap();
    let mut cred = AuthDesCred {
        namekind: 0,
        _pad: 0,
        name: name.as_ptr() as *mut c_char,
        key: [1, 2, 3, 4, 5, 6, 7, 8],
        window: [9, 10, 11, 12],
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_authdes_cred(xdr.as_mut_ptr(), (&mut cred as *mut AuthDesCred).cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = AuthDesCred {
        namekind: -1,
        _pad: 0,
        name: std::ptr::null_mut(),
        key: [0; 8],
        window: [0; 4],
    };
    assert_eq!(
        unsafe { xdr_authdes_cred(xdr.as_mut_ptr(), (&mut out as *mut AuthDesCred).cast()) },
        1
    );

    assert_eq!(out.namekind, 0);
    let decoded = unsafe { std::ffi::CStr::from_ptr(out.name) }
        .to_str()
        .unwrap();
    assert_eq!(decoded, "unix.1000@host");
    assert_eq!(out.key, [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(out.window, [9, 10, 11, 12]);

    unsafe { frankenlibc_abi::malloc_abi::free(out.name.cast()) };
}

#[test]
fn xdr_cryptkeyarg_roundtrip() {
    let mut buf = [0u8; 512];
    let mut xdr = XdrHandle::new();

    #[repr(C)]
    struct CryptKeyArg {
        remotename: *mut c_char,
        deskey: [u8; 8],
    }

    let name = std::ffi::CString::new("unix.2000@remote").unwrap();
    let mut arg = CryptKeyArg {
        remotename: name.as_ptr() as *mut c_char,
        deskey: [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80],
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_cryptkeyarg(xdr.as_mut_ptr(), (&mut arg as *mut CryptKeyArg).cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out = CryptKeyArg {
        remotename: std::ptr::null_mut(),
        deskey: [0; 8],
    };
    assert_eq!(
        unsafe { xdr_cryptkeyarg(xdr.as_mut_ptr(), (&mut out as *mut CryptKeyArg).cast()) },
        1
    );

    let decoded = unsafe { std::ffi::CStr::from_ptr(out.remotename) }
        .to_str()
        .unwrap();
    assert_eq!(decoded, "unix.2000@remote");
    assert_eq!(out.deskey, [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);

    unsafe { frankenlibc_abi::malloc_abi::free(out.remotename.cast()) };
}

type KeyProtocolMemoryFn = unsafe extern "C" fn(*mut c_void, *mut c_char, c_uint, c_int);
type KeyProtocolCodecFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
type KeyProtocolFreeFn = unsafe extern "C" fn(*mut c_void, *mut c_char);

/// Pair native Secure RPC serializers with the independently resolved GNU
/// serializer, memory backend, and matching release operation.
fn key_protocol_providers(
    candidate: KeyProtocolCodecFn,
    symbol: &std::ffi::CStr,
) -> Vec<(
    &'static str,
    KeyProtocolMemoryFn,
    KeyProtocolCodecFn,
    KeyProtocolFreeFn,
)> {
    let native = (
        "native",
        xdrmem_create as KeyProtocolMemoryFn,
        candidate,
        xdr_free as KeyProtocolFreeFn,
    );
    #[cfg(target_env = "gnu")]
    {
        static GNU: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
        let handle = *GNU.get_or_init(|| {
            // SAFETY: retain the host handle while any provider may use it.
            let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW) };
            assert!(!handle.is_null(), "GNU XDR oracle is required");
            handle as usize
        }) as *mut c_void;
        let resolve = |name: &std::ffi::CStr, candidate: *mut c_void| {
            let mut symbol = std::ptr::null_mut();
            for version in [c"GLIBC_2.2.5", c"GLIBC_2.17"] {
                // SAFETY: the live handle and terminated symbol/version names
                // select the host's public SunRPC ABI independently.
                symbol = unsafe { libc::dlvsym(handle, name.as_ptr(), version.as_ptr()) };
                if !symbol.is_null() {
                    break;
                }
            }
            assert!(!symbol.is_null(), "missing GNU XDR oracle: {name:?}");
            assert_ne!(symbol, candidate, "oracle resolved to candidate: {name:?}");
            symbol
        };
        // SAFETY: each public symbol has the corresponding declared ABI.
        let host = unsafe {
            (
                "GNU",
                std::mem::transmute::<*mut c_void, KeyProtocolMemoryFn>(resolve(
                    c"xdrmem_create",
                    xdrmem_create as *mut c_void,
                )),
                std::mem::transmute::<*mut c_void, KeyProtocolCodecFn>(resolve(
                    symbol,
                    candidate as *mut c_void,
                )),
                std::mem::transmute::<*mut c_void, KeyProtocolFreeFn>(resolve(
                    c"xdr_free",
                    xdr_free as *mut c_void,
                )),
            )
        };
        vec![native, host]
    }
    #[cfg(not(target_env = "gnu"))]
    {
        let _ = symbol;
        vec![native]
    }
}

#[test]
fn xdr_cryptkeyarg2_roundtrip() {
    // key_prot.x declares a counted binary netobj, not a second netname.
    // On LP64 its length and pointer occupy 16 bytes, placing deskey at 24.
    #[repr(C)]
    struct NetObj {
        len: c_uint,
        bytes: *mut c_char,
    }
    #[repr(C)]
    struct CryptKeyArg2 {
        remotename: *mut c_char,
        remotekey: NetObj,
        deskey: [u8; 8],
    }
    assert_eq!(std::mem::size_of::<CryptKeyArg2>(), 32);
    assert_eq!(std::mem::offset_of!(CryptKeyArg2, remotekey), 8);
    assert_eq!(std::mem::offset_of!(CryptKeyArg2, deskey), 24);

    let remote = c"unix.2000@remote";
    let key: [u8; 5] = [0xa1, 0, 0xff, 0x7f, 0x42];
    let deskey = [0xaa, 0xbb, 0xcc, 0xdd, 0x11, 0x22, 0x33, 0x44];
    let expected = [
        0, 0, 0, 16, b'u', b'n', b'i', b'x', b'.', b'2', b'0', b'0', b'0', b'@', b'r', b'e', b'm',
        b'o', b't', b'e', 0, 0, 0, 5, 0xa1, 0, 0xff, 0x7f, 0x42, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd,
        0x11, 0x22, 0x33, 0x44,
    ];

    for (name, memory, codec, release) in
        key_protocol_providers(xdr_cryptkeyarg2, c"xdr_cryptkeyarg2")
    {
        let mut wire = [0xa5; 40];
        let mut stream = XdrHandle::new();
        let mut input = CryptKeyArg2 {
            remotename: remote.as_ptr().cast_mut(),
            remotekey: NetObj {
                len: key.len() as c_uint,
                bytes: key.as_ptr().cast_mut().cast(),
            },
            deskey,
        };
        // SAFETY: every public field has the matching layout and live input
        // storage; the encode operation only reads those borrowed inputs.
        unsafe {
            memory(
                stream.as_mut_ptr(),
                wire.as_mut_ptr().cast(),
                wire.len() as c_uint,
                XDR_ENCODE,
            );
            assert_eq!(
                codec(
                    stream.as_mut_ptr(),
                    (&mut input as *mut CryptKeyArg2).cast()
                ),
                1,
                "{name} encode"
            );
        }
        assert_eq!(
            wire, expected,
            "{name} exact binary wire, including padding"
        );
        let mut output = CryptKeyArg2 {
            remotename: std::ptr::null_mut(),
            remotekey: NetObj {
                len: 0,
                bytes: std::ptr::null_mut(),
            },
            deskey: [0; 8],
        };
        // SAFETY: null pointer fields request provider-owned decode allocations.
        unsafe {
            memory(
                stream.as_mut_ptr(),
                wire.as_mut_ptr().cast(),
                wire.len() as c_uint,
                XDR_DECODE,
            );
            assert_eq!(
                codec(
                    stream.as_mut_ptr(),
                    (&mut output as *mut CryptKeyArg2).cast()
                ),
                1,
                "{name} decode"
            );
        }
        assert!(!output.remotename.is_null());
        assert!(!output.remotekey.bytes.is_null());
        assert_eq!(
            output.remotekey.len as usize,
            key.len(),
            "{name} key length"
        );
        // SAFETY: successful decode produced the declared name and counted key.
        unsafe {
            assert_eq!(
                std::ffi::CStr::from_ptr(output.remotename),
                remote,
                "{name} name"
            );
            assert_eq!(
                std::slice::from_raw_parts(output.remotekey.bytes.cast::<u8>(), key.len()),
                key,
                "{name} embedded-NUL key"
            );
        }
        assert_eq!(output.deskey, deskey, "{name} DES block");
        // SAFETY: free only decoded storage, through its owning provider's codec.
        unsafe {
            release(
                codec as *mut c_void,
                (&mut output as *mut CryptKeyArg2).cast(),
            )
        };
        assert!(output.remotename.is_null(), "{name} frees remote name");
        assert!(output.remotekey.bytes.is_null(), "{name} frees binary key");
    }
}

#[test]
fn xdr_getcredres_roundtrip() {
    // Public key_prot.h: KEY_SUCCESS selects a unixcred union arm, not a
    // client-name string. repr(C) supplies the required union alignment.
    #[repr(C)]
    struct UnixCred {
        uid: c_uint,
        gid: c_uint,
        gidlen: c_uint,
        gids: *mut c_uint,
    }
    #[repr(C)]
    struct GetCredRes {
        status: c_int,
        cred: UnixCred,
    }

    let expected: Vec<u8> = [0u32, 1000, 1001, 3, 10, 20, 0xFEDC_BA98]
        .into_iter()
        .flat_map(u32::to_be_bytes)
        .collect();
    for (name, memory, codec, release) in key_protocol_providers(xdr_getcredres, c"xdr_getcredres")
    {
        let mut buf = [0u8; 28];
        let mut xdr = XdrHandle::new();
        let mut groups = [10u32, 20, 0xFEDC_BA98];
        let mut res = GetCredRes {
            status: 0,
            cred: UnixCred {
                uid: 1000,
                gid: 1001,
                gidlen: groups.len() as c_uint,
                gids: groups.as_mut_ptr(),
            },
        };
        // SAFETY: this is the full public discriminated-union layout. The
        // borrowed input groups are only encoded and remain owned by this test.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 28, XDR_ENCODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), (&mut res as *mut GetCredRes).cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(buf.as_slice(), expected, "{name}: exact getcredres wire");
        let mut out = GetCredRes {
            status: -1,
            cred: UnixCred {
                uid: 0,
                gid: 0,
                gidlen: 0,
                gids: std::ptr::null_mut(),
            },
        };
        // SAFETY: the full output arm is initialized and its null group pointer
        // requests provider-owned storage; no input allocation can be aliased.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 28, XDR_DECODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), (&mut out as *mut GetCredRes).cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(
            (out.status, out.cred.uid, out.cred.gid, out.cred.gidlen),
            (0, 1000, 1001, 3),
            "{name}"
        );
        assert!(!out.cred.gids.is_null(), "{name}");
        assert_ne!(
            out.cred.gids,
            groups.as_mut_ptr(),
            "{name}: decoded ownership"
        );
        // SAFETY: the successful result contains three initialized groups.
        assert_eq!(
            unsafe { std::slice::from_raw_parts(out.cred.gids, 3) },
            groups,
            "{name}"
        );
        // SAFETY: XDR_FREE visits the active credential arm and frees only the
        // decoded group allocation, using the same provider that allocated it.
        unsafe { release(codec as *mut c_void, (&mut out as *mut GetCredRes).cast()) };
        assert!(out.cred.gids.is_null(), "{name}: decoded group cleanup");
    }
}

#[test]
fn xdr_key_netstarg_roundtrip() {
    // Each public keybuf has HEXKEYBYTES=48; the netname pointer follows
    // immediately after the two fixed arrays (offset 96 on LP64).
    #[repr(C)]
    struct KeyNetstArg {
        priv_key: [u8; 48],
        pub_key: [u8; 48],
        netname: *mut c_char,
    }

    for (name, memory, codec, release) in
        key_protocol_providers(xdr_key_netstarg, c"xdr_key_netstarg")
    {
        let mut buf = [0u8; 116];
        let mut xdr = XdrHandle::new();
        let netname = std::ffi::CString::new("unix.1000@net").unwrap();
        let mut arg = KeyNetstArg {
            priv_key: std::array::from_fn(|i| i as u8),
            pub_key: std::array::from_fn(|i| 128 + i as u8),
            netname: netname.as_ptr() as *mut c_char,
        };
        let mut expected = Vec::new();
        expected.extend_from_slice(&arg.priv_key);
        expected.extend_from_slice(&arg.pub_key);
        expected.extend_from_slice(&13u32.to_be_bytes());
        expected.extend_from_slice(netname.as_bytes());
        expected.extend_from_slice(&[0; 3]);
        // SAFETY: both arrays have their public width and netname is a live
        // borrowed string. The selected provider supplies its own XDR stream.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 116, XDR_ENCODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), (&mut arg as *mut KeyNetstArg).cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(buf.as_slice(), expected, "{name}: exact key_netstarg wire");
        let mut out = KeyNetstArg {
            priv_key: [0; 48],
            pub_key: [0; 48],
            netname: std::ptr::null_mut(),
        };
        // SAFETY: the initialized destination requests an owned decoded name.
        unsafe {
            memory(xdr.as_mut_ptr(), buf.as_mut_ptr().cast(), 116, XDR_DECODE);
            assert_eq!(
                codec(xdr.as_mut_ptr(), (&mut out as *mut KeyNetstArg).cast()),
                1,
                "{name}"
            );
        }
        assert_eq!(out.priv_key, arg.priv_key, "{name}");
        assert_eq!(out.pub_key, arg.pub_key, "{name}");
        assert!(!out.netname.is_null(), "{name}");
        assert_ne!(out.netname, arg.netname, "{name}: decoded name ownership");
        // SAFETY: successful decode returned a NUL-terminated name.
        assert_eq!(
            unsafe { std::ffi::CStr::from_ptr(out.netname) },
            netname.as_c_str(),
            "{name}"
        );
        // SAFETY: only the decoded name is owned by this XDR provider.
        unsafe { release(codec as *mut c_void, (&mut out as *mut KeyNetstArg).cast()) };
        assert!(out.netname.is_null(), "{name}: decoded name cleanup");
    }
}

#[test]
fn xdr_rmtcallres_roundtrip() {
    let mut buf = [0u8; 256];
    let mut xdr = XdrHandle::new();

    #[repr(C)]
    struct RmtCallRes {
        port_ptr: *mut c_ulong,
        resultslen: c_ulong,
        results_ptr: *mut c_char,
        xdr_results: *mut c_void,
    }

    let mut port: c_ulong = 111;
    let mut result: c_int = 42;
    let mut res = RmtCallRes {
        port_ptr: &mut port,
        resultslen: 4,
        results_ptr: (&mut result as *mut c_int).cast(),
        xdr_results: xdr_int as *mut c_void,
    };

    xdr_encode(&mut xdr, &mut buf);
    assert_eq!(
        unsafe { xdr_rmtcallres(xdr.as_mut_ptr(), (&mut res as *mut RmtCallRes).cast()) },
        1
    );

    xdr_decode(&mut xdr, &mut buf);
    let mut out_result: c_int = 0;
    let mut out = RmtCallRes {
        port_ptr: std::ptr::null_mut(),
        resultslen: 0,
        results_ptr: (&mut out_result as *mut c_int).cast(),
        xdr_results: xdr_int as *mut c_void,
    };
    assert_eq!(
        unsafe { xdr_rmtcallres(xdr.as_mut_ptr(), (&mut out as *mut RmtCallRes).cast()) },
        1
    );

    assert!(!out.port_ptr.is_null());
    assert_eq!(unsafe { *out.port_ptr } as u32, 111);
    assert_eq!(out.resultslen as u32, 4);
    assert_eq!(out_result, 42);

    unsafe { frankenlibc_abi::malloc_abi::free(out.port_ptr.cast()) };
}

// ===========================================================================
// 35. XDR record stream encode/decode (functional test with pipe)
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

    unsafe { frankenlibc_abi::malloc_abi::free(out_ptr.cast()) };
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

#[test]
fn xdr_array_rejects_impossible_known_codec_counts_without_allocating() {
    let codecs = [
        ("char", xdr_char as *mut c_void, 1),
        ("int", xdr_int as *mut c_void, 4),
        ("long", xdr_long as *mut c_void, 8),
        ("unsigned long", xdr_u_long as *mut c_void, 8),
        ("hyper", xdr_hyper as *mut c_void, 8),
        ("float", xdr_float as *mut c_void, 4),
        ("double", xdr_double as *mut c_void, 8),
        ("string", xdr_wrapstring as *mut c_void, 8),
    ];
    for (name, codec, stride) in codecs {
        // The product count*stride still fits u32, so only a sound wire-width
        // bound prevents the huge allocation. Do not run this hostile input
        // through the host oracle, which need not provide this admission guard.
        let mut wire = [0u8; 16];
        wire[..4].copy_from_slice(&0x1000_0000u32.to_be_bytes());
        let mut stream = XdrHandle::new();
        xdr_decode(&mut stream, &mut wire);
        let mut data = std::ptr::null_mut();
        let mut count = 0;
        // SAFETY: all inputs and the matching built-in codec are live; rejection
        // must happen before the declared oversized object can be allocated.
        assert_eq!(
            unsafe {
                xdr_array(
                    stream.as_mut_ptr(),
                    &mut data,
                    &mut count,
                    c_uint::MAX,
                    stride,
                    codec,
                )
            },
            0,
            "{name} must reject an impossible count"
        );
        assert_eq!(count, 0x1000_0000);
        assert!(data.is_null(), "{name} must reject before allocating");
    }

    // A narrow C char still requires a four-byte XDR integer. This small
    // truncated array checks the bound in the opposite direction from LP64.
    let mut wire = [0, 0, 0, 3, 0, 0, 0, b'a', 0, 0, 0, b'b'];
    let mut stream = XdrHandle::new();
    xdr_decode(&mut stream, &mut wire);
    let mut data = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: the codec matches the declared one-byte element storage.
    assert_eq!(
        unsafe {
            xdr_array(
                stream.as_mut_ptr(),
                &mut data,
                &mut count,
                3,
                1,
                xdr_char as *mut c_void,
            )
        },
        0
    );
    assert!(data.is_null(), "truncated char array must not allocate");
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
// 89. bd-xpgak regression: xdr_reference depth limit on recursive procs
// ===========================================================================
//
// Caller-supplied recursive procs (e.g., generated stubs for self-
// referential XDR types) used to recurse without bound through
// xdr_pointer → xdr_reference → user_proc → xdr_pointer. A wire stream
// of N "more=1" flags consumed N stack frames. Depth limit (256) must
// refuse the over-deep input with XDR_FALSE without crashing.

use frankenlibc_abi::rpc_abi::{xdr_int as xdr_int_ext, xdr_pointer as xdr_pointer_ext};

#[repr(C)]
struct RecursiveNode {
    value: c_int,
    _pad: c_int,
    next: *mut RecursiveNode,
}

unsafe extern "C" fn recursive_proc(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let n = p as *mut RecursiveNode;
    if unsafe { xdr_int_ext(xdrs, &mut (*n).value as *mut c_int) } != 1 {
        return 0;
    }
    // Recursive descent through the pointer field — would stack-overflow
    // without the bd-xpgak depth limit.
    unsafe {
        xdr_pointer_ext(
            xdrs,
            (&mut (*n).next as *mut *mut RecursiveNode).cast(),
            std::mem::size_of::<RecursiveNode>() as c_uint,
            recursive_proc as *mut c_void,
        )
    }
}

#[test]
fn xdr_reference_depth_limit_refuses_deep_recursive_wire_without_overflow() {
    // Build a wire stream of 1024 RecursiveNodes (way past the 256
    // depth limit). Each node = 4 bytes value + xdr_pointer (4 byte
    // more flag). Last node has more=0 to terminate.
    const ENTRIES: usize = 1024;
    // Per node: more=1 (4) + value (4) = 8 bytes; final: more=0 (4)
    let total = ENTRIES * 8 + 4;
    let mut buf = vec![0u8; total];
    // First more flag is implicit (xdr_pointer reads it after we call it
    // from the test). The schema is: pointer→[more, recursive_proc],
    // recursive_proc encodes [value, pointer→[more, recursive_proc...]].
    // For simplicity hand-encode big-endian:
    // outer pointer: more=1 (4), then recursive_proc body (value=42, more=1, value=42, more=1, ...)
    let mut off = 0;
    buf[off..off + 4].copy_from_slice(&1u32.to_be_bytes()); // outer more=1
    off += 4;
    for _ in 0..ENTRIES {
        buf[off..off + 4].copy_from_slice(&42u32.to_be_bytes()); // value
        off += 4;
        buf[off..off + 4].copy_from_slice(&1u32.to_be_bytes()); // next more=1
        off += 4;
    }
    // Last more flag overwritten as 0 (terminator).
    let last_more = off - 4;
    buf[last_more..last_more + 4].copy_from_slice(&0u32.to_be_bytes());

    let mut xdr = XdrHandle::new();
    xdr_decode(&mut xdr, &mut buf);

    let mut head: *mut c_void = std::ptr::null_mut();
    let rc = unsafe {
        xdr_pointer_ext(
            xdr.as_mut_ptr(),
            &mut head as *mut *mut c_void as *mut *mut c_char,
            std::mem::size_of::<RecursiveNode>() as c_uint,
            recursive_proc as *mut c_void,
        )
    };
    // Must refuse — depth limit hit. Return code is 0 (XDR_FALSE).
    // The test must not crash with stack overflow.
    assert_eq!(
        rc, 0,
        "xdr_pointer must refuse 1024-deep recursive stream (depth limit = 256)"
    );
    // Note: head may be partially populated up to depth 256 — that's
    // expected behavior of XDR's allocate-as-you-go contract. We don't
    // free the partial chain because doing so would also recurse and
    // is the caller's responsibility per the XDR mem_alloc/mem_free
    // contract; this test is purely a stack-overflow guard, not a
    // memory-leak harness.
    let _ = head;
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
    let rc = unsafe {
        xdr_pmaplist(
            xdr.as_mut_ptr(),
            &mut head as *mut *mut c_void as *mut c_void,
        )
    };
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
    let rc_free = unsafe {
        xdr_pmaplist(
            free_xdr.as_mut_ptr(),
            &mut head as *mut *mut c_void as *mut c_void,
        )
    };
    assert_eq!(rc_free, 1, "xdr_pmaplist free failed on deep list");
}
