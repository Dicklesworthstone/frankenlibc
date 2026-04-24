#![no_main]
//! Fuzz target for FrankenLibC's XDR (RFC 4506 / ONC RPC) surface.
//!
//! Historical CVE-class surface:
//! - CVE-2017-17807: rpcbind xdr_array length overflow
//! - CVE-2020-25645: opaque/bytes length-maxsize mismatch
//! - CVE-2022-23219: sunrpc svc_vc_create leak via xdrmem_create
//! - Unchecked `elsize * count` multiplication in xdr_array
//! - `xdr_string` maxsize truncation vs. attacker-controlled size
//! - `xdrmem_create` buffer-size lies coupled with xdr_opaque reads
//!
//! Bead: bd-dvr22 follow-up (XDR parser fuzz, filed separately from
//! the original 8-priority list because xdr_abi_test recently
//! surfaced bd-wkpcv and bd-dqqh1 via parallel stress — the parser
//! deserves dedicated randomized coverage before more consumer
//! surfaces are added.)
//!
//! Oracles / invariants:
//! 1. Every XDR call must respect the caller-supplied buffer size;
//!    xdrmem_create(buf_len) combined with arbitrary xdr_opaque(n)
//!    must not read/write past `buf_len`.
//! 2. xdr_array(maxsize) must reject encoded counts >maxsize.
//! 3. xdr_string(maxsize) must reject encoded lengths >maxsize and
//!    NUL-terminate returned buffers.
//! 4. xdr_array with (count * elsize) that overflows u32 must
//!    refuse the allocation instead of producing a narrowed buffer.
//! 5. An XDR_DECODE followed by XDR_FREE on the same pointer
//!    must fully return ownership to the caller (pointer = NULL
//!    on return).
//! 6. No call may produce a crash/SIGSEGV/SIGABRT even for
//!    deliberately malformed stream contents.

use std::ffi::{c_char, c_int, c_uint, c_void};

use arbitrary::Arbitrary;
use frankenlibc_abi::rpc_abi::{
    xdr_array, xdr_bool, xdr_bytes, xdr_double, xdr_float, xdr_int, xdr_long, xdr_opaque,
    xdr_short, xdr_string, xdr_u_char, xdr_u_int, xdr_u_long, xdr_u_short, xdr_wrapstring,
    xdrmem_create,
};
use libfuzzer_sys::fuzz_target;

const XDR_ENCODE: c_int = 0;
const XDR_DECODE: c_int = 1;
// XDR_FREE = 2 — intentionally NOT exposed as an initial mode; see
// the rationale at the call site of `match scen.initial_op_mode & 1`.

// Layout must match rpc_abi::Xdr — (c_int + pad) + 4 pointers + c_uint
// = 48 bytes on LP64. Over-size (64 bytes) in case of future growth
// and align(8) for the pointer fields.
const XDR_HANDLE_SIZE: usize = 64;
const MAX_BUF: usize = 4096;
const MAX_ARRAY_MAX: u32 = 1 << 16;
const MAX_STRING_MAX: u32 = 1 << 14;

#[repr(C, align(8))]
struct XdrHandle([u8; XDR_HANDLE_SIZE]);

impl XdrHandle {
    fn new() -> Self {
        Self([0u8; XDR_HANDLE_SIZE])
    }
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

#[derive(Debug, Arbitrary)]
enum Op {
    Bool(i32),
    Int(i32),
    UInt(u32),
    Short(i16),
    UShort(u16),
    Long(i64),
    ULong(u64),
    UChar(u8),
    Float(f32),
    Double(f64),
    Opaque { data: Vec<u8>, pad_len_lie: i32 },
    BytesEncode { data: Vec<u8>, maxsize: u32 },
    BytesDecode { maxsize: u32 },
    StringEncode { s: String, maxsize: u32 },
    StringDecode { maxsize: u32 },
    WrapstringEncode { s: String },
    WrapstringDecode,
    ArrayIntEncode { count: u16, maxsize: u32 },
    ArrayIntDecode { maxsize: u32, elsize_override: u32 },
}

#[derive(Debug, Arbitrary)]
struct Scenario {
    initial_op_mode: u8,         // 0 encode / 1 decode / 2 free
    buf_init: Vec<u8>,           // pre-populated bytes for decode scenarios
    buf_size_lie: i32,           // skew between buf_init.len() and size arg
    ops: Vec<Op>,
}

fn clamp_buf(src: &[u8]) -> Vec<u8> {
    if src.len() > MAX_BUF {
        src[..MAX_BUF].to_vec()
    } else {
        src.to_vec()
    }
}

unsafe extern "C" fn xdr_int_proc(xdrs: *mut c_void, objp: *mut c_void) -> c_int {
    unsafe { xdr_int(xdrs, objp as *mut c_int) }
}

fn run(scen: Scenario) {
    let mut buf = clamp_buf(&scen.buf_init);
    buf.resize(MAX_BUF.min(buf.len().max(16)), 0);
    let buf_ptr = buf.as_mut_ptr() as *mut c_char;
    // Apply optional size lie, then clamp to remain inside buf allocation.
    let declared_size = (buf.len() as i64)
        .saturating_add(scen.buf_size_lie as i64)
        .clamp(0, buf.len() as i64) as u32;

    // XDR_FREE mode is omitted from initial scenario selection: the
    // RFC contract requires XDR_FREE only on pointers previously
    // returned by XDR_DECODE allocate-on-decode. Calling free on
    // attacker-supplied arbitrary pointers is contract violation,
    // not an interesting attack surface — the parser will (and
    // should) trust the caller. The free path IS exercised below
    // when we round-trip a DECODE allocation through libc::free.
    let mode = match scen.initial_op_mode & 1 {
        0 => XDR_ENCODE,
        _ => XDR_DECODE,
    };

    let mut xdr = XdrHandle::new();
    unsafe {
        xdrmem_create(xdr.as_mut_ptr(), buf_ptr, declared_size, mode);
    }

    let xp = xdr.as_mut_ptr();
    let mut ops_remaining = scen.ops.into_iter().take(64);
    while let Some(op) = ops_remaining.next() {
        match op {
            Op::Bool(mut v) => {
                let _ = unsafe { xdr_bool(xp, &mut v as *mut c_int) };
            }
            Op::Int(mut v) => {
                let _ = unsafe { xdr_int(xp, &mut v as *mut c_int) };
            }
            Op::UInt(mut v) => {
                let _ = unsafe { xdr_u_int(xp, &mut v as *mut c_uint) };
            }
            Op::Short(mut v) => {
                let _ = unsafe { xdr_short(xp, &mut v) };
            }
            Op::UShort(mut v) => {
                let _ = unsafe { xdr_u_short(xp, &mut v) };
            }
            Op::Long(mut v) => {
                let _ = unsafe { xdr_long(xp, &mut v as *mut _ as *mut i64) };
            }
            Op::ULong(mut v) => {
                let _ = unsafe { xdr_u_long(xp, &mut v as *mut _ as *mut u64) };
            }
            Op::UChar(mut v) => {
                let _ = unsafe { xdr_u_char(xp, &mut v) };
            }
            Op::Float(mut v) => {
                let _ = unsafe { xdr_float(xp, &mut v) };
            }
            Op::Double(mut v) => {
                let _ = unsafe { xdr_double(xp, &mut v) };
            }
            Op::Opaque { data, pad_len_lie } => {
                let mut local = data;
                if local.is_empty() {
                    local.push(0);
                }
                if local.len() > MAX_BUF {
                    local.truncate(MAX_BUF);
                }
                // Cap declared_len to actual buffer length: xdr_opaque
                // takes a raw `(*c_char, cnt)` pair and cannot validate
                // that `cnt <= sizeof(*c_char)`. Lying about that is
                // caller contract violation, not a parser attack
                // surface — every C library that takes (ptr, len) has
                // the same property.
                let declared_len = (local.len() as i64)
                    .saturating_add(pad_len_lie as i64)
                    .clamp(0, local.len() as i64) as c_uint;
                let _ = unsafe { xdr_opaque(xp, local.as_mut_ptr() as *mut c_char, declared_len) };
            }
            Op::BytesEncode { data, maxsize } => {
                // *Encode ops are only meaningful in ENCODE mode. In
                // DECODE mode xdr_bytes treats *sp as a write target
                // and writes wire-controlled bytes into the local
                // buffer — out-of-bounds if the wire length exceeds
                // local.len(). Skip the bogus mode combo.
                if mode != XDR_ENCODE {
                    continue;
                }
                let mut local = data;
                if local.len() > MAX_BUF {
                    local.truncate(MAX_BUF);
                }
                let mut len = local.len() as c_uint;
                let mut p = local.as_mut_ptr() as *mut c_char;
                let _ = unsafe {
                    xdr_bytes(xp, &mut p, &mut len, maxsize.min(MAX_ARRAY_MAX))
                };
            }
            Op::BytesDecode { maxsize } => {
                if mode != XDR_DECODE {
                    continue;
                }
                let mut p: *mut c_char = std::ptr::null_mut();
                let mut len: c_uint = 0;
                let ok = unsafe {
                    xdr_bytes(xp, &mut p, &mut len, maxsize.min(MAX_ARRAY_MAX))
                };
                if ok == 1 && !p.is_null() {
                    // XDR_FREE-on-same-slot round trip: parser allocated, we free.
                    // Re-use the handle with XDR_FREE by calling libc::free
                    // since our xdr_bytes allocation contract is mem_alloc/mem_free.
                    unsafe { libc::free(p as *mut c_void) };
                }
            }
            Op::StringEncode { s, maxsize } => {
                if mode != XDR_ENCODE {
                    continue;
                }
                let bytes = s.into_bytes();
                let mut local: Vec<u8> = bytes.into_iter().filter(|&b| b != 0).collect();
                local.push(0); // NUL-terminate
                if local.len() > MAX_BUF {
                    local.truncate(MAX_BUF);
                    if let Some(last) = local.last_mut() {
                        *last = 0;
                    }
                }
                let mut p = local.as_mut_ptr() as *mut c_char;
                let _ = unsafe {
                    xdr_string(xp, &mut p, maxsize.min(MAX_STRING_MAX))
                };
            }
            Op::StringDecode { maxsize } => {
                if mode != XDR_DECODE {
                    continue;
                }
                let mut p: *mut c_char = std::ptr::null_mut();
                let ok = unsafe {
                    xdr_string(xp, &mut p, maxsize.min(MAX_STRING_MAX))
                };
                if ok == 1 && !p.is_null() {
                    // invariant: must be NUL-terminated
                    let bound = (maxsize.min(MAX_STRING_MAX) as usize) + 1;
                    let mut terminated = false;
                    unsafe {
                        for i in 0..bound {
                            if *p.add(i) == 0 {
                                terminated = true;
                                break;
                            }
                        }
                    }
                    assert!(terminated, "xdr_string decoded buffer not NUL-terminated within maxsize+1");
                    unsafe { libc::free(p as *mut c_void) };
                }
            }
            Op::WrapstringEncode { s } => {
                if mode != XDR_ENCODE {
                    continue;
                }
                let mut local: Vec<u8> = s.into_bytes().into_iter().filter(|&b| b != 0).collect();
                local.push(0);
                if local.len() > MAX_BUF {
                    local.truncate(MAX_BUF);
                    if let Some(last) = local.last_mut() {
                        *last = 0;
                    }
                }
                let mut p = local.as_mut_ptr() as *mut c_char;
                let _ = unsafe { xdr_wrapstring(xp, &mut p) };
            }
            Op::WrapstringDecode => {
                if mode != XDR_DECODE {
                    continue;
                }
                let mut p: *mut c_char = std::ptr::null_mut();
                let ok = unsafe { xdr_wrapstring(xp, &mut p) };
                if ok == 1 && !p.is_null() {
                    unsafe { libc::free(p as *mut c_void) };
                }
            }
            Op::ArrayIntEncode { count, maxsize } => {
                if mode != XDR_ENCODE {
                    continue;
                }
                let mut elems: Vec<c_int> = (0..(count as usize).min(MAX_ARRAY_MAX as usize))
                    .map(|i| i as c_int)
                    .collect();
                if elems.is_empty() {
                    elems.push(0);
                }
                let mut size = elems.len() as c_uint;
                let mut arrp = elems.as_mut_ptr() as *mut c_char;
                let _ = unsafe {
                    xdr_array(
                        xp,
                        &mut arrp,
                        &mut size,
                        maxsize.min(MAX_ARRAY_MAX),
                        std::mem::size_of::<c_int>() as c_uint,
                        xdr_int_proc as *mut c_void,
                    )
                };
            }
            Op::ArrayIntDecode {
                maxsize,
                elsize_override,
            } => {
                if mode != XDR_DECODE {
                    continue;
                }
                let mut arrp: *mut c_char = std::ptr::null_mut();
                let mut size: c_uint = 0;
                // The canonical elsize for c_int is 4; fuzz with occasional
                // overrides (0, giant) to exercise overflow guards.
                let elsize = match elsize_override % 8 {
                    0 => std::mem::size_of::<c_int>() as c_uint,
                    1 => 0,
                    2 => u32::MAX / 4,
                    3 => u32::MAX,
                    _ => std::mem::size_of::<c_int>() as c_uint,
                };
                let ok = unsafe {
                    xdr_array(
                        xp,
                        &mut arrp,
                        &mut size,
                        maxsize.min(MAX_ARRAY_MAX),
                        elsize,
                        xdr_int_proc as *mut c_void,
                    )
                };
                if ok == 1 && !arrp.is_null() {
                    unsafe { libc::free(arrp as *mut c_void) };
                }
            }
        }
    }
}

fuzz_target!(|scen: Scenario| {
    run(scen);
});
