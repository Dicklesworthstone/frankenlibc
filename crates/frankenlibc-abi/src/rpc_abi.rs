//! ABI layer for Sun RPC / XDR / SVC functions.
//!
//! These are legacy ONC RPC functions from glibc's `<rpc/rpc.h>`, `<rpc/xdr.h>`,
//! `<rpc/svc.h>`, `<rpc/clnt.h>`, `<rpc/auth.h>`, `<rpc/pmap_clnt.h>`, and
//! `<rpc/des_crypt.h>` families. XDR serialisation is natively implemented in
//! pure Rust. RPC client/server/auth functions return deterministic safe
//! defaults (null handles, 0/failure status) since Sun RPC is a legacy
//! subsystem and the internal RPC runtime state is not needed.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use std::ffi::{c_char, c_int, c_uint, c_void};

use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

/// Read a user-supplied C string pointer with a known-region bound so a
/// non-NUL-terminated argument cannot walk arbitrary process memory through
/// `CStr::from_ptr`. Returns `None` for null or unterminated input.
/// (REVIEW round 5 — same defense class as bd-z4k96 / iconv_open / dlopen /
/// inet_pton / execvp.)
#[inline]
unsafe fn read_bounded_cstr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    Some(bytes.to_vec())
}

type c_ulong = u64;
#[allow(dead_code)]
type c_long = i64;

/// `struct timeval` for by-value parameters in clntudp_create / pmap_rmtcall.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: c_long,
    pub tv_usec: c_long,
}

// ---------------------------------------------------------------------------
// Native safe-default macro for RPC functions
// ---------------------------------------------------------------------------
// Sun RPC is a legacy subsystem. Instead of delegating to host glibc via
// dlsym(RTLD_NEXT), we return deterministic safe defaults:
//   - c_int → 0 (FALSE / failure)
//   - *mut c_void → null (handle creation failed)
//   - () → no-op
//   - *mut c_char → null (no error string)
//   - c_ulong → 0
//   - u16 → 0
// This eliminates the last glibc call-through dependency for RPC symbols.
/// Deterministic safe-default macro for RPC functions.
///
/// Sun RPC is a legacy subsystem. Rather than delegating to host glibc,
/// we return deterministic safe defaults directly:
///   - c_int → 0 (FALSE / failure)
///   - *mut c_void → null (handle creation failed)
///   - () → no-op
///   - *mut c_char → null (no error string)
///   - c_ulong → 0
///   - u16 → 0
macro_rules! rpc_native {
    // Pattern 1: function returning c_int
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> c_int) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname: $pty),* ) -> c_int {
            $( let _ = $pname; )*
            0
        }
    };
    // Pattern 2: function returning *mut c_void
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> *mut c_void) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname: $pty),* ) -> *mut c_void {
            $( let _ = $pname; )*
            std::ptr::null_mut()
        }
    };
    // Pattern 3: function returning ()
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> ()) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname: $pty),* ) {
            $( let _ = $pname; )*
        }
    };
    // Pattern 4: function returning c_ulong
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> c_ulong) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname: $pty),* ) -> c_ulong {
            $( let _ = $pname; )*
            0
        }
    };
    // Pattern 5: function returning *mut c_char
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> *mut c_char) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname: $pty),* ) -> *mut c_char {
            $( let _ = $pname; )*
            std::ptr::null_mut()
        }
    };
    // Pattern 6: function returning u16
    ($name:ident ( $($pname:ident : $pty:ty),* ) -> u16) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name( $($pname: $pty),* ) -> u16 {
            $( let _ = $pname; )*
            0
        }
    };
}

// ===========================================================================
// Native XDR Implementation (RFC 4506 / RFC 1832)
//
// Replaces all 68 dlsym-delegated XDR symbols with pure Rust.
// Three stream backends: Memory, Stdio, Record (TCP).
// ===========================================================================

// --- XDR constants ---
const XDR_ENCODE: c_int = 0;
const XDR_DECODE: c_int = 1;
const XDR_FREE: c_int = 2;
const XDR_TRUE: c_int = 1;
const XDR_FALSE: c_int = 0;

// Type alias for XDR procedure (element serializers, union procs, etc.)
type XdrProc = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;

// --- XDR vtable and handle (ABI-compatible with glibc's struct XDR) ---

#[repr(C)]
pub struct Xdr {
    x_op: c_int,
    x_ops: *const XdrOps,
    x_public: *mut c_char,
    x_private: *mut c_void,
    x_base: *mut c_char,
    x_handy: c_uint,
}

#[repr(C)]
struct XdrOps {
    x_getlong: unsafe extern "C" fn(*mut Xdr, *mut c_long) -> c_int,
    x_putlong: unsafe extern "C" fn(*mut Xdr, *const c_long) -> c_int,
    x_getbytes: unsafe extern "C" fn(*mut Xdr, *mut c_char, c_uint) -> c_int,
    x_putbytes: unsafe extern "C" fn(*mut Xdr, *const c_char, c_uint) -> c_int,
    x_getpostn: unsafe extern "C" fn(*const Xdr) -> c_uint,
    x_setpostn: unsafe extern "C" fn(*mut Xdr, c_uint) -> c_int,
    x_inline: unsafe extern "C" fn(*mut Xdr, c_uint) -> *mut i32,
    x_destroy: unsafe extern "C" fn(*mut Xdr),
    x_getint32: unsafe extern "C" fn(*mut Xdr, *mut i32) -> c_int,
    x_putint32: unsafe extern "C" fn(*mut Xdr, *const i32) -> c_int,
}

// --- Vtable dispatch helpers ---
#[inline]
unsafe fn xg32(x: *mut Xdr, ip: *mut i32) -> c_int {
    unsafe { ((*(*x).x_ops).x_getint32)(x, ip) }
}
#[inline]
unsafe fn xp32(x: *mut Xdr, ip: *const i32) -> c_int {
    unsafe { ((*(*x).x_ops).x_putint32)(x, ip) }
}
#[inline]
unsafe fn xgb(x: *mut Xdr, a: *mut c_char, n: c_uint) -> c_int {
    unsafe { ((*(*x).x_ops).x_getbytes)(x, a, n) }
}
#[inline]
unsafe fn xpb(x: *mut Xdr, a: *const c_char, n: c_uint) -> c_int {
    unsafe { ((*(*x).x_ops).x_putbytes)(x, a, n) }
}
#[inline]
const fn rndup(n: usize) -> usize {
    (n + 3) & !3
}

static ZERO_PAD: [u8; 4] = [0; 4];

// ===================== Memory stream backend =====================

unsafe extern "C" fn mem_gi32(x: *mut Xdr, ip: *mut i32) -> c_int {
    let x = unsafe { &mut *x };
    if x.x_handy < 4 {
        return XDR_FALSE;
    }
    x.x_handy -= 4;
    let s = x.x_private as *const u8;
    unsafe {
        *ip = i32::from_be_bytes([*s, *s.add(1), *s.add(2), *s.add(3)]);
        x.x_private = s.add(4) as *mut c_void;
    }
    XDR_TRUE
}
unsafe extern "C" fn mem_pi32(x: *mut Xdr, ip: *const i32) -> c_int {
    let x = unsafe { &mut *x };
    if x.x_handy < 4 {
        return XDR_FALSE;
    }
    x.x_handy -= 4;
    let b = unsafe { (*ip).to_be_bytes() };
    let d = x.x_private as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(b.as_ptr(), d, 4);
        x.x_private = d.add(4) as *mut c_void;
    }
    XDR_TRUE
}
unsafe extern "C" fn mem_glong(x: *mut Xdr, lp: *mut c_long) -> c_int {
    let mut t: i32 = 0;
    if unsafe { mem_gi32(x, &mut t) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe {
        *lp = t as c_long;
    }
    XDR_TRUE
}
unsafe extern "C" fn mem_plong(x: *mut Xdr, lp: *const c_long) -> c_int {
    let t = unsafe { *lp } as i32;
    unsafe { mem_pi32(x, &t) }
}
unsafe extern "C" fn mem_gb(x: *mut Xdr, a: *mut c_char, n: c_uint) -> c_int {
    let x = unsafe { &mut *x };
    if x.x_handy < n {
        return XDR_FALSE;
    }
    x.x_handy -= n;
    unsafe {
        std::ptr::copy_nonoverlapping(x.x_private as *const u8, a as *mut u8, n as usize);
        x.x_private = (x.x_private as *mut u8).add(n as usize) as *mut c_void;
    }
    XDR_TRUE
}
unsafe extern "C" fn mem_pb(x: *mut Xdr, a: *const c_char, n: c_uint) -> c_int {
    let x = unsafe { &mut *x };
    if x.x_handy < n {
        return XDR_FALSE;
    }
    x.x_handy -= n;
    unsafe {
        std::ptr::copy_nonoverlapping(a as *const u8, x.x_private as *mut u8, n as usize);
        x.x_private = (x.x_private as *mut u8).add(n as usize) as *mut c_void;
    }
    XDR_TRUE
}
unsafe extern "C" fn mem_pos(x: *const Xdr) -> c_uint {
    let x = unsafe { &*x };
    (x.x_private as usize - x.x_base as usize) as c_uint
}
unsafe extern "C" fn mem_setpos(x: *mut Xdr, pos: c_uint) -> c_int {
    let x = unsafe { &mut *x };
    let total = (x.x_private as usize - x.x_base as usize) as c_uint + x.x_handy;
    if pos > total {
        return XDR_FALSE;
    }
    x.x_private = unsafe { x.x_base.add(pos as usize) as *mut c_void };
    x.x_handy = total - pos;
    XDR_TRUE
}
unsafe extern "C" fn mem_inline(x: *mut Xdr, len: c_uint) -> *mut i32 {
    let x = unsafe { &mut *x };
    if x.x_handy < len {
        return std::ptr::null_mut();
    }
    x.x_handy -= len;
    let p = x.x_private as *mut i32;
    x.x_private = unsafe { (x.x_private as *mut u8).add(len as usize) as *mut c_void };
    p
}
unsafe extern "C" fn mem_destroy(_x: *mut Xdr) {}

static XDRMEM_OPS: XdrOps = XdrOps {
    x_getlong: mem_glong,
    x_putlong: mem_plong,
    x_getbytes: mem_gb,
    x_putbytes: mem_pb,
    x_getpostn: mem_pos,
    x_setpostn: mem_setpos,
    x_inline: mem_inline,
    x_destroy: mem_destroy,
    x_getint32: mem_gi32,
    x_putint32: mem_pi32,
};

/// Create a memory-backed XDR stream. Native implementation (RFC 4506).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdrmem_create(
    xdrs: *mut c_void,
    addr: *mut c_char,
    size: c_uint,
    op: c_int,
) {
    let (_, decision) = runtime_policy::decide(
        ApiFamily::Stdio,
        addr as usize,
        size as usize,
        true,
        true,
        0,
    );
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
        return;
    }

    let x = xdrs as *mut Xdr;
    unsafe {
        (*x).x_op = op;
        (*x).x_ops = &XDRMEM_OPS;
        (*x).x_private = addr as *mut c_void;
        (*x).x_base = addr;
        (*x).x_handy = size;
        (*x).x_public = std::ptr::null_mut();
    }
    runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, false);
}

// ===================== Stdio stream backend =====================

unsafe extern "C" fn stdio_gi32(x: *mut Xdr, ip: *mut i32) -> c_int {
    let f = unsafe { (*x).x_private };
    let mut buf = [0u8; 4];
    if unsafe { crate::stdio_abi::fread(buf.as_mut_ptr().cast(), 1, 4, f.cast()) } != 4 {
        return XDR_FALSE;
    }
    unsafe {
        *ip = i32::from_be_bytes(buf);
    }
    XDR_TRUE
}
unsafe extern "C" fn stdio_pi32(x: *mut Xdr, ip: *const i32) -> c_int {
    let f = unsafe { (*x).x_private };
    let buf = unsafe { (*ip).to_be_bytes() };
    if unsafe { crate::stdio_abi::fwrite(buf.as_ptr().cast(), 1, 4, f.cast()) } != 4 {
        return XDR_FALSE;
    }
    XDR_TRUE
}
unsafe extern "C" fn stdio_glong(x: *mut Xdr, lp: *mut c_long) -> c_int {
    let mut t: i32 = 0;
    if unsafe { stdio_gi32(x, &mut t) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe {
        *lp = t as c_long;
    }
    XDR_TRUE
}
unsafe extern "C" fn stdio_plong(x: *mut Xdr, lp: *const c_long) -> c_int {
    let t = unsafe { *lp } as i32;
    unsafe { stdio_pi32(x, &t) }
}
unsafe extern "C" fn stdio_gb(x: *mut Xdr, a: *mut c_char, n: c_uint) -> c_int {
    if n == 0 {
        return XDR_TRUE;
    }
    let f = unsafe { (*x).x_private };
    if unsafe { crate::stdio_abi::fread(a.cast(), 1, n as usize, f.cast()) } as c_uint != n {
        return XDR_FALSE;
    }
    XDR_TRUE
}
unsafe extern "C" fn stdio_pb(x: *mut Xdr, a: *const c_char, n: c_uint) -> c_int {
    if n == 0 {
        return XDR_TRUE;
    }
    let f = unsafe { (*x).x_private };
    if unsafe { crate::stdio_abi::fwrite(a.cast(), 1, n as usize, f.cast()) } as c_uint != n {
        return XDR_FALSE;
    }
    XDR_TRUE
}
unsafe extern "C" fn stdio_pos(x: *const Xdr) -> c_uint {
    unsafe { crate::stdio_abi::ftell((*x).x_private.cast()) as c_uint }
}
unsafe extern "C" fn stdio_setpos(x: *mut Xdr, pos: c_uint) -> c_int {
    if unsafe { crate::stdio_abi::fseek((*x).x_private.cast(), pos as c_long, libc::SEEK_SET) } == 0
    {
        XDR_TRUE
    } else {
        XDR_FALSE
    }
}
unsafe extern "C" fn stdio_inline(_x: *mut Xdr, _n: c_uint) -> *mut i32 {
    std::ptr::null_mut()
}
unsafe extern "C" fn stdio_destroy(x: *mut Xdr) {
    if !unsafe { (*x).x_private.is_null() } {
        unsafe {
            crate::stdio_abi::fflush((*x).x_private.cast());
        }
    }
}

static XDRSTDIO_OPS: XdrOps = XdrOps {
    x_getlong: stdio_glong,
    x_putlong: stdio_plong,
    x_getbytes: stdio_gb,
    x_putbytes: stdio_pb,
    x_getpostn: stdio_pos,
    x_setpostn: stdio_setpos,
    x_inline: stdio_inline,
    x_destroy: stdio_destroy,
    x_getint32: stdio_gi32,
    x_putint32: stdio_pi32,
};

/// Create a stdio-backed XDR stream. Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdrstdio_create(xdrs: *mut c_void, file: *mut c_void, op: c_int) {
    let x = xdrs as *mut Xdr;
    unsafe {
        (*x).x_op = op;
        (*x).x_ops = &XDRSTDIO_OPS;
        (*x).x_private = file;
        (*x).x_base = std::ptr::null_mut();
        (*x).x_handy = 0;
        (*x).x_public = std::ptr::null_mut();
    }
}

// ===================== Record stream backend (TCP) =====================

/// Private state for record-marking XDR stream.
#[allow(dead_code)]
struct RecStream {
    out_base: *mut u8,
    out_finger: *mut u8,
    out_boundry: *mut u8,
    frag_header: *mut u32,
    in_base: *mut u8,
    in_finger: *mut u8,
    in_boundry: *mut u8,
    fbtbc: i64,
    last_frag: bool,
    sendsize: c_uint,
    recvsize: c_uint,
    tcp_handle: *mut c_void,
    readit: *mut c_void,  // fn(*mut c_void, *mut c_void, c_int) -> c_int
    writeit: *mut c_void, // fn(*mut c_void, *mut c_void, c_int) -> c_int
    in_haveheader: bool,
}

type RecIo = unsafe extern "C" fn(*mut c_void, *mut c_void, c_int) -> c_int;

impl RecStream {
    unsafe fn flush_out(&mut self, eor: bool) -> bool {
        let len = self.out_finger as usize - (self.frag_header as *mut u8 as usize) - 4;
        let hdr = if eor {
            len as u32 | 0x80000000
        } else {
            len as u32
        };
        unsafe {
            std::ptr::write_unaligned(self.frag_header, hdr.to_be());
        }
        let total = self.out_finger as usize - self.out_base as usize;
        let wfn: RecIo = unsafe { std::mem::transmute(self.writeit) };
        let n = unsafe { wfn(self.tcp_handle, self.out_base.cast(), total as c_int) };
        if (n as usize) != total {
            return false;
        }
        self.frag_header = self.out_base as *mut u32;
        self.out_finger = unsafe { self.out_base.add(4) };
        true
    }
    unsafe fn fill_input(&mut self) -> bool {
        let rfn: RecIo = unsafe { std::mem::transmute(self.readit) };
        let want = self.recvsize as c_int;
        let n = unsafe { rfn(self.tcp_handle, self.in_base.cast(), want) };
        if n <= 0 {
            return false;
        }
        self.in_finger = self.in_base;
        self.in_boundry = unsafe { self.in_base.add(n as usize) };
        true
    }
    unsafe fn get_frag_header(&mut self) -> bool {
        let avail = self.in_boundry as usize - self.in_finger as usize;
        if avail < 4 && !unsafe { self.fill_input() } {
            return false;
        }
        let avail = self.in_boundry as usize - self.in_finger as usize;
        if avail < 4 {
            return false;
        }
        let hdr = u32::from_be(unsafe { std::ptr::read_unaligned(self.in_finger as *const u32) });
        self.in_finger = unsafe { self.in_finger.add(4) };
        self.last_frag = hdr & 0x80000000 != 0;
        self.fbtbc = (hdr & 0x7FFFFFFF) as i64;
        self.in_haveheader = true;
        true
    }
}

unsafe extern "C" fn rec_gi32(x: *mut Xdr, ip: *mut i32) -> c_int {
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    let mut buf = [0u8; 4];
    let mut got: usize = 0;
    while got < 4 {
        if rs.fbtbc <= 0 {
            if rs.last_frag {
                return XDR_FALSE;
            }
            if !unsafe { rs.get_frag_header() } {
                return XDR_FALSE;
            }
        }
        let avail =
            ((rs.in_boundry as usize - rs.in_finger as usize) as i64).min(rs.fbtbc) as usize;
        if avail == 0 {
            if !unsafe { rs.fill_input() } {
                return XDR_FALSE;
            }
            continue;
        }
        let take = avail.min(4 - got);
        unsafe {
            std::ptr::copy_nonoverlapping(rs.in_finger, buf.as_mut_ptr().add(got), take);
        }
        rs.in_finger = unsafe { rs.in_finger.add(take) };
        rs.fbtbc -= take as i64;
        got += take;
    }
    unsafe {
        *ip = i32::from_be_bytes(buf);
    }
    XDR_TRUE
}
unsafe extern "C" fn rec_pi32(x: *mut Xdr, ip: *const i32) -> c_int {
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    if (rs.out_boundry as usize - rs.out_finger as usize) < 4 && !unsafe { rs.flush_out(false) } {
        return XDR_FALSE;
    }
    let buf = unsafe { (*ip).to_be_bytes() };
    unsafe {
        std::ptr::copy_nonoverlapping(buf.as_ptr(), rs.out_finger, 4);
        rs.out_finger = rs.out_finger.add(4);
    }
    XDR_TRUE
}
unsafe extern "C" fn rec_glong(x: *mut Xdr, lp: *mut c_long) -> c_int {
    let mut t: i32 = 0;
    if unsafe { rec_gi32(x, &mut t) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe {
        *lp = t as c_long;
    }
    XDR_TRUE
}
unsafe extern "C" fn rec_plong(x: *mut Xdr, lp: *const c_long) -> c_int {
    let t = unsafe { *lp } as i32;
    unsafe { rec_pi32(x, &t) }
}
unsafe extern "C" fn rec_gb(x: *mut Xdr, a: *mut c_char, n: c_uint) -> c_int {
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    let mut out = a as *mut u8;
    let mut rem = n as usize;
    while rem > 0 {
        if rs.fbtbc <= 0 {
            if rs.last_frag {
                return XDR_FALSE;
            }
            if !unsafe { rs.get_frag_header() } {
                return XDR_FALSE;
            }
        }
        let avail =
            ((rs.in_boundry as usize - rs.in_finger as usize) as i64).min(rs.fbtbc) as usize;
        if avail == 0 {
            if !unsafe { rs.fill_input() } {
                return XDR_FALSE;
            }
            continue;
        }
        let take = avail.min(rem);
        unsafe {
            std::ptr::copy_nonoverlapping(rs.in_finger, out, take);
            rs.in_finger = rs.in_finger.add(take);
            out = out.add(take);
        }
        rs.fbtbc -= take as i64;
        rem -= take;
    }
    XDR_TRUE
}
unsafe extern "C" fn rec_pb(x: *mut Xdr, a: *const c_char, n: c_uint) -> c_int {
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    let mut src = a as *const u8;
    let mut rem = n as usize;
    while rem > 0 {
        let avail = rs.out_boundry as usize - rs.out_finger as usize;
        if avail == 0 {
            if !unsafe { rs.flush_out(false) } {
                return XDR_FALSE;
            }
            continue;
        }
        let take = avail.min(rem);
        unsafe {
            std::ptr::copy_nonoverlapping(src, rs.out_finger, take);
            rs.out_finger = rs.out_finger.add(take);
            src = src.add(take);
        }
        rem -= take;
    }
    XDR_TRUE
}
unsafe extern "C" fn rec_pos(_x: *const Xdr) -> c_uint {
    0
}
unsafe extern "C" fn rec_setpos(_x: *mut Xdr, _pos: c_uint) -> c_int {
    XDR_FALSE
}
unsafe extern "C" fn rec_inline(x: *mut Xdr, len: c_uint) -> *mut i32 {
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    if unsafe { (*x).x_op } == XDR_ENCODE {
        let avail = rs.out_boundry as usize - rs.out_finger as usize;
        if avail < len as usize {
            return std::ptr::null_mut();
        }
        let p = rs.out_finger as *mut i32;
        rs.out_finger = unsafe { rs.out_finger.add(len as usize) };
        return p;
    }
    std::ptr::null_mut()
}
unsafe extern "C" fn rec_destroy(x: *mut Xdr) {
    let rs = unsafe { (*x).x_private as *mut RecStream };
    if !rs.is_null() {
        let r = unsafe { &*rs };
        if !r.out_base.is_null() {
            unsafe {
                crate::malloc_abi::raw_free(r.out_base.cast());
            }
        }
        if !r.in_base.is_null() {
            unsafe {
                crate::malloc_abi::raw_free(r.in_base.cast());
            }
        }
        unsafe {
            let _ = Box::from_raw(rs);
        }
    }
}

static XDRREC_OPS: XdrOps = XdrOps {
    x_getlong: rec_glong,
    x_putlong: rec_plong,
    x_getbytes: rec_gb,
    x_putbytes: rec_pb,
    x_getpostn: rec_pos,
    x_setpostn: rec_setpos,
    x_inline: rec_inline,
    x_destroy: rec_destroy,
    x_getint32: rec_gi32,
    x_putint32: rec_pi32,
};

/// Create a record-stream XDR (TCP record marking). Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_create(
    xdrs: *mut c_void,
    sendsize: c_uint,
    recvsize: c_uint,
    handle: *mut c_void,
    readit: *mut c_void,
    writeit: *mut c_void,
) {
    let ss = if sendsize == 0 { 4096 } else { sendsize };
    let rs_val = if recvsize == 0 { 4096 } else { recvsize };
    let out_buf = unsafe { crate::malloc_abi::raw_alloc(ss as usize + 4) as *mut u8 };
    let in_buf = unsafe { crate::malloc_abi::raw_alloc(rs_val as usize) as *mut u8 };
    if out_buf.is_null() || in_buf.is_null() {
        if !out_buf.is_null() {
            unsafe {
                crate::malloc_abi::raw_free(out_buf.cast());
            }
        }
        if !in_buf.is_null() {
            unsafe {
                crate::malloc_abi::raw_free(in_buf.cast());
            }
        }
        return;
    }
    let rs = Box::new(RecStream {
        out_base: out_buf,
        out_finger: unsafe { out_buf.add(4) },
        out_boundry: unsafe { out_buf.add(ss as usize + 4) },
        frag_header: out_buf as *mut u32,
        in_base: in_buf,
        in_finger: in_buf,
        in_boundry: in_buf,
        fbtbc: 0,
        last_frag: false,
        sendsize: ss,
        recvsize: rs_val,
        tcp_handle: handle,
        readit,
        writeit,
        in_haveheader: false,
    });
    let x = xdrs as *mut Xdr;
    unsafe {
        (*x).x_op = 0;
        (*x).x_ops = &XDRREC_OPS;
        (*x).x_private = Box::into_raw(rs) as *mut c_void;
        (*x).x_base = std::ptr::null_mut();
        (*x).x_handy = 0;
        (*x).x_public = std::ptr::null_mut();
    }
}

/// Mark end of a record in an XDR record stream. Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_endofrecord(xdrs: *mut c_void, sendnow: c_int) -> c_int {
    let x = xdrs as *mut Xdr;
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    if unsafe { rs.flush_out(true) } {
        if sendnow == 0 {
            return XDR_TRUE;
        }
        XDR_TRUE
    } else {
        XDR_FALSE
    }
}

/// Check if at end of current record in an XDR record stream. Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_eof(xdrs: *mut c_void) -> c_int {
    let x = xdrs as *mut Xdr;
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    // At EOF when we've consumed all fragment bytes and this is the last fragment
    while rs.fbtbc == 0 {
        if rs.last_frag {
            return XDR_TRUE;
        }
        if !unsafe { rs.get_frag_header() } {
            return XDR_TRUE;
        }
    }
    XDR_FALSE
}

/// Skip to end of current record in an XDR record stream. Native implementation.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdrrec_skiprecord(xdrs: *mut c_void) -> c_int {
    let x = xdrs as *mut Xdr;
    let rs = unsafe { &mut *((*x).x_private as *mut RecStream) };
    loop {
        // Skip remaining bytes in current fragment
        while rs.fbtbc > 0 {
            let avail = (rs.in_boundry as usize - rs.in_finger as usize) as i64;
            if avail <= 0 {
                if !unsafe { rs.fill_input() } {
                    return XDR_FALSE;
                }
                continue;
            }
            let skip = avail.min(rs.fbtbc) as usize;
            rs.in_finger = unsafe { rs.in_finger.add(skip) };
            rs.fbtbc -= skip as i64;
        }
        if rs.last_frag {
            break;
        }
        if !unsafe { rs.get_frag_header() } {
            return XDR_FALSE;
        }
    }
    rs.last_frag = false;
    rs.fbtbc = 0;
    rs.in_haveheader = false;
    XDR_TRUE
}

// ===================== Counting stream (for xdr_sizeof) =====================

unsafe extern "C" fn cnt_gi32(_x: *mut Xdr, _ip: *mut i32) -> c_int {
    XDR_FALSE
}
unsafe extern "C" fn cnt_pi32(x: *mut Xdr, _ip: *const i32) -> c_int {
    unsafe {
        (*x).x_handy += 4;
    }
    XDR_TRUE
}
unsafe extern "C" fn cnt_glong(_x: *mut Xdr, _lp: *mut c_long) -> c_int {
    XDR_FALSE
}
unsafe extern "C" fn cnt_plong(x: *mut Xdr, _lp: *const c_long) -> c_int {
    unsafe {
        (*x).x_handy += 4;
    }
    XDR_TRUE
}
unsafe extern "C" fn cnt_gb(_x: *mut Xdr, _a: *mut c_char, _n: c_uint) -> c_int {
    XDR_FALSE
}
unsafe extern "C" fn cnt_pb(x: *mut Xdr, _a: *const c_char, n: c_uint) -> c_int {
    unsafe {
        (*x).x_handy += n;
    }
    XDR_TRUE
}
unsafe extern "C" fn cnt_pos(x: *const Xdr) -> c_uint {
    unsafe { (*x).x_handy }
}
unsafe extern "C" fn cnt_setpos(_x: *mut Xdr, _p: c_uint) -> c_int {
    XDR_FALSE
}
unsafe extern "C" fn cnt_inline(_x: *mut Xdr, _n: c_uint) -> *mut i32 {
    std::ptr::null_mut()
}
unsafe extern "C" fn cnt_destroy(_x: *mut Xdr) {}

static XDRCNT_OPS: XdrOps = XdrOps {
    x_getlong: cnt_glong,
    x_putlong: cnt_plong,
    x_getbytes: cnt_gb,
    x_putbytes: cnt_pb,
    x_getpostn: cnt_pos,
    x_setpostn: cnt_setpos,
    x_inline: cnt_inline,
    x_destroy: cnt_destroy,
    x_getint32: cnt_gi32,
    x_putint32: cnt_pi32,
};

// ===================== XDR primitive serializers =====================

// --- Void ---

/// XDR void serializer — always returns TRUE (1).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_void() -> c_int {
    XDR_TRUE
}

// --- 32-bit types (use putint32/getint32 directly) ---

macro_rules! xdr_i32_prim {
    ($name:ident, $ty:ty) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(xdrs: *mut c_void, ip: *mut $ty) -> c_int {
            let x = xdrs as *mut Xdr;
            match unsafe { (*x).x_op } {
                XDR_ENCODE => unsafe { xp32(x, ip as *const i32) },
                XDR_DECODE => unsafe { xg32(x, ip as *mut i32) },
                _ => XDR_TRUE,
            }
        }
    };
}

xdr_i32_prim!(xdr_int, c_int);
xdr_i32_prim!(xdr_u_int, c_uint);
xdr_i32_prim!(xdr_int32_t, i32);
xdr_i32_prim!(xdr_uint32_t, u32);
xdr_i32_prim!(xdr_enum, c_int);

/// XDR bool: normalizes to 0/1 on both encode and decode (matches glibc).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_bool(xdrs: *mut c_void, bp: *mut c_int) -> c_int {
    let x = xdrs as *mut Xdr;
    match unsafe { (*x).x_op } {
        XDR_ENCODE => {
            let v: i32 = if unsafe { *bp } != 0 { 1 } else { 0 };
            unsafe { xp32(x, &v) }
        }
        XDR_DECODE => {
            let mut v: i32 = 0;
            if unsafe { xg32(x, &mut v) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe {
                *bp = if v != 0 { 1 } else { 0 };
            }
            XDR_TRUE
        }
        _ => XDR_TRUE,
    }
}

// --- Narrowing types (widen to i32 for XDR, narrow on decode) ---

macro_rules! xdr_narrow_prim {
    ($name:ident, $ty:ty) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(xdrs: *mut c_void, sp: *mut $ty) -> c_int {
            let x = xdrs as *mut Xdr;
            match unsafe { (*x).x_op } {
                XDR_ENCODE => {
                    let v = unsafe { *sp } as i32;
                    unsafe { xp32(x, &v) }
                }
                XDR_DECODE => {
                    let mut v: i32 = 0;
                    if unsafe { xg32(x, &mut v) } != XDR_TRUE {
                        return XDR_FALSE;
                    }
                    unsafe {
                        *sp = v as $ty;
                    }
                    XDR_TRUE
                }
                _ => XDR_TRUE,
            }
        }
    };
}

xdr_narrow_prim!(xdr_short, i16);
xdr_narrow_prim!(xdr_u_short, u16);
xdr_narrow_prim!(xdr_char, c_char);
xdr_narrow_prim!(xdr_u_char, u8);
xdr_narrow_prim!(xdr_int8_t, i8);
xdr_narrow_prim!(xdr_int16_t, i16);
xdr_narrow_prim!(xdr_uint8_t, u8);
xdr_narrow_prim!(xdr_uint16_t, u16);

// --- Long types (64-bit C long → 32-bit XDR) ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_long(xdrs: *mut c_void, lp: *mut c_long) -> c_int {
    let x = xdrs as *mut Xdr;
    match unsafe { (*x).x_op } {
        XDR_ENCODE => {
            let v = unsafe { *lp } as i32;
            unsafe { xp32(x, &v) }
        }
        XDR_DECODE => {
            let mut v: i32 = 0;
            if unsafe { xg32(x, &mut v) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe {
                *lp = v as c_long;
            }
            XDR_TRUE
        }
        _ => XDR_TRUE,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_u_long(xdrs: *mut c_void, lp: *mut c_ulong) -> c_int {
    let x = xdrs as *mut Xdr;
    match unsafe { (*x).x_op } {
        XDR_ENCODE => {
            let v = unsafe { *lp } as i32;
            unsafe { xp32(x, &v) }
        }
        XDR_DECODE => {
            let mut v: i32 = 0;
            if unsafe { xg32(x, &mut v) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe {
                *lp = v as c_long as c_ulong;
            }
            XDR_TRUE
        }
        _ => XDR_TRUE,
    }
}

// --- 64-bit types (two 32-bit XDR units, high word first) ---

macro_rules! xdr_i64_prim {
    ($name:ident, $ty:ty) => {
        #[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(xdrs: *mut c_void, hp: *mut $ty) -> c_int {
            let x = xdrs as *mut Xdr;
            match unsafe { (*x).x_op } {
                XDR_ENCODE => {
                    let v = unsafe { *hp } as u64;
                    let hi = (v >> 32) as i32;
                    let lo = v as i32;
                    if unsafe { xp32(x, &hi) } != XDR_TRUE {
                        return XDR_FALSE;
                    }
                    unsafe { xp32(x, &lo) }
                }
                XDR_DECODE => {
                    let (mut hi, mut lo): (i32, i32) = (0, 0);
                    if unsafe { xg32(x, &mut hi) } != XDR_TRUE {
                        return XDR_FALSE;
                    }
                    if unsafe { xg32(x, &mut lo) } != XDR_TRUE {
                        return XDR_FALSE;
                    }
                    unsafe {
                        *hp = (((hi as u32 as u64) << 32) | (lo as u32 as u64)) as $ty;
                    }
                    XDR_TRUE
                }
                _ => XDR_TRUE,
            }
        }
    };
}

xdr_i64_prim!(xdr_hyper, i64);
xdr_i64_prim!(xdr_u_hyper, u64);
xdr_i64_prim!(xdr_longlong_t, i64);
xdr_i64_prim!(xdr_u_longlong_t, u64);
xdr_i64_prim!(xdr_quad_t, i64);
xdr_i64_prim!(xdr_u_quad_t, u64);
xdr_i64_prim!(xdr_int64_t, i64);
xdr_i64_prim!(xdr_uint64_t, u64);

// --- Float/double: IEEE 754 bit pattern as 32/64-bit XDR ---

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_float(xdrs: *mut c_void, fp: *mut f32) -> c_int {
    // Float shares the same 32-bit big-endian encoding as int
    unsafe { xdr_int(xdrs, fp as *mut c_int) }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_double(xdrs: *mut c_void, dp: *mut f64) -> c_int {
    // Double shares the same 64-bit big-endian encoding as hyper
    unsafe { xdr_hyper(xdrs, dp as *mut i64) }
}

// ===================== XDR composite serializers =====================

/// Serialize fixed-length opaque data with padding to 4-byte boundary.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_opaque(xdrs: *mut c_void, cp: *mut c_char, cnt: c_uint) -> c_int {
    if cnt == 0 {
        return XDR_TRUE;
    }
    let x = xdrs as *mut Xdr;
    let pad = (rndup(cnt as usize) - cnt as usize) as c_uint;
    match unsafe { (*x).x_op } {
        XDR_ENCODE => {
            if unsafe { xpb(x, cp, cnt) } != XDR_TRUE {
                return XDR_FALSE;
            }
            if pad > 0 && unsafe { xpb(x, ZERO_PAD.as_ptr().cast(), pad) } != XDR_TRUE {
                return XDR_FALSE;
            }
            XDR_TRUE
        }
        XDR_DECODE => {
            if unsafe { xgb(x, cp, cnt) } != XDR_TRUE {
                return XDR_FALSE;
            }
            if pad > 0 {
                let mut d = [0u8; 4];
                if unsafe { xgb(x, d.as_mut_ptr().cast(), pad) } != XDR_TRUE {
                    return XDR_FALSE;
                }
            }
            XDR_TRUE
        }
        _ => XDR_TRUE,
    }
}

/// Return the remaining unread byte count for an `xdrmem` stream, or
/// `None` if the stream uses a different backend (rec/stdio) where the
/// remaining length is not directly observable.
///
/// Used by xdr_string / xdr_bytes / xdr_array DECODE paths to bound
/// caller-supplied lengths against the actual stream size BEFORE
/// allocating, defending against attacker-supplied 4 GiB length lies
/// that pass `maxsize` checks (bd-bhqcn, CVE-2017-17807 / -2020-25645
/// / -2022-23219 family).
#[inline]
fn xdrmem_remaining_bytes(xdrs: *mut c_void) -> Option<c_uint> {
    let x = xdrs as *mut Xdr;
    if x.is_null() {
        return None;
    }
    // SAFETY: xdrs is a caller-owned Xdr handle; we read the immutable
    // ops vtable pointer and the length-of-remaining-bytes counter.
    let ops = unsafe { (*x).x_ops };
    if std::ptr::eq(ops, &XDRMEM_OPS as *const XdrOps) {
        Some(unsafe { (*x).x_handy })
    } else {
        None
    }
}

/// Round `n` up to the next multiple of 4 (XDR's natural unit), saturating
/// at u32::MAX so we never wrap around. The decoded payload of a length-
/// prefixed XDR opaque is always 4-byte padded.
#[inline]
fn xdr_padded_len(n: c_uint) -> c_uint {
    n.saturating_add(3) & !3
}

/// Serialize counted bytes (length-prefixed, malloc on decode).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_bytes(
    xdrs: *mut c_void,
    sp: *mut *mut c_char,
    lp: *mut c_uint,
    maxsize: c_uint,
) -> c_int {
    let x = xdrs as *mut Xdr;
    match unsafe { (*x).x_op } {
        XDR_ENCODE => {
            let len = unsafe { *lp };
            if len > maxsize {
                return XDR_FALSE;
            }
            if unsafe { xdr_u_int(xdrs, lp) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe { xdr_opaque(xdrs, *sp, len) }
        }
        XDR_DECODE => {
            if unsafe { xdr_u_int(xdrs, lp) } != XDR_TRUE {
                return XDR_FALSE;
            }
            let len = unsafe { *lp };
            if len > maxsize {
                return XDR_FALSE;
            }
            if len == 0 {
                return XDR_TRUE;
            }
            // Defense in depth (bd-bhqcn): for xdrmem streams, refuse a
            // decoded length whose padded payload cannot fit in the
            // remaining stream. xdr_opaque would later catch this via
            // xgb, but only after we've already malloc'd the
            // attacker-supplied size — a 4 GiB length lie would OOM
            // before reaching the stream check.
            if let Some(remaining) = xdrmem_remaining_bytes(xdrs)
                && xdr_padded_len(len) > remaining
            {
                return XDR_FALSE;
            }
            if unsafe { (*sp).is_null() } {
                // Caller frees via libc::free per RFC 1832 mem_free contract;
                // raw_alloc may bump-fallback under parallel REENTRY pressure
                // and produce pointers glibc cannot free. (bd-zgifl)
                let buf = unsafe { libc::malloc(len as usize) as *mut c_char };
                if buf.is_null() {
                    return XDR_FALSE;
                }
                unsafe {
                    *sp = buf;
                }
            }
            unsafe { xdr_opaque(xdrs, *sp, len) }
        }
        XDR_FREE => {
            let p = unsafe { *sp };
            if !p.is_null() {
                unsafe {
                    libc::free(p.cast());
                    *sp = std::ptr::null_mut();
                }
            }
            XDR_TRUE
        }
        _ => XDR_FALSE,
    }
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_string(
    xdrs: *mut c_void,
    sp: *mut *mut c_char,
    maxsize: c_uint,
) -> c_int {
    if sp.is_null() {
        return XDR_FALSE;
    }

    let x = xdrs as *mut Xdr;
    let op = unsafe { (*x).x_op };
    let mut size: c_uint = match op {
        XDR_ENCODE | XDR_FREE => {
            let s = unsafe { *sp };
            if s.is_null() {
                return if op == XDR_FREE { XDR_TRUE } else { XDR_FALSE };
            }
            // Validate the string pointer before reading length.
            let (_, decision) =
                runtime_policy::decide(ApiFamily::Stdio, s as usize, 0, true, false, 0);
            if matches!(decision.action, MembraneAction::Deny) {
                runtime_policy::observe(ApiFamily::Stdio, decision.profile, 5, true);
                return XDR_FALSE;
            }
            (unsafe { crate::string_abi::strlen(s) }) as c_uint
        }
        _ => 0,
    };
    if unsafe { xdr_u_int(xdrs, &mut size) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if size > maxsize {
        return XDR_FALSE;
    }
    // Defense in depth (bd-bhqcn): refuse a decoded length whose
    // padded payload would overrun the xdrmem stream. xdr_wrapstring
    // passes maxsize=u32::MAX per RFC contract, so the maxsize check
    // alone leaves a 4 GiB allocation primitive for attackers.
    if op == XDR_DECODE
        && let Some(remaining) = xdrmem_remaining_bytes(xdrs)
        && xdr_padded_len(size) > remaining
    {
        return XDR_FALSE;
    }
    if op == XDR_DECODE && unsafe { (*sp).is_null() } {
        // mem_alloc semantics: caller frees via libc free (bd-zgifl).
        let buf = unsafe { libc::malloc(size as usize + 1) as *mut c_char };
        if buf.is_null() {
            return XDR_FALSE;
        }
        unsafe {
            *sp = buf;
        }
    }

    // Validate the buffer for the actual data transfer.
    if op == XDR_ENCODE || op == XDR_DECODE {
        let s = unsafe { *sp };
        let (_, decision) =
            runtime_policy::decide(ApiFamily::Stdio, s as usize, size as usize, true, true, 0);
        if matches!(decision.action, MembraneAction::Deny) {
            runtime_policy::observe(ApiFamily::Stdio, decision.profile, 10, true);
            return XDR_FALSE;
        }
    }

    let result = unsafe { xdr_opaque(xdrs, *sp, size) };
    if result == XDR_TRUE && op == XDR_DECODE {
        let p = unsafe { *sp };
        if !p.is_null() {
            unsafe {
                *p.add(size as usize) = 0;
            }
        }
    }
    if op == XDR_FREE {
        let p = unsafe { *sp };
        if !p.is_null() {
            unsafe {
                libc::free(p.cast());
                *sp = std::ptr::null_mut();
            }
        }
    }
    result
}

/// Serialize a string with no maximum length limit.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_wrapstring(xdrs: *mut c_void, sp: *mut *mut c_char) -> c_int {
    unsafe { xdr_string(xdrs, sp, c_uint::MAX) }
}

/// Serialize a variable-length array (count + elements).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_array(
    xdrs: *mut c_void,
    arrp: *mut *mut c_char,
    sizep: *mut c_uint,
    maxsize: c_uint,
    elsize: c_uint,
    elproc: *mut c_void,
) -> c_int {
    let x = xdrs as *mut Xdr;
    let op = unsafe { (*x).x_op };
    if unsafe { xdr_u_int(xdrs, sizep) } != XDR_TRUE {
        return XDR_FALSE;
    }
    let c = unsafe { *sizep };
    if c > maxsize && op != XDR_FREE {
        return XDR_FALSE;
    }
    if c == 0 {
        return XDR_TRUE;
    }
    // Reject elsize=0 outright: an array of zero-size elements is
    // nonsensical, but a caller (or attacker who controls a
    // generated-stub call site) supplying elsize=0 with a non-zero
    // count drops the overflow check below and ends up calling the
    // per-element proc on a 1-byte malloc, causing the element proc
    // to write past the allocation. Found by fuzz_xdr (bd-bhqcn).
    if elsize == 0 && c != 0 && op != XDR_FREE {
        return XDR_FALSE;
    }
    if elsize > 0 && c > u32::MAX / elsize && op != XDR_FREE {
        return XDR_FALSE;
    }
    // Defense in depth (bd-bhqcn): refuse an attacker-supplied count
    // whose total wire footprint cannot fit in the remaining xdrmem
    // stream. We treat each element as at least `elsize` wire bytes —
    // the per-element xdr proc may consume more (variable-length
    // members), but cannot consume less, so this is a sound lower
    // bound for the malloc-blocking check.
    if op == XDR_DECODE
        && elsize > 0
        && let Some(remaining) = xdrmem_remaining_bytes(xdrs)
        && (c as u64).saturating_mul(elsize as u64) > remaining as u64
    {
        return XDR_FALSE;
    }
    let target = if op == XDR_DECODE && unsafe { (*arrp).is_null() } {
        let total_bytes = match (c as usize).checked_mul(elsize as usize) {
            Some(b) => b,
            None => return XDR_FALSE,
        };
        // mem_alloc semantics: caller frees via libc free (bd-zgifl).
        let buf = unsafe { libc::malloc(total_bytes) as *mut c_char };
        if buf.is_null() {
            return XDR_FALSE;
        }
        unsafe {
            *arrp = buf;
        }
        buf
    } else {
        unsafe { *arrp }
    };
    let pf: XdrProc = unsafe { std::mem::transmute(elproc) };
    let mut ptr = target;
    for _ in 0..c {
        if unsafe { pf(xdrs, ptr.cast()) } != XDR_TRUE {
            return XDR_FALSE;
        }
        ptr = unsafe { ptr.add(elsize as usize) };
    }
    if op == XDR_FREE {
        let p = unsafe { *arrp };
        if !p.is_null() {
            unsafe {
                libc::free(p.cast());
                *arrp = std::ptr::null_mut();
            }
        }
    }
    XDR_TRUE
}

/// Serialize a fixed-length array (no count on wire).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_vector(
    xdrs: *mut c_void,
    arrp: *mut c_char,
    size: c_uint,
    elsize: c_uint,
    elproc: *mut c_void,
) -> c_int {
    let pf: XdrProc = unsafe { std::mem::transmute(elproc) };
    let mut ptr = arrp;
    for _ in 0..size {
        if unsafe { pf(xdrs, ptr.cast()) } != XDR_TRUE {
            return XDR_FALSE;
        }
        ptr = unsafe { ptr.add(elsize as usize) };
    }
    XDR_TRUE
}

// Per-thread recursion-depth counter for xdr_reference. Caps the
// nesting depth a wire stream can drive through caller-supplied
// recursive procs (e.g., generated stubs for self-referential XDR
// types like `struct tree { tree *left; tree *right; }`). Without
// this cap, a malicious stream of repeated `more=1` flags walks
// xdr_pointer → xdr_reference → user_proc → xdr_pointer recursion
// arbitrarily deep and exhausts the thread stack. (bd-xpgak)
//
// 256 is a generous practical ceiling — real RPC schemas rarely
// nest more than a handful of pointers deep. `Cell<u32>` has a
// trivial drop so this thread_local does NOT register through
// __cxa_thread_atexit_impl (avoids the bd-yf86e init-array
// deadlock class).
const XDR_REFERENCE_DEPTH_LIMIT: u32 = 256;

std::thread_local! {
    static XDR_REFERENCE_DEPTH: std::cell::Cell<u32> = const {
        std::cell::Cell::new(0)
    };
}

/// Serialize a non-null pointer to an object (allocate on decode).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_reference(
    xdrs: *mut c_void,
    pp: *mut *mut c_char,
    size: c_uint,
    proc_: *mut c_void,
) -> c_int {
    // Bounded recursion depth: caller-supplied procs may recursively
    // invoke xdr_pointer/xdr_reference; cap at 256 to prevent
    // wire-controlled stack exhaustion. (bd-xpgak)
    let depth_ok = XDR_REFERENCE_DEPTH
        .try_with(|cell| {
            let current = cell.get();
            if current >= XDR_REFERENCE_DEPTH_LIMIT {
                false
            } else {
                cell.set(current + 1);
                true
            }
        })
        .unwrap_or(false);
    if !depth_ok {
        return XDR_FALSE;
    }

    let x = xdrs as *mut Xdr;
    let op = unsafe { (*x).x_op };
    if unsafe { (*pp).is_null() } {
        if op != XDR_DECODE {
            let _ = XDR_REFERENCE_DEPTH.try_with(|c| c.set(c.get() - 1));
            return XDR_FALSE;
        }
        // mem_alloc semantics: caller frees via libc free (bd-zgifl).
        // Use calloc not malloc so recursive procs that read inner
        // pointer fields (e.g., a `next` link in a self-referential
        // struct) see a well-defined NULL — otherwise the caller's
        // first xdr_pointer call on `&buf->next` reads uninitialized
        // memory as a "pointer" and tries to use it. Mirrors glibc's
        // xdr_reference + memset(buf, 0, size) idiom.
        let buf = unsafe { libc::calloc(1, size as usize) as *mut c_char };
        if buf.is_null() {
            let _ = XDR_REFERENCE_DEPTH.try_with(|c| c.set(c.get() - 1));
            return XDR_FALSE;
        }
        unsafe {
            *pp = buf;
        }
    }
    let pf: XdrProc = unsafe { std::mem::transmute(proc_) };
    let result = unsafe { pf(xdrs, (*pp).cast()) };
    if op == XDR_FREE {
        let p = unsafe { *pp };
        if !p.is_null() {
            unsafe {
                libc::free(p.cast());
                *pp = std::ptr::null_mut();
            }
        }
    }
    let _ = XDR_REFERENCE_DEPTH.try_with(|c| c.set(c.get() - 1));
    result
}

/// Serialize an optional pointer (bool + reference if present).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pointer(
    xdrs: *mut c_void,
    pp: *mut *mut c_char,
    size: c_uint,
    proc_: *mut c_void,
) -> c_int {
    let mut more: c_int = if unsafe { !(*pp).is_null() } { 1 } else { 0 };
    if unsafe { xdr_bool(xdrs, &mut more) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if more == 0 {
        unsafe {
            *pp = std::ptr::null_mut();
        }
        return XDR_TRUE;
    }
    unsafe { xdr_reference(xdrs, pp, size, proc_) }
}

#[repr(C)]
struct XdrDiscrim {
    value: c_int,
    proc_: XdrProc,
}

/// Serialize a discriminated union.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_union(
    xdrs: *mut c_void,
    dscmp: *mut c_int,
    unp: *mut c_char,
    choices: *const c_void,
    dfault: *mut c_void,
) -> c_int {
    if unsafe { xdr_enum(xdrs, dscmp) } != XDR_TRUE {
        return XDR_FALSE;
    }
    let dscm = unsafe { *dscmp };

    // Walk xdr_discrim array. Per glibc ABI, the array is terminated by an
    // entry with a null proc_ function pointer.
    let mut entry = choices as *const XdrDiscrim;
    if !entry.is_null() {
        loop {
            // SAFETY: choices array is terminated by a null proc_ field.
            // We must be careful not to overshoot if the caller provided a bad pointer.
            let e = unsafe { &*entry };
            let p = e.proc_ as *mut c_void;
            if p.is_null() {
                break;
            }
            if e.value == dscm {
                let pf: XdrProc = unsafe { std::mem::transmute(p) };
                return unsafe { pf(xdrs, unp.cast()) };
            }
            entry = unsafe { entry.add(1) };
        }
    }

    if dfault.is_null() {
        return XDR_FALSE;
    }
    let pf: XdrProc = unsafe { std::mem::transmute(dfault) };
    unsafe { pf(xdrs, unp.cast()) }
}

/// Serialize a netobj (length-prefixed opaque, max 1024).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netobj(xdrs: *mut c_void, np: *mut c_void) -> c_int {
    // struct netobj { u_int n_len; [4pad]; char *n_bytes; } — 16 bytes on LP64
    let len_ptr = np as *mut c_uint;
    let bytes_ptr = unsafe { (np as *mut u8).add(8) as *mut *mut c_char };
    unsafe { xdr_bytes(xdrs, bytes_ptr, len_ptr, 1024) }
}

/// Call an XDR proc in FREE mode to release allocated memory.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_free(proc_: *mut c_void, objp: *mut c_char) {
    let mut xh: Xdr = unsafe { std::mem::zeroed() };
    xh.x_op = XDR_FREE;
    let pf: XdrProc = unsafe { std::mem::transmute(proc_) };
    unsafe {
        pf((&mut xh as *mut Xdr).cast(), objp.cast());
    }
}

/// Calculate the XDR-encoded size of data without writing.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_sizeof(func: *mut c_void, data: *mut c_void) -> c_ulong {
    let mut xh: Xdr = unsafe { std::mem::zeroed() };
    xh.x_op = XDR_ENCODE;
    xh.x_ops = &XDRCNT_OPS;
    xh.x_handy = 0;
    let pf: XdrProc = unsafe { std::mem::transmute(func) };
    if unsafe { pf((&mut xh as *mut Xdr).cast(), data) } == XDR_TRUE {
        xh.x_handy as c_ulong
    } else {
        0
    }
}

// ===================== RPC type serializers =====================

// --- RPC struct layouts (glibc ABI-compatible, LP64) ---

const MAX_AUTH_BYTES: c_uint = 400;
const RPC_MSG_VERSION: c_ulong = 2;
const MSG_CALL: c_int = 0;
#[allow(dead_code)]
const MSG_REPLY: c_int = 1;

#[repr(C)]
struct OpaqueAuth {
    oa_flavor: c_int,
    oa_base: *mut c_char,
    oa_length: c_uint,
}

#[repr(C)]
struct Pmap {
    pm_prog: c_ulong,
    pm_vers: c_ulong,
    pm_prot: c_ulong,
    pm_port: c_ulong,
}

#[repr(C)]
struct PmapList {
    pml_map: Pmap,
    pml_next: *mut PmapList,
}

#[repr(C)]
struct AuthUnixParms {
    aup_time: c_ulong,
    aup_machname: *mut c_char,
    aup_uid: u32,
    aup_gid: u32,
    aup_len: c_uint,
    aup_gids: *mut u32,
}

// AcceptedReply: { verf(24), stat(4+4pad), union(16) } = 48 bytes
#[repr(C)]
struct AcceptedReply {
    ar_verf: OpaqueAuth,
    ar_stat: c_int,
    ar_u1: c_ulong,
    ar_u2: c_ulong,
}

// RejectedReply: { stat(4+4pad), union(16) } = 24 bytes
#[repr(C)]
struct RejectedReply {
    rj_stat: c_int,
    rj_u1: c_ulong,
    rj_u2: c_ulong,
}

// RmtCallArgs/Res for portmapper remote call
#[repr(C)]
struct RmtCallArgs {
    prog: c_ulong,
    vers: c_ulong,
    proc_: c_ulong,
    arglen: c_ulong,
    args_ptr: *mut c_char,
    xdr_args: *mut c_void,
}
#[repr(C)]
struct RmtCallRes {
    port_ptr: *mut c_ulong,
    resultslen: c_ulong,
    results_ptr: *mut c_char,
    xdr_results: *mut c_void,
}

// UnixCred: { uid(4), gid(4), gidlen(2), [6pad], gids(*) } = 24 bytes
#[repr(C)]
struct UnixCred {
    uid: u32,
    gid: u32,
    gidlen: i16,
    gids: *mut u32,
}

// --- RPC type XDR functions ---

/// Serialize opaque_auth: flavor(enum) + body(counted bytes).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_opaque_auth(xdrs: *mut c_void, ap: *mut c_void) -> c_int {
    let a = ap as *mut OpaqueAuth;
    if unsafe { xdr_enum(xdrs, &mut (*a).oa_flavor) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_bytes(xdrs, &mut (*a).oa_base, &mut (*a).oa_length, MAX_AUTH_BYTES) }
}

/// Serialize accepted_reply: verf + stat + union(results|versions).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_accepted_reply(xdrs: *mut c_void, ar: *mut c_void) -> c_int {
    let a = ar as *mut AcceptedReply;
    if unsafe { xdr_opaque_auth(xdrs, (&mut (*a).ar_verf as *mut OpaqueAuth).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_enum(xdrs, &mut (*a).ar_stat) } != XDR_TRUE {
        return XDR_FALSE;
    }
    match unsafe { (*a).ar_stat } {
        0 => {
            // SUCCESS: call user proc (ar_u2) on ar_u1
            let proc_p = unsafe { (*a).ar_u2 } as *mut c_void;
            if proc_p.is_null() {
                return XDR_TRUE;
            }
            let pf: XdrProc = unsafe { std::mem::transmute(proc_p) };
            unsafe { pf(xdrs, (*a).ar_u1 as *mut c_void) }
        }
        2 => {
            // PROG_MISMATCH: version range (low, high)
            if unsafe { xdr_u_long(xdrs, &mut (*a).ar_u1) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe { xdr_u_long(xdrs, &mut (*a).ar_u2) }
        }
        _ => XDR_TRUE,
    }
}

/// Serialize rejected_reply: stat + union(versions|auth_error).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rejected_reply(xdrs: *mut c_void, rr: *mut c_void) -> c_int {
    let r = rr as *mut RejectedReply;
    if unsafe { xdr_enum(xdrs, &mut (*r).rj_stat) } != XDR_TRUE {
        return XDR_FALSE;
    }
    match unsafe { (*r).rj_stat } {
        0 => {
            // RPC_MISMATCH
            if unsafe { xdr_u_long(xdrs, &mut (*r).rj_u1) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe { xdr_u_long(xdrs, &mut (*r).rj_u2) }
        }
        1 => {
            // AUTH_ERROR: auth_stat stored in first 4 bytes of union
            unsafe { xdr_enum(xdrs, (&mut (*r).rj_u1 as *mut c_ulong).cast()) }
        }
        _ => XDR_FALSE,
    }
}

/// Serialize reply message: xid + direction + reply_stat + body.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_replymsg(xdrs: *mut c_void, rmsg: *mut c_void) -> c_int {
    // rpc_msg offsets: xid(0,8), direction(8,4+4pad), union(16)
    // reply_body in union: rp_stat(+0,4+4pad), body(+8)
    let b = rmsg as *mut u8;
    if unsafe { xdr_u_long(xdrs, b.add(0) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_enum(xdrs, b.add(8) as *mut c_int) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_enum(xdrs, b.add(16) as *mut c_int) } != XDR_TRUE {
        return XDR_FALSE;
    }
    match unsafe { *(b.add(16) as *const c_int) } {
        0 => unsafe { xdr_accepted_reply(xdrs, b.add(24).cast()) },
        1 => unsafe { xdr_rejected_reply(xdrs, b.add(24).cast()) },
        _ => XDR_FALSE,
    }
}

/// Serialize call header (ENCODE only): xid + CALL + rpcvers + prog + vers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_callhdr(xdrs: *mut c_void, cmsg: *mut c_void) -> c_int {
    let x = xdrs as *mut Xdr;
    if unsafe { (*x).x_op } != XDR_ENCODE {
        return XDR_FALSE;
    }
    let b = cmsg as *mut u8;
    unsafe {
        *(b.add(8) as *mut c_int) = MSG_CALL;
        *(b.add(16) as *mut c_ulong) = RPC_MSG_VERSION;
    }
    if unsafe { xdr_u_long(xdrs, b.add(0) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_enum(xdrs, b.add(8) as *mut c_int) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, b.add(16) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, b.add(24) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_u_long(xdrs, b.add(32) as *mut c_ulong) }
}

/// Serialize full call message: header + proc + cred + verf.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_callmsg(xdrs: *mut c_void, cmsg: *mut c_void) -> c_int {
    let b = cmsg as *mut u8;
    let x = xdrs as *mut Xdr;
    if unsafe { (*x).x_op } == XDR_ENCODE {
        unsafe {
            *(b.add(8) as *mut c_int) = MSG_CALL;
            *(b.add(16) as *mut c_ulong) = RPC_MSG_VERSION;
        }
    }
    // xid(0) + direction(8) + rpcvers(16) + prog(24) + vers(32) + proc(40) + cred(48) + verf(72)
    if unsafe { xdr_u_long(xdrs, b.add(0) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_enum(xdrs, b.add(8) as *mut c_int) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, b.add(16) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, b.add(24) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, b.add(32) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, b.add(40) as *mut c_ulong) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_opaque_auth(xdrs, b.add(48).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_opaque_auth(xdrs, b.add(72).cast()) }
}

/// Serialize AUTH_UNIX parameters: time + machname + uid + gid + gids.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authunix_parms(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let a = p as *mut AuthUnixParms;
    if unsafe { xdr_u_long(xdrs, &mut (*a).aup_time) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_string(xdrs, &mut (*a).aup_machname, 255) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_int(xdrs, (&mut (*a).aup_uid as *mut u32).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_int(xdrs, (&mut (*a).aup_gid as *mut u32).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe {
        xdr_array(
            xdrs,
            (&mut (*a).aup_gids as *mut *mut u32).cast(),
            &mut (*a).aup_len,
            16,
            4,
            xdr_u_int as *mut c_void,
        )
    }
}

/// Serialize portmap entry: prog + vers + prot + port.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pmap(xdrs: *mut c_void, regs: *mut c_void) -> c_int {
    let p = regs as *mut Pmap;
    if unsafe { xdr_u_long(xdrs, &mut (*p).pm_prog) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, &mut (*p).pm_vers) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, &mut (*p).pm_prot) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_u_long(xdrs, &mut (*p).pm_port) }
}

/// Helper: serialize one PmapList entry.
/// Serialize a linked list of portmap entries.
///
/// Iterative implementation mirroring glibc's `xdr_pmaplist`
/// (sunrpc/pmap_prot2.c). The previous recursion-via-xdr_pointer
/// implementation was vulnerable to unbounded stack growth on
/// attacker-controlled wire streams (bd-lc5ss).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_pmaplist(xdrs: *mut c_void, rp: *mut c_void) -> c_int {
    let x = xdrs as *mut Xdr;
    let op = unsafe { (*x).x_op };

    // XDR_FREE walks the list using only the in-memory pml_next chain,
    // freeing each entry directly. We can't use the same cursor pattern
    // as ENCODE/DECODE because xdr_reference (in XDR_FREE mode) frees
    // the entry pointed to by `*cursor` then sets `*cursor = null`,
    // dangling any reference into the just-freed entry's pml_next
    // field that we'd want to use as the next cursor. Iterate by
    // copying the pml_next VALUE into a local before the free.
    if op == XDR_FREE {
        let head_slot: *mut *mut PmapList = rp.cast();
        let mut node = unsafe { *head_slot };
        unsafe {
            *head_slot = std::ptr::null_mut();
        }
        while !node.is_null() {
            // SAFETY: node is a valid PmapList pointer we're about to free.
            let next = unsafe { (*node).pml_next };
            unsafe { libc::free(node.cast()) };
            node = next;
        }
        return XDR_TRUE;
    }

    // ENCODE/DECODE share the cursor pattern. Walk via xdr_bool more-
    // flag + xdr_reference per entry, advancing through pml_next.
    let mut cursor: *mut *mut PmapList = rp.cast();
    loop {
        let mut more: c_int = if unsafe { !(*cursor).is_null() } {
            1
        } else {
            0
        };
        if unsafe { xdr_bool(xdrs, &mut more) } != XDR_TRUE {
            return XDR_FALSE;
        }
        if more == 0 {
            unsafe {
                *cursor = std::ptr::null_mut();
            }
            return XDR_TRUE;
        }
        if unsafe {
            xdr_reference(
                xdrs,
                cursor as *mut *mut c_char,
                std::mem::size_of::<PmapList>() as c_uint,
                xdr_pmap as *mut c_void,
            )
        } != XDR_TRUE
        {
            return XDR_FALSE;
        }
        // xdr_reference allocates `sizeof(PmapList)` (40) but xdr_pmap
        // only initializes the first 32 (pm_prog..pm_port). Explicitly
        // null pml_next so the next iteration's `(*cursor).is_null()`
        // peek and the tail-of-list `*cursor = null` write target
        // initialized memory.
        unsafe {
            (**cursor).pml_next = std::ptr::null_mut();
            cursor = &mut (**cursor).pml_next as *mut *mut PmapList;
        }
    }
}

/// Serialize remote call arguments with arglen fixup.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rmtcall_args(xdrs: *mut c_void, cap: *mut c_void) -> c_int {
    let a = cap as *mut RmtCallArgs;
    let x = xdrs as *mut Xdr;
    if unsafe { xdr_u_long(xdrs, &mut (*a).prog) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, &mut (*a).vers) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, &mut (*a).proc_) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { (*x).x_op } == XDR_ENCODE {
        let lpos = unsafe { ((*(*x).x_ops).x_getpostn)(x as *const Xdr) };
        if unsafe { xdr_u_long(xdrs, &mut (*a).arglen) } != XDR_TRUE {
            return XDR_FALSE;
        }
        let apos = unsafe { ((*(*x).x_ops).x_getpostn)(x as *const Xdr) };
        let pf: XdrProc = unsafe { std::mem::transmute((*a).xdr_args) };
        if unsafe { pf(xdrs, (*a).args_ptr.cast()) } != XDR_TRUE {
            return XDR_FALSE;
        }
        let epos = unsafe { ((*(*x).x_ops).x_getpostn)(x as *const Xdr) };
        unsafe {
            (*a).arglen = (epos - apos) as c_ulong;
        }
        let _ = unsafe { ((*(*x).x_ops).x_setpostn)(x, lpos) };
        if unsafe { xdr_u_long(xdrs, &mut (*a).arglen) } != XDR_TRUE {
            return XDR_FALSE;
        }
        let _ = unsafe { ((*(*x).x_ops).x_setpostn)(x, epos) };
        XDR_TRUE
    } else {
        if unsafe { xdr_u_long(xdrs, &mut (*a).arglen) } != XDR_TRUE {
            return XDR_FALSE;
        }
        let pf: XdrProc = unsafe { std::mem::transmute((*a).xdr_args) };
        unsafe { pf(xdrs, (*a).args_ptr.cast()) }
    }
}

/// Serialize remote call results.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_rmtcallres(xdrs: *mut c_void, crp: *mut c_void) -> c_int {
    let r = crp as *mut RmtCallRes;
    if unsafe {
        xdr_reference(
            xdrs,
            (&mut (*r).port_ptr as *mut *mut c_ulong).cast(),
            std::mem::size_of::<c_ulong>() as c_uint,
            xdr_u_long as *mut c_void,
        )
    } != XDR_TRUE
    {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_long(xdrs, &mut (*r).resultslen) } != XDR_TRUE {
        return XDR_FALSE;
    }
    let pf: XdrProc = unsafe { std::mem::transmute((*r).xdr_results) };
    unsafe { pf(xdrs, (*r).results_ptr.cast()) }
}

/// Serialize a DES block (8 bytes opaque).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_des_block(xdrs: *mut c_void, blkp: *mut c_void) -> c_int {
    unsafe { xdr_opaque(xdrs, blkp as *mut c_char, 8) }
}

/// Serialize UNIX credentials: uid + gid + gidlen + gids.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_unixcred(xdrs: *mut c_void, ucp: *mut c_void) -> c_int {
    let u = ucp as *mut UnixCred;
    if unsafe { xdr_u_int(xdrs, (&mut (*u).uid as *mut u32).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_u_int(xdrs, (&mut (*u).gid as *mut u32).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    let mut glen = unsafe { (*u).gidlen } as c_uint;
    if unsafe { xdr_u_int(xdrs, &mut glen) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe {
        (*u).gidlen = glen as i16;
    }
    unsafe {
        xdr_array(
            xdrs,
            (&mut (*u).gids as *mut *mut u32).cast(),
            &mut glen,
            16,
            4,
            xdr_u_int as *mut c_void,
        )
    }
}

/// Serialize DES auth credential (deprecated — minimal implementation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authdes_cred(xdrs: *mut c_void, cred: *mut c_void) -> c_int {
    // DES auth is cryptographically broken. Provide wire-format support for
    // the discriminated union: namekind(enum) + fullname{name,key,window} or nickname.
    let b = cred as *mut u8;
    let nk = b as *mut c_int;
    if unsafe { xdr_enum(xdrs, nk) } != XDR_TRUE {
        return XDR_FALSE;
    }
    match unsafe { *nk } {
        0 => {
            // ADN_FULLNAME: name(string) + key(8 opaque) + window(4 opaque)
            if unsafe { xdr_string(xdrs, b.add(8) as *mut *mut c_char, 255) } != XDR_TRUE {
                return XDR_FALSE;
            }
            if unsafe { xdr_opaque(xdrs, b.add(16) as *mut c_char, 8) } != XDR_TRUE {
                return XDR_FALSE;
            }
            unsafe { xdr_opaque(xdrs, b.add(24) as *mut c_char, 4) }
        }
        1 => {
            // ADN_NICKNAME: 4-byte opaque
            unsafe { xdr_opaque(xdrs, b.add(8) as *mut c_char, 4) }
        }
        _ => XDR_FALSE,
    }
}

/// Serialize DES auth verifier (deprecated — minimal implementation).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_authdes_verf(xdrs: *mut c_void, verf: *mut c_void) -> c_int {
    // DES verifier: timestamp_sec(4) + timestamp_usec(4) + nickname(4) = 12 bytes
    // Stored as opaque in the wire format within the verifier body.
    // Since verifier data is already in opaque_auth body, this just serializes the raw fields.
    let b = verf as *mut u8;
    if unsafe { xdr_opaque(xdrs, b as *mut c_char, 8) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_opaque(xdrs, b.add(8) as *mut c_char, 4) }
}

// --- Key server XDR types (Secure RPC / keyserv protocol) ---
// These are only used with the key server daemon which we don't support.
// Each type serializes fields used in the keyserv RPC protocol.

/// Serialize a key buffer (HEXKEYBYTES = 144 bytes of opaque data).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keybuf(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    unsafe { xdr_opaque(xdrs, p as *mut c_char, 144) }
}

/// Serialize key status enum.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_keystatus(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    unsafe { xdr_enum(xdrs, p as *mut c_int) }
}

/// Serialize a netname string (max 255 chars).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_netnamestr(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    unsafe { xdr_string(xdrs, p as *mut *mut c_char, 255) }
}

/// Serialize cryptkeyarg: remotename(string) + deskey(des_block=8).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let b = p as *mut u8;
    // { char *remotename; des_block deskey; }
    if unsafe { xdr_netnamestr(xdrs, b.cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_des_block(xdrs, b.add(8).cast()) }
}

/// Serialize cryptkeyarg2: remotename(string) + netname(netnamestr) + deskey(des_block).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyarg2(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let b = p as *mut u8;
    if unsafe { xdr_netnamestr(xdrs, b.cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_netnamestr(xdrs, b.add(8).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_des_block(xdrs, b.add(16).cast()) }
}

/// Serialize cryptkeyres: status(keystatus) + deskey(des_block).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_cryptkeyres(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let b = p as *mut u8;
    if unsafe { xdr_keystatus(xdrs, b.cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_des_block(xdrs, b.add(4).cast()) }
}

/// Serialize getcredres: status(keystatus) + client_name(netnamestr).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_getcredres(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let b = p as *mut u8;
    if unsafe { xdr_keystatus(xdrs, b.cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_netnamestr(xdrs, b.add(8).cast()) }
}

/// Serialize key_netstarg: priv_key(keybuf) + pub_key(keybuf) + netname(string).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstarg(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let b = p as *mut u8;
    if unsafe { xdr_keybuf(xdrs, b.cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_keybuf(xdrs, b.add(144).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_netnamestr(xdrs, b.add(288).cast()) }
}

/// Serialize key_netstres: status(keystatus) + priv_key(keybuf) + pub_key(keybuf).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdr_key_netstres(xdrs: *mut c_void, p: *mut c_void) -> c_int {
    let b = p as *mut u8;
    if unsafe { xdr_keystatus(xdrs, b.cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    if unsafe { xdr_keybuf(xdrs, b.add(8).cast()) } != XDR_TRUE {
        return XDR_FALSE;
    }
    unsafe { xdr_keybuf(xdrs, b.add(152).cast()) }
}

// ===========================================================================
// RPC authentication (7 symbols)
// ===========================================================================

rpc_native!(authnone_create() -> *mut c_void);

rpc_native!(authunix_create(
    machname: *mut c_char,
    uid: c_int,
    gid: c_int,
    len: c_int,
    aup_gids: *mut c_int
) -> *mut c_void);

rpc_native!(authunix_create_default() -> *mut c_void);

/// Create a DES authentication handle. Returns NULL — DES is cryptographically broken.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_create(
    _servername: *mut c_char,
    _window: c_uint,
    _syncaddr: *mut c_void,
    _ckey: *mut c_void,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// Create a DES authentication handle with public key. Returns NULL — DES is broken.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_pk_create(
    _servername: *mut c_char,
    _pkey: *mut c_void,
    _window: c_uint,
    _syncaddr: *mut c_void,
    _ckey: *mut c_void,
) -> *mut c_void {
    std::ptr::null_mut()
}

/// Extract UNIX credentials from a DES auth handle. Returns 0 (failure) — DES is broken.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn authdes_getucred(
    _adc: *mut c_void,
    _uid: *mut u32,
    _gid: *mut u32,
    _grouplen: *mut i16,
    _groups: *mut c_int,
) -> c_int {
    0
}

rpc_native!(_authenticate(rqst: *mut c_void, msg: *mut c_void) -> c_int);

// ===========================================================================
// RPC client creation and error handling (14 symbols)
// ===========================================================================

rpc_native!(clnt_create(
    host: *const c_char,
    prog: c_ulong,
    vers: c_ulong,
    proto: *const c_char
) -> *mut c_void);

rpc_native!(clntraw_create(prog: c_ulong, vers: c_ulong) -> *mut c_void);

rpc_native!(clnttcp_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_native!(clntudp_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    wait: Timeval,
    sockp: *mut c_int
) -> *mut c_void);

rpc_native!(clntudp_bufcreate(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    wait: Timeval,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_native!(clntunix_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_native!(callrpc(
    host: *const c_char,
    prognum: c_ulong,
    versnum: c_ulong,
    procnum: c_ulong,
    inproc: *mut c_void,
    in_: *mut c_char,
    outproc: *mut c_void,
    out: *mut c_char
) -> c_int);

/// Broadcast an RPC call to all hosts on the local network.
/// Returns RPC_UNKNOWNPROTO (17) — broadcast requires portmapper which is not supported.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_broadcast(
    _prog: c_ulong,
    _vers: c_ulong,
    _proc_: c_ulong,
    _xargs: *mut c_void,
    _argsp: *mut c_void,
    _xresults: *mut c_void,
    _resultsp: *mut c_void,
    _eachresult: *mut c_void,
) -> c_int {
    17 // RPC_UNKNOWNPROTO — no broadcast support
}

/// Print RPC error number description to stderr. Native implementation.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_perrno(stat: c_int) {
    let msg = rpc_errstr(stat);
    // Write to stderr: "RPC: <message>\n"
    let _ = unsafe { crate::unistd_abi::write(2, b"RPC: ".as_ptr().cast(), 5) };
    let _ = unsafe { crate::unistd_abi::write(2, msg.as_ptr().cast(), msg.len()) };
    let _ = unsafe { crate::unistd_abi::write(2, b"\n".as_ptr().cast(), 1) };
}

rpc_native!(clnt_perror(clnt: *mut c_void, s: *const c_char) -> ());

/// Print RPC client creation error to stderr. Native implementation.
/// Reads from thread-local rpc_createerr (via __rpc_thread_createerr).
///
/// # Safety
/// ABI boundary function. `s` must be a valid C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_pcreateerror(s: *const c_char) {
    let msg = unsafe { clnt_spcreateerror(s) };
    if !msg.is_null() {
        let len = unsafe { crate::string_abi::strlen(msg) };
        let _ = unsafe { crate::unistd_abi::write(2, msg.cast(), len) };
        let _ = unsafe { crate::unistd_abi::write(2, b"\n".as_ptr().cast(), 1) };
    }
}

// Thread-local buffer for clnt_sperrno return value.
std::thread_local! {
    static SPERRNO_BUF: std::cell::UnsafeCell<[u8; 64]> =
        const { std::cell::UnsafeCell::new([0u8; 64]) };
}

/// Return a string describing an RPC error status code. Native implementation.
/// Uses RPC_* status codes from glibc's <rpc/clnt_stat.h>.
///
/// # Safety
/// ABI boundary function. Returns a pointer valid until the next call from the same thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_sperrno(stat: c_int) -> *mut c_char {
    let msg = rpc_errstr(stat);
    SPERRNO_BUF.with(|cell| {
        let buf = unsafe { &mut *cell.get() };
        let len = msg.len().min(63);
        buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
        buf[len] = 0;
        buf.as_mut_ptr().cast()
    })
}

rpc_native!(clnt_sperror(clnt: *mut c_void, s: *const c_char) -> *mut c_char);

// Thread-local buffer for clnt_spcreateerror return value.
std::thread_local! {
    static SPCREATEERR_BUF: std::cell::UnsafeCell<[u8; 256]> =
        const { std::cell::UnsafeCell::new([0u8; 256]) };
}

/// Return a string describing the RPC client creation error. Native implementation.
/// Reads from thread-local rpc_createerr (cf_stat field at offset 0).
///
/// # Safety
/// ABI boundary function. `s` must be a valid C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_spcreateerror(s: *const c_char) -> *mut c_char {
    let prefix = unsafe { read_bounded_cstr(s) }
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .unwrap_or_default();
    // Read cf_stat from thread-local rpc_createerr (first 4 bytes = clnt_stat enum)
    let createerr = unsafe { __rpc_thread_createerr() };
    let cf_stat = if createerr.is_null() {
        0i32
    } else {
        unsafe { std::ptr::read_unaligned(createerr as *const i32) }
    };
    let err_msg = rpc_errstr(cf_stat);
    let formatted = format!("{}: {}\0", prefix, err_msg);
    SPCREATEERR_BUF.with(|cell| {
        let buf = unsafe { &mut *cell.get() };
        let len = formatted.len().min(255);
        buf[..len].copy_from_slice(&formatted.as_bytes()[..len]);
        buf[len] = 0;
        buf.as_mut_ptr().cast()
    })
}

// rpc_errstr moved to frankenlibc_core::rpc::status_message. Local
// alias preserves the call sites in clnt_perrno / clnt_sperrno /
// clnt_spcreateerror unchanged.
use frankenlibc_core::rpc::status_message as rpc_errstr;

// ===========================================================================
// RPC server / SVC (24 symbols)
// ===========================================================================

rpc_native!(svc_register(
    xprt: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    dispatch: *mut c_void,
    protocol: c_int
) -> c_int);

rpc_native!(svc_unregister(prog: c_ulong, vers: c_ulong) -> ());

rpc_native!(svc_sendreply(
    xprt: *mut c_void,
    xdr_results: *mut c_void,
    xdr_location: *mut c_void
) -> c_int);

rpc_native!(svc_run() -> ());
rpc_native!(svc_exit() -> ());

rpc_native!(svc_getreq(rdfds: c_int) -> ());
rpc_native!(svc_getreqset(readfds: *mut c_void) -> ());
rpc_native!(svc_getreq_common(fd: c_int) -> ());
rpc_native!(svc_getreq_poll(pfds: *mut c_void, nfds: c_int) -> ());

// --- SVC error replies ---

rpc_native!(svcerr_auth(xprt: *mut c_void, why: c_int) -> ());
rpc_native!(svcerr_decode(xprt: *mut c_void) -> ());
rpc_native!(svcerr_noproc(xprt: *mut c_void) -> ());
rpc_native!(svcerr_noprog(xprt: *mut c_void) -> ());
rpc_native!(svcerr_progvers(
    xprt: *mut c_void,
    low_vers: c_ulong,
    high_vers: c_ulong
) -> ());
rpc_native!(svcerr_systemerr(xprt: *mut c_void) -> ());
rpc_native!(svcerr_weakauth(xprt: *mut c_void) -> ());

// --- SVC transport creation ---

rpc_native!(svcraw_create() -> *mut c_void);
rpc_native!(svcfd_create(fd: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);
rpc_native!(svctcp_create(sock: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);
rpc_native!(svcudp_create(sock: c_int) -> *mut c_void);

rpc_native!(svcudp_bufcreate(
    sock: c_int,
    sendsz: c_uint,
    recvsz: c_uint
) -> *mut c_void);

rpc_native!(svcudp_enablecache(xprt: *mut c_void, cachesz: c_ulong) -> c_int);
rpc_native!(svcunix_create(sock: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);
rpc_native!(svcunixfd_create(fd: c_int, sendsize: c_uint, recvsize: c_uint) -> *mut c_void);

// ===========================================================================
// RPC misc: registerrpc, dtablesize, createerr thread locals (14+ symbols)
// ===========================================================================

rpc_native!(registerrpc(
    prognum: c_ulong,
    versnum: c_ulong,
    procnum: c_ulong,
    progname: *mut c_void,
    inproc: *mut c_void,
    outproc: *mut c_void
) -> c_int);

/// Returns the file descriptor table size (same as getdtablesize).
/// Uses getrlimit(RLIMIT_NOFILE) with a fallback to FD_SETSIZE (1024).
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _rpc_dtablesize() -> c_int {
    // SAFETY: zero-init rlimit struct, then getrlimit fills it.
    let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
    let rc = unsafe { crate::resource_abi::getrlimit(libc::RLIMIT_NOFILE as c_int, &mut rl) };
    const FD_SETSIZE: c_int = libc::FD_SETSIZE as c_int;
    if rc == 0 && rl.rlim_cur > 0 {
        // Clamp to FD_SETSIZE to match glibc _rpc_dtablesize behavior.
        let limit = rl.rlim_cur as c_int;
        if limit > FD_SETSIZE {
            FD_SETSIZE
        } else {
            limit
        }
    } else {
        FD_SETSIZE
    }
}

// --- Thread-local RPC state accessors (native TLS) ---
//
// In glibc these return pointers to thread-local structs. We provide native
// TLS storage for the rpc_createerr, svc_fdset, svc_max_pollfd, and
// svc_pollfd thread-local variables. Programs that use these accessors will
// get per-thread storage without needing to call into glibc.

// rpc_createerr: struct rpc_createerr { enum clnt_stat cf_stat; struct rpc_err cf_error; }
// This is 24 bytes on x86_64 (4 + padding + 16 for rpc_err).
// We allocate 32 bytes to be safe for alignment.
std::thread_local! {
    static RPC_CREATEERR_TLS: std::cell::UnsafeCell<[u8; 32]> =
        const { std::cell::UnsafeCell::new([0u8; 32]) };
}

/// Returns pointer to thread-local rpc_createerr struct.
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_createerr() -> *mut c_void {
    RPC_CREATEERR_TLS.with(|cell| cell.get().cast())
}

// fd_set size derived from FD_SETSIZE (1024 on Linux → 128 bytes).
const RPC_FD_SET_BYTES: usize = libc::FD_SETSIZE / 8;
std::thread_local! {
    static RPC_SVC_FDSET_TLS: std::cell::UnsafeCell<[u8; RPC_FD_SET_BYTES]> =
        const { std::cell::UnsafeCell::new([0u8; RPC_FD_SET_BYTES]) };
}

/// Returns pointer to thread-local svc_fdset (fd_set).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_fdset() -> *mut c_void {
    RPC_SVC_FDSET_TLS.with(|cell| cell.get().cast())
}

std::thread_local! {
    static RPC_SVC_MAX_POLLFD_TLS: std::cell::UnsafeCell<c_int> =
        const { std::cell::UnsafeCell::new(0) };
}

/// Returns pointer to thread-local svc_max_pollfd (int).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_max_pollfd() -> *mut c_void {
    RPC_SVC_MAX_POLLFD_TLS.with(|cell| cell.get().cast())
}

std::thread_local! {
    static RPC_SVC_POLLFD_TLS: std::cell::UnsafeCell<*mut c_void> =
        const { std::cell::UnsafeCell::new(std::ptr::null_mut()) };
}

/// Returns pointer to thread-local svc_pollfd (struct pollfd *).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_pollfd() -> *mut c_void {
    RPC_SVC_POLLFD_TLS.with(|cell| cell.get().cast())
}

// --- _seterr_reply (native) ---

/// Extract error information from an RPC reply message into an rpc_err struct.
/// This parses msg->rm_reply.rp_stat to determine accept/reject status and
/// populates the error struct accordingly.
///
/// struct rpc_msg layout at field rm_reply (offset ~12):
///   rp_stat (enum reply_stat): 0=MSG_ACCEPTED, 1=MSG_DENIED
///
/// For MSG_ACCEPTED (rp_stat==0):
///   ar_stat (enum accept_stat): acceptance status at offset +4
///   ar_vers.low/high (u32,u32): if PROG_MISMATCH, at +8/+12
///
/// For MSG_DENIED (rp_stat==1):
///   rj_stat (enum reject_stat): 0=RPC_MISMATCH, 1=AUTH_ERROR
///   rj_vers.low/high or rj_why: at +4/+8/+12
///
/// rpc_err layout: re_status(enum, 4 bytes), then union (rpc_err_union).
///
/// Since the exact struct layouts are ABI-dependent and complex, we provide a
/// minimal implementation that just zeroes the error struct (success case).
/// Programs needing full RPC error parsing will work via host delegation for
/// the actual RPC calls themselves.
///
/// # Safety
/// ABI boundary function. Both pointers must be valid or null.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _seterr_reply(msg: *mut c_void, error: *mut c_void) {
    if msg.is_null() || error.is_null() {
        return;
    }
    // Zero out the error struct (24 bytes for rpc_err on x86_64).
    // This is safe because rpc_err is a C struct with only integer/enum fields.
    unsafe {
        std::ptr::write_bytes(error.cast::<u8>(), 0, 24);
    }

    // Read reply stat from the message. The rm_reply union starts after
    // rm_xid(u32) + rm_direction(enum=4 bytes) = offset 8 in struct rpc_msg.
    // rm_reply.rp_stat is the first field.
    let msg_bytes = msg.cast::<u8>();
    let rp_stat = unsafe { std::ptr::read_unaligned(msg_bytes.add(8).cast::<u32>()) };

    // error->re_status: map RPC reply status
    let error_bytes = error.cast::<u8>();
    if rp_stat == 0 {
        // MSG_ACCEPTED — read ar_stat at offset +12 in rpc_msg
        let ar_stat = unsafe { std::ptr::read_unaligned(msg_bytes.add(12).cast::<u32>()) };
        // Map accept_stat to clnt_stat: SUCCESS=0, PROG_UNAVAIL=8, etc.
        let re_status: u32 = match ar_stat {
            0 => 0,  // SUCCESS
            1 => 8,  // PROG_UNAVAIL → RPC_PROGUNAVAIL
            2 => 9,  // PROG_MISMATCH → RPC_PROGVERSMISMATCH
            3 => 10, // PROC_UNAVAIL → RPC_PROCUNAVAIL
            4 => 11, // GARBAGE_ARGS → RPC_CANTDECODEARGS
            5 => 12, // SYSTEM_ERR → RPC_SYSTEMERROR
            _ => 16, // RPC_FAILED
        };
        unsafe {
            std::ptr::write_unaligned(error_bytes.cast::<u32>(), re_status);
        }
        // If PROG_MISMATCH, copy version range
        if ar_stat == 2 {
            let low = unsafe { std::ptr::read_unaligned(msg_bytes.add(16).cast::<u32>()) };
            let high = unsafe { std::ptr::read_unaligned(msg_bytes.add(20).cast::<u32>()) };
            unsafe {
                std::ptr::write_unaligned(error_bytes.add(4).cast::<u32>(), low);
                std::ptr::write_unaligned(error_bytes.add(8).cast::<u32>(), high);
            }
        }
    } else {
        // MSG_DENIED — read rj_stat at offset +12
        let rj_stat = unsafe { std::ptr::read_unaligned(msg_bytes.add(12).cast::<u32>()) };
        if rj_stat == 0 {
            // RPC_MISMATCH
            unsafe {
                std::ptr::write_unaligned(error_bytes.cast::<u32>(), 6); // RPC_VERSMISMATCH
            }
            let low = unsafe { std::ptr::read_unaligned(msg_bytes.add(16).cast::<u32>()) };
            let high = unsafe { std::ptr::read_unaligned(msg_bytes.add(20).cast::<u32>()) };
            unsafe {
                std::ptr::write_unaligned(error_bytes.add(4).cast::<u32>(), low);
                std::ptr::write_unaligned(error_bytes.add(8).cast::<u32>(), high);
            }
        } else {
            // AUTH_ERROR
            unsafe {
                std::ptr::write_unaligned(error_bytes.cast::<u32>(), 7); // RPC_AUTHERROR
            }
            let why = unsafe { std::ptr::read_unaligned(msg_bytes.add(16).cast::<u32>()) };
            unsafe {
                std::ptr::write_unaligned(error_bytes.add(4).cast::<u32>(), why);
            }
        }
    }
}

// --- _null_auth: this is a global variable in glibc, we export a function
//     that fetches its address from the host. Programs typically access it
//     directly; for LD_PRELOAD interposition we provide a function-based
//     accessor. The linker symbol is handled separately in the version script. ---

// ===========================================================================
// Key management / Secure RPC (16+ symbols)
// ===========================================================================

/// Decrypt a session key using the key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession(
    _remotename: *const c_char,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Decrypt a session key with a public key. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_decryptsession_pk(
    _remotename: *const c_char,
    _remotekey: *mut c_void,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Encrypt a session key using the key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession(
    _remotename: *const c_char,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Encrypt a session key with a public key. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_encryptsession_pk(
    _remotename: *const c_char,
    _remotekey: *mut c_void,
    _deskey: *mut c_void,
) -> c_int {
    -1 // No keyserver available
}

/// Generate a DES key using the key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_gendes(_deskey: *mut c_void) -> c_int {
    -1 // No keyserver available
}

/// Get conversation key from public key. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_get_conv(_pkey: *mut c_char, _deskey: *mut c_void) -> c_int {
    -1 // No keyserver available
}
/// Check if the secret key has been set with the key server.
/// Returns 0 (FALSE) — no keyserv integration in FrankenLibC.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_secretkey_is_set() -> c_int {
    0 // No keyserv client installed
}

/// Set network key parameters. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_setnet(_arg: *mut c_void) -> c_int {
    -1 // No keyserver available
}

/// Set secret key with key server. Returns -1 (failure) — no keyserv.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn key_setsecret(_secretkey: *const c_char) -> c_int {
    -1 // No keyserver available
}

// --- Internal key function pointer globals ---
// In glibc these are `int (*__key_*_LOCAL)(...)` global function pointers.
// We export them as mutable static AtomicPtrs so programs and libraries
// can read/write them. Initialized to null (no keyserv client installed).

use std::sync::atomic::AtomicPtr;

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_decryptsession_pk_LOCAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_encryptsession_pk_LOCAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub static __key_gendes_LOCAL: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// ===========================================================================
// Portmapper client (5 symbols)
// ===========================================================================

/// Get portmapper registrations from a host. Returns NULL — no portmapper support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getmaps(_address: *mut c_void) -> *mut c_void {
    std::ptr::null_mut()
}

/// Get the port for an RPC program. Returns 0 — no portmapper support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getport(
    _address: *mut c_void,
    _prog: c_ulong,
    _vers: c_ulong,
    _proto: c_uint,
) -> u16 {
    0
}

/// Perform a remote procedure call via portmapper. Returns RPC_UNKNOWNPROTO (17).
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_rmtcall(
    _addr: *mut c_void,
    _prog: c_ulong,
    _vers: c_ulong,
    _proc_: c_ulong,
    _xdrargs: *mut c_void,
    _argsp: *mut c_void,
    _xdrres: *mut c_void,
    _resp: *mut c_void,
    _tout: Timeval,
    _portp: *mut c_ulong,
) -> c_int {
    17 // RPC_UNKNOWNPROTO
}

/// Register an RPC program with portmapper. Returns 0 (FALSE) — no portmapper support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_set(
    _prog: c_ulong,
    _vers: c_ulong,
    _proto: c_int,
    _port: u16,
) -> c_int {
    0
}

/// Unregister an RPC program from portmapper. Returns 0 (FALSE) — no portmapper support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_unset(_prog: c_ulong, _vers: c_ulong) -> c_int {
    0
}

// ===========================================================================
// DES crypt helpers (6 symbols) — Native stubs
//
// DES is cryptographically broken (56-bit key). These functions are from
// <rpc/des_crypt.h> and are deprecated. We return DESERR_NOHWDEVICE (4)
// for cbc_crypt/ecb_crypt to indicate no DES hardware is available,
// and 0 (failure) for xencrypt/xdecrypt/passwd2des. des_setparity is
// a no-op since we don't use DES.
// ===========================================================================

/// DESERR_NOHWDEVICE — no DES hardware available (standard return code).
const DESERR_NOHWDEVICE: c_int = 4;

/// CBC-mode DES encryption/decryption. Returns DESERR_NOHWDEVICE.
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn cbc_crypt(
    _key: *mut c_char,
    _buf: *mut c_char,
    _len: c_uint,
    _mode: c_uint,
    _ivec: *mut c_char,
) -> c_int {
    DESERR_NOHWDEVICE
}

/// ECB-mode DES encryption/decryption. Returns DESERR_NOHWDEVICE.
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn ecb_crypt(
    _key: *mut c_char,
    _buf: *mut c_char,
    _len: c_uint,
    _mode: c_uint,
) -> c_int {
    DESERR_NOHWDEVICE
}

/// Set DES key parity bits. No-op since DES is not supported.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn des_setparity(_key: *mut c_char) {
    // No-op: DES parity is irrelevant without DES support.
}

/// Hex-encrypt a secret key with a password. Returns 0 (failure).
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xencrypt(_secret: *mut c_char, _passwd: *mut c_char) -> c_int {
    0 // failure — no DES support
}

/// Hex-decrypt a secret key with a password. Returns 0 (failure).
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn xdecrypt(_secret: *mut c_char, _passwd: *mut c_char) -> c_int {
    0 // failure — no DES support
}

/// Convert a password to a DES key. Returns 0 (failure).
///
/// # Safety
/// ABI boundary function; parameters are unchecked raw pointers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn passwd2des(_passwd: *mut c_char, _key: *mut c_char) -> c_int {
    0 // failure — no DES support
}

// ===========================================================================
// RPC network identity and utility functions (18 symbols)
// ===========================================================================

/// Get the machine's IP address into a `struct sockaddr_in`.
/// Fills with INADDR_LOOPBACK (127.0.0.1) as a safe default.
/// In glibc this queries network interfaces; we use the loopback
/// address since RPC programs typically bind to it anyway.
///
/// # Safety
/// ABI boundary function. `addr` must point to a valid `struct sockaddr_in`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn get_myaddress(addr: *mut c_void) {
    if addr.is_null() {
        return;
    }
    // struct sockaddr_in layout: sin_family(u16) + sin_port(u16) + sin_addr(u32) + sin_zero(8)
    let sa: *mut libc::sockaddr_in = addr.cast();
    unsafe {
        (*sa).sin_family = libc::AF_INET as u16;
        (*sa).sin_port = 0;
        (*sa).sin_addr = libc::in_addr {
            s_addr: u32::to_be(0x7f000001), // 127.0.0.1 in network byte order
        };
        std::ptr::write_bytes((*sa).sin_zero.as_mut_ptr(), 0, 8);
    }
}

/// Get the netname for the current effective uid.
/// Format: "unix.<uid>@<domain>" — we use "localhost" as the domain.
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function. `name` must point to a buffer of at least MAXNETNAMELEN+1 (256) bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetname(name: *mut c_char) -> c_int {
    if name.is_null() {
        return 0;
    }
    let uid = raw_syscall::sys_geteuid();
    // Format: "unix.<uid>@localhost"
    let netname = format!("unix.{}@localhost\0", uid);
    let bytes = netname.as_bytes();
    // MAXNETNAMELEN is typically 255 in glibc
    if bytes.len() > 256 {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), name.cast(), bytes.len());
    }
    1
}

/// Get the public key for a netname from the publickey database.
/// Returns 0 (failure) — no publickey database support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpublickey(_netname: *const c_char, _publickey: *mut c_char) -> c_int {
    0 // Not found
}

/// Get the secret key for a netname from the publickey database.
/// Returns 0 (failure) — no publickey database support.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getsecretkey(
    _netname: *const c_char,
    _secretkey: *mut c_char,
    _passwd: *const c_char,
) -> c_int {
    0 // Not found
}

/// Get the port number for an RPC program on a remote host.
/// Returns 0 (not found) — portmapper queries not supported natively.
/// Programs needing real portmapper lookups will use clnt_create which
/// delegates to host glibc.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcport(
    _host: *const c_char,
    _prognum: c_ulong,
    _versnum: c_ulong,
    _proto: c_int,
) -> c_int {
    0 // Not found — no native portmapper support
}

/// Convert a hostname to a netname. Format: "unix.<host>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function. `netname` must point to a valid `*mut c_char` pointer.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn host2netname(
    netname: *mut *mut c_char,
    host: *const c_char,
    domain: *const c_char,
) -> c_int {
    if netname.is_null() {
        return 0;
    }
    // Bounded reads — non-NUL-terminated host/domain pointers must not
    // walk arbitrary memory. (REVIEW round 5: bd-z4k96 class.)
    let host_owned = if host.is_null() {
        b"localhost".to_vec()
    } else {
        match unsafe { read_bounded_cstr(host) } {
            Some(b) => b,
            None => return 0,
        }
    };
    let domain_owned = if domain.is_null() {
        b"localhost".to_vec()
    } else {
        match unsafe { read_bounded_cstr(domain) } {
            Some(b) => b,
            None => return 0,
        }
    };
    let host_str = match std::str::from_utf8(&host_owned) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let domain_str = match std::str::from_utf8(&domain_owned) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let name = format!("unix.{}@{}\0", host_str, domain_str);
    // POSIX host2netname returns a heap buffer that the CALLER frees with the
    // standard free(). That means we must allocate through the allocator whose
    // free() matches: when frankenlibc is linked as a normal dep (test build,
    // no LD_PRELOAD), `libc::free` binds to host glibc's free, so the malloc
    // side has to match. If we allocate via our internal raw_alloc (arena),
    // the caller's free sees a non-glibc chunk header and aborts with
    // `free(): invalid size` (bd-dqqh1 cluster). Using libc::malloc keeps the
    // alloc/free pair consistent in both the LD_PRELOAD and non-preload
    // contexts — under LD_PRELOAD the host libc::malloc is our own interposed
    // symbol anyway.
    let buf = unsafe { libc::malloc(name.len()) } as *mut c_char;
    if buf.is_null() {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast(), name.len());
        *netname = buf;
    }
    1
}

/// Extract hostname from a netname. Format: "unix.<host>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn netname2host(
    netname: *const c_char,
    hostname: *mut c_char,
    hostlen: c_int,
) -> c_int {
    if netname.is_null() || hostname.is_null() || hostlen <= 0 {
        return 0;
    }
    // Bounded read — see bd-z4k96 class. (REVIEW round 5.)
    let name_owned = match unsafe { read_bounded_cstr(netname) } {
        Some(b) => b,
        None => return 0,
    };
    let name = match std::str::from_utf8(&name_owned) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    // Parse "unix.<host>@<domain>"
    let rest = match name.strip_prefix("unix.") {
        Some(r) => r,
        None => return 0,
    };
    let host = match rest.find('@') {
        Some(idx) => &rest[..idx],
        None => return 0,
    };
    if host.len() >= hostlen as usize {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(host.as_ptr(), hostname.cast(), host.len());
        *hostname.add(host.len()) = 0;
    }
    1
}

/// Extract user info from a netname. Format: "unix.<uid>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn netname2user(
    netname: *const c_char,
    uidp: *mut c_ulong,
    gidp: *mut c_ulong,
    gidlenp: *mut c_int,
    _gidlist: *mut c_int,
) -> c_int {
    if netname.is_null() || uidp.is_null() || gidp.is_null() || gidlenp.is_null() {
        return 0;
    }
    // Bounded read — see bd-z4k96 class. (REVIEW round 5.)
    let name_owned = match unsafe { read_bounded_cstr(netname) } {
        Some(b) => b,
        None => return 0,
    };
    let name = match std::str::from_utf8(&name_owned) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let rest = match name.strip_prefix("unix.") {
        Some(r) => r,
        None => return 0,
    };
    let uid_str = match rest.find('@') {
        Some(idx) => &rest[..idx],
        None => return 0,
    };
    let uid: u64 = match uid_str.parse() {
        Ok(v) => v,
        Err(_) => return 0,
    };
    unsafe {
        *uidp = uid;
        *gidp = uid; // Default: gid = uid
        *gidlenp = 0; // No supplementary groups
    }
    1
}

/// Convert a uid to a netname. Format: "unix.<uid>@<domain>".
/// Returns 1 on success, 0 on failure.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn user2netname(
    netname: *mut *mut c_char,
    uid: c_ulong,
    domain: *const c_char,
) -> c_int {
    if netname.is_null() {
        return 0;
    }
    // Bounded read — see bd-z4k96 class. (REVIEW round 5.)
    let domain_owned = if domain.is_null() {
        b"localhost".to_vec()
    } else {
        match unsafe { read_bounded_cstr(domain) } {
            Some(b) => b,
            None => return 0,
        }
    };
    let domain_str = match std::str::from_utf8(&domain_owned) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    let name = format!("unix.{}@{}\0", uid, domain_str);
    // Sibling of host2netname (bd-dqqh1) — POSIX returns a buffer freed by
    // the caller's free(), so use libc::malloc to keep the alloc/free pair
    // consistent across LD_PRELOAD and non-preload contexts (bd-zgifl).
    let buf = unsafe { libc::malloc(name.len()) } as *mut c_char;
    if buf.is_null() {
        return 0;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(name.as_ptr(), buf.cast(), name.len());
        *netname = buf;
    }
    1
}

/// Get time from a remote time server (RFC 868). Returns -1 (failure).
/// Programs should use NTP or local clock instead of the legacy TIME protocol.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn rtime(
    _addrp: *mut c_void,
    _timep: *mut c_void,
    _timeout: *mut c_void,
) -> c_int {
    -1 // Not supported — use local clock
}

/// Bind a socket to a reserved port (ports 512-1023).
/// Tries ports in the range until one succeeds. If `sin` is NULL,
/// creates a default AF_INET sockaddr_in. Returns 0 on success, -1 on failure.
///
/// # Safety
/// ABI boundary function. `sin` must be NULL or point to a valid `struct sockaddr_in`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bindresvport(sd: c_int, sin: *mut c_void) -> c_int {
    // Use a local sockaddr_in if none provided
    let mut local_sin: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let sa: *mut libc::sockaddr_in = if sin.is_null() {
        local_sin.sin_family = libc::AF_INET as u16;
        &mut local_sin
    } else {
        sin.cast()
    };

    // Try ports 512..1024 (reserved range per glibc convention)
    // Start from a "random" offset based on process ID for spread (bd-h5x)
    let pid = raw_syscall::sys_getpid() as u16;
    let start = 600 + (pid % 424); // range [600, 1023]

    for i in 0..512 {
        let port = 512 + ((start as u32 + i as u32) % 512) as u16;
        unsafe {
            (*sa).sin_port = port.to_be();
        }
        match unsafe {
            raw_syscall::sys_bind(
                sd,
                (sa as *const libc::sockaddr_in).cast::<u8>(),
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        } {
            Ok(()) => return 0,
            Err(err) => {
                if err != libc::EADDRINUSE {
                    unsafe { set_abi_errno(err) };
                    return -1;
                }
            }
        }
    }
    // Exhausted all reserved ports
    unsafe { set_abi_errno(libc::EADDRINUSE) };
    -1
}

/// Bind a socket to a reserved IPv6 port (512..1023). IPv6
/// companion to [`bindresvport`]. Tries ports in a
/// process-id-rotated order until one binds successfully. If
/// `sin6` is NULL, an in6addr_any sockaddr_in6 is synthesized.
/// Returns 0 on success, -1 on failure with errno set
/// (EADDRINUSE if no reserved port is available).
///
/// # Safety
///
/// `sin6` must be NULL or point to a valid `struct sockaddr_in6`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn bindresvport6(sd: c_int, sin6: *mut c_void) -> c_int {
    let mut local_sin6: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let sa: *mut libc::sockaddr_in6 = if sin6.is_null() {
        local_sin6.sin6_family = libc::AF_INET6 as u16;
        // sin6_addr is already zero (in6addr_any) from the zeroed init.
        &mut local_sin6
    } else {
        sin6.cast()
    };

    let pid = raw_syscall::sys_getpid() as u16;
    let start = 600 + (pid % 424); // range [600, 1023]

    for i in 0..512 {
        let port = 512 + ((start as u32 + i as u32) % 512) as u16;
        unsafe {
            (*sa).sin6_port = port.to_be();
        }
        match unsafe {
            raw_syscall::sys_bind(
                sd,
                (sa as *const libc::sockaddr_in6).cast::<u8>(),
                std::mem::size_of::<libc::sockaddr_in6>() as u32,
            )
        } {
            Ok(()) => return 0,
            Err(err) => {
                if err != libc::EADDRINUSE {
                    unsafe { set_abi_errno(err) };
                    return -1;
                }
            }
        }
    }
    unsafe { set_abi_errno(libc::EADDRINUSE) };
    -1
}

// --- rpc_createerr: this is a thread-local struct in glibc. The
//     __rpc_thread_createerr() accessor above returns a pointer to it.
//     Direct symbol interposition of the variable is not needed because
//     programs use the accessor or the linker resolves to glibc's copy. ---

// ===========================================================================
// pmap_getport with u16 return — specialized signature for portmapper
// The pmap_getport above already handles this with u16 return type.
// ===========================================================================

// ===========================================================================
// RPC global variable note
// ===========================================================================
//
// The following are global variables in glibc, NOT functions:
//   svc_fdset, svc_max_pollfd, svc_pollfd, _null_auth, rpc_createerr,
//   rexecoptions, svcauthdes_stats
//
// For LD_PRELOAD interposition these are automatically resolved from
// glibc's data segment. We do NOT re-export them here because:
// 1. Rust cannot reliably export mutable global C data with correct ABI
// 2. Programs link against glibc's copy directly
// 3. The __rpc_thread_* accessors above provide function-based access
//    to the thread-local variants where needed.
