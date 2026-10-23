//! ABI layer for Sun RPC / XDR / SVC functions.
//!
//! These are legacy ONC RPC functions from glibc's `<rpc/rpc.h>`, `<rpc/xdr.h>`,
//! `<rpc/svc.h>`, `<rpc/clnt.h>`, `<rpc/auth.h>`, `<rpc/pmap_clnt.h>`, and
//! `<rpc/des_crypt.h>` families. XDR serialisation is natively implemented in
//! pure Rust. Native clients/services cover IPv4 UDP/TCP, Unix streams and
//! synchronous memory RPC with AUTH_NONE/AUTH_SYS. Legacy authentication
//! constructors retain their explicitly limited behavior; see README coverage.

#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]

use std::ffi::{c_char, c_int, c_uint, c_void};
use std::mem::size_of;

use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

#[path = "rpc_client_create.rs"]
mod rpc_client_create;
#[path = "rpc_svc.rs"]
mod rpc_svc;
#[path = "rpc_svc_cache.rs"]
mod rpc_svc_cache;
#[path = "rpc_udp.rs"]
mod rpc_udp;
pub use rpc_client_create::{callrpc, clnt_create};
pub use rpc_svc::{
    _authenticate, registerrpc, svc_exit, svc_getreq, svc_getreq_common, svc_getreq_poll,
    svc_getreqset, svc_register, svc_run, svc_sendreply, svc_unregister, svcerr_auth,
    svcerr_decode, svcerr_noproc, svcerr_noprog, svcerr_progvers, svcerr_systemerr,
    svcerr_weakauth, svcfd_create, svctcp_create, svcudp_bufcreate, svcudp_create,
    svcudp_enablecache, svcunix_create, svcunixfd_create,
};

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
                // Caller frees via free per RFC 1832 mem_free contract.
                let buf = unsafe { crate::malloc_abi::malloc(len as usize) as *mut c_char };
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
                    crate::malloc_abi::free(p.cast());
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
        // mem_alloc semantics: caller frees via free.
        let buf = unsafe { crate::malloc_abi::malloc(size as usize + 1) as *mut c_char };
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
                crate::malloc_abi::free(p.cast());
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
        // mem_alloc semantics: caller frees via free.
        let buf = unsafe { crate::malloc_abi::malloc(total_bytes) as *mut c_char };
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
                crate::malloc_abi::free(p.cast());
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

#[cfg(feature = "owned-tls-cache")]
static XDR_REFERENCE_DEPTH_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<u32> =
    crate::owned_tls_cache::OwnedTlsCache::new(zero_u32);

#[cfg(feature = "owned-tls-cache")]
fn zero_u32() -> u32 {
    0
}

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static XDR_REFERENCE_DEPTH: std::cell::Cell<u32> = const {
        std::cell::Cell::new(0)
    };
}

#[inline]
fn try_enter_xdr_reference_depth() -> bool {
    #[cfg(feature = "owned-tls-cache")]
    {
        XDR_REFERENCE_DEPTH_OWNED_TLS.with(|depth| {
            if *depth >= XDR_REFERENCE_DEPTH_LIMIT {
                false
            } else {
                *depth += 1;
                true
            }
        })
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        XDR_REFERENCE_DEPTH
            .try_with(|cell| {
                let current = cell.get();
                if current >= XDR_REFERENCE_DEPTH_LIMIT {
                    false
                } else {
                    cell.set(current + 1);
                    true
                }
            })
            .unwrap_or(false)
    }
}

#[inline]
fn leave_xdr_reference_depth() {
    #[cfg(feature = "owned-tls-cache")]
    {
        XDR_REFERENCE_DEPTH_OWNED_TLS.with(|depth| {
            *depth = depth.saturating_sub(1);
        });
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        let _ = XDR_REFERENCE_DEPTH.try_with(|cell| cell.set(cell.get() - 1));
    }
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
    if !try_enter_xdr_reference_depth() {
        return XDR_FALSE;
    }

    let x = xdrs as *mut Xdr;
    let op = unsafe { (*x).x_op };
    if unsafe { (*pp).is_null() } {
        if op != XDR_DECODE {
            leave_xdr_reference_depth();
            return XDR_FALSE;
        }
        // mem_alloc semantics: caller frees via libc free (bd-zgifl).
        // Use calloc not malloc so recursive procs that read inner
        // pointer fields (e.g., a `next` link in a self-referential
        // struct) see a well-defined NULL — otherwise the caller's
        // first xdr_pointer call on `&buf->next` reads uninitialized
        // memory as a "pointer" and tries to use it. Mirrors glibc's
        // xdr_reference + memset(buf, 0, size) idiom.
        let buf = unsafe { crate::malloc_abi::calloc(1, size as usize) as *mut c_char };
        if buf.is_null() {
            leave_xdr_reference_depth();
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
                crate::malloc_abi::free(p.cast());
                *pp = std::ptr::null_mut();
            }
        }
    }
    leave_xdr_reference_depth();
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
            unsafe { crate::malloc_abi::free(node.cast()) };
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

/// Return the process-lifetime native AUTH_NONE authenticator.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn authnone_create() -> *mut c_void {
    rpc_udp::authnone()
}

/// Create owned AUTH_SYS credentials (not cryptographic authentication).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn authunix_create(
    machname: *mut c_char,
    uid: c_int,
    gid: c_int,
    len: c_int,
    aup_gids: *mut c_int,
) -> *mut c_void {
    unsafe { rpc_udp::authunix_create(machname, uid, gid, len, aup_gids) }
}

/// Create AUTH_SYS credentials from the effective process identity.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn authunix_create_default() -> *mut c_void {
    unsafe { rpc_udp::authunix_create_default() }
}

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

// ===========================================================================
// RPC client creation and error handling (14 symbols)
// ===========================================================================

/// Return the caller-thread memory RPC client; construction reuses its handle
/// and resets AUTH_NONE. No socket or descriptor is created. The handle remains
/// live until thread exit; its destroy/geterr operations are GNU no-ops.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn clntraw_create(prog: c_ulong, vers: c_ulong) -> *mut c_void {
    rpc_udp::create_raw(prog, vers)
}

/// Create a native IPv4 TCP RPC client with bounded record framing.
/// Borrowed descriptors must already be connected and remain caller-owned.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnttcp_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint,
) -> *mut c_void {
    unsafe { rpc_udp::create_tcp(raddr, prog, vers, sockp, sendsz, recvsz) }
}

/// Create an IPv4 UDP RPC client with native XDR and retransmission handling.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    wait: Timeval,
    sockp: *mut c_int,
) -> *mut c_void {
    unsafe { rpc_udp::create(raddr, prog, vers, wait, sockp, 0, 0) }
}

/// Create an IPv4 UDP RPC client with explicit bounded transport buffers.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clntudp_bufcreate(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    wait: Timeval,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint,
) -> *mut c_void {
    unsafe { rpc_udp::create(raddr, prog, vers, wait, sockp, sendsz, recvsz) }
}

/// Create a native Unix RPC stream client with credential-bearing records.
///
/// # Safety
/// raddr and sockp point to live public sockaddr_un/int objects. A supplied
/// connected descriptor must have no competing consumer. It stays caller-owned
/// unless CLSET_FD_CLOSE transfers ownership; Unix I/O enables SO_PASSCRED.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clntunix_create(
    raddr: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    sockp: *mut c_int,
    sendsz: c_uint,
    recvsz: c_uint,
) -> *mut c_void {
    // SAFETY: native construction imports all user structures with fault checks.
    unsafe { rpc_udp::create_unix(raddr, prog, vers, sockp, sendsz, recvsz) }
}

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
    write_rpc_diagnostic(rpc_errstr(stat).to_bytes());
}

fn write_rpc_diagnostic(bytes: &[u8]) {
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: the complete byte range remains live during each raw write.
        // These reporting functions introduce no cancellation point in C frames.
        let written = unsafe {
            crate::unistd_abi::sys_write_fd(
                2,
                bytes.as_ptr().add(offset).cast(),
                bytes.len() - offset,
            )
        };
        // SAFETY: __errno_location provides this thread's live errno slot.
        if written > 0 {
            offset += written as usize;
        } else if written < 0 && unsafe { *crate::errno_abi::__errno_location() } == libc::EINTR {
            continue;
        } else {
            break;
        }
    }
}

/// Print the CLIENT's last error using its own geterr callback. The rendered
/// message already has the status-specific newline, if any.
///
/// # Safety
/// The CLIENT/table/callback and optional C prefix must remain live for the call.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn clnt_perror(clnt: *mut c_void, s: *const c_char) {
    // SAFETY: the caller supplies the same CLIENT and prefix contract.
    let message = unsafe { clnt_sperror(clnt, s) };
    if !message.is_null() {
        // SAFETY: clnt_sperror published an owned NUL-terminated thread buffer.
        write_rpc_diagnostic(unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes());
    }
}

/// Print RPC client creation error to stderr. Native implementation.
/// Reads from thread-local rpc_createerr (via __rpc_thread_createerr).
///
/// # Safety
/// ABI boundary function. `s` must be a valid C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_pcreateerror(s: *const c_char) {
    let msg = unsafe { clnt_spcreateerror(s) };
    if !msg.is_null() {
        // SAFETY: the creation formatter published a complete terminated buffer.
        write_rpc_diagnostic(unsafe { std::ffi::CStr::from_ptr(msg) }.to_bytes());
    }
}

/// Return a string describing an RPC error status code. Native implementation.
/// Uses RPC_* status codes from glibc's <rpc/clnt_stat.h>.
///
/// # Safety
/// The returned pointer refers to immutable process-lifetime C-locale storage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_sperrno(stat: c_int) -> *mut c_char {
    rpc_errstr(stat).as_ptr().cast_mut()
}

#[cfg(feature = "owned-tls-cache")]
static RPC_DIAGNOSTIC_BUF_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<Vec<u8>> =
    crate::owned_tls_cache::OwnedTlsCache::new(Vec::new);

// GNU client/creation diagnostics share one per-thread allocation. Build the
// next message before replacing it, including when the prefix aliases it.
#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static RPC_DIAGNOSTIC_BUF: std::cell::UnsafeCell<Vec<u8>> =
        const { std::cell::UnsafeCell::new(Vec::new()) };
}

#[inline]
fn with_rpc_diagnostic_buf<R>(f: impl FnOnce(&mut Vec<u8>) -> R) -> R {
    #[cfg(feature = "owned-tls-cache")]
    {
        RPC_DIAGNOSTIC_BUF_OWNED_TLS.with(f)
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        // SAFETY: only this thread accesses the cell; callers replace the Vec
        // without invoking application callbacks while the borrow is held.
        RPC_DIAGNOSTIC_BUF.with(|cell| f(unsafe { &mut *cell.get() }))
    }
}

unsafe fn rpc_diagnostic_prefix(prefix: *const c_char) -> Vec<u8> {
    if prefix.is_null() {
        b"(null)".to_vec()
    } else {
        // SAFETY: the caller supplies a live C string; the existing bounded
        // reader applies the mode-specific checked-prefix policy.
        unsafe { read_bounded_cstr(prefix) }.unwrap_or_default()
    }
}

fn rpc_errno_description(number: c_int) -> Option<&'static [u8]> {
    let message = crate::string_abi::strerrordesc_np(number);
    if message.is_null() {
        None
    } else {
        // SAFETY: strerrordesc_np returns immutable NUL-terminated static data.
        Some(unsafe { std::ffi::CStr::from_ptr(message) }.to_bytes())
    }
}

fn publish_rpc_diagnostic(
    message: Result<Vec<u8>, std::collections::TryReserveError>,
) -> *mut c_char {
    match message {
        Ok(message) => with_rpc_diagnostic_buf(|previous| {
            *previous = message;
            previous.as_mut_ptr().cast()
        }),
        Err(_) => {
            // SAFETY: setting errno accesses only the current thread's slot.
            unsafe { set_abi_errno(libc::ENOMEM) };
            std::ptr::null_mut()
        }
    }
}

/// Render a live CLIENT's last error. Prefix bytes are copied before calling
/// application geterr code; no diagnostic storage borrow/lock crosses it.
///
/// # Safety
/// The CLIENT/table/callback must be live. A non-null prefix must be a valid C
/// string. The result lasts until the next client/creation diagnostic on this thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C-unwind" fn clnt_sperror(clnt: *mut c_void, s: *const c_char) -> *mut c_char {
    // SAFETY: the public prefix contract is forwarded to the bounded reader.
    let prefix = unsafe { rpc_diagnostic_prefix(s) };
    // SAFETY: the caller keeps the CLIENT/table/geterr callback live.
    let (status, words) = match unsafe { rpc_udp::client_error(clnt) } {
        Ok(error) => error,
        Err(error) => {
            // SAFETY: setting errno accesses only the current thread's slot.
            unsafe { set_abi_errno(error) };
            return std::ptr::null_mut();
        }
    };
    publish_rpc_diagnostic(frankenlibc_core::rpc::client_error_message(
        &prefix,
        status,
        words,
        rpc_errno_description(words[0] as c_int),
    ))
}

/// Return a string describing the RPC client creation error. Native implementation.
/// Reads from thread-local rpc_createerr (cf_stat field at offset 0).
///
/// # Safety
/// ABI boundary function. `s` must be a valid C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn clnt_spcreateerror(s: *const c_char) -> *mut c_char {
    // SAFETY: the public prefix contract is forwarded to the bounded reader.
    let prefix = unsafe { rpc_diagnostic_prefix(s) };
    let (status, nested_status, words) = rpc_udp::creation_error_details();
    let error_number = words[0] as c_int;
    publish_rpc_diagnostic(frankenlibc_core::rpc::creation_error_message(
        &prefix,
        status,
        nested_status,
        error_number,
        rpc_errno_description(error_number),
    ))
}

use frankenlibc_core::rpc::status_message as rpc_errstr;

// ===========================================================================
// RPC server / SVC (24 symbols; 18 UDP service symbols provided by rpc_svc)
// ===========================================================================

/// Return a caller-thread memory RPC service with a logical descriptor of zero.
/// It never owns stdin and is excluded from socket readiness sets. Register
/// dispatch with svc_register(..., 0); the native raw client invokes it directly.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub extern "C" fn svcraw_create() -> *mut c_void {
    rpc_svc::create_raw()
}

// ===========================================================================
// RPC misc: registerrpc, dtablesize, createerr thread locals (14+ symbols)
// ===========================================================================

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
// This is 32 bytes on x86_64 (4 + padding + 24 for rpc_err).
// We allocate exactly 32 bytes — and, since callers receive this
// address as a `struct rpc_createerr *` and write `cf_stat`/`cf_error` fields
// through it, for ALIGNMENT too: a bare `[u8; 32]` has align 1, which is the
// class that aborted `re_comp` and `getmntent` with misaligned pointer
// dereference. `#[repr(C, align(8))]` is what actually makes the cast safe.
#[repr(C, align(8))]
struct RpcCreateErrBuf([u8; 32]);

#[cfg(feature = "owned-tls-cache")]
static RPC_CREATEERR_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<RpcCreateErrBuf> =
    crate::owned_tls_cache::OwnedTlsCache::new(empty_rpc_createerr);

#[cfg(feature = "owned-tls-cache")]
fn empty_rpc_createerr() -> RpcCreateErrBuf {
    RpcCreateErrBuf([0u8; 32])
}

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static RPC_CREATEERR_TLS: std::cell::UnsafeCell<RpcCreateErrBuf> =
        const { std::cell::UnsafeCell::new(RpcCreateErrBuf([0u8; 32])) };
}

#[inline]
fn rpc_createerr_ptr() -> *mut c_void {
    #[cfg(feature = "owned-tls-cache")]
    {
        RPC_CREATEERR_OWNED_TLS.with(|buf| buf.0.as_mut_ptr().cast())
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        RPC_CREATEERR_TLS.with(|cell| cell.get().cast::<u8>().cast())
    }
}

/// Returns pointer to thread-local rpc_createerr struct.
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_createerr() -> *mut c_void {
    rpc_createerr_ptr()
}

// fd_set size derived from FD_SETSIZE (1024 on Linux → 128 bytes).
const RPC_FD_SET_BYTES: usize = libc::FD_SETSIZE / 8;

// ALIGNMENT IS LOAD-BEARING. `fd_set` is an array of `__fd_mask` (`long`), and
// `__rpc_thread_svc_fdset()` hands this address to C code whose FD_SET/FD_ISSET/
// FD_CLR write pointer-width words through it — and whose `select()` is handed the
// same pointer, so the kernel reads it as `unsigned long[]` too. A bare
// `[u8; N]` has align 1 and the TLS block can place it anywhere, which is the
// class that aborted `re_comp` and `getmntent` with `misaligned pointer
// dereference`. `#[repr(C, align(8))]` pins offset 0 and the alignment.
#[repr(C, align(8))]
struct RpcSvcFdSetBuf([u8; RPC_FD_SET_BYTES]);

#[cfg(feature = "owned-tls-cache")]
static RPC_SVC_FDSET_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<RpcSvcFdSetBuf> =
    crate::owned_tls_cache::OwnedTlsCache::new(empty_rpc_svc_fdset);

#[cfg(feature = "owned-tls-cache")]
fn empty_rpc_svc_fdset() -> RpcSvcFdSetBuf {
    RpcSvcFdSetBuf([0u8; RPC_FD_SET_BYTES])
}

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static RPC_SVC_FDSET_TLS: std::cell::UnsafeCell<RpcSvcFdSetBuf> =
        const { std::cell::UnsafeCell::new(RpcSvcFdSetBuf([0u8; RPC_FD_SET_BYTES])) };
}

#[inline]
fn rpc_svc_fdset_ptr() -> *mut c_void {
    #[cfg(feature = "owned-tls-cache")]
    {
        RPC_SVC_FDSET_OWNED_TLS.with(|buf| buf.0.as_mut_ptr().cast())
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        RPC_SVC_FDSET_TLS.with(|cell| cell.get().cast::<u8>().cast())
    }
}

/// Returns pointer to thread-local svc_fdset (fd_set).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_fdset() -> *mut c_void {
    rpc_svc::refresh();
    rpc_svc_fdset_ptr()
}

#[cfg(feature = "owned-tls-cache")]
static RPC_SVC_MAX_POLLFD_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<c_int> =
    crate::owned_tls_cache::OwnedTlsCache::new(zero_c_int);

#[cfg(feature = "owned-tls-cache")]
fn zero_c_int() -> c_int {
    0
}

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static RPC_SVC_MAX_POLLFD_TLS: std::cell::UnsafeCell<c_int> =
        const { std::cell::UnsafeCell::new(0) };
}

#[inline]
fn rpc_svc_max_pollfd_ptr() -> *mut c_void {
    #[cfg(feature = "owned-tls-cache")]
    {
        RPC_SVC_MAX_POLLFD_OWNED_TLS.with(|value| (value as *mut c_int).cast())
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        RPC_SVC_MAX_POLLFD_TLS.with(|cell| cell.get().cast())
    }
}

/// Returns pointer to thread-local svc_max_pollfd (int).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_max_pollfd() -> *mut c_void {
    rpc_svc::refresh();
    rpc_svc_max_pollfd_ptr()
}

#[cfg(feature = "owned-tls-cache")]
static RPC_SVC_POLLFD_OWNED_TLS: crate::owned_tls_cache::OwnedTlsCache<usize> =
    crate::owned_tls_cache::OwnedTlsCache::new(zero_usize);

#[cfg(feature = "owned-tls-cache")]
fn zero_usize() -> usize {
    0
}

#[cfg(not(feature = "owned-tls-cache"))]
std::thread_local! {
    static RPC_SVC_POLLFD_TLS: std::cell::UnsafeCell<*mut c_void> =
        const { std::cell::UnsafeCell::new(std::ptr::null_mut()) };
}

#[inline]
fn rpc_svc_pollfd_ptr() -> *mut c_void {
    #[cfg(feature = "owned-tls-cache")]
    {
        RPC_SVC_POLLFD_OWNED_TLS.with(|value| (value as *mut usize).cast())
    }
    #[cfg(not(feature = "owned-tls-cache"))]
    {
        RPC_SVC_POLLFD_TLS.with(|cell| cell.get().cast())
    }
}

/// Returns pointer to thread-local svc_pollfd (struct pollfd *).
///
/// # Safety
/// ABI boundary function. Returns a pointer valid for the lifetime of the calling thread.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __rpc_thread_svc_pollfd() -> *mut c_void {
    rpc_svc::refresh();
    rpc_svc_pollfd_ptr()
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

/// Get a program's port from the remote portmapper v2 service.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_getport(
    address: *mut c_void,
    prog: c_ulong,
    vers: c_ulong,
    proto: c_uint,
) -> u16 {
    unsafe { rpc_udp::getport(address, prog, vers, proto) }
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

/// Register a program with the local portmapper v2 service.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_set(prog: c_ulong, vers: c_ulong, proto: c_int, port: u16) -> c_int {
    rpc_udp::registration(prog, vers, proto, port, false)
}

/// Unregister a program/version from the local portmapper v2 service.
///
/// # Safety
/// ABI boundary function.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn pmap_unset(prog: c_ulong, vers: c_ulong) -> c_int {
    rpc_udp::registration(prog, vers, 0, 0, true)
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

/// Read the kernel hostname or NIS domain without inventing an identity.
fn rpc_netname_system_component(host: bool) -> Option<Vec<u8>> {
    let mut bytes = [0u8; 65];
    // SAFETY: both native entry points receive writable storage large enough
    // for a Linux UTS field and its terminating NUL.
    let status = unsafe {
        if host {
            crate::unistd_abi::gethostname(bytes.as_mut_ptr().cast(), bytes.len())
        } else {
            crate::unistd_abi::getdomainname(bytes.as_mut_ptr().cast(), bytes.len())
        }
    };
    if status != 0 {
        return None;
    }
    let end = bytes.iter().position(|&byte| byte == 0)?;
    Some(bytes[..end].to_vec())
}

/// Publish a Secure RPC name in the caller's buffer.
///
/// # Safety
/// destination is non-null and writable for 256 bytes, or its smaller extent
/// is registered with the allocator. Both input components are owned bytes.
unsafe fn rpc_netname_write(destination: *mut c_char, identity: &[u8], domain: &[u8]) -> c_int {
    let len = 5 + identity.len() + 1 + domain.len() + 1;
    if len > 256 || known_remaining(destination as usize).is_some_and(|remaining| remaining < len) {
        return 0;
    }
    let mut bytes = [0u8; 256];
    bytes[..5].copy_from_slice(b"unix.");
    let separator = 5 + identity.len();
    bytes[5..separator].copy_from_slice(identity);
    bytes[separator] = b'@';
    bytes[separator + 1..len - 1].copy_from_slice(domain);
    // SAFETY: callers validate the destination, the tracked extent is checked,
    // and the complete output, including its NUL, fits in the local buffer.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), destination.cast(), len);
    }
    1
}

/// Get the current Secure RPC netname. Root uses the machine identity;
/// other effective users use their uid and the kernel NIS domain.
///
/// # Safety
/// name must point to a writable buffer of at least 256 bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getnetname(name: *mut c_char) -> c_int {
    let uid = raw_syscall::sys_geteuid();
    // SAFETY: both delegates validate null pointers and share this function's
    // caller-owned output contract; null inputs select system components.
    unsafe {
        if uid == 0 {
            host2netname(name, std::ptr::null(), std::ptr::null())
        } else {
            user2netname(name, uid, std::ptr::null())
        }
    }
}

/// Read a bounded native Secure RPC database image. A descriptor is closed on
/// every exit; interrupted reads retry without publishing a partial image.
fn rpc_identity_file<T>(
    path: &std::ffi::CStr,
    parse: impl FnOnce(&[u8]) -> Option<T>,
) -> frankenlibc_core::nss::Answer<T> {
    use frankenlibc_core::nss::Answer;
    const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;
    struct File(c_int);
    impl Drop for File {
        fn drop(&mut self) {
            let _ = raw_syscall::sys_close(self.0);
        }
    }
    let read = || -> Result<Vec<u8>, c_int> {
        // SAFETY: path is a live NUL-terminated constant; no mode is needed
        // for a read-only open. No host libc lookup is used for file access.
        let fd = File(unsafe {
            raw_syscall::sys_openat(
                libc::AT_FDCWD,
                path.as_ptr().cast(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0,
            )?
        });
        let mut image = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            // SAFETY: chunk is writable for its complete length and fd is
            // owned by this call until its RAII guard closes it.
            let count =
                match unsafe { raw_syscall::sys_read(fd.0, chunk.as_mut_ptr(), chunk.len()) } {
                    Ok(0) => return Ok(image),
                    Ok(count) => count,
                    Err(libc::EINTR) => continue,
                    Err(error) => return Err(error),
                };
            if count > MAX_IMAGE_BYTES - image.len() {
                return Err(libc::EFBIG);
            }
            image.try_reserve(count).map_err(|_| libc::ENOMEM)?;
            image.extend_from_slice(&chunk[..count]);
        }
    };
    match read() {
        Ok(image) => parse(&image).map_or(Answer::NotFound, Answer::Found),
        Err(error) => {
            // SAFETY: this updates only the current thread's valid errno slot.
            unsafe { set_abi_errno(error) };
            Answer::Unavailable(error)
        }
    }
}

/// Get the public key for an exact network identity through the publickey
/// NSS database. The native files source reads `/etc/publickey`; configured
/// modules use their public GNU nss_getpublickey entry point.
///
/// # Safety
/// netname is a readable C string and publickey is writable for 49 bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn getpublickey(netname: *const c_char, publickey: *mut c_char) -> c_int {
    use frankenlibc_core::nss::{Answer, Database};
    use frankenlibc_core::rpc::PUBLICKEY_HEX_BYTES;
    if publickey.is_null()
        || known_remaining(publickey as usize)
            .is_some_and(|remaining| remaining < PUBLICKEY_HEX_BYTES + 1)
    {
        return 0;
    }
    // SAFETY: the caller supplies a C string; known allocation bounds apply.
    let Some(name) = (unsafe { read_bounded_cstr(netname) }) else {
        return 0;
    };
    if name.is_empty() || name.len() > 255 {
        return 0;
    }
    let services = crate::nss_module::services(Database::Publickey);
    let answer = frankenlibc_core::nss::lookup(
        &services,
        |service| {
            if service.name() == b"files" {
                rpc_identity_file(c"/etc/publickey", |image| {
                    frankenlibc_core::rpc::lookup_publickey(image, &name)
                })
            } else {
                crate::nss_module::getpublickey(service.name(), &name)
            }
        },
        None,
    );
    let Answer::Found(key) = answer else {
        return 0;
    };
    // SAFETY: the entire fixed-size output was validated before the lookup;
    // the owned key is disjoint from caller storage and includes no NUL.
    unsafe {
        std::ptr::copy_nonoverlapping(key.as_ptr(), publickey.cast(), key.len());
        *publickey.add(key.len()) = 0;
    }
    1
}

/// Get the secret key for a netname from the publickey database.
/// Returns 0 (failure): encrypted secret-key decryption is not implemented.
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

/// Convert a hostname to a Secure RPC netname in a caller-owned buffer.
/// A null host selects the kernel hostname. A null domain uses the hostname
/// suffix when present, otherwise the kernel NIS domain.
///
/// # Safety
/// netname must point to a writable buffer of at least 256 bytes.
/// Non-null host and domain must point to readable C strings.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn host2netname(
    netname: *mut c_char,
    host: *const c_char,
    domain: *const c_char,
) -> c_int {
    if netname.is_null() || known_remaining(netname as usize) == Some(0) {
        return 0;
    }
    // GNU clears the output on a rejected host/domain pair.
    // SAFETY: the destination is non-null with at least one writable byte.
    unsafe {
        *netname = 0;
    }
    let host_owned = if host.is_null() {
        rpc_netname_system_component(true)
    } else {
        // SAFETY: the caller supplies a C string; the helper checks known bounds.
        unsafe { read_bounded_cstr(host) }
    };
    let Some(host_owned) = host_owned else {
        return 0;
    };
    // The host ABI bounds each component before applying its dot rules.
    let host = &host_owned[..host_owned.len().min(64)];
    let dot = host.iter().position(|&byte| byte == b'.');
    let domain_owned = if !domain.is_null() {
        // SAFETY: the caller supplies a C string; the helper checks known bounds.
        unsafe { read_bounded_cstr(domain) }
    } else if let Some(dot) = dot {
        Some(host[dot + 1..].to_vec())
    } else {
        rpc_netname_system_component(false)
    };
    let Some(domain_owned) = domain_owned else {
        return 0;
    };
    let domain = &domain_owned[..domain_owned.len().min(64)];
    if domain.is_empty() {
        return 0;
    }
    let domain = domain.strip_suffix(b".").unwrap_or(domain);
    let host = &host[..dot.unwrap_or(host.len())];
    // SAFETY: the output was validated above and both components are owned.
    unsafe { rpc_netname_write(netname, host, domain) }
}

/// Resolve a network identity to the authoritative `/etc/netid` host mapping.
/// The publickey NSS source order and status actions apply. GNU defines no
/// netname2host service-module entry point, so other sources are unavailable.
/// A successful files answer copies and pads exactly hostlen bytes, matching
/// the public netid implementation's strncpy contract (truncation may omit NUL).
///
/// # Safety
/// netname is a readable C string; hostname is writable for hostlen bytes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn netname2host(
    netname: *const c_char,
    hostname: *mut c_char,
    hostlen: c_int,
) -> c_int {
    use frankenlibc_core::nss::{Answer, Database};
    if hostlen < 0 || (hostlen > 0 && hostname.is_null()) {
        return 0;
    }
    let hostlen = hostlen as usize;
    if known_remaining(hostname as usize).is_some_and(|remaining| remaining < hostlen) {
        return 0;
    }
    // SAFETY: the caller supplies a C string; known allocation bounds apply.
    let Some(name) = (unsafe { read_bounded_cstr(netname) }) else {
        return 0;
    };
    if name.is_empty() || name.len() > 255 {
        return 0;
    }
    let services = crate::nss_module::services(Database::Publickey);
    let answer = frankenlibc_core::nss::lookup(
        &services,
        |service| {
            if service.name() == b"files" {
                rpc_identity_file(c"/etc/netid", |image| {
                    frankenlibc_core::rpc::lookup_netid_host(image, &name).map(<[u8]>::to_vec)
                })
            } else {
                Answer::Unavailable(libc::ENOSYS)
            }
        },
        None,
    );
    let Answer::Found(host) = answer else {
        return 0;
    };
    if hostlen == 0 {
        return 1;
    }
    let copied = host.len().min(hostlen);
    // SAFETY: the caller and tracked extent authorize hostlen writable bytes;
    // the owned host image cannot alias the destination. Both ranges fit.
    unsafe {
        std::ptr::copy_nonoverlapping(host.as_ptr(), hostname.cast(), copied);
        std::ptr::write_bytes(hostname.add(copied), 0, hostlen - copied);
    }
    1
}

/// Resolve an exact network name through the publickey NSS database to an
/// authoritative uid, primary gid and supplementary group list. The files
/// source reads `/etc/netid`; other sources use nss_netname2user modules.
/// No local credentials are inferred from the spelling of the network name.
///
/// # Safety
/// netname is a readable C string; scalar outputs are writable uid_t/gid_t/int
/// slots. gidlist has the public NGROUPS capacity, or a tracked smaller extent
/// sufficient for the returned supplementary groups. A zero-group result may
/// use a null gidlist. Failure does not publish partial caller outputs.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn netname2user(
    netname: *const c_char,
    uidp: *mut libc::uid_t,
    gidp: *mut libc::gid_t,
    gidlenp: *mut c_int,
    gidlist: *mut libc::gid_t,
) -> c_int {
    use frankenlibc_core::nss::{Answer, Database};
    if uidp.is_null()
        || gidp.is_null()
        || gidlenp.is_null()
        || known_remaining(uidp as usize)
            .is_some_and(|remaining| remaining < size_of::<libc::uid_t>())
        || known_remaining(gidp as usize)
            .is_some_and(|remaining| remaining < size_of::<libc::gid_t>())
        || known_remaining(gidlenp as usize).is_some_and(|remaining| remaining < size_of::<c_int>())
    {
        return 0;
    }
    // SAFETY: the caller supplies a C string; known allocation bounds apply.
    let Some(name) = (unsafe { read_bounded_cstr(netname) }) else {
        return 0;
    };
    if name.is_empty() || name.len() > 255 {
        return 0;
    }
    let services = crate::nss_module::services(Database::Publickey);
    let answer = frankenlibc_core::nss::lookup(
        &services,
        |service| {
            if service.name() == b"files" {
                rpc_identity_file(c"/etc/netid", |image| {
                    frankenlibc_core::rpc::lookup_netid_user(image, &name)
                })
            } else {
                crate::nss_module::netname2user(service.name(), &name)
            }
        },
        None,
    );
    let Answer::Found(user) = answer else {
        return 0;
    };
    let group_bytes = user.groups.len() * size_of::<libc::gid_t>();
    if !user.groups.is_empty()
        && (gidlist.is_null()
            || known_remaining(gidlist as usize).is_some_and(|remaining| remaining < group_bytes))
    {
        return 0;
    }
    // SAFETY: all caller extents were checked before any publication. uid_t
    // and gid_t remain 32-bit on LP64; no adjacent word or unused group slot
    // is changed. Private module/file buffers cannot alias caller outputs.
    unsafe {
        if !user.groups.is_empty() {
            std::ptr::copy_nonoverlapping(user.groups.as_ptr(), gidlist, user.groups.len());
        }
        *uidp = user.uid;
        *gidp = user.gid;
        *gidlenp = user.groups.len() as c_int;
    }
    1
}

/// Convert a uid to a Secure RPC netname in a caller-owned buffer.
/// A null domain selects the kernel NIS domain.
///
/// # Safety
/// netname must point to a writable buffer of at least 256 bytes.
/// A non-null domain must point to a readable C string.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn user2netname(
    netname: *mut c_char,
    uid: libc::uid_t,
    domain: *const c_char,
) -> c_int {
    if netname.is_null() {
        return 0;
    }
    let domain_owned = if domain.is_null() {
        rpc_netname_system_component(false)
    } else {
        // SAFETY: the caller supplies a C string; the helper checks known bounds.
        unsafe { read_bounded_cstr(domain) }
    };
    let Some(domain_owned) = domain_owned else {
        return 0;
    };
    // GNU reserves space for the longest signed uid before stripping a dot.
    // A rejected user domain must leave the entire destination unchanged.
    if domain_owned.len() > 237 {
        return 0;
    }
    let domain = domain_owned.strip_suffix(b".").unwrap_or(&domain_owned);
    let identity = (uid as i32).to_string();
    // SAFETY: the output is non-null and the publisher checks its known extent.
    unsafe { rpc_netname_write(netname, identity.as_bytes(), domain) }
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
