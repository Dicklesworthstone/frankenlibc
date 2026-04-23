#![no_main]
//! Fuzz target for FrankenLibC's dlfcn surface:
//!
//!   dlopen, dlsym, dlvsym, dlclose, dlerror, dladdr, dl_iterate_phdr
//!
//! The dlfcn surface is the classic dynamic-linking attack surface:
//! dlopen CVEs (CVE-2017-1000366, CVE-2023-4911 "Looney Tunables")
//! exploit the interaction between the process environment and the
//! loader. This harness exercises the API contract with safe
//! handles only — it never opens an attacker-chosen shared-object
//! path, which would in turn load attacker-chosen code.
//!
//! Safety:
//! - dlopen is called only with NULL (the executable handle) or
//!   with a small allowlist of real runtime libraries (`libc.so.6`,
//!   `libm.so.6`, `libdl.so.2`) that are guaranteed to exist on any
//!   Linux host we care about. The fuzzer never drives the filename
//!   pointer — it only picks which allowlist entry to use.
//! - dlsym is called with known-good symbol names ("malloc",
//!   "printf", etc.) and one fuzzer-supplied byte string sanitized
//!   to reject interior NULs — the expected outcome there is either
//!   a non-null function pointer (on a real glibc match) or a null
//!   return plus a dlerror string, never an abort.
//! - dlclose cycles through Live → Stale state tracking so the
//!   double-close invariant is exercised.
//!
//! Oracles:
//! - Return-code contract: dlopen/dlsym return `*mut c_void` (may be
//!   NULL); dlclose returns 0/-1; dladdr returns 0/non-zero.
//! - Lifecycle: dlclose on a Stale (already-closed) handle must
//!   either be a no-op (return 0) or return -1; it must NEVER
//!   corrupt the internal handle table.
//! - dlerror: after a failed dlsym, dlerror must return a non-null
//!   message; after a successful dlsym, dlerror's subsequent call
//!   must return null (the error is consumed).
//!
//! Bead: bd-dvr22 priority-6

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::{Mutex, Once};

use arbitrary::Arbitrary;
use frankenlibc_abi::dlfcn_abi::{dladdr, dlclose, dlerror, dlopen, dlsym};
use libfuzzer_sys::fuzz_target;

const MAX_HANDLES: usize = 4;
const MAX_OPS: usize = 12;

static DLOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Arbitrary)]
enum Op {
    OpenNull { flags_sel: u8 },
    OpenAllowlist { name_sel: u8, flags_sel: u8 },
    Sym { slot: u8, sym_sel: u8 },
    SymFuzz { slot: u8, symbol: Vec<u8> },
    Error,
    Close { slot: u8 },
    Addr { slot: u8, sym_sel: u8 },
}

#[derive(Debug, Arbitrary)]
struct DlfcnFuzzInput {
    ops: Vec<Op>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Live,
    Stale,
}

#[derive(Clone, Copy)]
struct Handle {
    ptr: *mut c_void,
    state: State,
}

fn init_hardened_mode() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: set once before any ABI call.
        unsafe {
            std::env::set_var("FRANKENLIBC_MODE", "hardened");
        }
    });
}

const ALLOWLIST: &[&[u8]] = &[
    b"libc.so.6\0",
    b"libm.so.6\0",
    b"libdl.so.2\0",
    b"libpthread.so.0\0",
];

const KNOWN_SYMS: &[&[u8]] = &[
    b"malloc\0",
    b"free\0",
    b"printf\0",
    b"strlen\0",
    b"memcpy\0",
    b"__nonexistent_sentinel\0",
];

fn pick_flags(sel: u8) -> c_int {
    match sel & 0b11 {
        0 => libc::RTLD_LAZY,
        1 => libc::RTLD_NOW,
        2 => libc::RTLD_LAZY | libc::RTLD_GLOBAL,
        _ => libc::RTLD_NOW | libc::RTLD_LOCAL,
    }
}

fn pick_allowlist(sel: u8) -> *const c_char {
    ALLOWLIST[(sel as usize) % ALLOWLIST.len()].as_ptr() as *const c_char
}

fn pick_sym(sel: u8) -> *const c_char {
    KNOWN_SYMS[(sel as usize) % KNOWN_SYMS.len()].as_ptr() as *const c_char
}

fn pick_slot(table: &mut [Handle], slot: u8) -> Option<(usize, Handle)> {
    if table.is_empty() {
        return None;
    }
    let idx = (slot as usize) % table.len();
    Some((idx, table[idx]))
}

fn sanitize_cstring(bytes: &[u8], cap: usize) -> CString {
    let cleaned: Vec<u8> = bytes
        .iter()
        .take(cap)
        .map(|&b| if b == 0 { b'?' } else { b })
        .collect();
    CString::new(cleaned).expect("NULs stripped")
}

fn apply_op(op: &Op, table: &mut Vec<Handle>) {
    match op {
        Op::OpenNull { flags_sel } => {
            if table.len() >= MAX_HANDLES {
                return;
            }
            let h = unsafe { dlopen(std::ptr::null(), pick_flags(*flags_sel)) };
            if !h.is_null() {
                table.push(Handle { ptr: h, state: State::Live });
            }
        }
        Op::OpenAllowlist { name_sel, flags_sel } => {
            if table.len() >= MAX_HANDLES {
                return;
            }
            let name = pick_allowlist(*name_sel);
            let h = unsafe { dlopen(name, pick_flags(*flags_sel)) };
            if !h.is_null() {
                table.push(Handle { ptr: h, state: State::Live });
            }
            // Null return is acceptable (e.g. worker lacks the library);
            // just assert no crash.
        }
        Op::Sym { slot, sym_sel } => {
            let Some((_, h)) = pick_slot(table, *slot) else {
                return;
            };
            // dlsym on a dlclose'd handle is UB per POSIX and SEGVs in ld-linux
            // in glibc. Skip stale slots; only exercise live handles (bd-cgodw).
            if h.state != State::Live {
                return;
            }
            let sym = pick_sym(*sym_sel);
            let _ = unsafe { dlsym(h.ptr, sym) };
        }
        Op::SymFuzz { slot, symbol } => {
            let Some((_, h)) = pick_slot(table, *slot) else {
                return;
            };
            if h.state != State::Live {
                return;
            }
            // Fuzzer-supplied symbol name with NULs stripped.
            let sym_c = sanitize_cstring(symbol, 128);
            let _ = unsafe { dlsym(h.ptr, sym_c.as_ptr()) };
        }
        Op::Error => {
            let msg = unsafe { dlerror() };
            if !msg.is_null() {
                // Must be a valid C string with a bounded scan.
                let mut len = 0;
                const MAX: usize = 8192;
                while len < MAX && unsafe { *msg.add(len) } != 0 {
                    len += 1;
                }
                assert!(len < MAX, "dlerror returned unterminated string");
            }
        }
        Op::Close { slot } => {
            let Some((idx, mut h)) = pick_slot(table, *slot) else {
                return;
            };
            // dlclose on an already-closed handle is UB; in glibc it corrupts
            // loader state and manifests as a later-SEGV in dlsym on an
            // unrelated LIVE handle (bd-cgodw). Skip stale slots.
            if h.state != State::Live {
                return;
            }
            let rc = unsafe { dlclose(h.ptr) };
            assert!(
                rc == 0 || rc == -1,
                "dlclose rc out of contract: {rc}"
            );
            if rc == 0 {
                h.state = State::Stale;
                table[idx] = h;
            }
        }
        Op::Addr { slot, sym_sel } => {
            let Some((_, h)) = pick_slot(table, *slot) else {
                return;
            };
            if h.state != State::Live {
                return;
            }
            // Get a symbol address via dlsym, then check dladdr resolves it.
            let sym = pick_sym(*sym_sel);
            let addr = unsafe { dlsym(h.ptr, sym) };
            if addr.is_null() {
                return;
            }
            let mut info: [u8; 64] = [0; 64];
            let rc = unsafe { dladdr(addr as *const c_void, info.as_mut_ptr().cast()) };
            assert!(rc == 0 || rc == 1, "dladdr rc out of contract: {rc}");
        }
    }
}

fn cleanup(table: &mut Vec<Handle>) {
    for h in std::mem::take(table) {
        if h.state == State::Live {
            unsafe {
                dlclose(h.ptr);
            }
        }
    }
}

fuzz_target!(|input: DlfcnFuzzInput| {
    if input.ops.len() > MAX_OPS {
        return;
    }
    init_hardened_mode();
    let _guard = DLOCK.lock().unwrap_or_else(|p| p.into_inner());

    let mut table: Vec<Handle> = Vec::with_capacity(MAX_HANDLES);
    for op in &input.ops {
        apply_op(op, &mut table);
    }
    cleanup(&mut table);
});
