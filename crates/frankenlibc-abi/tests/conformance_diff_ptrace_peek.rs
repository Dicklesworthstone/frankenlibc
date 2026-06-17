//! Differential gate: ptrace PEEK request return value vs live host glibc.
//!
//! glibc's ptrace bridges PEEKTEXT/PEEKDATA/PEEKUSER (the kernel writes the word
//! via `data` and returns 0; the C API expects the word as the return value).
//! fl previously passed the caller's `data` (NULL) through and returned 0, so a
//! PEEK faulted / returned the wrong value. We fork a self-tracing child, stop
//! it, and PEEKDATA a known global through both fl and glibc, requiring the same
//! word. glibc reached via dlsym. Skips gracefully if ptrace is restricted.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;
use std::ffi::{c_int, c_long, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn ptrace(request: c_int, pid: c_int, addr: *mut c_void, data: *mut c_void) -> c_long;
    fn _exit(code: c_int) -> !;
}
type PtraceFn = unsafe extern "C" fn(c_int, c_int, *mut c_void, *mut c_void) -> c_long;

const PTRACE_TRACEME: c_int = 0;
const PTRACE_PEEKDATA: c_int = 2;
const PTRACE_KILL: c_int = 8;
const SIGSTOP: c_int = 19;

// A fixed-value global; its address is identical in the forked child (COW), so
// the tracing parent can PEEK it there.
static MARKER: u64 = 0x1234_5678_9abc_def0;

fn glibc_ptrace() -> PtraceFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2);
        assert!(!h.is_null());
        std::mem::transmute(dlsym(h, c"ptrace".as_ptr()))
    }
}

fn wifstopped(status: c_int) -> bool {
    (status & 0xff) == 0x7f
}

#[test]
fn ptrace_peekdata_returns_word_like_glibc() {
    let g = glibc_ptrace();
    let addr = std::ptr::addr_of!(MARKER) as *mut c_void;

    unsafe {
        let child = fork();
        if child < 0 {
            eprintln!("fork failed; skipping");
            return;
        }
        if child == 0 {
            // Child: opt into tracing, then stop so the parent can peek.
            if ptrace(PTRACE_TRACEME, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0 {
                _exit(2);
            }
            kill(std::process::id() as c_int, SIGSTOP);
            _exit(0);
        }

        // Parent: wait for the child to stop under ptrace.
        let mut status: c_int = 0;
        if waitpid(child, &mut status, 0) != child || !wifstopped(status) {
            // ptrace likely restricted (yama/container); clean up and skip.
            ptrace(PTRACE_KILL, child, std::ptr::null_mut(), std::ptr::null_mut());
            let _ = waitpid(child, &mut status, 0);
            eprintln!("child did not stop under ptrace (restricted?); skipping");
            return;
        }

        // PEEKDATA the marker through glibc and fl — same word, no data ptr.
        let gw = g(PTRACE_PEEKDATA, child, addr, std::ptr::null_mut());
        let fw = fl::ptrace(PTRACE_PEEKDATA, child, addr, std::ptr::null_mut());

        // Tear the child down before asserting.
        ptrace(PTRACE_KILL, child, std::ptr::null_mut(), std::ptr::null_mut());
        let _ = waitpid(child, &mut status, 0);

        assert_eq!(gw, fw, "ptrace PEEKDATA: glibc={gw:#x} fl={fw:#x}");
        assert_eq!(gw as u64, MARKER, "PEEKDATA did not read the marker: {gw:#x}");
    }
}
