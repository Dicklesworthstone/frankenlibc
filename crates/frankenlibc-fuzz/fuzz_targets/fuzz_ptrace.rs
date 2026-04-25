#![no_main]
//! Structure-aware fuzz target for Linux ptrace(2).
//!
//! ptrace has ~20 request codes, each interpreting `addr` and `data`
//! arguments differently. Without an actual tracee process most calls
//! return ESRCH/EPERM, but the user-space wrapper still has to map
//! requests, validate pids, propagate errnos, and never panic.
//!
//! Strategy:
//! - Always call against a non-existent or invalid pid so we never
//!   actually attach to a running process. Real attach paths require
//!   privileges and would risk damaging unrelated processes.
//! - Deliberately omit PTRACE_TRACEME because that request ignores the
//!   pid argument and mutates the current fuzzing process instead.
//! - Cover both the "control" requests (CONT/SYSCALL/DETACH/KILL/SEIZE)
//!   and the "memory" requests (PEEKDATA/POKEDATA/PEEKTEXT/PEEKUSER) on
//!   bogus addresses to exercise the kernel's pid-lookup + addr
//!   validation.
//!
//! Invariants:
//! - Never panic for any (request, pid, addr, data) tuple
//! - Return value is c_long: -1 on error or any value (PEEKDATA is
//!   allowed to return any 64-bit value including -1; we don't use
//!   the return to derive control flow)
//!
//! Bead: bd-ptrace

use std::ffi::c_void;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::unistd_abi::ptrace;

const MAX_OUT_BUF_BYTES: usize = 256;

const REQUESTS: &[libc::c_int] = &[
    libc::PTRACE_PEEKTEXT as libc::c_int,
    libc::PTRACE_PEEKDATA as libc::c_int,
    libc::PTRACE_PEEKUSER as libc::c_int,
    libc::PTRACE_POKETEXT as libc::c_int,
    libc::PTRACE_POKEDATA as libc::c_int,
    libc::PTRACE_POKEUSER as libc::c_int,
    libc::PTRACE_CONT as libc::c_int,
    libc::PTRACE_KILL as libc::c_int,
    libc::PTRACE_SINGLESTEP as libc::c_int,
    libc::PTRACE_GETREGS as libc::c_int,
    libc::PTRACE_SETREGS as libc::c_int,
    libc::PTRACE_GETFPREGS as libc::c_int,
    libc::PTRACE_SETFPREGS as libc::c_int,
    libc::PTRACE_ATTACH as libc::c_int,
    libc::PTRACE_DETACH as libc::c_int,
    libc::PTRACE_GETFPXREGS as libc::c_int,
    libc::PTRACE_SETFPXREGS as libc::c_int,
    libc::PTRACE_SYSCALL as libc::c_int,
    libc::PTRACE_SETOPTIONS as libc::c_int,
    libc::PTRACE_GETEVENTMSG as libc::c_int,
    libc::PTRACE_GETSIGINFO as libc::c_int,
    libc::PTRACE_SETSIGINFO as libc::c_int,
    libc::PTRACE_GETREGSET as libc::c_int,
    libc::PTRACE_SETREGSET as libc::c_int,
    libc::PTRACE_SEIZE as libc::c_int,
    libc::PTRACE_INTERRUPT as libc::c_int,
    libc::PTRACE_LISTEN as libc::c_int,
    libc::PTRACE_PEEKSIGINFO as libc::c_int,
    libc::PTRACE_GETSIGMASK as libc::c_int,
    libc::PTRACE_SETSIGMASK as libc::c_int,
    // Intentionally invalid request codes:
    -1,
    0x7fffffff,
];

#[derive(Debug, Arbitrary)]
struct PtraceInput {
    req_sel: u8,
    pid_kind: u8,
    addr_raw: u64,
    data_raw: u64,
    /// Bytes for an out-of-process buffer the kernel may copy into.
    out_buf_bytes: Vec<u8>,
    use_buf_addr: bool,
    use_buf_data: bool,
}

fn pick_pid(kind: u8) -> libc::pid_t {
    // Always non-existent / bogus pids. We avoid pid=1 (init) and pid=0
    // (current process group) to be safe.
    match kind % 5 {
        0 => -1,
        1 => libc::pid_t::MAX,
        2 => libc::pid_t::MIN,
        3 => 0x7ffffffe,
        // A high pid that's almost certainly not in use on this system
        // (PID_MAX_LIMIT is typically 4194304 on Linux).
        _ => 999_999_999,
    }
}

fn pick_request(sel: u8) -> libc::c_int {
    REQUESTS[(sel as usize) % REQUESTS.len()]
}

fuzz_target!(|input: PtraceInput| {
    if input.out_buf_bytes.len() > MAX_OUT_BUF_BYTES {
        return;
    }

    let req = pick_request(input.req_sel);
    let pid = pick_pid(input.pid_kind);

    // Allocate a small per-iteration buffer that the kernel can write
    // into (for GET* requests). It's bounded so it never causes huge
    // allocations.
    let mut out_buf = vec![0u8; MAX_OUT_BUF_BYTES];
    let seed = &input.out_buf_bytes;
    let n = seed.len().min(out_buf.len());
    out_buf[..n].copy_from_slice(&seed[..n]);

    let addr = if input.use_buf_addr {
        out_buf.as_mut_ptr() as *mut c_void
    } else {
        input.addr_raw as *mut c_void
    };
    let data = if input.use_buf_data {
        out_buf.as_mut_ptr() as *mut c_void
    } else {
        input.data_raw as *mut c_void
    };

    // Invoke. ptrace returns c_long; -1 indicates error (and PEEK*
    // can return any value, even -1, in success). We just want no
    // panic and a sane errno on the failure path.
    let _ = unsafe { ptrace(req, pid, addr, data) };
});
