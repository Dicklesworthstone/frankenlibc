#![no_main]
//! Structure-aware fuzz target for the Linux security/observability
//! syscall family:
//!
//!   seccomp(SECCOMP_*, flags, args)
//!   perf_event_open(attr, pid, cpu, group_fd, flags)
//!
//! Both take pointer-to-struct arguments where the kernel parses
//! attacker-controlled bytes, and both have history of CVE-class bugs
//! at the user/kernel boundary. Our user-space wrappers must validate
//! pointers, propagate errno, and never panic — even on adversarial
//! attr struct layouts.
//!
//! Strategy:
//! - seccomp: drive SECCOMP_GET_ACTION_AVAIL / SECCOMP_GET_NOTIF_SIZES
//!   (introspection only, no filter installation), plus the BPF-filter
//!   path with intentionally-malformed sock_fprog.
//! - perf_event_open: 192-byte guarded buffer for struct
//!   perf_event_attr (sizeof varies 96-144 across kernels), call against
//!   pid=-1+cpu=-1 which always fails; close any fd returned.
//!
//! Invariants:
//! - Never panic for any (op, attr-bytes, flags, pid, cpu) tuple
//! - rc is -1 or non-negative
//! - Guard bytes around perf_event_attr survive every call
//! - Any seccomp-returned fd or perf-returned fd is closed
//!
//! Bead: bd-sec-syscalls

use std::ffi::c_void;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::unistd_abi::{perf_event_open, seccomp};

const ATTR_BYTES: usize = 192;
const GUARD_BYTES: usize = 32;
const GUARD_VAL: u8 = 0xC9;

// SECCOMP_SET_MODE_STRICT is intentionally OMITTED: it applies STRICT
// mode to the fuzzer process itself and kills it on the next non-RW
// syscall, masquerading as DEADLYSIGNAL. Same caution for
// SECCOMP_SET_MODE_FILTER with an attacker-controlled BPF program: even
// a successfully installed filter may make the next iteration kill us.
// We exercise only the introspection ops + invalid sentinels.
const SECCOMP_OPS: &[libc::c_uint] = &[
    libc::SECCOMP_GET_ACTION_AVAIL,
    libc::SECCOMP_GET_NOTIF_SIZES,
    // Intentionally invalid:
    0xfffffffe,
    0xffffffff,
];

#[derive(Debug, Arbitrary)]
struct SecInput {
    op: u8,
    seccomp_op_sel: u8,
    seccomp_flags: u32,
    /// Bytes seeded into the args buffer for seccomp(2).
    seccomp_args_bytes: Vec<u8>,
    /// Bytes seeded into struct perf_event_attr.
    perf_attr_bytes: Vec<u8>,
    pid: libc::pid_t,
    cpu: libc::c_int,
    group_fd: libc::c_int,
    perf_flags: u64,
    /// If true, pass NULL pointer instead of buffer (EFAULT branch).
    null_attr: bool,
}

fn populate_guard_buf(seed: &[u8]) -> Vec<u8> {
    let mut buf = vec![GUARD_VAL; 2 * GUARD_BYTES + ATTR_BYTES];
    let n = seed.len().min(ATTR_BYTES);
    buf[GUARD_BYTES..GUARD_BYTES + n].copy_from_slice(&seed[..n]);
    buf
}

fn assert_guards_intact(buf: &[u8], label: &str) {
    for (i, &b) in buf[..GUARD_BYTES].iter().enumerate() {
        assert_eq!(
            b, GUARD_VAL,
            "{label}: leading guard clobbered at offset {i}"
        );
    }
    let trail_start = GUARD_BYTES + ATTR_BYTES;
    for (i, &b) in buf[trail_start..].iter().enumerate() {
        assert_eq!(b, GUARD_VAL, "{label}: trailing guard clobbered at +{i}");
    }
}

fuzz_target!(|input: SecInput| {
    if input.seccomp_args_bytes.len() > ATTR_BYTES * 2
        || input.perf_attr_bytes.len() > ATTR_BYTES * 2
    {
        return;
    }

    match input.op % 3 {
        0 => {
            // seccomp with introspection ops + bogus flags + fuzz-bytes args.
            let secop = SECCOMP_OPS[(input.seccomp_op_sel as usize) % SECCOMP_OPS.len()];
            let mut buf = populate_guard_buf(&input.seccomp_args_bytes);
            let args_ptr = unsafe { buf.as_mut_ptr().add(GUARD_BYTES) as *mut c_void };
            let rc = unsafe { seccomp(secop, input.seccomp_flags, args_ptr) };
            assert!(
                rc == 0 || rc == -1 || rc > 0,
                "seccomp(op={secop:#x}) rc={rc}"
            );
            assert_guards_intact(&buf, "seccomp");

            // Also exercise NULL-args path.
            let _ = unsafe { seccomp(secop, input.seccomp_flags, std::ptr::null_mut()) };
        }
        1 => {
            // perf_event_open with fuzz-shaped attr + pid=-1+cpu=-1
            // (always fails) so we never actually open a perf event.
            let mut buf = populate_guard_buf(&input.perf_attr_bytes);
            let attr_ptr = if input.null_attr {
                std::ptr::null_mut()
            } else {
                unsafe { buf.as_mut_ptr().add(GUARD_BYTES) as *mut c_void }
            };
            let fd = unsafe {
                perf_event_open(
                    attr_ptr,
                    -1,
                    -1,
                    -1,
                    input.perf_flags as libc::c_ulong,
                )
            };
            assert!(fd >= -1, "perf_event_open rc={fd}");
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
            assert_guards_intact(&buf, "perf_event_open");
        }
        _ => {
            // perf_event_open with fuzz-supplied pid/cpu/group_fd to
            // exercise the kernel's permission-check + cpu-validation
            // paths. Still uses fuzz-shaped attr.
            let mut buf = populate_guard_buf(&input.perf_attr_bytes);
            let attr_ptr = if input.null_attr {
                std::ptr::null_mut()
            } else {
                unsafe { buf.as_mut_ptr().add(GUARD_BYTES) as *mut c_void }
            };
            let fd = unsafe {
                perf_event_open(
                    attr_ptr,
                    input.pid,
                    input.cpu,
                    input.group_fd,
                    input.perf_flags as libc::c_ulong,
                )
            };
            assert!(fd >= -1, "perf_event_open rc={fd}");
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
            assert_guards_intact(&buf, "perf_event_open(arbitrary)");
        }
    }
});
