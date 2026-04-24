#![no_main]
//! Structure-aware fuzz target for the Linux async-IO surface:
//!
//!   io_uring_setup, io_uring_enter, io_uring_register
//!   io_setup, io_destroy, io_submit, io_cancel, io_getevents
//!
//! Both APIs have intricate kernel-ABI rules around ring indices,
//! struct alignment, and per-opcode arg semantics. Our user-space
//! wrappers must validate pointers, propagate errno, never panic.
//!
//! Strategy:
//! - Always use small entry counts (≤16) and bogus contexts so we
//!   never actually submit IO that touches real fds. Most calls fail
//!   with EINVAL/EFAULT at the kernel boundary.
//! - 192-byte guarded buffer for the io_uring_params struct
//!   (sizeof(struct io_uring_params) is 120 bytes; we double-buffer to
//!   exercise alignment).
//! - For io_setup/io_destroy, drive a small known-bad ctx_id through
//!   the lifecycle.
//!
//! Invariants:
//! - Never panic for any (entries, params, opcode, fd, args) tuple
//! - Setup: rc is -1 or non-negative fd; harness closes any fd
//! - Enter/register: rc is -1 or a documented count
//! - Guard bytes around the params buffer survive every call
//!
//! Bead: bd-io-uring

use std::ffi::c_void;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::unistd_abi::{
    io_cancel, io_destroy, io_getevents, io_setup, io_submit, io_uring_enter, io_uring_register,
    io_uring_setup,
};

const PARAMS_BYTES: usize = 192;
const GUARD_BYTES: usize = 32;
const GUARD_VAL: u8 = 0xCD;

#[derive(Debug, Arbitrary)]
struct IoUringInput {
    op: u8,
    entries: u32,
    /// Bytes seeded into a 192-byte io_uring_params buffer.
    params_seed: Vec<u8>,
    /// Pass NULL params to exercise the EFAULT branch.
    null_params: bool,
    /// io_uring_enter args.
    to_submit: u32,
    min_complete: u32,
    enter_flags: u32,
    /// io_uring_register args.
    register_opcode: u32,
    register_arg_bytes: Vec<u8>,
    register_nr_args: u32,
    /// Classic AIO args.
    aio_nr_events: u32,
    aio_ctx_id: u64,
    aio_min_nr: i64,
    aio_max_nr: i64,
    aio_timeout_sec: i64,
    aio_timeout_nsec: i64,
}

fn populate_guard_buf(seed: &[u8]) -> Vec<u8> {
    let mut buf = vec![GUARD_VAL; 2 * GUARD_BYTES + PARAMS_BYTES];
    let n = seed.len().min(PARAMS_BYTES);
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
    let trail_start = GUARD_BYTES + PARAMS_BYTES;
    for (i, &b) in buf[trail_start..].iter().enumerate() {
        assert_eq!(b, GUARD_VAL, "{label}: trailing guard clobbered at +{i}");
    }
}

fuzz_target!(|input: IoUringInput| {
    if input.params_seed.len() > PARAMS_BYTES * 2
        || input.register_arg_bytes.len() > PARAMS_BYTES * 2
    {
        return;
    }

    match input.op % 8 {
        0 => {
            // io_uring_setup: bound entries to keep allocations small.
            let entries = input.entries % 17; // 0..=16
            let mut buf = populate_guard_buf(&input.params_seed);
            let params_ptr = if input.null_params {
                std::ptr::null_mut()
            } else {
                unsafe { buf.as_mut_ptr().add(GUARD_BYTES) as *mut c_void }
            };
            let fd = unsafe { io_uring_setup(entries, params_ptr) };
            assert!(fd >= -1, "io_uring_setup rc={fd}");
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
            assert_guards_intact(&buf, "io_uring_setup");
        }
        1 => {
            // io_uring_enter on a known-bad fd. Pass NULL sig.
            let rc = unsafe {
                io_uring_enter(
                    u32::MAX,
                    input.to_submit,
                    input.min_complete,
                    input.enter_flags,
                    std::ptr::null(),
                )
            };
            assert!(rc >= -1, "io_uring_enter rc={rc}");
        }
        2 => {
            // io_uring_register on a known-bad fd, fuzz-shaped args.
            let mut buf = populate_guard_buf(&input.register_arg_bytes);
            let arg_ptr = unsafe { buf.as_mut_ptr().add(GUARD_BYTES) as *mut c_void };
            let rc = unsafe {
                io_uring_register(u32::MAX, input.register_opcode, arg_ptr, input.register_nr_args)
            };
            assert!(rc >= -1, "io_uring_register rc={rc}");
            assert_guards_intact(&buf, "io_uring_register");
        }
        3 => {
            // io_setup with bounded nr_events.
            let mut ctx: libc::c_ulong = 0;
            let rc = unsafe { io_setup(input.aio_nr_events % 33, &mut ctx as *mut _) };
            assert!(rc == 0 || rc == -1, "io_setup rc={rc}");
            if rc == 0 {
                let drc = unsafe { io_destroy(ctx) };
                assert!(drc == 0 || drc == -1, "io_destroy rc={drc}");
            }
        }
        4 => {
            // io_destroy on a fuzz-supplied bogus ctx_id.
            let rc = unsafe { io_destroy(input.aio_ctx_id) };
            assert!(rc == 0 || rc == -1, "io_destroy(bogus) rc={rc}");
        }
        5 => {
            // io_submit with NULL iocbpp + bogus ctx_id (EFAULT/EINVAL path).
            let rc = unsafe {
                io_submit(input.aio_ctx_id, input.aio_max_nr as libc::c_long, std::ptr::null_mut())
            };
            assert!(rc >= -1, "io_submit rc={rc}");
        }
        6 => {
            // io_getevents with bogus ctx_id, valid scratch buffer.
            let mut events = [0u8; 256];
            let mut timeout = libc::timespec {
                tv_sec: input.aio_timeout_sec,
                tv_nsec: input.aio_timeout_nsec & 0x3FFFFFFF,
            };
            let rc = unsafe {
                io_getevents(
                    input.aio_ctx_id,
                    input.aio_min_nr,
                    input.aio_max_nr,
                    events.as_mut_ptr() as *mut c_void,
                    &mut timeout as *mut libc::timespec,
                )
            };
            assert!(rc >= -1, "io_getevents rc={rc}");
        }
        _ => {
            // io_cancel with NULL iocb + bogus ctx_id.
            let mut result = [0u8; 64];
            let rc = unsafe {
                io_cancel(
                    input.aio_ctx_id,
                    std::ptr::null_mut(),
                    result.as_mut_ptr() as *mut c_void,
                )
            };
            assert!(rc == 0 || rc == -1, "io_cancel rc={rc}");
        }
    }
});
