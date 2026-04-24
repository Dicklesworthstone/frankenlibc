#![no_main]
//! Structure-aware fuzz target for the Linux zero-copy IO family:
//! splice, sendfile, tee, vmsplice, copy_file_range.
//!
//! These share an offset + length + flags surface and all have historical
//! bugs around int overflow on `len`, non-null-offset semantics, and
//! fd-type-specific requirements (e.g. splice requires at least one
//! pipe end).
//!
//! Scratch:
//!   - Two pipes for splice/tee source and sink
//!   - Two memfds pre-seeded with known bytes for sendfile + copy_file_range
//!
//! Invariants:
//! - Never panic on any (len, flags, offset) combination
//! - rc is -1 or non-negative; rc <= the requested byte count
//! - Non-null offsets advance by exactly rc on successful calls where Linux
//!   documents offset-pointer advancement.
//!
//! Bead: bd-4z5o3

use std::ffi::c_void;
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::io_abi::{copy_file_range, sendfile, splice, tee, vmsplice};

/// Keep `len` bounded so we don't stall on outlier cases (PIPE_BUF is
/// 4096 on Linux; a few multiples is plenty to cover the interesting
/// paths).
const LEN_CAP: usize = 16 * 1024;
const SEED_BYTES: usize = 4096;

#[derive(Debug, Arbitrary)]
struct SpliceInput {
    op: u8,
    raw_len: i64,
    len_shape: u8,
    flags: u32,
    off_in: i64,
    off_out: i64,
    splice_shape: u8,
    /// Controls whether splice/sendfile pass null vs &mut i64 offsets.
    null_off_in: bool,
    null_off_out: bool,
    /// vmsplice iovec bytes.
    iov_bufs: Vec<Vec<u8>>,
    /// Pipe seeding (0..LEN_CAP) so splice from pipe has something to read.
    seed_into_pipe: u16,
}

struct Scratch {
    memfd_src: libc::c_int,
    memfd_dst: libc::c_int,
    pipe_a_r: libc::c_int,
    pipe_a_w: libc::c_int,
    pipe_b_r: libc::c_int,
    pipe_b_w: libc::c_int,
}

fn create_seeded_memfd(name: &[u8]) -> libc::c_int {
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0u32) as libc::c_int };
    if fd >= 0 {
        let seed: Vec<u8> = (0..SEED_BYTES).map(|i| (i & 0xFF) as u8).collect();
        let _ = unsafe { libc::write(fd, seed.as_ptr() as *const _, seed.len()) };
        let _ = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
    }
    fd
}

fn scratch() -> &'static Scratch {
    static S: OnceLock<Scratch> = OnceLock::new();
    S.get_or_init(|| {
        let mut a = [-1i32; 2];
        let mut b = [-1i32; 2];
        let _ = unsafe { libc::pipe2(a.as_mut_ptr(), libc::O_NONBLOCK) };
        let _ = unsafe { libc::pipe2(b.as_mut_ptr(), libc::O_NONBLOCK) };
        Scratch {
            memfd_src: create_seeded_memfd(b"fuzz_splice_src\0"),
            memfd_dst: create_seeded_memfd(b"fuzz_splice_dst\0"),
            pipe_a_r: a[0],
            pipe_a_w: a[1],
            pipe_b_r: b[0],
            pipe_b_w: b[1],
        }
    })
}

fn reset_memfd(fd: libc::c_int) {
    let _ = unsafe { libc::ftruncate(fd, SEED_BYTES as libc::off_t) };
    let _ = unsafe { libc::lseek(fd, 0, libc::SEEK_SET) };
}

fn reset_pipe(r: libc::c_int) {
    // Drain non-blocking.
    let mut buf = [0u8; 4096];
    loop {
        let n = unsafe { libc::read(r, buf.as_mut_ptr() as *mut _, buf.len()) };
        if n <= 0 {
            break;
        }
    }
}

fn seed_pipe(w: libc::c_int, nbytes: usize) {
    let n = nbytes.min(LEN_CAP);
    if n == 0 {
        return;
    }
    let data: Vec<u8> = (0..n).map(|i| (i as u8) ^ 0xA5).collect();
    let _ = unsafe { libc::write(w, data.as_ptr() as *const _, n) };
}

fn requested_len(input: &SpliceInput) -> usize {
    match input.len_shape % 7 {
        0 => 0,
        1 => 1,
        2 => input.raw_len.unsigned_abs().min(LEN_CAP as u64) as usize,
        3 => LEN_CAP,
        4 => LEN_CAP * 2,
        5 => usize::MAX,
        _ => input.raw_len as usize,
    }
}

fn bounded_offset(offset: i64) -> i64 {
    offset.rem_euclid(SEED_BYTES as i64)
}

fn assert_transfer_result(op: u8, rc: libc::ssize_t, requested: usize) {
    assert!(
        rc == -1 || (rc >= 0 && (rc as usize) <= requested),
        "op={op} rc={rc} requested={requested}",
    );
}

fn assert_offset_advanced(op: u8, label: &str, before: i64, after: i64, rc: libc::ssize_t) {
    if rc > 0 {
        assert_eq!(
            after,
            before + rc as i64,
            "op={op} {label} offset advanced incorrectly for rc={rc}",
        );
    }
}

fuzz_target!(|input: SpliceInput| {
    let s = scratch();
    if s.memfd_src < 0
        || s.memfd_dst < 0
        || s.pipe_a_r < 0
        || s.pipe_a_w < 0
        || s.pipe_b_r < 0
        || s.pipe_b_w < 0
    {
        return;
    }

    // Drain pipes and reset memfd offsets to a known state each iteration.
    reset_pipe(s.pipe_a_r);
    reset_pipe(s.pipe_b_r);
    reset_memfd(s.memfd_src);
    reset_memfd(s.memfd_dst);

    let len = requested_len(&input);
    let flags = input.flags;
    let mut off_in = bounded_offset(input.off_in);
    let mut off_out = bounded_offset(input.off_out);
    let mut transfer_bound = len;

    let off_in_ptr = if input.null_off_in {
        std::ptr::null_mut()
    } else {
        &mut off_in
    };
    let off_out_ptr = if input.null_off_out {
        std::ptr::null_mut()
    } else {
        &mut off_out
    };

    let rc = match input.op % 5 {
        0 => {
            // splice: rotate through pipe->pipe, memfd->pipe, and pipe->memfd.
            seed_pipe(s.pipe_a_w, input.seed_into_pipe as usize);
            let off_in_before = off_in;
            let off_out_before = off_out;
            let shape = input.splice_shape % 3;
            let (fd_in, fd_out) = match shape {
                0 => (s.pipe_a_r, s.pipe_b_w),
                1 => (s.memfd_src, s.pipe_b_w),
                _ => (s.pipe_a_r, s.memfd_dst),
            };
            let rc = unsafe { splice(fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags) };
            if shape == 1 && !input.null_off_in {
                assert_offset_advanced(input.op % 5, "splice off_in", off_in_before, off_in, rc);
            }
            if shape == 2 && !input.null_off_out {
                assert_offset_advanced(input.op % 5, "splice off_out", off_out_before, off_out, rc);
            }
            rc
        }
        1 => {
            // sendfile: memfd -> pipe_a_w. memfd seek is preserved if
            // `off` is null; otherwise the kernel reads from *off.
            let off_in_before = off_in;
            let rc = unsafe { sendfile(s.pipe_a_w, s.memfd_src, off_in_ptr, len) };
            if !input.null_off_in {
                assert_offset_advanced(input.op % 5, "sendfile offset", off_in_before, off_in, rc);
            }
            rc
        }
        2 => {
            // tee: both ends must be pipes. duplicate pipe_a -> pipe_b.
            seed_pipe(s.pipe_a_w, input.seed_into_pipe as usize);
            unsafe { tee(s.pipe_a_r, s.pipe_b_w, len, flags) }
        }
        3 => {
            // vmsplice: push user pages into pipe_a_w.
            let bufs: Vec<Vec<u8>> = input
                .iov_bufs
                .iter()
                .take(8)
                .map(|b| {
                    let take = b.len().min(512);
                    b[..take].to_vec()
                })
                .collect();
            if bufs.is_empty() {
                return;
            }
            let iov: Vec<libc::iovec> = bufs
                .iter()
                .map(|b| libc::iovec {
                    iov_base: b.as_ptr() as *mut c_void,
                    iov_len: b.len(),
                })
                .collect();
            transfer_bound = iov.iter().map(|entry| entry.iov_len).sum();
            unsafe { vmsplice(s.pipe_a_w, iov.as_ptr(), iov.len(), flags) }
        }
        _ => {
            // copy_file_range: memfd_src -> memfd_dst with independent offsets.
            let off_in_before = off_in;
            let off_out_before = off_out;
            let rc = unsafe {
                copy_file_range(
                    s.memfd_src,
                    off_in_ptr,
                    s.memfd_dst,
                    off_out_ptr,
                    len,
                    flags,
                )
            };
            if !input.null_off_in {
                assert_offset_advanced(
                    input.op % 5,
                    "copy_file_range off_in",
                    off_in_before,
                    off_in,
                    rc,
                );
            }
            if !input.null_off_out {
                assert_offset_advanced(
                    input.op % 5,
                    "copy_file_range off_out",
                    off_out_before,
                    off_out,
                    rc,
                );
            }
            rc
        }
    };

    assert_transfer_result(input.op % 5, rc, transfer_bound);
});
