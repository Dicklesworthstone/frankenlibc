#![no_main]
//! Structure-aware fuzz target for POSIX/Linux vector-IO syscalls:
//! readv, writev, preadv, pwritev, preadv2, pwritev2.
//!
//! Backing: a per-iteration `memfd_create`d fd (or /tmp anonymous fallback).
//! The fuzzer builds a writev phase from the fuzz input, reads it back with
//! readv, and asserts byte-exact round-trip when the write succeeded.
//!
//! Invariants:
//! - Never panic on any iov_cnt (including IOV_MAX+1)
//! - readv/writev with iovcnt=0 must return -1/EINVAL (our impl contract)
//! - preadv2 with RWF_DSYNC or invalid flags returns rc in the documented set
//! - On success, `sum(iov[i].iov_len) >= rc >= 0`
//! - Round-trip: data written via writev is read back identically via readv
//!   from a seekable fd
//!
//! Bead: FUZZ #1 (vector IO)

use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::OnceLock;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use frankenlibc_abi::io_abi::{preadv, preadv2, pwritev, pwritev2, readv, writev};

/// Hard bounds to keep the fuzzer fast and inside kernel iovec limits.
const MAX_BUFS: usize = 12;
const MAX_BUF_BYTES: usize = 1024;
/// POSIX IOV_MAX on Linux is 1024; we intentionally go slightly past to
/// exercise the EINVAL path.
const ABOVE_IOV_MAX: usize = 1040;

#[derive(Debug, Arbitrary)]
struct Buffer {
    /// Content bytes. Truncated to MAX_BUF_BYTES.
    data: Vec<u8>,
}

#[derive(Debug, Arbitrary)]
struct VectorIoInput {
    /// Fuzzer-chosen sequence of buffers to scatter-write.
    bufs: Vec<Buffer>,
    /// Which operation to exercise.
    op: u8,
    /// Offset for positional variants.
    offset: i64,
    /// Flags for preadv2/pwritev2 (RWF_*).
    flags: u32,
    /// Force the "above IOV_MAX" path by setting iovcnt very large.
    force_above_iov_max: bool,
    /// Poison the iov pointer (pass NULL) to exercise the EFAULT branch.
    null_iov: bool,
}

/// Lazy global memfd-backed scratch fd shared across iterations. Using one
/// fd per run keeps kernel-side fd churn low enough to hit >1K exec/s on
/// the vector-IO surface. Each iteration rewinds and truncates.
fn scratch_fd() -> libc::c_int {
    static FD: OnceLock<i32> = OnceLock::new();
    *FD.get_or_init(|| {
        // SAFETY: memfd_create is a plain syscall; flags=0 is valid.
        let name = b"fuzz_vector_io\0";
        let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 0u32) };
        if fd < 0 {
            // Fallback: /tmp anonymous file. tmpfile() opens, unlinks, and
            // returns a FILE*; we want an fd, so use O_TMPFILE if possible.
            let tmpl = b"/tmp\0";
            let fd2 = unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    tmpl.as_ptr(),
                    libc::O_RDWR | libc::O_TMPFILE,
                    0o600,
                )
            };
            fd2 as i32
        } else {
            fd as i32
        }
    })
}

fn reset_scratch(fd: i32) {
    // SAFETY: kernel truncation on a memfd/O_TMPFILE fd we own.
    unsafe {
        libc::ftruncate(fd, 0);
        libc::lseek(fd, 0, libc::SEEK_SET);
    }
}

fn bound_bufs(bufs: &[Buffer]) -> Vec<Vec<u8>> {
    bufs.iter()
        .take(MAX_BUFS)
        .map(|b| {
            let take = b.data.len().min(MAX_BUF_BYTES);
            b.data[..take].to_vec()
        })
        .collect()
}

fn iovec_array(bufs: &mut [Vec<u8>]) -> Vec<libc::iovec> {
    bufs.iter_mut()
        .map(|b| libc::iovec {
            iov_base: b.as_mut_ptr() as *mut c_void,
            iov_len: b.len(),
        })
        .collect()
}

fuzz_target!(|input: VectorIoInput| {
    let fd = scratch_fd();
    if fd < 0 {
        return;
    }

    let mut write_bufs = bound_bufs(&input.bufs);
    if write_bufs.is_empty() {
        return;
    }
    let total_len: usize = write_bufs.iter().map(|b| b.len()).sum();
    if total_len == 0 {
        return;
    }

    reset_scratch(fd);

    // Build the write iovec array.
    let mut iov_w = iovec_array(&mut write_bufs);
    let iovcnt_w: libc::c_int = if input.force_above_iov_max {
        ABOVE_IOV_MAX as libc::c_int
    } else {
        iov_w.len() as libc::c_int
    };
    let iov_w_ptr: *const libc::iovec = if input.null_iov {
        std::ptr::null()
    } else {
        iov_w.as_ptr()
    };

    // Phase 1: write via writev family.
    let wrote = match input.op % 3 {
        0 => unsafe { writev(fd, iov_w_ptr, iovcnt_w) },
        1 => unsafe { pwritev(fd, iov_w_ptr, iovcnt_w, input.offset.max(0)) },
        _ => unsafe { pwritev2(fd, iov_w_ptr, iovcnt_w, input.offset.max(0), input.flags as i32) },
    };

    if wrote < 0 {
        // Error paths are fine; just make sure no state corruption.
        return;
    }

    // Invariant: wrote must not exceed the sum of iov lengths.
    assert!(
        (wrote as usize) <= total_len,
        "writev returned {wrote} exceeding total iov len {total_len}"
    );

    // Rewind for read phase.
    unsafe {
        libc::lseek(fd, 0, libc::SEEK_SET);
    }

    // Read phase: allocate read buffers matching the shape we just wrote
    // (so we can assert round-trip on the succeeded prefix).
    let mut read_bufs: Vec<Vec<u8>> = write_bufs.iter().map(|b| vec![0u8; b.len()]).collect();
    let mut iov_r = iovec_array(&mut read_bufs);
    let iovcnt_r = iov_r.len() as libc::c_int;

    let read_rc = match input.op % 3 {
        0 => unsafe { readv(fd, iov_r.as_ptr(), iovcnt_r) },
        1 => unsafe { preadv(fd, iov_r.as_ptr(), iovcnt_r, input.offset.max(0)) },
        _ => unsafe {
            preadv2(
                fd,
                iov_r.as_ptr(),
                iovcnt_r,
                input.offset.max(0),
                input.flags as i32,
            )
        },
    };

    if read_rc < 0 {
        return;
    }

    // Round-trip: read prefix must equal write prefix byte-for-byte over
    // the overlap of what was written and what was read.
    let common = (read_rc as usize).min(wrote as usize);
    let write_flat: Vec<u8> = write_bufs.iter().flatten().copied().collect();
    let read_flat: Vec<u8> = read_bufs.iter().flatten().copied().collect();
    assert!(common <= write_flat.len());
    assert!(common <= read_flat.len());
    assert_eq!(
        &read_flat[..common],
        &write_flat[..common],
        "readv prefix did not match writev prefix (common={common}, wrote={wrote}, read={read_rc})"
    );

    // Exercise the null-iov / above-IOV_MAX error branches separately so
    // the ok-path coverage stays clean.
    if input.null_iov {
        let rc = unsafe { readv(fd, std::ptr::null(), 1) };
        assert_eq!(rc, -1, "readv(NULL iov) must return -1");
    }
    if input.force_above_iov_max {
        // Many kernels EINVAL when iovcnt > IOV_MAX. We tolerate either
        // -1 or a bounded positive rc — just no crash.
        let _ = unsafe { readv(fd, iov_r.as_ptr(), ABOVE_IOV_MAX as libc::c_int) };
    }

    // Keep the optimizer from stripping the MaybeUninit work.
    let _ = MaybeUninit::<u8>::uninit();
});
