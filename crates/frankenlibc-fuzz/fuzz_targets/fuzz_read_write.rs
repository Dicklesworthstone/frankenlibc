#![no_main]
//! Crash-detector + differential fuzz target for read/write/pread/pwrite
//! argument validation.
//!
//! Exercises `frankenlibc_abi::unistd_abi::{read, write}` and
//! `frankenlibc_abi::io_abi::{pread, pwrite, readv, writev}` against
//! fuzzer-generated combinations of fd, buffer size/alignment, count,
//! and offset. The underlying file descriptors are pre-opened onto
//! deterministic backends (/dev/zero, /dev/null, and a pipe pair) so
//! that host parity comparisons are meaningful.
//!
//! Sentinel pages are placed before and after every buffer window; a
//! tampered sentinel byte is a hard fail because it means the wrapper
//! wrote/read past the requested count.
//!
//! Bead: bd-sttk9
//!
//! Parent: bd-jy4qu

use arbitrary::Arbitrary;
use libc::{c_int, c_void, ssize_t};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

#[derive(Debug, Arbitrary)]
struct RwFuzzInput {
    op: u8,
    fd_kind: u8,
    buf_size: u16,
    buf_offset: u8,
    count: u32,
    offset: i64,
    iovec_count: u8,
    iov_byte_lens: [u8; 8],
}

const MAX_BUF: usize = 16 * 1024;
const SENTINEL: u8 = 0xAA;
const PRE_PAD: usize = 64;
const POST_PAD: usize = 64;

struct Backends {
    dev_zero: c_int,
    dev_null: c_int,
    pipe_read: c_int,
    pipe_write: c_int,
    closed_fd: c_int,
}

fn backends() -> &'static Backends {
    static CACHED: OnceLock<Backends> = OnceLock::new();
    CACHED.get_or_init(|| {
        let dev_zero = unsafe { libc::open(c"/dev/zero".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let dev_null = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        let mut pipefds = [0i32; 2];
        let pipe_rc =
            unsafe { libc::pipe2(pipefds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(pipe_rc, 0, "pipe2 failed during fuzz setup");
        // Create a closed fd so we can test EBADF handling on a
        // known-good-then-known-closed fd.
        let closed_fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        unsafe {
            libc::close(closed_fd);
        }
        Backends {
            dev_zero,
            dev_null,
            pipe_read: pipefds[0],
            pipe_write: pipefds[1],
            closed_fd,
        }
    })
}

fn resolve_fd(kind: u8) -> c_int {
    let b = backends();
    match kind % 7 {
        0 => b.dev_zero,
        1 => b.dev_null,
        2 => b.pipe_read,
        3 => b.pipe_write,
        4 => b.closed_fd,
        5 => -1,           // plainly invalid
        _ => i32::MAX / 2, // plausibly-invalid "wild" fd
    }
}

/// Describe what we expect from the backend on read.
#[derive(Copy, Clone, PartialEq, Eq)]
enum Direction {
    Read,
    Write,
}

fn is_documented_errno(e: c_int) -> bool {
    // EWOULDBLOCK and EAGAIN are the same value on Linux; skip the
    // second spelling so the match isn't flagged as unreachable.
    matches!(
        e,
        0 | libc::EAGAIN
            | libc::EBADF
            | libc::EFAULT
            | libc::EINTR
            | libc::EINVAL
            | libc::EIO
            | libc::EISDIR
            | libc::ENOBUFS
            | libc::ENOMEM
            | libc::ENXIO
            | libc::EPERM
            | libc::EPIPE
            | libc::ERANGE
            | libc::ESPIPE
            | libc::EOVERFLOW
            | libc::EOPNOTSUPP
            | libc::ENOSPC
            | libc::EDQUOT
            | libc::EFBIG
    )
}

struct SentinelBuf {
    storage: Vec<u8>,
    window_offset: usize,
    window_len: usize,
}

impl SentinelBuf {
    fn new(win_len: usize) -> Self {
        let total = PRE_PAD + win_len + POST_PAD;
        let mut storage = vec![SENTINEL; total];
        // Zero the window so read-from-/dev/null (EOF) doesn't leave
        // junk.
        for b in &mut storage[PRE_PAD..PRE_PAD + win_len] {
            *b = 0;
        }
        SentinelBuf {
            storage,
            window_offset: PRE_PAD,
            window_len: win_len,
        }
    }

    fn ptr(&mut self) -> *mut c_void {
        self.storage[self.window_offset..].as_mut_ptr() as *mut c_void
    }

    fn const_ptr(&self) -> *const c_void {
        self.storage[self.window_offset..].as_ptr() as *const c_void
    }

    fn check_sentinels(&self, label: &str) {
        for (i, &b) in self.storage.iter().take(PRE_PAD).enumerate() {
            assert_eq!(
                b, SENTINEL,
                "{label}: pre-sentinel byte {i} was overwritten"
            );
        }
        let tail_start = self.window_offset + self.window_len;
        for (i, &b) in self.storage[tail_start..].iter().enumerate() {
            assert_eq!(
                b, SENTINEL,
                "{label}: post-sentinel byte {i} was overwritten"
            );
        }
    }
}

fuzz_target!(|input: RwFuzzInput| {
    let buf_size = (input.buf_size as usize).min(MAX_BUF);
    // Clamp count to the window size so we never ask the kernel to
    // read/write past the allocation. Note: zero-sized buffers are a
    // valid test case on their own (read/write with count=0 must
    // return 0 without touching memory).
    let count = (input.count as usize).min(buf_size);
    let fd = resolve_fd(input.fd_kind);
    let _ = input.buf_offset; // reserved for future alignment-sensitivity coverage

    let op = input.op % 6;

    let direction = match op {
        0 | 2 | 4 => Direction::Read,
        _ => Direction::Write,
    };

    // readv/writev need separate iovec handling.
    if op >= 4 {
        run_vectored(&input, fd, direction, buf_size);
        return;
    }

    let mut buf = SentinelBuf::new(buf_size);

    let our_rc: ssize_t = unsafe {
        match op {
            0 => frankenlibc_abi::unistd_abi::read(fd, buf.ptr(), count),
            1 => frankenlibc_abi::unistd_abi::write(fd, buf.const_ptr(), count),
            2 => frankenlibc_abi::io_abi::pread(fd, buf.ptr(), count, input.offset),
            3 => frankenlibc_abi::io_abi::pwrite(fd, buf.const_ptr(), count, input.offset),
            _ => unreachable!(),
        }
    };
    let our_errno = unsafe { *libc::__errno_location() };
    buf.check_sentinels("after our call");

    // Crash-detector invariants: rc is non-negative bytes returned OR
    // -1 with a documented errno. Guard against the -1-wraps-as-usize
    // trap before comparing to `count`.
    if our_rc < 0 {
        assert_eq!(our_rc, -1, "ssize_t out of range: {our_rc}");
        assert!(
            is_documented_errno(our_errno),
            "read/write errno {our_errno} not in documented set, op={op} fd_kind={fd_kind}",
            fd_kind = input.fd_kind,
        );
    } else {
        assert!(
            (our_rc as usize) <= count,
            "our_rc={our_rc} exceeds count={count}"
        );
    }

    // Differential: replay the same call against the host libc for
    // backends where the outcome is deterministic (no shared pipe
    // state). /dev/null (writes), /dev/zero (reads+writes), closed
    // fd, and the wild fd are all deterministic; skip the pipe fds
    // because our writes to the pipe are observable state.
    if matches!(input.fd_kind % 7, 2 | 3) {
        return;
    }

    let mut host_buf = SentinelBuf::new(buf_size);
    unsafe { *libc::__errno_location() = 0 };
    let host_rc: ssize_t = unsafe {
        match op {
            0 => libc::read(fd, host_buf.ptr(), count),
            1 => libc::write(fd, host_buf.const_ptr(), count),
            2 => libc::pread(fd, host_buf.ptr(), count, input.offset),
            3 => libc::pwrite(fd, host_buf.const_ptr(), count, input.offset),
            _ => unreachable!(),
        }
    };
    let host_errno = unsafe { *libc::__errno_location() };
    host_buf.check_sentinels("after host call");

    // Parity on success vs failure.
    assert_eq!(
        our_rc >= 0,
        host_rc >= 0,
        "op={op} fd_kind={fd} success divergence ours={our_rc}/errno{our_errno} host={host_rc}/errno{host_errno}",
        fd = input.fd_kind,
    );
    if our_rc >= 0 && host_rc >= 0 {
        assert_eq!(our_rc, host_rc, "byte-count divergence op={op}");
    }
});

fn run_vectored(input: &RwFuzzInput, fd: c_int, direction: Direction, buf_size: usize) {
    let iovcnt = (input.iovec_count as usize).min(8);
    if iovcnt == 0 {
        // Zero-iovec read/write must complete without side effects.
        let empty: [libc::iovec; 0] = [];
        let our_rc = unsafe {
            match direction {
                Direction::Read => frankenlibc_abi::io_abi::readv(fd, empty.as_ptr(), 0),
                Direction::Write => frankenlibc_abi::io_abi::writev(fd, empty.as_ptr(), 0),
            }
        };
        assert!(our_rc == 0 || our_rc == -1, "zero-iovec rc={our_rc}");
        return;
    }

    // Split `buf_size` bytes into `iovcnt` windows sized by
    // iov_byte_lens.
    let total_reserved = (iovcnt * PRE_PAD) + buf_size + (iovcnt * POST_PAD);
    let mut backing = vec![SENTINEL; total_reserved];
    let mut iovs = Vec::with_capacity(iovcnt);
    let mut cursor = 0usize;
    let mut remaining = buf_size;
    for i in 0..iovcnt {
        let requested = input.iov_byte_lens[i] as usize;
        let len = requested.min(remaining);
        cursor += PRE_PAD;
        for b in &mut backing[cursor..cursor + len] {
            *b = 0;
        }
        iovs.push(libc::iovec {
            iov_base: backing[cursor..].as_mut_ptr() as *mut c_void,
            iov_len: len,
        });
        cursor += len + POST_PAD;
        remaining = remaining.saturating_sub(len);
    }

    let our_rc = unsafe {
        match direction {
            Direction::Read => {
                frankenlibc_abi::io_abi::readv(fd, iovs.as_ptr(), iovs.len() as c_int)
            }
            Direction::Write => {
                frankenlibc_abi::io_abi::writev(fd, iovs.as_ptr(), iovs.len() as c_int)
            }
        }
    };
    let our_errno = unsafe { *libc::__errno_location() };

    // Sentinel integrity: every pre/post pad stayed SENTINEL.
    let mut pos = 0usize;
    for (i, iov) in iovs.iter().enumerate() {
        for j in 0..PRE_PAD {
            assert_eq!(
                backing[pos + j],
                SENTINEL,
                "iovec {i} pre-pad byte {j} overwritten"
            );
        }
        pos += PRE_PAD + iov.iov_len;
        for j in 0..POST_PAD {
            assert_eq!(
                backing[pos + j],
                SENTINEL,
                "iovec {i} post-pad byte {j} overwritten"
            );
        }
        pos += POST_PAD;
    }

    // Sum of iov_lens bounds the rc.
    let total: usize = iovs.iter().map(|v| v.iov_len).sum();
    assert!(
        our_rc == -1 || (our_rc as usize) <= total,
        "readv/writev rc={our_rc} exceeds sum of iov_lens {total}"
    );
    if our_rc < 0 {
        assert!(
            is_documented_errno(our_errno),
            "readv/writev errno {our_errno} not in documented set"
        );
    }
}
