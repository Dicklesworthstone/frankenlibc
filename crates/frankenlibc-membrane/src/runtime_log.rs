//! Bounded JSONL file output for repair/deny diagnostics.
//!
//! On Linux x86_64/aarch64, the write path uses a raw writev syscall over
//! borrowed bytes and one newline: no allocation, libc cancellation point,
//! errno mutation, or write_all loop. Initialization and callers' formatting
//! are separate and are NOT claimed to be async-signal-safe. The syscall
//! count is bounded; a regular-file write can still wait for the filesystem.

use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};

/// Includes the terminating newline. Oversized records are dropped, not cut
/// into invalid UTF-8/JSON or split into independently interleavable writes.
const MAX_RECORD_BYTES: usize = 4096;
const MAX_WRITE_ATTEMPTS: usize = 4;
const EINTR: i32 = 4;

static WRITTEN: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static SHORT_WRITES: AtomicU64 = AtomicU64::new(0);
static OPEN_FAILURES: AtomicU64 = AtomicU64::new(0);

/// Process-local file-sink counters. A failed sink must not hide lost records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeLogSnapshot {
    pub written_records: u64,
    pub dropped_records: u64,
    pub short_writes: u64,
    pub open_failures: u64,
}

/// Read without allocating, locking, opening files, or formatting messages.
#[must_use]
pub fn runtime_log_snapshot() -> RuntimeLogSnapshot {
    RuntimeLogSnapshot {
        written_records: WRITTEN.load(Ordering::Relaxed),
        dropped_records: DROPPED.load(Ordering::Relaxed),
        short_writes: SHORT_WRITES.load(Ordering::Relaxed),
        open_failures: OPEN_FAILURES.load(Ordering::Relaxed),
    }
}

/// Open only regular files. On Linux O_NONBLOCK prevents a configured FIFO
/// from hanging initialization; rejecting non-files avoids SIGPIPE on output.
/// This is an initialization operation, not an async-signal-safe API.
pub(super) fn open_file(path: &std::ffi::OsStr) -> Option<File> {
    let file = open_impl(path).filter(|file| {
        file.metadata()
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    });
    if file.is_none() {
        OPEN_FAILURES.fetch_add(1, Ordering::Relaxed);
    }
    file
}

/// Record an unavailable configured sink. An unset FRANKENLIBC_LOG is not a
/// failed write: only unsuccessful opens count as unavailable output.
pub(super) fn note_unavailable() {
    if OPEN_FAILURES.load(Ordering::Relaxed) != 0 {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteFailure {
    InvalidRecord,
    ShortWrite(usize),
    Io(i32),
}

/// At most four attempts, and retry ONLY EINTR (which wrote no bytes).
/// Never retry a positive short write: another writer could append between
/// attempts, splicing two JSON records. Short writes are explicitly counted;
/// they mean a partial record may remain in a failing file, not valid JSONL.
fn write_record_with(
    line: &str,
    mut write: impl FnMut(&[u8], &[u8]) -> Result<usize, i32>,
) -> Result<(), WriteFailure> {
    if line.is_empty()
        || line.len() >= MAX_RECORD_BYTES
        || line.bytes().any(|b| matches!(b, b'\n' | b'\r'))
    {
        return Err(WriteFailure::InvalidRecord);
    }
    let expected = line.len() + 1;
    for _ in 0..MAX_WRITE_ATTEMPTS {
        match write(line.as_bytes(), b"\n") {
            Ok(written) if written == expected => return Ok(()),
            Ok(written) => return Err(WriteFailure::ShortWrite(written)),
            Err(EINTR) => continue,
            Err(error) => return Err(WriteFailure::Io(error)),
        }
    }
    Err(WriteFailure::Io(EINTR))
}

pub(super) fn append_line(file: &File, line: &str) {
    match write_record_with(line, |body, newline| write_chunks(file, body, newline)) {
        Ok(()) => {
            WRITTEN.fetch_add(1, Ordering::Relaxed);
        }
        Err(error) => {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            if matches!(error, WriteFailure::ShortWrite(_)) {
                SHORT_WRITES.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(unsafe_code)]
fn open_impl(path: &std::ffi::OsStr) -> Option<File> {
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    let bytes = path.as_bytes();
    if bytes.is_empty() || bytes.len() >= 4096 || bytes.contains(&0) {
        return None;
    }
    let mut terminated = [0u8; 4096];
    terminated[..bytes.len()].copy_from_slice(bytes);
    // Linux UAPI: O_WRONLY | O_CREAT | O_APPEND | O_NONBLOCK | O_CLOEXEC.
    const FLAGS: usize = 1 | 0o100 | 0o2000 | 0o4000 | 0o2000000;
    #[cfg(target_arch = "x86_64")]
    const SYS_OPENAT: usize = 257;
    #[cfg(target_arch = "aarch64")]
    const SYS_OPENAT: usize = 56;
    let fd = syscall4(
        SYS_OPENAT,
        (-100isize) as usize, // AT_FDCWD
        terminated.as_ptr() as usize,
        FLAGS,
        0o600,
    );
    if fd < 0 {
        None
    } else {
        // SAFETY: successful openat returned a new owned descriptor.
        Some(unsafe { File::from_raw_fd(fd as i32) })
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn open_impl(path: &std::ffi::OsStr) -> Option<File> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn write_chunks(file: &File, body: &[u8], newline: &[u8]) -> Result<usize, i32> {
    use std::os::fd::AsRawFd;

    #[repr(C)]
    struct IoVec {
        base: *const u8,
        len: usize,
    }
    let vectors = [
        IoVec {
            base: body.as_ptr(),
            len: body.len(),
        },
        IoVec {
            base: newline.as_ptr(),
            len: newline.len(),
        },
    ];
    #[cfg(target_arch = "x86_64")]
    const SYS_WRITEV: usize = 20;
    #[cfg(target_arch = "aarch64")]
    const SYS_WRITEV: usize = 66;
    let result = syscall4(
        SYS_WRITEV,
        file.as_raw_fd() as usize,
        vectors.as_ptr() as usize,
        2,
        0,
    );
    if result < 0 {
        Err((-result) as i32)
    } else {
        Ok(result as usize)
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn write_chunks(mut file: &File, body: &[u8], newline: &[u8]) -> Result<usize, i32> {
    use std::io::{IoSlice, Write};
    file.write_vectored(&[IoSlice::new(body), IoSlice::new(newline)])
        .map_err(|error| error.raw_os_error().unwrap_or(5))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
fn syscall4(number: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
    let result: isize;
    // SAFETY: callers pass a live path or two live iovecs; openat/writev
    // validate descriptors and flags in the kernel. All syscall clobbers are
    // declared. Do not use nomem/readonly: the kernel may read caller memory.
    unsafe {
        std::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") a,
            in("rsi") b,
            in("rdx") c,
            in("r10") d,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
#[allow(unsafe_code)]
fn syscall4(number: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
    let result: isize;
    // SAFETY: same live-buffer contract as the x86_64 implementation.
    unsafe {
        std::arch::asm!(
            "svc 0",
            in("x8") number,
            inlateout("x0") a => result,
            in("x1") b,
            in("x2") c,
            in("x3") d,
            options(nostack),
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn vectored_record_keeps_utf8_and_newline_together() {
        let mut calls = 0;
        let result = write_record_with("{\"text\":\"é水\"}", |body, newline| {
            calls += 1;
            assert_eq!(body, "{\"text\":\"é水\"}".as_bytes());
            assert_eq!(newline, b"\n");
            Ok(body.len() + newline.len())
        });
        assert_eq!(result, Ok(()));
        assert_eq!(calls, 1);
    }

    #[test]
    fn interrupted_writes_have_a_finite_budget() {
        let mut calls = 0;
        let result = write_record_with("{}", |_, _| {
            calls += 1;
            Err(EINTR)
        });
        assert_eq!(result, Err(WriteFailure::Io(EINTR)));
        assert_eq!(calls, MAX_WRITE_ATTEMPTS);
        let mut calls = 0;
        let result = write_record_with("{}", |body, newline| {
            calls += 1;
            if calls < MAX_WRITE_ATTEMPTS {
                Err(EINTR)
            } else {
                Ok(body.len() + newline.len())
            }
        });
        assert_eq!(result, Ok(()));
        assert_eq!(calls, MAX_WRITE_ATTEMPTS);
    }

    #[test]
    fn partial_zero_and_non_interrupt_errors_are_not_retried() {
        for result in [Ok(0), Ok(1), Err(9), Err(11), Err(28)] {
            let mut calls = 0;
            let outcome = write_record_with("{}", |_, _| {
                calls += 1;
                result
            });
            assert!(outcome.is_err());
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn invalid_and_oversized_records_never_reach_the_writer() {
        for line in ["", "{}\n", "{}\r{}", "{}\n{}"] {
            let result = write_record_with(line, |_, _| panic!("invalid record was written"));
            assert_eq!(result, Err(WriteFailure::InvalidRecord));
        }
        let largest = "x".repeat(MAX_RECORD_BYTES - 1);
        let result = write_record_with(&largest, |a, b| {
            assert_eq!(a.len() + b.len(), MAX_RECORD_BYTES);
            Ok(MAX_RECORD_BYTES)
        });
        assert_eq!(result, Ok(()));
        let oversized = "x".repeat(MAX_RECORD_BYTES);
        let result = write_record_with(&oversized, |_, _| panic!("oversized record was written"));
        assert_eq!(result, Err(WriteFailure::InvalidRecord));
    }

    #[test]
    fn append_preserves_existing_bytes_and_emits_whole_lines() {
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-raw-log-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "{\"existing\":1}\n").unwrap();
        let file = open_file(path.as_os_str()).unwrap();
        append_line(&file, "{\"a\":1}");
        append_line(&file, "{\"b\":\"水\"}");
        let mut reader = File::open(&path).unwrap();
        reader.seek(SeekFrom::Start(0)).unwrap();
        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        assert_eq!(output, "{\"existing\":1}\n{\"a\":1}\n{\"b\":\"水\"}\n");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn concurrent_append_records_do_not_interleave() {
        let path = std::env::temp_dir().join(format!(
            "frankenlibc-concurrent-log-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, b"").unwrap();
        let file = std::sync::Arc::new(open_file(path.as_os_str()).unwrap());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|thread| {
                let file = file.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for row in 0..200 {
                        append_line(&file, &format!("{{\"thread\":{thread},\"row\":{row}}}"));
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let output = std::fs::read_to_string(path).unwrap();
        let actual: std::collections::BTreeSet<_> = output.lines().map(str::to_string).collect();
        let expected: std::collections::BTreeSet<_> = (0..8)
            .flat_map(|thread| {
                (0..200).map(move |row| format!("{{\"thread\":{thread},\"row\":{row}}}"))
            })
            .collect();
        assert_eq!(output.lines().count(), 1600);
        assert_eq!(actual, expected);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    #[allow(unsafe_code)]
    fn raw_write_failure_preserves_errno() {
        let file = File::open("/dev/null").unwrap();
        // Read-only descriptor: the kernel must return EBADF, without the
        // logging path overwriting the errno of the operation being repaired.
        unsafe { *libc::__errno_location() = libc::EDOM };
        let result = write_record_with("{}", |a, b| write_chunks(&file, a, b));
        let after = unsafe { *libc::__errno_location() };
        assert_eq!(result, Err(WriteFailure::Io(libc::EBADF)));
        assert_eq!(after, libc::EDOM);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_regular_sink_is_rejected() {
        assert!(open_file(std::ffi::OsStr::new("/dev/null")).is_none());
    }
}
