//! Bounded JSONL file output for repair/deny diagnostics.
//!
//! On Linux x86_64/aarch64, the write path uses a raw writev syscall over
//! borrowed bytes and one newline: no allocation, libc cancellation point,
//! errno mutation, or write_all loop. Sink initialization is a separate,
//! pre-signal operation. The syscall count is bounded; a regular-file write
//! can still wait for the filesystem.

use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};

/// Includes the terminating newline. Oversized records are dropped, not cut
/// into invalid UTF-8/JSON or split into independently interleavable writes.
pub(super) const MAX_RECORD_BYTES: usize = 4096;
const MAX_WRITE_ATTEMPTS: usize = 4;
const EINTR: i32 = 4;

static WRITTEN: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static RATE_LIMITED: AtomicU64 = AtomicU64::new(0);
static ADMISSION_CLOCK_FAILURES: AtomicU64 = AtomicU64::new(0);
static SHORT_WRITES: AtomicU64 = AtomicU64::new(0);
static OPEN_FAILURES: AtomicU64 = AtomicU64::new(0);
/// One process-local namespace for every deployed runtime-log event.  This is
/// deliberately independent of heal and denial counters: those count semantic
/// outcomes even when the sink is disabled, while this number orders records
/// that were actually attempted for the configured JSONL stream.
static EVENT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Bound adverse-event output without heap state, locks, TLS, or libc. The
/// packed word stores a truncated monotonic second and the number of records
/// admitted during that second. 1024 maximum-size rows cap the configured
/// sink at 4 MiB/s while retaining ample detail for ordinary fault diagnosis.
const RATE_COUNT_BITS: u32 = 16;
const RATE_COUNT_MASK: u64 = (1 << RATE_COUNT_BITS) - 1;
const RATE_PROCESS_TRANSITION_BIT: u64 = 1 << 32;
pub const RATE_LIMIT_PER_SECOND: u64 = 1024;
/// Linux `getpid` returns the thread-group ID, so every thread in one process
/// shares this identity while a non-`CLONE_VM` child observes that it inherited
/// another process's limiter state and starts a fresh window automatically.
static RATE_PROCESS_ID: AtomicU64 = AtomicU64::new(0);
static RATE_WINDOW: AtomicU64 = AtomicU64::new(0);

/// Reserve the next process-local event sequence number without allocating,
/// locking, touching TLS, or entering libc.
#[must_use]
pub fn next_runtime_log_sequence() -> u64 {
    EVENT_SEQUENCE.fetch_add(1, Ordering::Relaxed) + 1
}

/// Process-local file-sink counters. A failed sink must not hide lost records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RuntimeLogSnapshot {
    pub written_records: u64,
    pub dropped_records: u64,
    pub rate_limited_records: u64,
    pub admission_clock_failures: u64,
    pub short_writes: u64,
    pub open_failures: u64,
}

/// Read without allocating, locking, opening files, or formatting messages.
#[must_use]
pub fn runtime_log_snapshot() -> RuntimeLogSnapshot {
    // The two reason counters are published subsets: their writers update
    // DROPPED first and release the subset counter last. An acquire that
    // observes either reason therefore also observes its aggregate increment.
    let rate_limited_records = RATE_LIMITED.load(Ordering::Acquire);
    let admission_clock_failures = ADMISSION_CLOCK_FAILURES.load(Ordering::Acquire);
    RuntimeLogSnapshot {
        written_records: WRITTEN.load(Ordering::Relaxed),
        dropped_records: DROPPED.load(Ordering::Relaxed),
        rate_limited_records,
        admission_clock_failures,
        short_writes: SHORT_WRITES.load(Ordering::Relaxed),
        open_failures: OPEN_FAILURES.load(Ordering::Relaxed),
    }
}

/// Reserve one record in the current monotonic-second output window. A false
/// result is already reflected in both the rate-limited and aggregate dropped
/// counters. The bounded compare-exchange loop intentionally sheds a record
/// under extreme admission contention instead of spinning in a signal handler.
pub(super) fn admit_record() -> bool {
    admit_record_for_second(monotonic_second())
}

fn admit_record_for_second(second: Option<u64>) -> bool {
    let Some(second) = second else {
        note_admission_clock_failure();
        return false;
    };
    if admit_record_at(&RATE_PROCESS_ID, &RATE_WINDOW, process_id(), second) {
        true
    } else {
        note_rate_limited();
        false
    }
}

fn admit_record_at(process: &AtomicU64, window: &AtomicU64, process_id: u32, second: u64) -> bool {
    // A process child created without CLONE_VM receives a private copy of the
    // parent's atomics. Claiming the copied state under its own TGID clears the
    // inherited budget before the first admission. Threads use the same TGID
    // and therefore continue sharing one budget. The transition sentinel keeps
    // two first-time callers from clearing admissions behind each other; as in
    // the window CAS loop below, bounded contention sheds a record rather than
    // spinning in a signal handler.
    let owned_state = u64::from(process_id);
    let transition_state = owned_state | RATE_PROCESS_TRANSITION_BIT;
    let mut owns_window = false;
    for _ in 0..8 {
        let current_process = process.load(Ordering::Acquire);
        if current_process == owned_state {
            owns_window = true;
            break;
        }
        if current_process == transition_state {
            std::hint::spin_loop();
            continue;
        }
        // A transition carries its owner's TGID. A fork-like child that
        // inherited another process while it was between the CAS and publish
        // may therefore take over instead of treating the sentinel as stuck
        // forever. Reentry in the SAME process still follows the bounded-drop
        // path above and cannot clear admissions behind the interrupted call.
        if process
            .compare_exchange_weak(
                current_process,
                transition_state,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            window.store(0, Ordering::Relaxed);
            process.store(owned_state, Ordering::Release);
            owns_window = true;
            break;
        }
    }
    if !owns_window {
        return false;
    }

    let second = second & (u64::MAX >> RATE_COUNT_BITS);
    for _ in 0..8 {
        let current = window.load(Ordering::Relaxed);
        let current_second = current >> RATE_COUNT_BITS;
        let current_count = current & RATE_COUNT_MASK;
        if current_second == second && current_count >= RATE_LIMIT_PER_SECOND {
            return false;
        }
        let next = if current_second == second {
            current + 1
        } else {
            (second << RATE_COUNT_BITS) | 1
        };
        if window
            .compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
    }
    false
}

fn note_rate_limited() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
    RATE_LIMITED.fetch_add(1, Ordering::Release);
}

fn note_admission_clock_failure() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
    ADMISSION_CLOCK_FAILURES.fetch_add(1, Ordering::Release);
}

/// The child is a new process-local evidence stream even when it forks within
/// the parent's current monotonic second.
pub(super) fn reset_rate_limit_after_fork() {
    RATE_WINDOW.store(0, Ordering::Relaxed);
    RATE_PROCESS_ID.store(u64::from(process_id()), Ordering::Release);
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

/// Open a sink and transfer ownership of its descriptor to the process-wide
/// atomic sink state. Process teardown closes it; fork-child replacement
/// closes the inherited descriptor explicitly.
pub(super) fn open_fd(path: &std::ffi::OsStr) -> Option<i32> {
    use std::os::fd::IntoRawFd;

    open_file(path).map(IntoRawFd::into_raw_fd)
}

/// Record an unavailable configured sink. An unset FRANKENLIBC_LOG is not a
/// failed write: only unsuccessful opens count as unavailable output.
pub(super) fn note_unavailable() {
    if OPEN_FAILURES.load(Ordering::Relaxed) != 0 {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

/// Count a record that could not reach an initialized sink (for example, a
/// signal arriving before constructor initialization or during another log
/// write). This operation is allocation-free and lock-free.
pub(super) fn note_dropped() {
    DROPPED.fetch_add(1, Ordering::Relaxed);
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

#[cfg(test)]
pub(super) fn append_line(file: &File, line: &str) {
    use std::os::fd::AsRawFd;

    append_fd(file.as_raw_fd(), line);
}

/// Append through an already-owned raw descriptor. The caller guarantees the
/// descriptor remains open for this call.
pub(super) fn append_fd(fd: i32, line: &str) {
    match write_record_with(line, |body, newline| write_chunks_fd(fd, body, newline)) {
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
fn write_chunks_fd(fd: i32, body: &[u8], newline: &[u8]) -> Result<usize, i32> {
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
    let result = syscall4(SYS_WRITEV, fd as usize, vectors.as_ptr() as usize, 2, 0);
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
#[allow(unsafe_code)]
fn write_chunks_fd(fd: i32, body: &[u8], newline: &[u8]) -> Result<usize, i32> {
    use std::io::{IoSlice, Write};
    use std::os::fd::FromRawFd;

    // SAFETY: the caller owns a live descriptor for the duration of this
    // call. ManuallyDrop prevents this borrowed wrapper from closing it.
    let mut file = std::mem::ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
    file.write_vectored(&[IoSlice::new(body), IoSlice::new(newline)])
        .map_err(|error| error.raw_os_error().unwrap_or(5))
}

/// Close an inherited/replaced sink descriptor without entering libc.
pub(super) fn close_fd(fd: i32) {
    if fd < 0 {
        return;
    }
    close_fd_impl(fd);
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn close_fd_impl(fd: i32) {
    #[cfg(target_arch = "x86_64")]
    const SYS_CLOSE: usize = 3;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLOSE: usize = 57;
    let _ = syscall4(SYS_CLOSE, fd as usize, 0, 0, 0);
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[allow(unsafe_code)]
fn close_fd_impl(fd: i32) {
    use std::os::fd::FromRawFd;

    // SAFETY: replacement transfers ownership of the old descriptor here.
    drop(unsafe { File::from_raw_fd(fd) });
}

/// Process id without libc or allocation on the supported signal-safe path.
pub(super) fn process_id() -> u32 {
    process_id_impl()
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn process_id_impl() -> u32 {
    #[cfg(target_arch = "x86_64")]
    const SYS_GETPID: usize = 39;
    #[cfg(target_arch = "aarch64")]
    const SYS_GETPID: usize = 172;
    syscall4(SYS_GETPID, 0, 0, 0, 0) as u32
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn process_id_impl() -> u32 {
    std::process::id()
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn monotonic_second() -> Option<u64> {
    #[repr(C)]
    struct KernelTimespec {
        seconds: i64,
        nanoseconds: i64,
    }

    #[cfg(target_arch = "x86_64")]
    const SYS_CLOCK_GETTIME: usize = 228;
    #[cfg(target_arch = "aarch64")]
    const SYS_CLOCK_GETTIME: usize = 113;
    const CLOCK_MONOTONIC: usize = 1;

    let mut timestamp = KernelTimespec {
        seconds: 0,
        nanoseconds: 0,
    };
    let result = syscall4(
        SYS_CLOCK_GETTIME,
        CLOCK_MONOTONIC,
        (&raw mut timestamp) as usize,
        0,
        0,
    );
    (result == 0 && timestamp.seconds >= 0).then_some(timestamp.seconds as u64)
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn monotonic_second() -> Option<u64> {
    // The deployed async-signal-safe evidence contract is Linux-only. Fail
    // closed elsewhere rather than silently running an unbounded sink.
    None
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[allow(unsafe_code)]
fn syscall4(number: usize, a: usize, b: usize, c: usize, d: usize) -> isize {
    let result: isize;
    // SAFETY: pointer-bearing callers pass a live path, two live iovecs, or a
    // writable KernelTimespec. The kernel validates descriptors, flags, and
    // syscall arguments. All syscall clobbers are declared. Do not use
    // nomem/readonly: the kernel may read or write caller memory.
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
    fn event_sequence_is_positive_and_process_global() {
        let first = next_runtime_log_sequence();
        let second = next_runtime_log_sequence();
        assert!(first > 0);
        assert!(second > first);
    }

    #[test]
    fn rate_limit_admits_exact_budget_and_reopens_next_window() {
        let process = AtomicU64::new(0);
        let window = AtomicU64::new(0);
        for _ in 0..RATE_LIMIT_PER_SECOND {
            assert!(admit_record_at(&process, &window, 17, 41));
        }
        assert!(!admit_record_at(&process, &window, 17, 41));
        assert!(!admit_record_at(&process, &window, 17, 41));
        assert!(admit_record_at(&process, &window, 17, 42));
        assert_eq!(window.load(Ordering::Relaxed), (42 << RATE_COUNT_BITS) | 1);
    }

    #[test]
    fn rate_limit_keys_windows_by_process_not_thread() {
        let process = AtomicU64::new(0);
        let window = AtomicU64::new(0);

        for _ in 0..RATE_LIMIT_PER_SECOND {
            assert!(admit_record_at(&process, &window, 101, 41));
        }
        // Another caller in the same TGID shares the exhausted budget.
        assert!(!admit_record_at(&process, &window, 101, 41));

        // A non-CLONE_VM child sees a different TGID in its copied state and
        // receives a fresh budget even within the same monotonic second.
        assert!(admit_record_at(&process, &window, 202, 41));
        assert_eq!(process.load(Ordering::Acquire), 202);
        assert_eq!(window.load(Ordering::Relaxed), (41 << RATE_COUNT_BITS) | 1);
    }

    #[test]
    fn rate_limit_child_recovers_an_inherited_parent_transition() {
        let process = AtomicU64::new(u64::from(101_u32) | RATE_PROCESS_TRANSITION_BIT);
        let window = AtomicU64::new((41 << RATE_COUNT_BITS) | RATE_LIMIT_PER_SECOND);

        assert!(admit_record_at(&process, &window, 202, 41));
        assert_eq!(process.load(Ordering::Acquire), 202);
        assert_eq!(window.load(Ordering::Relaxed), (41 << RATE_COUNT_BITS) | 1);
    }

    #[test]
    fn monotonic_rate_clock_is_available_on_deployed_linux_targets() {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let first = monotonic_second().expect("raw CLOCK_MONOTONIC syscall must succeed");
            let second = monotonic_second().expect("raw CLOCK_MONOTONIC syscall must succeed");
            assert!(second >= first);
        }
    }

    #[test]
    fn unavailable_rate_clock_is_counted_separately_from_rate_limiting() {
        let before = runtime_log_snapshot();
        assert!(!admit_record_for_second(None));
        let after = runtime_log_snapshot();
        assert_eq!(
            after.admission_clock_failures,
            before.admission_clock_failures + 1
        );
        assert_eq!(after.rate_limited_records, before.rate_limited_records);
        assert!(after.dropped_records > before.dropped_records);
    }

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
        use std::os::fd::AsRawFd;

        let file = File::open("/dev/null").unwrap();
        // Read-only descriptor: the kernel must return EBADF, without the
        // logging path overwriting the errno of the operation being repaired.
        unsafe { *libc::__errno_location() = libc::EDOM };
        let result = write_record_with("{}", |a, b| write_chunks_fd(file.as_raw_fd(), a, b));
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
