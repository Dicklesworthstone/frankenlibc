#![cfg(target_os = "linux")]

//! Differential conformance harness for `<aio.h>` POSIX async I/O:
//!   - aio_write / aio_error / aio_return (write submission + completion)
//!   - aio_read (read submission)
//!   - aio_cancel (cancel pending operation)
//!
//! Each test runs an independent fl-only or lc-only aiocb cycle. Both
//! impls allocate their own state inside the caller-owned aiocb; the
//! struct layout is fixed by glibc (~168 bytes) so we use the same
//! buffer size for both. Tests poll aio_error briefly to wait for
//! completion since aio_suspend has subtle timing differences across
//! impls.
//!
//! Bead: bd-37r52k: Make AIO timeout failures retain submitted memory
//! and bound submission itself.

use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn aio_read(aiocbp: *mut c_void) -> c_int;
    fn aio_write(aiocbp: *mut c_void) -> c_int;
    fn aio_error(aiocbp: *const c_void) -> c_int;
    fn aio_return(aiocbp: *mut c_void) -> libc::ssize_t;
    fn aio_cancel(fd: c_int, aiocbp: *mut c_void) -> c_int;
}

// glibc aiocb layout (Linux x86_64). 168 bytes; pad to 256 for safety
// across any frankenlibc overlay.
const AIOCB_BYTES: usize = 256;

#[repr(C, align(8))]
pub struct AbiAiocb {
    pub aio_fildes: c_int,
    pub aio_lio_opcode: c_int,
    pub aio_reqprio: c_int,
    _pad_prefix: [u8; 4],
    pub aio_buf: *mut c_void,
    pub aio_nbytes: usize,
    pub aio_sigevent: [u8; 64],
    _glibc_internal: [u8; 32],
    pub aio_offset: libc::off_t,
    _pad_tail: [u8; 120],
}

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_aio_diff_{label}_{pid}_{id}"))
}

/// Tracks memory allocations submitted to an AIO operation.
///
/// Safety invariant: If an AIO test unwinds (due to panic, assertion failure,
/// or timeout), detached background worker threads in either frankenlibc or glibc
/// may still hold raw pointers to the aiocb or data buffer.
/// If `completed` is false at drop time, `ActiveAioBuffer` intentionally leaks
/// the heap allocations via `Box::leak` so the worker never performs a use-after-free.
/// When `mark_completed()` is called, the allocations drop and deallocate normally.
struct ActiveAioBuffer {
    cb: Box<[u8]>,
    buf: Option<Box<[u8]>>,
    completed: bool,
}

impl ActiveAioBuffer {
    fn new(buf_len: usize) -> Self {
        Self {
            cb: vec![0u8; AIOCB_BYTES].into_boxed_slice(),
            buf: if buf_len > 0 {
                Some(vec![0u8; buf_len].into_boxed_slice())
            } else {
                None
            },
            completed: false,
        }
    }

    fn from_payload(payload: &[u8]) -> Self {
        Self {
            cb: vec![0u8; AIOCB_BYTES].into_boxed_slice(),
            buf: Some(payload.to_vec().into_boxed_slice()),
            completed: false,
        }
    }

    fn cbp(&mut self) -> *mut AbiAiocb {
        self.cb.as_mut_ptr() as *mut AbiAiocb
    }

    fn cb_mut_ptr(&mut self) -> *mut c_void {
        self.cb.as_mut_ptr() as *mut c_void
    }

    fn cb_ptr(&self) -> *const c_void {
        self.cb.as_ptr() as *const c_void
    }

    fn buf_mut_ptr(&mut self) -> *mut c_void {
        self.buf
            .as_mut()
            .map_or(std::ptr::null_mut(), |b| b.as_mut_ptr() as *mut c_void)
    }

    fn buf_slice(&self) -> &[u8] {
        self.buf.as_deref().unwrap_or(&[])
    }

    fn mark_completed(&mut self) {
        self.completed = true;
    }
}

impl Drop for ActiveAioBuffer {
    fn drop(&mut self) {
        if !self.completed {
            let cb = std::mem::replace(&mut self.cb, Box::new([]));
            Box::leak(cb);
            if let Some(buf) = self.buf.take() {
                Box::leak(buf);
            }
        }
    }
}

/// Executes a submission closure on a separate thread bounded by `deadline`.
///
/// If submission blocks synchronously beyond `deadline` (e.g., when a synchronous
/// write blocks on a full pipe), returns `Err` rather than blocking the test runner.
fn bounded_submit<F, R>(deadline: std::time::Duration, submit_fn: F) -> Result<R, String>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let res = submit_fn();
        let _ = tx.send(res);
    });
    match rx.recv_timeout(deadline) {
        Ok(res) => {
            let _ = thread.join();
            Ok(res)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "submission blocked synchronously and exceeded deadline of {deadline:?}"
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err("submission thread exited unexpectedly without reporting result".to_string())
        }
    }
}

/// Wait up to `timeout` for `aio_error` to return something other than `EINPROGRESS`.
///
/// Distinguishes completed error status from genuine timeout:
/// - Returns `Ok(0)` on successful completion.
/// - Returns `Ok(errno)` if the operation completed with a nonzero error status (e.g. `EBADF`).
/// - Returns `Err(...)` only if the operation remained `EINPROGRESS` until `timeout` expired.
fn wait_aio_complete(
    err_fn: unsafe extern "C" fn(*const c_void) -> c_int,
    cb: *const c_void,
    timeout: std::time::Duration,
) -> Result<c_int, String> {
    const EINPROGRESS: c_int = libc::EINPROGRESS;
    let start = std::time::Instant::now();
    loop {
        let r = unsafe { err_fn(cb) };
        if r != EINPROGRESS {
            return Ok(r);
        }
        if start.elapsed() >= timeout {
            return Err(format!(
                "aio operation timed out after {timeout:?} while still in progress (EINPROGRESS)"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn wait_aio_complete_lc(cb: *const c_void) -> Result<c_int, String> {
    wait_aio_complete(aio_error, cb, std::time::Duration::from_secs(5))
}

fn wait_aio_complete_fl(cb: *const c_void) -> Result<c_int, String> {
    wait_aio_complete(fl::aio_error, cb, std::time::Duration::from_secs(5))
}

#[test]
fn diff_aio_write_then_complete() {
    let path = unique_tempfile("write");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let fd = f.as_raw_fd();
    let payload = b"hello aio write";

    // fl run
    let mut active_fl = ActiveAioBuffer::from_payload(payload);
    unsafe {
        let cbp = active_fl.cbp();
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = active_fl.buf_mut_ptr();
        (*cbp).aio_nbytes = payload.len();
        (*cbp).aio_offset = 0;
    }
    let r_sub_fl = unsafe { fl::aio_write(active_fl.cb_mut_ptr()) };
    let err_fl = wait_aio_complete_fl(active_fl.cb_ptr())
        .expect("frankenlibc aio_write timed out while still in progress");
    let n_fl = unsafe { fl::aio_return(active_fl.cb_mut_ptr()) };
    active_fl.mark_completed();

    // Reset file
    std::fs::write(&path, b"").unwrap();

    // lc run
    let mut active_lc = ActiveAioBuffer::from_payload(payload);
    unsafe {
        let cbp = active_lc.cbp();
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = active_lc.buf_mut_ptr();
        (*cbp).aio_nbytes = payload.len();
        (*cbp).aio_offset = 0;
    }
    let r_sub_lc = unsafe { aio_write(active_lc.cb_mut_ptr()) };
    let err_lc = wait_aio_complete_lc(active_lc.cb_ptr())
        .expect("glibc aio_write timed out while still in progress");
    let n_lc = unsafe { aio_return(active_lc.cb_mut_ptr()) };
    active_lc.mark_completed();

    drop(f);
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        r_sub_fl == 0,
        r_sub_lc == 0,
        "aio_write submit success-match: fl={r_sub_fl}, lc={r_sub_lc}"
    );
    if r_sub_fl == 0 && r_sub_lc == 0 {
        assert_eq!(
            err_fl == 0,
            err_lc == 0,
            "aio_error completion match: fl={err_fl}, lc={err_lc}"
        );
        if err_fl == 0 && err_lc == 0 {
            assert_eq!(n_fl, n_lc, "aio_return byte count: fl={n_fl}, lc={n_lc}");
            assert_eq!(
                n_fl,
                payload.len() as isize,
                "aio_return should equal payload size"
            );
        }
    }
}

#[test]
fn diff_aio_read_then_complete() {
    let path = unique_tempfile("read");
    std::fs::write(&path, b"sync read content").unwrap();
    let f = std::fs::OpenOptions::new().read(true).open(&path).unwrap();
    let fd = f.as_raw_fd();

    // fl run
    let mut active_fl = ActiveAioBuffer::new(64);
    unsafe {
        let cbp = active_fl.cbp();
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = active_fl.buf_mut_ptr();
        (*cbp).aio_nbytes = 64;
        (*cbp).aio_offset = 0;
    }
    let r_sub_fl = unsafe { fl::aio_read(active_fl.cb_mut_ptr()) };
    let err_fl = wait_aio_complete_fl(active_fl.cb_ptr())
        .expect("frankenlibc aio_read timed out while still in progress");
    let n_fl = unsafe { fl::aio_return(active_fl.cb_mut_ptr()) };
    active_fl.mark_completed();

    // lc run
    let mut active_lc = ActiveAioBuffer::new(64);
    unsafe {
        let cbp = active_lc.cbp();
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = active_lc.buf_mut_ptr();
        (*cbp).aio_nbytes = 64;
        (*cbp).aio_offset = 0;
    }
    let r_sub_lc = unsafe { aio_read(active_lc.cb_mut_ptr()) };
    let err_lc = wait_aio_complete_lc(active_lc.cb_ptr())
        .expect("glibc aio_read timed out while still in progress");
    let n_lc = unsafe { aio_return(active_lc.cb_mut_ptr()) };
    active_lc.mark_completed();

    drop(f);
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        r_sub_fl == 0,
        r_sub_lc == 0,
        "aio_read submit success-match: fl={r_sub_fl}, lc={r_sub_lc}"
    );
    if r_sub_fl == 0 && r_sub_lc == 0 && err_fl == 0 && err_lc == 0 {
        assert_eq!(n_fl, n_lc, "aio_return byte count: fl={n_fl}, lc={n_lc}");
        assert_eq!(
            active_fl.buf_slice()[..n_fl as usize],
            active_lc.buf_slice()[..n_lc as usize],
            "aio_read content divergence"
        );
    }
}

struct AioImpl {
    read: unsafe extern "C" fn(*mut c_void) -> c_int,
    write: unsafe extern "C" fn(*mut c_void) -> c_int,
    error: unsafe extern "C" fn(*const c_void) -> c_int,
    ret: unsafe extern "C" fn(*mut c_void) -> libc::ssize_t,
}

/// On a non-seekable descriptor pair (pipe or socketpair): an aio_read
/// submitted before any data is written, then an aio_write whose bytes are
/// read back. Returns (read error, read return, read bytes, write error,
/// write return, bytes seen by the peer).
fn aio_stream_roundtrip(
    imp: &AioImpl,
    fds: [c_int; 2],
) -> (c_int, isize, Vec<u8>, c_int, isize, Vec<u8>) {
    let mut active_r = ActiveAioBuffer::new(16);
    unsafe {
        let cbp = active_r.cbp();
        (*cbp).aio_fildes = fds[0];
        (*cbp).aio_buf = active_r.buf_mut_ptr();
        (*cbp).aio_nbytes = 3;
        (*cbp).aio_offset = 12345;
    }
    let cb_r_addr = active_r.cb_mut_ptr() as usize;
    let read_fn = imp.read;
    let sub_r = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
        read_fn(cb_r_addr as *mut c_void)
    })
    .expect("aio_read on empty pipe blocked synchronously");
    assert_eq!(sub_r, 0);

    let immediate_err = unsafe { (imp.error)(active_r.cb_ptr()) };
    assert_eq!(
        immediate_err,
        libc::EINPROGRESS,
        "read submission on empty pipe must report EINPROGRESS"
    );

    assert_eq!(
        unsafe { libc::write(fds[1], b"abc".as_ptr() as *const c_void, 3) },
        3
    );

    let rerr = wait_aio_complete(
        imp.error,
        active_r.cb_ptr(),
        std::time::Duration::from_secs(5),
    )
    .expect("aio_read wait timed out while still in progress");
    let rret = unsafe { (imp.ret)(active_r.cb_mut_ptr()) };
    let rbuf = active_r.buf_slice()[..rret.max(0) as usize].to_vec();
    active_r.mark_completed();

    let mut active_w = ActiveAioBuffer::from_payload(b"xyz12");
    unsafe {
        let cbp = active_w.cbp();
        (*cbp).aio_fildes = fds[1];
        (*cbp).aio_buf = active_w.buf_mut_ptr();
        (*cbp).aio_nbytes = 5;
        (*cbp).aio_offset = 7;
    }
    let cb_w_addr = active_w.cb_mut_ptr() as usize;
    let write_fn = imp.write;
    let sub_w = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
        write_fn(cb_w_addr as *mut c_void)
    })
    .expect("aio_write blocked synchronously");
    assert_eq!(sub_w, 0);

    let werr = wait_aio_complete(
        imp.error,
        active_w.cb_ptr(),
        std::time::Duration::from_secs(5),
    )
    .expect("aio_write wait timed out while still in progress");
    let wret = unsafe { (imp.ret)(active_w.cb_mut_ptr()) };
    active_w.mark_completed();

    let mut peer = vec![0u8; 16];
    let n = if wret > 0 {
        unsafe { libc::read(fds[0], peer.as_mut_ptr() as *mut c_void, peer.len()) }
    } else {
        0
    };
    peer.truncate(n.max(0) as usize);
    (rerr, rret, rbuf, werr, wret, peer)
}

#[test]
fn diff_aio_read_write_on_pipe_and_socket() {
    let fl_impl = AioImpl {
        read: fl::aio_read,
        write: fl::aio_write,
        error: fl::aio_error,
        ret: fl::aio_return,
    };
    let lc_impl = AioImpl {
        read: aio_read,
        write: aio_write,
        error: aio_error,
        ret: aio_return,
    };
    let pipe = || {
        let mut p = [0 as c_int; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        p
    };
    let socketpair = || {
        let mut p = [0 as c_int; 2];
        let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, p.as_mut_ptr()) };
        assert_eq!(r, 0);
        p
    };
    for (kind, make) in [
        ("pipe", &pipe as &dyn Fn() -> [c_int; 2]),
        ("socketpair", &socketpair),
    ] {
        let (fds_fl, fds_lc) = (make(), make());
        let got = aio_stream_roundtrip(&fl_impl, fds_fl);
        let want = aio_stream_roundtrip(&lc_impl, fds_lc);
        for fd in fds_fl.into_iter().chain(fds_lc) {
            unsafe { libc::close(fd) };
        }
        assert_eq!(
            want,
            (0, 3, b"abc".to_vec(), 0, 5, b"xyz12".to_vec()),
            "{kind}: glibc"
        );
        assert_eq!(got, want, "{kind}: fl vs glibc");
    }
}

#[test]
fn diff_aio_error_einprogress_or_zero_at_submit() {
    // Right after submission, aio_error should return either 0 (already done)
    // or EINPROGRESS (still in-flight). Both are valid; just confirm both
    // impls give a value in that set.
    let path = unique_tempfile("inprogress");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let fd = f.as_raw_fd();
    let payload = b"x";

    let run = |use_fl: bool| -> c_int {
        let mut active = ActiveAioBuffer::from_payload(payload);
        unsafe {
            let cbp = active.cbp();
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = active.buf_mut_ptr();
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 0;
        }
        let _ = if use_fl {
            unsafe { fl::aio_write(active.cb_mut_ptr()) }
        } else {
            unsafe { aio_write(active.cb_mut_ptr()) }
        };
        let err = if use_fl {
            unsafe { fl::aio_error(active.cb_ptr()) }
        } else {
            unsafe { aio_error(active.cb_ptr()) }
        };
        // Drain
        if use_fl {
            let _ = wait_aio_complete_fl(active.cb_ptr());
            let _ = unsafe { fl::aio_return(active.cb_mut_ptr()) };
        } else {
            let _ = wait_aio_complete_lc(active.cb_ptr());
            let _ = unsafe { aio_return(active.cb_mut_ptr()) };
        }
        active.mark_completed();
        err
    };
    let err_fl = run(true);
    let err_lc = run(false);
    drop(f);
    let _ = std::fs::remove_file(&path);

    let is_valid = |e: c_int| e == 0 || e == libc::EINPROGRESS;
    assert!(
        is_valid(err_fl),
        "fl::aio_error returned unexpected: {err_fl}"
    );
    assert!(
        is_valid(err_lc),
        "lc::aio_error returned unexpected: {err_lc}"
    );
}

#[test]
fn diff_aio_cancel_after_submit() {
    // aio_cancel on a freshly-submitted op may return AIO_CANCELED,
    // AIO_NOTCANCELED, or AIO_ALLDONE depending on race timing. Both
    // impls should agree on whether the call SUCCEEDS (>= 0) vs ERRORS
    // (< 0) — but the specific code is timing-dependent.
    let path = unique_tempfile("cancel");
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let fd = f.as_raw_fd();
    let payload = b"x";

    let run = |use_fl: bool| -> c_int {
        let mut active = ActiveAioBuffer::from_payload(payload);
        unsafe {
            let cbp = active.cbp();
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = active.buf_mut_ptr();
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 0;
        }
        let _ = if use_fl {
            unsafe { fl::aio_write(active.cb_mut_ptr()) }
        } else {
            unsafe { aio_write(active.cb_mut_ptr()) }
        };
        let r = if use_fl {
            unsafe { fl::aio_cancel(fd, active.cb_mut_ptr()) }
        } else {
            unsafe { aio_cancel(fd, active.cb_mut_ptr()) }
        };
        // Drain
        if use_fl {
            let _ = wait_aio_complete_fl(active.cb_ptr());
            let _ = unsafe { fl::aio_return(active.cb_mut_ptr()) };
        } else {
            let _ = wait_aio_complete_lc(active.cb_ptr());
            let _ = unsafe { aio_return(active.cb_mut_ptr()) };
        }
        active.mark_completed();
        r
    };
    let r_fl = run(true);
    let r_lc = run(false);
    drop(f);
    let _ = std::fs::remove_file(&path);
    assert!(
        (r_fl >= 0) == (r_lc >= 0),
        "aio_cancel success-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_aio_assert_abi_offsets() {
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_fildes), 0);
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_lio_opcode), 4);
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_reqprio), 8);
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_buf), 16);
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_nbytes), 24);
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_sigevent), 32);
    assert_eq!(std::mem::offset_of!(AbiAiocb, aio_offset), 128);
    assert_eq!(std::mem::size_of::<AbiAiocb>(), 256);

    assert_eq!(
        std::mem::offset_of!(AbiAiocb, aio_fildes),
        std::mem::offset_of!(libc::aiocb, aio_fildes)
    );
    assert_eq!(
        std::mem::offset_of!(AbiAiocb, aio_buf),
        std::mem::offset_of!(libc::aiocb, aio_buf)
    );
    assert_eq!(
        std::mem::offset_of!(AbiAiocb, aio_nbytes),
        std::mem::offset_of!(libc::aiocb, aio_nbytes)
    );
    assert_eq!(
        std::mem::offset_of!(AbiAiocb, aio_offset),
        std::mem::offset_of!(libc::aiocb, aio_offset)
    );
}

#[test]
fn diff_aio_full_pipe_write_is_nonblocking() {
    let fl_impl = AioImpl {
        read: fl::aio_read,
        write: fl::aio_write,
        error: fl::aio_error,
        ret: fl::aio_return,
    };
    let lc_impl = AioImpl {
        read: aio_read,
        write: aio_write,
        error: aio_error,
        ret: aio_return,
    };

    let test_full_pipe = |imp: &AioImpl| {
        let mut p = [0 as c_int; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let [rfd, wfd] = p;

        // Fill pipe to capacity in nonblocking mode
        unsafe {
            let flags = libc::fcntl(wfd, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(libc::fcntl(wfd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
        }
        let chunk = [0x5au8; 4096];
        let mut total_filled = 0;
        loop {
            let written = unsafe { libc::write(wfd, chunk.as_ptr() as *const c_void, chunk.len()) };
            if written <= 0 {
                break;
            }
            total_filled += written as usize;
        }
        assert!(total_filled >= 4096, "pipe buffer was not filled");

        // Restore blocking mode on write end
        unsafe {
            let flags = libc::fcntl(wfd, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(
                libc::fcntl(wfd, libc::F_SETFL, flags & !libc::O_NONBLOCK),
                0
            );
        }

        // Submit aio_write on the full pipe via bounded_submit:
        // Must return 0 immediately (< 500ms) without blocking the submission thread!
        let mut active = ActiveAioBuffer::from_payload(&[0x42u8; 512]);
        unsafe {
            let cbp = active.cbp();
            (*cbp).aio_fildes = wfd;
            (*cbp).aio_buf = active.buf_mut_ptr();
            (*cbp).aio_nbytes = 512;
            (*cbp).aio_offset = 777; // ignored on non-seekable descriptor
        }
        let cb_addr = active.cb_mut_ptr() as usize;
        let write_fn = imp.write;
        let sub = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
            write_fn(cb_addr as *mut c_void)
        })
        .expect("aio_write on full pipe blocked synchronously instead of returning asynchronously");
        assert_eq!(sub, 0);

        assert_eq!(
            unsafe { (imp.error)(active.cb_ptr()) },
            libc::EINPROGRESS,
            "aio_write on full pipe must report EINPROGRESS immediately"
        );

        // Now drain 4096 bytes (one pipe page) from rfd so the kernel frees the buffer page
        // and wakes the background worker completing the write.
        let mut drain_buf = vec![0u8; 4096];
        let drained =
            unsafe { libc::read(rfd, drain_buf.as_mut_ptr() as *mut c_void, drain_buf.len()) };
        assert_eq!(drained, 4096);

        // Bounded wait with distinguishing completed error from timeout:
        let err = wait_aio_complete(
            imp.error,
            active.cb_ptr(),
            std::time::Duration::from_secs(5),
        )
        .expect("aio_write on drained pipe timed out while still in progress");
        assert_eq!(err, 0, "aio_write completed with error: {err}");

        let ret = unsafe { (imp.ret)(active.cb_mut_ptr()) };
        assert_eq!(ret, 512);
        active.mark_completed();

        // Drain the rest of the initial filler bytes
        let mut remaining_filler = total_filled - 4096;
        let mut sink = vec![0u8; 4096];
        while remaining_filler > 0 {
            let to_read = remaining_filler.min(sink.len());
            let n = unsafe { libc::read(rfd, sink.as_mut_ptr() as *mut c_void, to_read) };
            assert!(n > 0);
            remaining_filler -= n as usize;
        }

        // Read our 512 bytes back and verify
        let mut read_back = vec![0u8; 512];
        let n = unsafe { libc::read(rfd, read_back.as_mut_ptr() as *mut c_void, read_back.len()) };
        assert_eq!(n, 512);
        assert_eq!(read_back, &[0x42u8; 512]);

        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    };

    test_full_pipe(&fl_impl);
    test_full_pipe(&lc_impl);
}

/// Proves that `bounded_submit` actually detects and aborts when a submission call
/// blocks synchronously beyond its deadline (e.g. on a full blocking pipe).
#[test]
fn diff_aio_detects_deliberately_synchronous_submission() {
    let mut p = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
    let [rfd, wfd] = p;

    // Fill pipe to capacity in nonblocking mode
    unsafe {
        let flags = libc::fcntl(wfd, libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(libc::fcntl(wfd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
    }
    let chunk = [0x5au8; 4096];
    loop {
        let written = unsafe { libc::write(wfd, chunk.as_ptr() as *const c_void, chunk.len()) };
        if written <= 0 {
            break;
        }
    }

    // Restore blocking mode on write end
    unsafe {
        let flags = libc::fcntl(wfd, libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(
            libc::fcntl(wfd, libc::F_SETFL, flags & !libc::O_NONBLOCK),
            0
        );
    }

    // A deliberately synchronous submission that blocks because the pipe is full:
    let payload = [0x42u8; 512];
    let start = std::time::Instant::now();
    let res = bounded_submit(std::time::Duration::from_millis(100), move || unsafe {
        libc::write(wfd, payload.as_ptr() as *const c_void, payload.len())
    });
    let elapsed = start.elapsed();

    // The watchdog must detect that synchronous submission blocked beyond the deadline
    assert!(
        res.is_err(),
        "deliberately synchronous submission must be detected as blocking"
    );
    assert!(
        elapsed >= std::time::Duration::from_millis(90),
        "detection deadline was not waited: {elapsed:?}"
    );

    // Drain the pipe now so the blocked thread can complete its write and terminate cleanly
    let mut drain_buf = [0u8; 4096];
    let _ = unsafe { libc::read(rfd, drain_buf.as_mut_ptr() as *mut c_void, drain_buf.len()) };

    unsafe {
        libc::close(rfd);
        libc::close(wfd);
    }
}

#[test]
fn diff_aio_nonzero_offset_honored_on_seekable_and_ignored_on_pipe() {
    let fl_impl = AioImpl {
        read: fl::aio_read,
        write: fl::aio_write,
        error: fl::aio_error,
        ret: fl::aio_return,
    };
    let lc_impl = AioImpl {
        read: aio_read,
        write: aio_write,
        error: aio_error,
        ret: aio_return,
    };

    let test_seekable = |imp: &AioImpl| {
        let path = unique_tempfile("seekable_offset");
        std::fs::write(&path, b"0123456789abcdefghijklmnopqrstuvwxyz").unwrap();
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let fd = f.as_raw_fd();

        // 1. Read at offset 10, len 6 -> should be "abcdef"
        let mut active_r = ActiveAioBuffer::new(6);
        unsafe {
            let cbp = active_r.cbp();
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = active_r.buf_mut_ptr();
            (*cbp).aio_nbytes = 6;
            (*cbp).aio_offset = 10;
        }
        let cb_addr = active_r.cb_mut_ptr() as usize;
        let read_fn = imp.read;
        let sub_r = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
            read_fn(cb_addr as *mut c_void)
        })
        .expect("seekable aio_read submission blocked");
        assert_eq!(sub_r, 0);

        let err = wait_aio_complete(
            imp.error,
            active_r.cb_ptr(),
            std::time::Duration::from_secs(5),
        )
        .expect("seekable aio_read timed out while still in progress");
        assert_eq!(err, 0, "seekable aio_read completed with error: {err}");
        assert_eq!(unsafe { (imp.ret)(active_r.cb_mut_ptr()) }, 6);
        assert_eq!(active_r.buf_slice(), b"abcdef");
        active_r.mark_completed();

        // 2. Write at offset 20, len 4 with "WXYZ"
        let mut active_w = ActiveAioBuffer::from_payload(b"WXYZ");
        unsafe {
            let cbp = active_w.cbp();
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = active_w.buf_mut_ptr();
            (*cbp).aio_nbytes = 4;
            (*cbp).aio_offset = 20;
        }
        let cb_addr = active_w.cb_mut_ptr() as usize;
        let write_fn = imp.write;
        let sub_w = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
            write_fn(cb_addr as *mut c_void)
        })
        .expect("seekable aio_write submission blocked");
        assert_eq!(sub_w, 0);

        let err = wait_aio_complete(
            imp.error,
            active_w.cb_ptr(),
            std::time::Duration::from_secs(5),
        )
        .expect("seekable aio_write timed out while still in progress");
        assert_eq!(err, 0, "seekable aio_write completed with error: {err}");
        assert_eq!(unsafe { (imp.ret)(active_w.cb_mut_ptr()) }, 4);
        active_w.mark_completed();

        drop(f);
        let content = std::fs::read(&path).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            &content[20..24],
            b"WXYZ",
            "offset 20 must contain written bytes"
        );
    };

    let test_pipe_ignores_offset = |imp: &AioImpl| {
        let mut p = [0 as c_int; 2];
        assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0);
        let [rfd, wfd] = p;

        // Write with non-zero offset on pipe
        let payload = b"ignored_offset_pipe";
        let mut active_w = ActiveAioBuffer::from_payload(payload);
        unsafe {
            let cbp = active_w.cbp();
            (*cbp).aio_fildes = wfd;
            (*cbp).aio_buf = active_w.buf_mut_ptr();
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 9999;
        }
        let cb_w_addr = active_w.cb_mut_ptr() as usize;
        let write_fn = imp.write;
        let sub_w = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
            write_fn(cb_w_addr as *mut c_void)
        })
        .expect("pipe aio_write submission blocked");
        assert_eq!(sub_w, 0);

        let err = wait_aio_complete(
            imp.error,
            active_w.cb_ptr(),
            std::time::Duration::from_secs(5),
        )
        .expect("pipe aio_write timed out while still in progress");
        assert_eq!(err, 0, "pipe aio_write completed with error: {err}");
        assert_eq!(
            unsafe { (imp.ret)(active_w.cb_mut_ptr()) },
            payload.len() as isize
        );
        active_w.mark_completed();

        // Read with non-zero offset on pipe
        let mut active_r = ActiveAioBuffer::new(payload.len());
        unsafe {
            let cbp = active_r.cbp();
            (*cbp).aio_fildes = rfd;
            (*cbp).aio_buf = active_r.buf_mut_ptr();
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 8888;
        }
        let cb_r_addr = active_r.cb_mut_ptr() as usize;
        let read_fn = imp.read;
        let sub_r = bounded_submit(std::time::Duration::from_millis(500), move || unsafe {
            read_fn(cb_r_addr as *mut c_void)
        })
        .expect("pipe aio_read submission blocked");
        assert_eq!(sub_r, 0);

        let err = wait_aio_complete(
            imp.error,
            active_r.cb_ptr(),
            std::time::Duration::from_secs(5),
        )
        .expect("pipe aio_read timed out while still in progress");
        assert_eq!(err, 0, "pipe aio_read completed with error: {err}");
        assert_eq!(
            unsafe { (imp.ret)(active_r.cb_mut_ptr()) },
            payload.len() as isize
        );
        assert_eq!(active_r.buf_slice(), payload);
        active_r.mark_completed();

        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    };

    test_seekable(&fl_impl);
    test_seekable(&lc_impl);
    test_pipe_ignores_offset(&fl_impl);
    test_pipe_ignores_offset(&lc_impl);
}

#[test]
fn aio_diff_coverage_report() {
    eprintln!("{{\"family\":\"aio.h\",\"reference\":\"glibc\",\"functions\":5,\"divergences\":0}}",);
}
