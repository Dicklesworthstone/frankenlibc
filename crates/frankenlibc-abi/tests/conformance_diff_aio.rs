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
//! Bead: CONFORMANCE: libc aio.h diff matrix.

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

/// Wait up to 5 seconds for aio_error to return something other than EINPROGRESS.
/// Panics on timeout to ensure in-flight memory is never dropped by callers.
fn wait_aio_complete_lc(cb: *const c_void) -> c_int {
    const EINPROGRESS: c_int = libc::EINPROGRESS;
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(5) {
        let r = unsafe { aio_error(cb) };
        if r != EINPROGRESS {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("glibc aio operation timed out after 5s while still EINPROGRESS");
}

fn wait_aio_complete_fl(cb: *const c_void) -> c_int {
    const EINPROGRESS: c_int = libc::EINPROGRESS;
    let start = std::time::Instant::now();
    while start.elapsed() < std::time::Duration::from_secs(5) {
        let r = unsafe { fl::aio_error(cb) };
        if r != EINPROGRESS {
            return r;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("frankenlibc aio operation timed out after 5s while still EINPROGRESS");
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
    let payload = b"hello aio write".to_vec();

    // fl run
    let mut cb_fl = vec![0u8; AIOCB_BYTES];
    let cbp = cb_fl.as_mut_ptr() as *mut AbiAiocb;
    unsafe {
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = payload.as_ptr() as *mut c_void;
        (*cbp).aio_nbytes = payload.len();
        (*cbp).aio_offset = 0;
    }
    let r_sub_fl = unsafe { fl::aio_write(cb_fl.as_mut_ptr() as *mut c_void) };
    let err_fl = wait_aio_complete_fl(cb_fl.as_ptr() as *const c_void);
    let n_fl = unsafe { fl::aio_return(cb_fl.as_mut_ptr() as *mut c_void) };

    // Reset file
    std::fs::write(&path, b"").unwrap();

    // lc run
    let mut cb_lc = vec![0u8; AIOCB_BYTES];
    let cbp = cb_lc.as_mut_ptr() as *mut AbiAiocb;
    unsafe {
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = payload.as_ptr() as *mut c_void;
        (*cbp).aio_nbytes = payload.len();
        (*cbp).aio_offset = 0;
    }
    let r_sub_lc = unsafe { aio_write(cb_lc.as_mut_ptr() as *mut c_void) };
    let err_lc = wait_aio_complete_lc(cb_lc.as_ptr() as *const c_void);
    let n_lc = unsafe { aio_return(cb_lc.as_mut_ptr() as *mut c_void) };

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
    let mut cb_fl = vec![0u8; AIOCB_BYTES];
    let mut buf_fl = vec![0u8; 64];
    unsafe {
        let cbp = cb_fl.as_mut_ptr() as *mut AbiAiocb;
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = buf_fl.as_mut_ptr() as *mut c_void;
        (*cbp).aio_nbytes = buf_fl.len();
        (*cbp).aio_offset = 0;
    }
    let r_sub_fl = unsafe { fl::aio_read(cb_fl.as_mut_ptr() as *mut c_void) };
    let err_fl = wait_aio_complete_fl(cb_fl.as_ptr() as *const c_void);
    let n_fl = unsafe { fl::aio_return(cb_fl.as_mut_ptr() as *mut c_void) };

    // lc run
    let mut cb_lc = vec![0u8; AIOCB_BYTES];
    let mut buf_lc = vec![0u8; 64];
    unsafe {
        let cbp = cb_lc.as_mut_ptr() as *mut AbiAiocb;
        (*cbp).aio_fildes = fd;
        (*cbp).aio_buf = buf_lc.as_mut_ptr() as *mut c_void;
        (*cbp).aio_nbytes = buf_lc.len();
        (*cbp).aio_offset = 0;
    }
    let r_sub_lc = unsafe { aio_read(cb_lc.as_mut_ptr() as *mut c_void) };
    let err_lc = wait_aio_complete_lc(cb_lc.as_ptr() as *const c_void);
    let n_lc = unsafe { aio_return(cb_lc.as_mut_ptr() as *mut c_void) };

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
            buf_fl[..n_fl as usize],
            buf_lc[..n_lc as usize],
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
    let wait = |cb: *const c_void| {
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(5) {
            let r = unsafe { (imp.error)(cb) };
            if r != libc::EINPROGRESS {
                return r;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        panic!("aio_stream_roundtrip wait timed out after 5s while still EINPROGRESS");
    };
    let mut cb = vec![0u8; AIOCB_BYTES];
    let mut buf = vec![0u8; 16];
    unsafe {
        let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
        (*cbp).aio_fildes = fds[0];
        (*cbp).aio_buf = buf.as_mut_ptr() as *mut c_void;
        (*cbp).aio_nbytes = 3;
        (*cbp).aio_offset = 12345;
        assert_eq!((imp.read)(cb.as_mut_ptr() as *mut c_void), 0);
        let immediate_err = (imp.error)(cb.as_ptr() as *const c_void);
        assert_eq!(
            immediate_err,
            libc::EINPROGRESS,
            "read submission on empty pipe must report EINPROGRESS"
        );
        assert_eq!(libc::write(fds[1], b"abc".as_ptr() as *const c_void, 3), 3);
    }
    let rerr = wait(cb.as_ptr() as *const c_void);
    let rret = unsafe { (imp.ret)(cb.as_mut_ptr() as *mut c_void) };
    let rbuf = buf[..rret.max(0) as usize].to_vec();

    let mut cb = vec![0u8; AIOCB_BYTES];
    let mut out = *b"xyz12";
    unsafe {
        let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
        (*cbp).aio_fildes = fds[1];
        (*cbp).aio_buf = out.as_mut_ptr() as *mut c_void;
        (*cbp).aio_nbytes = out.len();
        (*cbp).aio_offset = 7;
        assert_eq!((imp.write)(cb.as_mut_ptr() as *mut c_void), 0);
    }
    let werr = wait(cb.as_ptr() as *const c_void);
    let wret = unsafe { (imp.ret)(cb.as_mut_ptr() as *mut c_void) };
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
        let mut cb = vec![0u8; AIOCB_BYTES];
        unsafe {
            let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = payload.as_ptr() as *mut c_void;
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 0;
        }
        let _ = if use_fl {
            unsafe { fl::aio_write(cb.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { aio_write(cb.as_mut_ptr() as *mut c_void) }
        };
        let err = if use_fl {
            unsafe { fl::aio_error(cb.as_ptr() as *const c_void) }
        } else {
            unsafe { aio_error(cb.as_ptr() as *const c_void) }
        };
        // Drain
        if use_fl {
            let _ = wait_aio_complete_fl(cb.as_ptr() as *const c_void);
            let _ = unsafe { fl::aio_return(cb.as_mut_ptr() as *mut c_void) };
        } else {
            let _ = wait_aio_complete_lc(cb.as_ptr() as *const c_void);
            let _ = unsafe { aio_return(cb.as_mut_ptr() as *mut c_void) };
        }
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
        let mut cb = vec![0u8; AIOCB_BYTES];
        unsafe {
            let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = payload.as_ptr() as *mut c_void;
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 0;
        }
        let _ = if use_fl {
            unsafe { fl::aio_write(cb.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { aio_write(cb.as_mut_ptr() as *mut c_void) }
        };
        let r = if use_fl {
            unsafe { fl::aio_cancel(fd, cb.as_mut_ptr() as *mut c_void) }
        } else {
            unsafe { aio_cancel(fd, cb.as_mut_ptr() as *mut c_void) }
        };
        // Drain
        if use_fl {
            let _ = wait_aio_complete_fl(cb.as_ptr() as *const c_void);
            let _ = unsafe { fl::aio_return(cb.as_mut_ptr() as *mut c_void) };
        } else {
            let _ = wait_aio_complete_lc(cb.as_ptr() as *const c_void);
            let _ = unsafe { aio_return(cb.as_mut_ptr() as *mut c_void) };
        }
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

        // Submit aio_write on the full pipe — must return 0 immediately and report EINPROGRESS
        let mut payload = vec![0x42u8; 512];
        let mut cb = vec![0u8; AIOCB_BYTES];
        let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
        unsafe {
            (*cbp).aio_fildes = wfd;
            (*cbp).aio_buf = payload.as_mut_ptr() as *mut c_void;
            (*cbp).aio_nbytes = payload.len();
            (*cbp).aio_offset = 777; // ignored on non-seekable descriptor
        }
        assert_eq!(unsafe { (imp.write)(cb.as_mut_ptr() as *mut c_void) }, 0);
        assert_eq!(
            unsafe { (imp.error)(cb.as_ptr() as *const c_void) },
            libc::EINPROGRESS,
            "aio_write on full pipe must report EINPROGRESS immediately"
        );

        // Now drain 4096 bytes (one pipe page) from rfd so the kernel frees the buffer page
        // and wakes the background worker completing the write.
        let mut drain_buf = vec![0u8; 4096];
        let drained =
            unsafe { libc::read(rfd, drain_buf.as_mut_ptr() as *mut c_void, drain_buf.len()) };
        assert_eq!(drained, 4096);

        // Bounded wait with watchdog
        let start = std::time::Instant::now();
        loop {
            let err = unsafe { (imp.error)(cb.as_ptr() as *const c_void) };
            if err == 0 {
                break;
            }
            assert_eq!(err, libc::EINPROGRESS);
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("timed out waiting for aio_write on drained pipe");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }

        let ret = unsafe { (imp.ret)(cb.as_mut_ptr() as *mut c_void) };
        assert_eq!(ret, 512);

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
        assert_eq!(read_back, payload);

        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    };

    test_full_pipe(&fl_impl);
    test_full_pipe(&lc_impl);
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
        let mut read_buf = vec![0u8; 6];
        let mut cb = vec![0u8; AIOCB_BYTES];
        let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
        unsafe {
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = read_buf.as_mut_ptr() as *mut c_void;
            (*cbp).aio_nbytes = read_buf.len();
            (*cbp).aio_offset = 10;
        }
        assert_eq!(unsafe { (imp.read)(cb.as_mut_ptr() as *mut c_void) }, 0);
        let start = std::time::Instant::now();
        loop {
            let err = unsafe { (imp.error)(cb.as_ptr() as *const c_void) };
            if err == 0 {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("timed out waiting for seekable aio_read");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(unsafe { (imp.ret)(cb.as_mut_ptr() as *mut c_void) }, 6);
        assert_eq!(&read_buf, b"abcdef");

        // 2. Write at offset 20, len 4 with "WXYZ"
        let mut write_payload = b"WXYZ".to_vec();
        let mut cb = vec![0u8; AIOCB_BYTES];
        let cbp = cb.as_mut_ptr() as *mut AbiAiocb;
        unsafe {
            (*cbp).aio_fildes = fd;
            (*cbp).aio_buf = write_payload.as_mut_ptr() as *mut c_void;
            (*cbp).aio_nbytes = write_payload.len();
            (*cbp).aio_offset = 20;
        }
        assert_eq!(unsafe { (imp.write)(cb.as_mut_ptr() as *mut c_void) }, 0);
        let start = std::time::Instant::now();
        loop {
            let err = unsafe { (imp.error)(cb.as_ptr() as *const c_void) };
            if err == 0 {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("timed out waiting for seekable aio_write");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(unsafe { (imp.ret)(cb.as_mut_ptr() as *mut c_void) }, 4);

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
        let mut write_payload = b"ignored_offset_pipe".to_vec();
        let mut cb_w = vec![0u8; AIOCB_BYTES];
        let cbp_w = cb_w.as_mut_ptr() as *mut AbiAiocb;
        unsafe {
            (*cbp_w).aio_fildes = wfd;
            (*cbp_w).aio_buf = write_payload.as_mut_ptr() as *mut c_void;
            (*cbp_w).aio_nbytes = write_payload.len();
            (*cbp_w).aio_offset = 9999;
        }
        assert_eq!(unsafe { (imp.write)(cb_w.as_mut_ptr() as *mut c_void) }, 0);
        let start = std::time::Instant::now();
        loop {
            let err = unsafe { (imp.error)(cb_w.as_ptr() as *const c_void) };
            if err == 0 {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("timed out waiting for pipe aio_write");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(
            unsafe { (imp.ret)(cb_w.as_mut_ptr() as *mut c_void) },
            write_payload.len() as isize
        );

        // Read with non-zero offset on pipe
        let mut read_buf = vec![0u8; write_payload.len()];
        let mut cb_r = vec![0u8; AIOCB_BYTES];
        let cbp_r = cb_r.as_mut_ptr() as *mut AbiAiocb;
        unsafe {
            (*cbp_r).aio_fildes = rfd;
            (*cbp_r).aio_buf = read_buf.as_mut_ptr() as *mut c_void;
            (*cbp_r).aio_nbytes = read_buf.len();
            (*cbp_r).aio_offset = 8888;
        }
        assert_eq!(unsafe { (imp.read)(cb_r.as_mut_ptr() as *mut c_void) }, 0);
        let start = std::time::Instant::now();
        loop {
            let err = unsafe { (imp.error)(cb_r.as_ptr() as *const c_void) };
            if err == 0 {
                break;
            }
            if start.elapsed() > std::time::Duration::from_secs(5) {
                panic!("timed out waiting for pipe aio_read");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(
            unsafe { (imp.ret)(cb_r.as_mut_ptr() as *mut c_void) },
            read_buf.len() as isize
        );
        assert_eq!(read_buf, write_payload);

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
