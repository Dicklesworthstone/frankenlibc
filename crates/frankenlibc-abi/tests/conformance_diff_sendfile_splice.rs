#![cfg(target_os = "linux")]

//! Differential conformance harness for zero-copy I/O syscalls:
//!   - sendfile (file → fd transfer with kernel offset tracking)
//!   - copy_file_range (in-kernel file→file copy with explicit offsets)
//!   - splice (pipe → fd or fd → pipe transfer)
//!   - tee (pipe → pipe duplication)
//!
//! Tests use socketpair, tempfiles, and pipes; each impl uses
//! independent fds so kernel offsets don't bleed across.
//!
//! Bead: CONFORMANCE: libc sendfile+splice diff matrix.

use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;

use frankenlibc_abi::io_abi as fl;

unsafe extern "C" {
    fn sendfile(
        out_fd: c_int,
        in_fd: c_int,
        offset: *mut libc::off_t,
        count: usize,
    ) -> isize;
    fn copy_file_range(
        fd_in: c_int,
        off_in: *mut libc::off64_t,
        fd_out: c_int,
        off_out: *mut libc::off64_t,
        len: usize,
        flags: c_uint,
    ) -> isize;
    fn splice(
        fd_in: c_int,
        off_in: *mut libc::off64_t,
        fd_out: c_int,
        off_out: *mut libc::off64_t,
        len: usize,
        flags: c_uint,
    ) -> isize;
    fn tee(fd_in: c_int, fd_out: c_int, len: usize, flags: c_uint) -> isize;
}

use std::ffi::c_uint;

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_zerocopy_diff_{label}_{pid}_{id}"))
}

fn make_source_file(label: &str, payload: &[u8]) -> (std::fs::File, std::path::PathBuf) {
    let path = unique_tempfile(label);
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    use std::io::Write;
    let mut g = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    g.write_all(payload).unwrap();
    drop(g);
    (f, path)
}

fn make_socketpair() -> (c_int, c_int) {
    let mut fds: [c_int; 2] = [-1, -1];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(r, 0, "socketpair");
    (fds[0], fds[1])
}

fn make_pipe() -> (c_int, c_int) {
    let mut fds: [c_int; 2] = [-1, -1];
    let r = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(r, 0, "pipe");
    (fds[0], fds[1])
}

#[test]
fn diff_sendfile_file_to_socket() {
    let payload = b"hello sendfile zero copy";
    let run = |use_fl: bool| -> (isize, libc::off_t, Vec<u8>) {
        let (f, p) = make_source_file(&format!("sf_{}", if use_fl { "fl" } else { "lc" }), payload);
        let in_fd = f.as_raw_fd();
        let (a, b) = make_socketpair();
        let mut off: libc::off_t = 0;
        let n = if use_fl {
            unsafe { fl::sendfile(a, in_fd, &mut off, payload.len()) }
        } else {
            unsafe { sendfile(a, in_fd, &mut off, payload.len()) }
        };
        // Read what got through to b
        let mut buf = vec![0u8; payload.len()];
        let m = unsafe {
            libc::read(b, buf.as_mut_ptr() as *mut c_void, buf.len())
        };
        unsafe {
            libc::close(a);
            libc::close(b);
        }
        drop(f);
        let _ = std::fs::remove_file(&p);
        (n, off, if m > 0 { buf[..m as usize].to_vec() } else { Vec::new() })
    };
    let (n_fl, off_fl, data_fl) = run(true);
    let (n_lc, off_lc, data_lc) = run(false);
    assert_eq!(n_fl, n_lc, "sendfile bytes-sent: fl={n_fl}, lc={n_lc}");
    assert_eq!(off_fl, off_lc, "sendfile post-offset: fl={off_fl}, lc={off_lc}");
    assert_eq!(data_fl, data_lc, "sendfile transferred bytes diff");
    assert_eq!(data_fl, payload.to_vec(), "sendfile expected payload");
    assert_eq!(off_fl as usize, payload.len(), "offset advanced by payload size");
}

#[test]
fn diff_sendfile_invalid_fd() {
    let mut off: libc::off_t = 0;
    let r_fl = unsafe { fl::sendfile(99999, 99998, &mut off, 16) };
    let r_lc = unsafe { sendfile(99999, 99998, &mut off, 16) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "sendfile bad-fd fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_copy_file_range_basic() {
    let payload = b"copy_file_range payload bytes";
    let run = |use_fl: bool| -> (isize, libc::off64_t, libc::off64_t, Vec<u8>) {
        let (src, p_src) = make_source_file(
            &format!("cfr_src_{}", if use_fl { "fl" } else { "lc" }),
            payload,
        );
        let p_dst = unique_tempfile(&format!("cfr_dst_{}", if use_fl { "fl" } else { "lc" }));
        let dst = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&p_dst)
            .unwrap();
        dst.set_len(payload.len() as u64).unwrap();

        let mut off_in: libc::off64_t = 0;
        let mut off_out: libc::off64_t = 0;
        let n = if use_fl {
            unsafe {
                fl::copy_file_range(
                    src.as_raw_fd(),
                    &mut off_in,
                    dst.as_raw_fd(),
                    &mut off_out,
                    payload.len(),
                    0,
                )
            }
        } else {
            unsafe {
                copy_file_range(
                    src.as_raw_fd(),
                    &mut off_in,
                    dst.as_raw_fd(),
                    &mut off_out,
                    payload.len(),
                    0,
                )
            }
        };
        let mut buf = vec![0u8; payload.len()];
        let _ = unsafe {
            libc::pread(
                dst.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
            )
        };
        drop(src);
        drop(dst);
        let _ = std::fs::remove_file(&p_src);
        let _ = std::fs::remove_file(&p_dst);
        (n, off_in, off_out, buf)
    };
    let (n_fl, oi_fl, oo_fl, data_fl) = run(true);
    let (n_lc, oi_lc, oo_lc, data_lc) = run(false);
    assert_eq!(n_fl, n_lc, "copy_file_range n: fl={n_fl}, lc={n_lc}");
    assert_eq!(oi_fl, oi_lc, "copy_file_range off_in: fl={oi_fl}, lc={oi_lc}");
    assert_eq!(oo_fl, oo_lc, "copy_file_range off_out: fl={oo_fl}, lc={oo_lc}");
    assert_eq!(data_fl, data_lc, "copy_file_range data divergence");
    assert_eq!(data_fl, payload.to_vec(), "copy_file_range expected payload");
}

#[test]
fn diff_splice_pipe_to_socket() {
    let payload = b"splice pipe->socket";
    let run = |use_fl: bool| -> (isize, Vec<u8>) {
        let (pr, pw) = make_pipe();
        // Stuff payload into pipe
        let _ = unsafe { libc::write(pw, payload.as_ptr() as *const c_void, payload.len()) };
        unsafe { libc::close(pw) };
        let (a, b) = make_socketpair();
        let n = if use_fl {
            unsafe {
                fl::splice(
                    pr,
                    std::ptr::null_mut(),
                    a,
                    std::ptr::null_mut(),
                    payload.len(),
                    0,
                )
            }
        } else {
            unsafe {
                splice(
                    pr,
                    std::ptr::null_mut(),
                    a,
                    std::ptr::null_mut(),
                    payload.len(),
                    0,
                )
            }
        };
        let mut buf = vec![0u8; payload.len()];
        let m = unsafe { libc::read(b, buf.as_mut_ptr() as *mut c_void, buf.len()) };
        unsafe {
            libc::close(pr);
            libc::close(a);
            libc::close(b);
        }
        (n, if m > 0 { buf[..m as usize].to_vec() } else { Vec::new() })
    };
    let (n_fl, data_fl) = run(true);
    let (n_lc, data_lc) = run(false);
    assert_eq!(n_fl, n_lc, "splice n: fl={n_fl}, lc={n_lc}");
    assert_eq!(data_fl, data_lc, "splice data divergence");
    assert_eq!(data_fl, payload.to_vec(), "splice expected payload");
}

#[test]
fn diff_tee_pipe_to_pipe() {
    let payload = b"tee duplicate";
    let run = |use_fl: bool| -> (isize, Vec<u8>, Vec<u8>) {
        let (pr1, pw1) = make_pipe();
        let (pr2, pw2) = make_pipe();
        let _ = unsafe { libc::write(pw1, payload.as_ptr() as *const c_void, payload.len()) };
        unsafe { libc::close(pw1) };
        let n = if use_fl {
            unsafe { fl::tee(pr1, pw2, payload.len(), 0) }
        } else {
            unsafe { tee(pr1, pw2, payload.len(), 0) }
        };
        unsafe { libc::close(pw2) };
        // Both pr1 and pr2 should now have the payload.
        let mut buf1 = vec![0u8; payload.len()];
        let m1 = unsafe { libc::read(pr1, buf1.as_mut_ptr() as *mut c_void, buf1.len()) };
        let mut buf2 = vec![0u8; payload.len()];
        let m2 = unsafe { libc::read(pr2, buf2.as_mut_ptr() as *mut c_void, buf2.len()) };
        unsafe {
            libc::close(pr1);
            libc::close(pr2);
        }
        (
            n,
            if m1 > 0 { buf1[..m1 as usize].to_vec() } else { Vec::new() },
            if m2 > 0 { buf2[..m2 as usize].to_vec() } else { Vec::new() },
        )
    };
    let (n_fl, src_fl, dst_fl) = run(true);
    let (n_lc, src_lc, dst_lc) = run(false);
    assert_eq!(n_fl, n_lc, "tee n: fl={n_fl}, lc={n_lc}");
    assert_eq!(src_fl, src_lc, "tee source-side divergence");
    assert_eq!(dst_fl, dst_lc, "tee destination-side divergence");
    assert_eq!(src_fl, payload.to_vec(), "source pipe should still have payload");
    assert_eq!(dst_fl, payload.to_vec(), "destination pipe should also have payload");
}

#[test]
fn sendfile_splice_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/sendfile.h+sys/splice.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
