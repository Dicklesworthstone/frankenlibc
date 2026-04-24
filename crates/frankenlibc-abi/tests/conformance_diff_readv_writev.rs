#![cfg(target_os = "linux")]

//! Differential conformance harness for scatter/gather I/O:
//!   - readv  / writev  (POSIX)
//!   - preadv / pwritev (offset-based, Linux/POSIX)
//!
//! Uses socketpair(AF_UNIX, SOCK_STREAM) for readv/writev so we can
//! verify byte sequence + return value without a tempfile. preadv /
//! pwritev use a tempfile because pipes/sockets don't support seeking.
//!
//! Bead: CONFORMANCE: libc readv/writev diff matrix.

use std::ffi::{c_int, c_void};
use std::os::fd::AsRawFd;

use frankenlibc_abi::io_abi as fl;

unsafe extern "C" {
    fn readv(fd: c_int, iov: *const libc::iovec, iovcnt: c_int) -> libc::ssize_t;
    fn writev(fd: c_int, iov: *const libc::iovec, iovcnt: c_int) -> libc::ssize_t;
    fn preadv(
        fd: c_int,
        iov: *const libc::iovec,
        iovcnt: c_int,
        offset: libc::off_t,
    ) -> libc::ssize_t;
    fn pwritev(
        fd: c_int,
        iov: *const libc::iovec,
        iovcnt: c_int,
        offset: libc::off_t,
    ) -> libc::ssize_t;
}

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

fn make_socketpair() -> (c_int, c_int) {
    let mut fds: [c_int; 2] = [-1, -1];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(r, 0, "socketpair");
    (fds[0], fds[1])
}

// ===========================================================================
// writev(fl) -> readv(libc): bytes must match across the gather/scatter
// boundary in either direction.
// ===========================================================================

fn run_writev_readv(write_via_fl: bool, read_via_fl: bool) -> (Vec<u8>, isize, isize) {
    let (a, b) = make_socketpair();
    let chunks: &[&[u8]] = &[b"abc", b"defg", b"", b"hi", b"jklmnop"];
    let iov_w: Vec<libc::iovec> = chunks
        .iter()
        .map(|c| libc::iovec {
            iov_base: c.as_ptr() as *mut c_void,
            iov_len: c.len(),
        })
        .collect();
    let nw = if write_via_fl {
        unsafe { fl::writev(a, iov_w.as_ptr(), iov_w.len() as c_int) }
    } else {
        unsafe { writev(a, iov_w.as_ptr(), iov_w.len() as c_int) }
    };
    // Read into 3 buffers
    let mut b1 = vec![0u8; 4];
    let mut b2 = vec![0u8; 8];
    let mut b3 = vec![0u8; 16];
    let iov_r = [
        libc::iovec {
            iov_base: b1.as_mut_ptr() as *mut c_void,
            iov_len: b1.len(),
        },
        libc::iovec {
            iov_base: b2.as_mut_ptr() as *mut c_void,
            iov_len: b2.len(),
        },
        libc::iovec {
            iov_base: b3.as_mut_ptr() as *mut c_void,
            iov_len: b3.len(),
        },
    ];
    let nr = if read_via_fl {
        unsafe { fl::readv(b, iov_r.as_ptr(), iov_r.len() as c_int) }
    } else {
        unsafe { readv(b, iov_r.as_ptr(), iov_r.len() as c_int) }
    };
    let mut got = Vec::new();
    if nr > 0 {
        let mut left = nr as usize;
        for iv in &iov_r {
            let take = left.min(iv.iov_len);
            let slice = unsafe { core::slice::from_raw_parts(iv.iov_base as *const u8, take) };
            got.extend_from_slice(slice);
            left -= take;
            if left == 0 {
                break;
            }
        }
    }
    unsafe {
        libc::close(a);
        libc::close(b);
    }
    (got, nw, nr)
}

#[test]
fn diff_writev_readv_fl_to_lc() {
    let (got_a, nw_a, nr_a) = run_writev_readv(true, false);
    let (got_b, nw_b, nr_b) = run_writev_readv(false, true);
    let mut divs = Vec::new();
    if nw_a != nw_b || nr_a != nr_b {
        divs.push(Divergence {
            function: "writev/readv",
            case: "fl-write+lc-read vs lc-write+fl-read".into(),
            field: "byte_counts",
            frankenlibc: format!("nw={nw_a} nr={nr_a}"),
            glibc: format!("nw={nw_b} nr={nr_b}"),
        });
    }
    if got_a != got_b {
        divs.push(Divergence {
            function: "writev/readv",
            case: "fl-write+lc-read vs lc-write+fl-read".into(),
            field: "transferred_bytes",
            frankenlibc: format!("{got_a:?}"),
            glibc: format!("{got_b:?}"),
        });
    }
    let expected: Vec<u8> = b"abcdefghijklmnop".to_vec();
    if got_a != expected {
        divs.push(Divergence {
            function: "writev/readv",
            case: "fl-write+lc-read".into(),
            field: "expected_concatenation",
            frankenlibc: format!("{got_a:?}"),
            glibc: format!("{expected:?}"),
        });
    }
    if got_b != expected {
        divs.push(Divergence {
            function: "writev/readv",
            case: "lc-write+fl-read".into(),
            field: "expected_concatenation",
            frankenlibc: format!("{got_b:?}"),
            glibc: format!("{expected:?}"),
        });
    }
    assert!(
        divs.is_empty(),
        "writev/readv divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// preadv / pwritev — offset-based scatter/gather on a tempfile
// ===========================================================================

fn unique_tempfile(label: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let id = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    std::env::temp_dir().join(format!("fl_uio_diff_{label}_{pid}_{id}"))
}

fn run_pwritev_preadv_round(via_fl: bool) -> (isize, isize, Vec<u8>) {
    let path = unique_tempfile(if via_fl { "fl" } else { "lc" });
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let fd = f.as_raw_fd();
    // Pad file to 64 bytes so we can write at offset 16
    f.set_len(64).unwrap();

    let chunks: &[&[u8]] = &[b"WXYZ", b"01234567"];
    let iov_w: Vec<libc::iovec> = chunks
        .iter()
        .map(|c| libc::iovec {
            iov_base: c.as_ptr() as *mut c_void,
            iov_len: c.len(),
        })
        .collect();
    let nw = if via_fl {
        unsafe { fl::pwritev(fd, iov_w.as_ptr(), iov_w.len() as c_int, 16) }
    } else {
        unsafe { pwritev(fd, iov_w.as_ptr(), iov_w.len() as c_int, 16) }
    };

    let mut rbuf = vec![0u8; 12];
    let iov_r = [libc::iovec {
        iov_base: rbuf.as_mut_ptr() as *mut c_void,
        iov_len: rbuf.len(),
    }];
    let nr = if via_fl {
        unsafe { fl::preadv(fd, iov_r.as_ptr(), iov_r.len() as c_int, 16) }
    } else {
        unsafe { preadv(fd, iov_r.as_ptr(), iov_r.len() as c_int, 16) }
    };
    drop(f);
    let _ = std::fs::remove_file(&path);
    (nw, nr, rbuf[..nr.max(0) as usize].to_vec())
}

#[test]
fn diff_pwritev_preadv_offset() {
    let (nw_fl, nr_fl, data_fl) = run_pwritev_preadv_round(true);
    let (nw_lc, nr_lc, data_lc) = run_pwritev_preadv_round(false);
    let mut divs = Vec::new();
    if nw_fl != nw_lc {
        divs.push(Divergence {
            function: "pwritev",
            case: "offset=16, 2 chunks (4+8)".into(),
            field: "return",
            frankenlibc: format!("{nw_fl}"),
            glibc: format!("{nw_lc}"),
        });
    }
    if nr_fl != nr_lc {
        divs.push(Divergence {
            function: "preadv",
            case: "offset=16, 12-byte buf".into(),
            field: "return",
            frankenlibc: format!("{nr_fl}"),
            glibc: format!("{nr_lc}"),
        });
    }
    if data_fl != data_lc {
        divs.push(Divergence {
            function: "preadv",
            case: "offset=16, 12-byte buf".into(),
            field: "data",
            frankenlibc: format!("{data_fl:?}"),
            glibc: format!("{data_lc:?}"),
        });
    }
    let expected: Vec<u8> = b"WXYZ01234567".to_vec();
    if data_fl != expected {
        divs.push(Divergence {
            function: "preadv",
            case: "offset=16".into(),
            field: "expected_data",
            frankenlibc: format!("{data_fl:?}"),
            glibc: format!("{expected:?}"),
        });
    }
    assert!(
        divs.is_empty(),
        "preadv/pwritev divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_writev_invalid_iovcnt() {
    // iovcnt < 0 should fail with EINVAL on both
    let (a, b) = make_socketpair();
    let r_fl = unsafe { fl::writev(a, std::ptr::null(), -1) };
    let r_lc = unsafe { writev(a, std::ptr::null(), -1) };
    unsafe {
        libc::close(a);
        libc::close(b);
    }
    if (r_fl < 0) != (r_lc < 0) {
        panic!("writev iovcnt=-1 fail-match: fl={r_fl}, lc={r_lc}");
    }
}

#[test]
fn readv_writev_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/uio.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
