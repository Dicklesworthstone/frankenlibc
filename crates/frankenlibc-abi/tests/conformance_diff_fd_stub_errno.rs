#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-differential calls on deliberately invalid fds

//! An fd-taking stub must reject a bad descriptor the way glibc does, not with
//! `ENOSYS`.
//!
//! ## Why this exists
//!
//! `fchflags` was fixed to return `EINVAL` for a negative fd before falling
//! through to `ENOSYS` (bd-5r3gxb), and the obvious question is how many of its
//! siblings have the same shape. A scan for fd-taking functions that mention
//! `ENOSYS` found nine that never look at the fd — but a scan is not evidence:
//! it matched `lockf`, which is fully implemented, because the crude
//! function-range heuristic ran past the end of the body.
//!
//! So this gate asks the HOST instead. Each function below is called with fd
//! `-1` on both implementations and the `(return value, errno)` pair is
//! compared. A live probe of glibc 2.42 showed the answers are NOT uniform —
//! `fchflags`, `gtty` and `stty` report `EINVAL` while `pwritev2` and `lockf`
//! report `EBADF` — so "validate the fd first" is not one rule, it is per
//! function, and only the host can say which.
//!
//! ## Functions glibc does not export
//!
//! `fattach`, `getmsg`, `getpmsg`, `putmsg` and `putpmsg` are absent from host
//! glibc 2.42 entirely (STREAMS was removed). fl exports them, which is a
//! superset rather than a divergence, and there is no oracle to compare against
//! — so they are deliberately NOT in this table, and that absence is recorded
//! here rather than left to be rediscovered.

use std::ffi::{CStr, c_char, c_int, c_long, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr_optional;

/// `(return value, errno)` for one call — the whole observable contract of a
/// failing stub.
#[derive(Debug, PartialEq, Eq)]
struct Outcome {
    rc: i64,
    errno: c_int,
}

fn errno_now() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default()
}

fn clear_errno() {
    // SAFETY: writing the thread's own errno slot through libc's accessor.
    unsafe { *libc::__errno_location() = 0 };
}

/// Call a `fn(c_int, c_ulong) -> c_int` shape with fd = -1.
fn call_fd_ulong(f: usize) -> Outcome {
    // SAFETY: the caller passes an address whose C signature is this shape.
    let f: unsafe extern "C" fn(c_int, libc::c_ulong) -> c_int = unsafe { std::mem::transmute(f) };
    clear_errno();
    // SAFETY: fd -1 is invalid by construction; no memory is dereferenced.
    let rc = unsafe { f(-1, 0) };
    Outcome {
        rc: rc as i64,
        errno: errno_now(),
    }
}

/// Call a `fn(c_int, *mut c_void) -> c_int` shape with fd = -1 and a REAL
/// buffer.
///
/// Both shapes are needed and one would have been a trap: `gtty`/`stty` answer
/// EINVAL for a NULL params pointer and ENOSYS for a valid one, so a table that
/// only passed NULL would pin half the contract and a table that only passed a
/// buffer would have shown fl already correct.
fn call_fd_buf(f: usize) -> Outcome {
    // SAFETY: the caller passes an address whose C signature is this shape.
    let f: unsafe extern "C" fn(c_int, *mut c_void) -> c_int = unsafe { std::mem::transmute(f) };
    let mut buf = [0u8; 64];
    clear_errno();
    // SAFETY: fd -1 is invalid; neither implementation writes through the
    // pointer before failing, and the buffer outlives the call regardless.
    let rc = unsafe { f(-1, buf.as_mut_ptr().cast()) };
    Outcome {
        rc: rc as i64,
        errno: errno_now(),
    }
}

/// Call a `fn(c_int, *mut c_void) -> c_int` shape with fd = -1 and a NULL arg.
fn call_fd_ptr(f: usize) -> Outcome {
    // SAFETY: the caller passes an address whose C signature is this shape.
    let f: unsafe extern "C" fn(c_int, *mut c_void) -> c_int = unsafe { std::mem::transmute(f) };
    clear_errno();
    // SAFETY: fd -1 is rejected before the pointer is read on both
    // implementations — which is precisely the property under test, so a
    // divergence here shows up as a differing errno rather than a crash.
    let rc = unsafe { f(-1, std::ptr::null_mut()) };
    Outcome {
        rc: rc as i64,
        errno: errno_now(),
    }
}

/// Call `lockf(fd, cmd, len)` with fd = -1.
fn call_lockf(f: usize) -> Outcome {
    // SAFETY: the caller passes `lockf`'s address.
    let f: unsafe extern "C" fn(c_int, c_int, libc::off_t) -> c_int = unsafe { std::mem::transmute(f) };
    clear_errno();
    // SAFETY: fd -1 is invalid; F_ULOCK on it touches no memory.
    let rc = unsafe { f(-1, 0, 0) };
    Outcome {
        rc: rc as i64,
        errno: errno_now(),
    }
}

/// Call `pwritev2(fd, iov, iovcnt, offset, flags)` with fd = -1.
fn call_pwritev2(f: usize) -> Outcome {
    // SAFETY: the caller passes a `pwritev2`-shaped address.
    let f: unsafe extern "C" fn(c_int, *const c_void, c_int, libc::off_t, c_int) -> isize =
        unsafe { std::mem::transmute(f) };
    clear_errno();
    // SAFETY: fd -1 with a zero-length iovec array; no memory is read.
    let rc = unsafe { f(-1, std::ptr::null(), 0, 0, 0) };
    Outcome {
        rc: rc as i64,
        errno: errno_now(),
    }
}

fn probe(name: &CStr, fl: *const (), call: fn(usize) -> Outcome) -> Option<(Outcome, Outcome)> {
    // SAFETY: `name` is NUL-terminated; the helper only resolves an address.
    let host = unsafe { host_addr_optional(name, fl) }?;
    let host_out = call(host as usize);
    let fl_out = call(fl as usize);
    Some((host_out, fl_out))
}

/// The whole iovec family: a zero count is a SUCCESSFUL no-op, and the fd is
/// checked first.
///
/// fl answered `EINVAL` to both questions for all six functions. The bad-fd case
/// is errno cosmetics; the zero-count case is not — a caller looping over
/// batches that can be empty saw `-1` where every other libc returns `0`, and
/// the return value, not just errno, was wrong.
#[test]
fn iovec_calls_treat_a_zero_count_the_way_glibc_does() {
    use std::os::unix::io::AsRawFd;

    let dir = std::env::temp_dir().join("fl_iovec_zero_count");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dir.join("probe"))
        .expect("open probe file");
    let good = file.as_raw_fd();

    // Three shapes: (fd, iov, iovcnt) plus an offset, plus an offset and flags.
    type V3 = unsafe extern "C" fn(c_int, *const c_void, c_int) -> isize;
    type V4 = unsafe extern "C" fn(c_int, *const c_void, c_int, libc::off_t) -> isize;
    type V5 = unsafe extern "C" fn(c_int, *const c_void, c_int, libc::off_t, c_int) -> isize;

    let call3 = |f: usize, fd: c_int| -> Outcome {
        // SAFETY: the address is a `readv`/`writev`-shaped symbol; a zero count
        // means the NULL vector is never read.
        let f: V3 = unsafe { std::mem::transmute(f) };
        clear_errno();
        let rc = unsafe { f(fd, std::ptr::null(), 0) };
        Outcome { rc: rc as i64, errno: errno_now() }
    };
    let call4 = |f: usize, fd: c_int| -> Outcome {
        // SAFETY: as above, with an offset argument.
        let f: V4 = unsafe { std::mem::transmute(f) };
        clear_errno();
        let rc = unsafe { f(fd, std::ptr::null(), 0, 0) };
        Outcome { rc: rc as i64, errno: errno_now() }
    };
    let call5 = |f: usize, fd: c_int| -> Outcome {
        // SAFETY: as above, with offset and flags.
        let f: V5 = unsafe { std::mem::transmute(f) };
        clear_errno();
        let rc = unsafe { f(fd, std::ptr::null(), 0, 0, 0) };
        Outcome { rc: rc as i64, errno: errno_now() }
    };

    #[allow(clippy::type_complexity)]
    let cases: &[(&CStr, *const (), u8)] = &[
        (c"readv", frankenlibc_abi::io_abi::readv as *const (), 3),
        (c"writev", frankenlibc_abi::io_abi::writev as *const (), 3),
        (c"preadv", frankenlibc_abi::io_abi::preadv as *const (), 4),
        (c"pwritev", frankenlibc_abi::io_abi::pwritev as *const (), 4),
        (c"preadv2", frankenlibc_abi::io_abi::preadv2 as *const (), 5),
        (c"pwritev2", frankenlibc_abi::io_abi::pwritev2 as *const (), 5),
    ];

    let mut compared = 0usize;
    for (name, fl, shape) in cases {
        let label = name.to_str().expect("ASCII symbol name");
        // SAFETY: NUL-terminated name paired with fl's own definition.
        let Some(host) = (unsafe { host_addr_optional(name, *fl) }) else {
            continue;
        };
        for (what, fd) in [("bad fd", -1_i32), ("good fd", good)] {
            let (h, m) = match shape {
                3 => (call3(host as usize, fd), call3(*fl as usize, fd)),
                4 => (call4(host as usize, fd), call4(*fl as usize, fd)),
                _ => (call5(host as usize, fd), call5(*fl as usize, fd)),
            };
            println!("{label} {what}: host {h:?}  fl {m:?}");
            assert_eq!(
                m, h,
                "{label}({what}, NULL, 0) produced {m:?}, host glibc produced {h:?}"
            );
            compared += 1;
        }
    }
    assert_eq!(
        compared,
        cases.len() * 2,
        "only {compared} of {} comparisons ran; the host arms must all resolve",
        cases.len() * 2
    );
    println!("compared {compared} iovec zero-count contracts");
}

#[test]
fn fd_taking_stubs_reject_a_bad_descriptor_the_way_glibc_does() {
    let mut compared = 0usize;
    let mut skipped: Vec<&str> = Vec::new();

    let cases: &[(&CStr, *const (), fn(usize) -> Outcome)] = &[
        (
            c"fchflags",
            frankenlibc_abi::glibc_internal_abi::fchflags as *const (),
            call_fd_ulong as fn(usize) -> Outcome,
        ),
        (
            c"gtty",
            frankenlibc_abi::glibc_internal_abi::gtty as *const (),
            call_fd_ptr as fn(usize) -> Outcome,
        ),
        (
            c"stty",
            frankenlibc_abi::glibc_internal_abi::stty as *const (),
            call_fd_ptr as fn(usize) -> Outcome,
        ),
        (
            c"gtty",
            frankenlibc_abi::glibc_internal_abi::gtty as *const (),
            call_fd_buf as fn(usize) -> Outcome,
        ),
        (
            c"stty",
            frankenlibc_abi::glibc_internal_abi::stty as *const (),
            call_fd_buf as fn(usize) -> Outcome,
        ),
        (
            c"lockf",
            frankenlibc_abi::unistd_abi::lockf as *const (),
            call_lockf as fn(usize) -> Outcome,
        ),
        (
            c"pwritev2",
            frankenlibc_abi::io_abi::pwritev2 as *const (),
            call_pwritev2 as fn(usize) -> Outcome,
        ),
    ];

    for (name, fl, call) in cases {
        let label = name.to_str().expect("ASCII symbol name");
        match probe(name, *fl, *call) {
            None => skipped.push(label),
            Some((host, mine)) => {
                println!("{label}: host {host:?}  fl {mine:?}");
                assert_eq!(
                    mine, host,
                    "{label}(-1, ...) produced {mine:?}, host glibc produced {host:?}. \
                     An fd-taking stub must reject a bad descriptor the way glibc does; \
                     ENOSYS for an invalid fd is a divergence a caller can see."
                );
                compared += 1;
            }
        }
    }

    // Assert the positive fact. A run where every symbol failed to resolve would
    // otherwise pass silently, which is the shape of four green-because-nothing-ran
    // mechanisms this repo has already found.
    assert!(
        compared >= 5,
        "only {compared} of {} symbols were compared (skipped: {skipped:?}); this gate \
         proves nothing if the host arms did not resolve",
        cases.len()
    );
    println!("compared {compared} fd-stub errno contracts; skipped {skipped:?}");
}
