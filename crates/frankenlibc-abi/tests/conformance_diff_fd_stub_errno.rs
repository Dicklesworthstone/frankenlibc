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

use std::ffi::{CStr, c_int, c_void};

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

type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

fn glibc_errno_slot() -> *mut c_int {
    // SAFETY: the resolved address is glibc's `__errno_location`; fl's own
    // export is the collapse guard, so a self-comparison aborts loudly.
    unsafe {
        let addr = dlsym_oracle::host_addr(
            c"__errno_location",
            frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn as *const (),
        );
        core::mem::transmute::<*mut c_void, ErrnoLocationFn>(addr)()
    }
}

fn fl_errno_slot() -> *mut c_int {
    unsafe { frankenlibc_abi::errno_abi::__errno_location() }
}

/// Call a `fn(c_int, c_ulong) -> c_int` shape with fd = -1.
fn call_fd_ulong(f: usize, slot: *mut c_int) -> Outcome {
    // SAFETY: the caller passes an address whose C signature is this shape.
    let f: unsafe extern "C" fn(c_int, libc::c_ulong) -> c_int = unsafe { std::mem::transmute(f) };
    unsafe { *slot = 0 };
    // SAFETY: fd -1 is invalid by construction; no memory is dereferenced.
    let rc = unsafe { f(-1, 0) };
    Outcome {
        rc: rc as i64,
        errno: unsafe { *slot },
    }
}

/// Call a `fn(c_int, *mut c_void) -> c_int` shape with fd = -1 and a REAL
/// buffer.
///
/// Both shapes are needed and one would have been a trap: `gtty`/`stty` answer
/// EINVAL for a NULL params pointer and ENOSYS for a valid one, so a table that
/// only passed NULL would pin half the contract and a table that only passed a
/// buffer would have shown fl already correct.
fn call_fd_buf(f: usize, slot: *mut c_int) -> Outcome {
    // SAFETY: the caller passes an address whose C signature is this shape.
    let f: unsafe extern "C" fn(c_int, *mut c_void) -> c_int = unsafe { std::mem::transmute(f) };
    let mut buf = [0u8; 64];
    unsafe { *slot = 0 };
    // SAFETY: fd -1 is invalid; neither implementation writes through the
    // pointer before failing, and the buffer outlives the call regardless.
    let rc = unsafe { f(-1, buf.as_mut_ptr().cast()) };
    Outcome {
        rc: rc as i64,
        errno: unsafe { *slot },
    }
}

/// Call a `fn(c_int, *mut c_void) -> c_int` shape with fd = -1 and a NULL arg.
fn call_fd_ptr(f: usize, slot: *mut c_int) -> Outcome {
    // SAFETY: the caller passes an address whose C signature is this shape.
    let f: unsafe extern "C" fn(c_int, *mut c_void) -> c_int = unsafe { std::mem::transmute(f) };
    unsafe { *slot = 0 };
    // SAFETY: fd -1 is rejected before the pointer is read on both
    // implementations — which is precisely the property under test, so a
    // divergence here shows up as a differing errno rather than a crash.
    let rc = unsafe { f(-1, std::ptr::null_mut()) };
    Outcome {
        rc: rc as i64,
        errno: unsafe { *slot },
    }
}

/// Call `lockf(fd, cmd, len)` with fd = -1.
fn call_lockf(f: usize, slot: *mut c_int) -> Outcome {
    // SAFETY: the caller passes `lockf`'s address.
    let f: unsafe extern "C" fn(c_int, c_int, libc::off_t) -> c_int =
        unsafe { std::mem::transmute(f) };
    unsafe { *slot = 0 };
    // SAFETY: fd -1 is invalid; F_ULOCK on it touches no memory.
    let rc = unsafe { f(-1, 0, 0) };
    Outcome {
        rc: rc as i64,
        errno: unsafe { *slot },
    }
}

/// Call `pwritev2(fd, iov, iovcnt, offset, flags)` with fd = -1.
fn call_pwritev2(f: usize, slot: *mut c_int) -> Outcome {
    // SAFETY: the caller passes a `pwritev2`-shaped address.
    let f: unsafe extern "C" fn(c_int, *const c_void, c_int, libc::off_t, c_int) -> isize =
        unsafe { std::mem::transmute(f) };
    unsafe { *slot = 0 };
    // SAFETY: fd -1 with a zero-length iovec array; no memory is read.
    let rc = unsafe { f(-1, std::ptr::null(), 0, 0, 0) };
    Outcome {
        rc: rc as i64,
        errno: unsafe { *slot },
    }
}

fn probe(
    name: &CStr,
    fl: *const (),
    call: fn(usize, *mut c_int) -> Outcome,
) -> Option<(Outcome, Outcome)> {
    // SAFETY: `name` is NUL-terminated; the helper only resolves an address.
    let host = unsafe { host_addr_optional(name, fl) }?;
    let host_out = call(host as usize, glibc_errno_slot());
    let fl_out = call(fl as usize, fl_errno_slot());
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

    let call3 = |f: usize, fd: c_int, slot: *mut c_int| -> Outcome {
        // SAFETY: the address is a `readv`/`writev`-shaped symbol; a zero count
        // means the NULL vector is never read.
        let f: V3 = unsafe { std::mem::transmute(f) };
        unsafe { *slot = 0 };
        let rc = unsafe { f(fd, std::ptr::null(), 0) };
        Outcome {
            rc: rc as i64,
            errno: unsafe { *slot },
        }
    };
    let call4 = |f: usize, fd: c_int, slot: *mut c_int| -> Outcome {
        // SAFETY: as above, with an offset argument.
        let f: V4 = unsafe { std::mem::transmute(f) };
        unsafe { *slot = 0 };
        let rc = unsafe { f(fd, std::ptr::null(), 0, 0) };
        Outcome {
            rc: rc as i64,
            errno: unsafe { *slot },
        }
    };
    let call5 = |f: usize, fd: c_int, slot: *mut c_int| -> Outcome {
        // SAFETY: as above, with offset and flags.
        let f: V5 = unsafe { std::mem::transmute(f) };
        unsafe { *slot = 0 };
        let rc = unsafe { f(fd, std::ptr::null(), 0, 0, 0) };
        Outcome {
            rc: rc as i64,
            errno: unsafe { *slot },
        }
    };

    #[allow(clippy::type_complexity)]
    let cases: &[(&CStr, *const (), u8)] = &[
        (c"readv", frankenlibc_abi::io_abi::readv as *const (), 3),
        (c"writev", frankenlibc_abi::io_abi::writev as *const (), 3),
        (c"preadv", frankenlibc_abi::io_abi::preadv as *const (), 4),
        (c"pwritev", frankenlibc_abi::io_abi::pwritev as *const (), 4),
        (c"preadv2", frankenlibc_abi::io_abi::preadv2 as *const (), 5),
        (
            c"pwritev2",
            frankenlibc_abi::io_abi::pwritev2 as *const (),
            5,
        ),
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
                3 => (
                    call3(host as usize, fd, glibc_errno_slot()),
                    call3(*fl as usize, fd, fl_errno_slot()),
                ),
                4 => (
                    call4(host as usize, fd, glibc_errno_slot()),
                    call4(*fl as usize, fd, fl_errno_slot()),
                ),
                _ => (
                    call5(host as usize, fd, glibc_errno_slot()),
                    call5(*fl as usize, fd, fl_errno_slot()),
                ),
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

/// Boundary arguments across the fd family, compared against the host.
///
/// The zero-count iovec bug was found by asking the host what it does rather
/// than by reading fl, so this table does the same for the neighbouring
/// boundaries: a negative offset, a negative length, an invalid `whence`, an
/// `iovcnt` past `IOV_MAX`, and a bad fd on `ftruncate`/`dup2`. It also pins the
/// zero-length `read`/`write`/`pread`/`pwrite` contract, which fl already gets
/// right — that is exactly the property the iovec family got wrong, so a
/// regression there would otherwise be silent.
#[test]
fn boundary_arguments_match_the_host_across_the_fd_family() {
    use std::os::unix::io::AsRawFd;

    let dir = std::env::temp_dir().join("fl_fd_boundary");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(dir.join("probe"))
        .expect("open probe file");
    let good = file.as_raw_fd();
    let mut buf = [0u8; 64];
    let bufp = buf.as_mut_ptr().cast::<c_void>();

    type Rw = unsafe extern "C" fn(c_int, *mut c_void, usize) -> isize;
    type PRw = unsafe extern "C" fn(c_int, *mut c_void, usize, libc::off_t) -> isize;
    type Ftr = unsafe extern "C" fn(c_int, libc::off_t) -> c_int;
    type Lseek = unsafe extern "C" fn(c_int, libc::off_t, c_int) -> libc::off_t;
    type Rv = unsafe extern "C" fn(c_int, *const c_void, c_int) -> isize;
    type Dup2 = unsafe extern "C" fn(c_int, c_int) -> c_int;

    let mut compared = 0usize;
    macro_rules! compare {
        ($name:expr, $fl:expr, $ty:ty, $body:expr) => {{
            let name: &CStr = $name;
            let label = name.to_str().expect("ASCII symbol name");
            // SAFETY: NUL-terminated name paired with fl's own definition.
            if let Some(host) = unsafe { host_addr_optional(name, $fl) } {
                let run = |addr: usize, slot: *mut c_int| -> Outcome {
                    // SAFETY: the address has the C signature named by `$ty`,
                    // and every call below uses arguments the host was probed
                    // with, so neither implementation reads unmapped memory.
                    let f: $ty = unsafe { std::mem::transmute(addr) };
                    unsafe { *slot = 0 };
                    let rc = $body(f);
                    Outcome {
                        rc: rc as i64,
                        errno: unsafe { *slot },
                    }
                };
                let h = run(host as usize, glibc_errno_slot());
                let m = run($fl as usize, fl_errno_slot());
                println!("{label}: host {h:?}  fl {m:?}");
                assert_eq!(m, h, "{label} boundary case: fl {m:?}, host glibc {h:?}");
                compared += 1;
            }
        }};
    }

    // Zero length is a success on a good fd, for the scalar calls too.
    compare!(
        c"read",
        frankenlibc_abi::unistd_abi::read as *const (),
        Rw,
        |f: Rw| unsafe { f(good, bufp, 0) }
    );
    compare!(
        c"write",
        frankenlibc_abi::unistd_abi::write as *const (),
        Rw,
        |f: Rw| unsafe { f(good, bufp, 0) }
    );
    compare!(
        c"pread",
        frankenlibc_abi::io_abi::pread as *const (),
        PRw,
        |f: PRw| unsafe { f(good, bufp, 0, 0) }
    );
    compare!(
        c"pwrite",
        frankenlibc_abi::io_abi::pwrite as *const (),
        PRw,
        |f: PRw| unsafe { f(good, bufp, 0, 0) }
    );

    // A NEGATIVE offset is EINVAL, not a wrapped huge unsigned offset.
    compare!(
        c"pread",
        frankenlibc_abi::io_abi::pread as *const (),
        PRw,
        |f: PRw| unsafe { f(good, bufp, 8, -1) }
    );
    compare!(
        c"pwrite",
        frankenlibc_abi::io_abi::pwrite as *const (),
        PRw,
        |f: PRw| unsafe { f(good, bufp, 8, -1) }
    );

    // Negative length, and a bad fd, on ftruncate.
    compare!(
        c"ftruncate",
        frankenlibc_abi::unistd_abi::ftruncate as *const (),
        Ftr,
        |f: Ftr| unsafe { f(good, -1) }
    );
    compare!(
        c"ftruncate",
        frankenlibc_abi::unistd_abi::ftruncate as *const (),
        Ftr,
        |f: Ftr| unsafe { f(-1, 0) }
    );

    // Invalid whence, and a negative resulting offset.
    compare!(
        c"lseek",
        frankenlibc_abi::unistd_abi::lseek as *const (),
        Lseek,
        |f: Lseek| unsafe { f(good, 0, 99) }
    );
    compare!(
        c"lseek",
        frankenlibc_abi::unistd_abi::lseek as *const (),
        Lseek,
        |f: Lseek| unsafe { f(good, -1, libc::SEEK_SET) }
    );

    // iovcnt past IOV_MAX is EINVAL even though the vector is NULL.
    compare!(
        c"readv",
        frankenlibc_abi::io_abi::readv as *const (),
        Rv,
        |f: Rv| unsafe { f(good, std::ptr::null(), 2000) }
    );

    // A bad source fd on dup2.
    compare!(
        c"dup2",
        frankenlibc_abi::io_abi::dup2 as *const (),
        Dup2,
        |f: Dup2| unsafe { f(-1, 5) }
    );

    assert!(
        compared >= 10,
        "only {compared} boundary comparisons ran; the host arms must resolve for \
         this gate to mean anything"
    );
    println!("compared {compared} boundary contracts against the host");
}

#[test]
fn fd_taking_stubs_reject_a_bad_descriptor_the_way_glibc_does() {
    let mut compared = 0usize;
    let mut skipped: Vec<&str> = Vec::new();

    let cases: &[(&CStr, *const (), fn(usize, *mut c_int) -> Outcome)] = &[
        (
            c"fchflags",
            frankenlibc_abi::glibc_internal_abi::fchflags as *const (),
            call_fd_ulong as fn(usize, *mut c_int) -> Outcome,
        ),
        (
            c"gtty",
            frankenlibc_abi::glibc_internal_abi::gtty as *const (),
            call_fd_ptr as fn(usize, *mut c_int) -> Outcome,
        ),
        (
            c"stty",
            frankenlibc_abi::glibc_internal_abi::stty as *const (),
            call_fd_ptr as fn(usize, *mut c_int) -> Outcome,
        ),
        (
            c"gtty",
            frankenlibc_abi::glibc_internal_abi::gtty as *const (),
            call_fd_buf as fn(usize, *mut c_int) -> Outcome,
        ),
        (
            c"stty",
            frankenlibc_abi::glibc_internal_abi::stty as *const (),
            call_fd_buf as fn(usize, *mut c_int) -> Outcome,
        ),
        (
            c"lockf",
            frankenlibc_abi::unistd_abi::lockf as *const (),
            call_lockf as fn(usize, *mut c_int) -> Outcome,
        ),
        (
            c"pwritev2",
            frankenlibc_abi::io_abi::pwritev2 as *const (),
            call_pwritev2 as fn(usize, *mut c_int) -> Outcome,
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
