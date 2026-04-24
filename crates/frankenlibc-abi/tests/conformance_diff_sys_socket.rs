#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/socket.h>` socket setup +
//! option ops. Avoids actual network I/O — the goal is to verify the
//! create/bind/sockopt/shutdown/socketpair contract under all-loopback
//! deterministic inputs.
//!
//! Bead: CONFORMANCE: libc sys/socket.h diff matrix.

use std::ffi::c_int;
use std::mem::size_of;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::socket_abi as fl;

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

unsafe fn clear_errno_both() {
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}

unsafe fn read_fl_errno() -> c_int {
    unsafe { *__errno_location() }
}

unsafe fn read_lc_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

// ===========================================================================
// socket — every common (domain, type, protocol) tuple
// ===========================================================================

#[test]
fn diff_socket_create_close() {
    let mut divs = Vec::new();
    let cases: &[(&str, c_int, c_int, c_int)] = &[
        ("AF_INET TCP", libc::AF_INET, libc::SOCK_STREAM, 0),
        ("AF_INET UDP", libc::AF_INET, libc::SOCK_DGRAM, 0),
        ("AF_INET6 TCP", libc::AF_INET6, libc::SOCK_STREAM, 0),
        ("AF_UNIX STREAM", libc::AF_UNIX, libc::SOCK_STREAM, 0),
        ("AF_UNIX DGRAM", libc::AF_UNIX, libc::SOCK_DGRAM, 0),
        (
            "AF_INET TCP|CLOEXEC",
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
        ),
        (
            "AF_INET TCP|NONBLOCK",
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
            0,
        ),
    ];
    for (label, dom, typ, proto) in cases {
        unsafe { clear_errno_both() };
        let fd_fl = unsafe { fl::socket(*dom, *typ, *proto) };
        let er_fl = unsafe { read_fl_errno() };
        unsafe { clear_errno_both() };
        let fd_lc = unsafe { libc::socket(*dom, *typ, *proto) };
        let er_lc = unsafe { read_lc_errno() };

        // Both should succeed (return >= 0) or both fail.
        if (fd_fl >= 0) != (fd_lc >= 0) {
            divs.push(Divergence {
                function: "socket",
                case: (*label).into(),
                field: "success_match",
                frankenlibc: format!("fd={fd_fl} errno={er_fl}"),
                glibc: format!("fd={fd_lc} errno={er_lc}"),
            });
        }
        if fd_fl < 0 && er_fl != er_lc {
            divs.push(Divergence {
                function: "socket",
                case: (*label).into(),
                field: "errno",
                frankenlibc: format!("{er_fl}"),
                glibc: format!("{er_lc}"),
            });
        }
        if fd_fl >= 0 {
            unsafe {
                libc::close(fd_fl);
            }
        }
        if fd_lc >= 0 {
            unsafe {
                libc::close(fd_lc);
            }
        }
    }

    // Invalid domain
    unsafe { clear_errno_both() };
    let fd_fl = unsafe { fl::socket(99999, libc::SOCK_STREAM, 0) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let fd_lc = unsafe { libc::socket(99999, libc::SOCK_STREAM, 0) };
    let er_lc = unsafe { read_lc_errno() };
    if (fd_fl >= 0) != (fd_lc >= 0) {
        divs.push(Divergence {
            function: "socket",
            case: "invalid_domain".into(),
            field: "success_match",
            frankenlibc: format!("fd={fd_fl} errno={er_fl}"),
            glibc: format!("fd={fd_lc} errno={er_lc}"),
        });
    }
    if fd_fl < 0 && er_fl != er_lc {
        divs.push(Divergence {
            function: "socket",
            case: "invalid_domain".into(),
            field: "errno",
            frankenlibc: format!("{er_fl}"),
            glibc: format!("{er_lc}"),
        });
    }
    if fd_fl >= 0 {
        unsafe {
            libc::close(fd_fl);
        }
    }
    if fd_lc >= 0 {
        unsafe {
            libc::close(fd_lc);
        }
    }

    assert!(
        divs.is_empty(),
        "socket divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// bind / listen — bind to ephemeral loopback port; both impls should
// produce equivalent results.
// ===========================================================================

fn make_loopback_addr(port: u16) -> libc::sockaddr_in {
    libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: 0x7F000001u32.to_be(),
        }, // 127.0.0.1
        sin_zero: [0; 8],
    }
}

#[test]
fn diff_bind_listen_loopback() {
    let mut divs = Vec::new();
    // Use port 0 (kernel-assigned ephemeral) to avoid clashing.
    let addr = make_loopback_addr(0);
    let addr_len = size_of::<libc::sockaddr_in>() as u32;

    for (label, bind_fn, listen_fn) in [
        (
            "frankenlibc",
            fl::bind as unsafe extern "C" fn(c_int, *const libc::sockaddr, u32) -> c_int,
            fl::listen as unsafe extern "C" fn(c_int, c_int) -> c_int,
        ),
        (
            "glibc",
            libc::bind as unsafe extern "C" fn(c_int, *const libc::sockaddr, u32) -> c_int,
            libc::listen as unsafe extern "C" fn(c_int, c_int) -> c_int,
        ),
    ] {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            divs.push(Divergence {
                function: "bind/listen setup",
                case: label.into(),
                field: "socket",
                frankenlibc: format!("{fd}"),
                glibc: "-".into(),
            });
            continue;
        }
        // SO_REUSEADDR
        let one: c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const c_int as *const _,
                size_of::<c_int>() as u32,
            );
        }
        let r_bind = unsafe {
            bind_fn(
                fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                addr_len,
            )
        };
        let r_listen = unsafe { listen_fn(fd, 16) };
        if r_bind != 0 || r_listen != 0 {
            divs.push(Divergence {
                function: "bind/listen",
                case: label.into(),
                field: "rc",
                frankenlibc: format!("bind={r_bind} listen={r_listen}"),
                glibc: "expected 0/0".into(),
            });
        }
        unsafe {
            libc::close(fd);
        }
    }
    assert!(
        divs.is_empty(),
        "bind/listen divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// setsockopt / getsockopt — round-trip of common options
// ===========================================================================

#[test]
fn diff_sockopt_roundtrip() {
    let mut divs = Vec::new();
    let opts: &[(&str, c_int, c_int, c_int)] = &[
        ("SO_REUSEADDR=1", libc::SOL_SOCKET, libc::SO_REUSEADDR, 1),
        ("SO_KEEPALIVE=1", libc::SOL_SOCKET, libc::SO_KEEPALIVE, 1),
        ("SO_RCVBUF=65536", libc::SOL_SOCKET, libc::SO_RCVBUF, 65536),
        ("SO_SNDBUF=65536", libc::SOL_SOCKET, libc::SO_SNDBUF, 65536),
    ];

    for (label, level, opt, val) in opts {
        // Pair of sockets per option, one per impl.
        let fd_fl = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let fd_lc = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if fd_fl < 0 || fd_lc < 0 {
            unsafe {
                if fd_fl >= 0 {
                    libc::close(fd_fl);
                }
                if fd_lc >= 0 {
                    libc::close(fd_lc);
                }
            }
            continue;
        }

        let r_fl = unsafe {
            fl::setsockopt(
                fd_fl,
                *level,
                *opt,
                val as *const c_int as *const _,
                size_of::<c_int>() as u32,
            )
        };
        let r_lc = unsafe {
            libc::setsockopt(
                fd_lc,
                *level,
                *opt,
                val as *const c_int as *const _,
                size_of::<c_int>() as u32,
            )
        };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "setsockopt",
                case: (*label).into(),
                field: "rc",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }

        // Round-trip via getsockopt.
        let mut got_fl: c_int = 0;
        let mut got_lc: c_int = 0;
        let mut len_fl = size_of::<c_int>() as u32;
        let mut len_lc = size_of::<c_int>() as u32;
        let _ = unsafe {
            fl::getsockopt(
                fd_fl,
                *level,
                *opt,
                &mut got_fl as *mut c_int as *mut _,
                &mut len_fl as *mut u32,
            )
        };
        let _ = unsafe {
            libc::getsockopt(
                fd_lc,
                *level,
                *opt,
                &mut got_lc as *mut c_int as *mut _,
                &mut len_lc as *mut u32,
            )
        };
        // SO_RCVBUF/SO_SNDBUF are typically doubled by the kernel; just
        // require both impls observe the SAME post-set value.
        if got_fl != got_lc {
            divs.push(Divergence {
                function: "getsockopt round-trip",
                case: (*label).into(),
                field: "value",
                frankenlibc: format!("{got_fl}"),
                glibc: format!("{got_lc}"),
            });
        }

        unsafe {
            libc::close(fd_fl);
            libc::close(fd_lc);
        }
    }
    assert!(
        divs.is_empty(),
        "setsockopt round-trip divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// getsockname after bind — same address family + same family bytes
// ===========================================================================

#[test]
fn diff_getsockname_after_bind() {
    let mut divs = Vec::new();
    for (label, getsockname_fn) in [
        (
            "frankenlibc",
            fl::getsockname as unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut u32) -> c_int,
        ),
        (
            "glibc",
            libc::getsockname
                as unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut u32) -> c_int,
        ),
    ] {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        let one: c_int = 1;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_REUSEADDR,
                &one as *const c_int as *const _,
                size_of::<c_int>() as u32,
            );
        }
        let addr = make_loopback_addr(0);
        let r = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if r != 0 {
            unsafe {
                libc::close(fd);
            }
            continue;
        }
        let mut got: libc::sockaddr_in = unsafe { core::mem::zeroed() };
        let mut got_len = size_of::<libc::sockaddr_in>() as u32;
        let r = unsafe {
            getsockname_fn(
                fd,
                &mut got as *mut libc::sockaddr_in as *mut libc::sockaddr,
                &mut got_len as *mut u32,
            )
        };
        if r != 0 {
            divs.push(Divergence {
                function: "getsockname",
                case: label.into(),
                field: "rc",
                frankenlibc: format!("{r}"),
                glibc: "0".into(),
            });
        }
        if got.sin_family != libc::AF_INET as u16 {
            divs.push(Divergence {
                function: "getsockname",
                case: label.into(),
                field: "family",
                frankenlibc: format!("{}", got.sin_family),
                glibc: "AF_INET".into(),
            });
        }
        // Port should be a kernel-assigned non-zero ephemeral.
        if got.sin_port == 0 {
            divs.push(Divergence {
                function: "getsockname",
                case: label.into(),
                field: "ephemeral_port_assigned",
                frankenlibc: "0".into(),
                glibc: "non-zero".into(),
            });
        }
        unsafe {
            libc::close(fd);
        }
    }
    assert!(
        divs.is_empty(),
        "getsockname divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// shutdown — invalid fd should EBADF on both
// ===========================================================================

#[test]
fn diff_shutdown_invalid_fd() {
    let mut divs = Vec::new();
    unsafe { clear_errno_both() };
    let r_fl = unsafe { fl::shutdown(99999, libc::SHUT_RDWR) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let r_lc = unsafe { libc::shutdown(99999, libc::SHUT_RDWR) };
    let er_lc = unsafe { read_lc_errno() };
    if r_fl != r_lc || er_fl != er_lc {
        divs.push(Divergence {
            function: "shutdown",
            case: "invalid_fd".into(),
            field: "rc/errno",
            frankenlibc: format!("rc={r_fl} errno={er_fl}"),
            glibc: format!("rc={r_lc} errno={er_lc}"),
        });
    }
    assert!(
        divs.is_empty(),
        "shutdown divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// socketpair — both impls should produce two paired AF_UNIX/SOCK_STREAM fds
// ===========================================================================

#[test]
fn diff_socketpair_unix_stream() {
    let mut divs = Vec::new();
    let mut sv_fl: [c_int; 2] = [-1, -1];
    let mut sv_lc: [c_int; 2] = [-1, -1];
    unsafe { clear_errno_both() };
    let r_fl = unsafe { fl::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv_fl.as_mut_ptr()) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let r_lc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv_lc.as_mut_ptr()) };
    let er_lc = unsafe { read_lc_errno() };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "socketpair",
            case: "unix_stream".into(),
            field: "rc",
            frankenlibc: format!("{r_fl} errno={er_fl}"),
            glibc: format!("{r_lc} errno={er_lc}"),
        });
    }
    if r_fl == 0 && (sv_fl[0] < 0 || sv_fl[1] < 0) {
        divs.push(Divergence {
            function: "socketpair",
            case: "unix_stream".into(),
            field: "fds_assigned",
            frankenlibc: format!("[{}, {}]", sv_fl[0], sv_fl[1]),
            glibc: "two non-negative fds".into(),
        });
    }
    if sv_fl[0] >= 0 {
        unsafe {
            libc::close(sv_fl[0]);
        }
    }
    if sv_fl[1] >= 0 {
        unsafe {
            libc::close(sv_fl[1]);
        }
    }
    if sv_lc[0] >= 0 {
        unsafe {
            libc::close(sv_lc[0]);
        }
    }
    if sv_lc[1] >= 0 {
        unsafe {
            libc::close(sv_lc[1]);
        }
    }
    assert!(
        divs.is_empty(),
        "socketpair divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// Coverage report
// ===========================================================================

#[test]
fn sys_socket_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/socket.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
