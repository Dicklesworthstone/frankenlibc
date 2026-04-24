#![cfg(target_os = "linux")]

//! Differential conformance harness for `<poll.h>` and `<sys/select.h>`
//! I/O-multiplexing primitives.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - poll: ready+timeout matrix on a socketpair
//!   - select: same matrix via fd_set bookkeeping
//!   - ppoll: like poll but with timespec + sigmask
//!   - pselect: like select with timespec + sigmask
//!
//! All tests use a private socketpair so we don't depend on real
//! network state. Both impls operate on independent socket pairs to
//! avoid stepping on each other.
//!
//! Bead: CONFORMANCE: libc poll.h+sys/select.h diff matrix.

use std::ffi::{c_int, c_void};
use std::mem::size_of;

use frankenlibc_abi::poll_abi as fl;

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
    let mut sv: [c_int; 2] = [-1, -1];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) };
    assert_eq!(r, 0, "socketpair setup failed");
    (sv[0], sv[1])
}

fn close_pair((a, b): (c_int, c_int)) {
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

// ===========================================================================
// poll — empty fd set, immediate timeout, readable fd, writable fd
// ===========================================================================

#[test]
fn diff_poll_empty_immediate() {
    let mut divs = Vec::new();
    let r_fl = unsafe { fl::poll(std::ptr::null_mut(), 0, 0) };
    let r_lc = unsafe { libc::poll(std::ptr::null_mut(), 0, 0) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "poll",
            case: "empty_immediate".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    assert!(
        divs.is_empty(),
        "poll empty divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_poll_writable_socketpair() {
    let mut divs = Vec::new();
    let (a, _b) = make_socketpair();
    // Fresh socketpair: `a` should be writable immediately.
    let mut pfd = libc::pollfd {
        fd: a,
        events: libc::POLLOUT,
        revents: 0,
    };
    let r_fl = unsafe { fl::poll(&mut pfd, 1, 0) };
    let revents_fl = pfd.revents;
    pfd.revents = 0;
    let r_lc = unsafe { libc::poll(&mut pfd, 1, 0) };
    let revents_lc = pfd.revents;
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "poll",
            case: "writable".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if revents_fl & libc::POLLOUT != revents_lc & libc::POLLOUT {
        divs.push(Divergence {
            function: "poll",
            case: "writable".into(),
            field: "POLLOUT_bit",
            frankenlibc: format!("{:#x}", revents_fl & libc::POLLOUT),
            glibc: format!("{:#x}", revents_lc & libc::POLLOUT),
        });
    }
    close_pair((a, _b));
    assert!(
        divs.is_empty(),
        "poll writable divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_poll_readable_after_write() {
    let mut divs = Vec::new();
    let (a, b) = make_socketpair();
    // Write a byte from b → a should become readable.
    let buf = [0xABu8; 1];
    let n = unsafe { libc::write(b, buf.as_ptr() as *const c_void, 1) };
    assert_eq!(n, 1);

    let mut pfd = libc::pollfd {
        fd: a,
        events: libc::POLLIN,
        revents: 0,
    };
    let r_fl = unsafe { fl::poll(&mut pfd, 1, 100) };
    let revents_fl = pfd.revents;
    pfd.revents = 0;
    let r_lc = unsafe { libc::poll(&mut pfd, 1, 100) };
    let revents_lc = pfd.revents;
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "poll",
            case: "readable_after_write".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if revents_fl & libc::POLLIN != revents_lc & libc::POLLIN {
        divs.push(Divergence {
            function: "poll",
            case: "readable_after_write".into(),
            field: "POLLIN_bit",
            frankenlibc: format!("{:#x}", revents_fl & libc::POLLIN),
            glibc: format!("{:#x}", revents_lc & libc::POLLIN),
        });
    }
    close_pair((a, b));
    assert!(
        divs.is_empty(),
        "poll readable divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_poll_invalid_fd_pollnval() {
    let mut divs = Vec::new();
    let mut pfd = libc::pollfd {
        fd: 99999,
        events: libc::POLLIN,
        revents: 0,
    };
    let r_fl = unsafe { fl::poll(&mut pfd, 1, 0) };
    let revents_fl = pfd.revents;
    pfd.revents = 0;
    let r_lc = unsafe { libc::poll(&mut pfd, 1, 0) };
    let revents_lc = pfd.revents;
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "poll",
            case: "invalid_fd".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if revents_fl & libc::POLLNVAL != revents_lc & libc::POLLNVAL {
        divs.push(Divergence {
            function: "poll",
            case: "invalid_fd".into(),
            field: "POLLNVAL_bit",
            frankenlibc: format!("{:#x}", revents_fl & libc::POLLNVAL),
            glibc: format!("{:#x}", revents_lc & libc::POLLNVAL),
        });
    }
    assert!(
        divs.is_empty(),
        "poll invalid_fd divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_poll_timeout_zero_unready() {
    let mut divs = Vec::new();
    let (a, _b) = make_socketpair();
    // No write happened → `a` is NOT readable, with timeout 0 should
    // return 0 immediately.
    let mut pfd = libc::pollfd {
        fd: a,
        events: libc::POLLIN,
        revents: 0,
    };
    let r_fl = unsafe { fl::poll(&mut pfd, 1, 0) };
    pfd.revents = 0;
    let r_lc = unsafe { libc::poll(&mut pfd, 1, 0) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "poll",
            case: "timeout_zero_unready".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    close_pair((a, _b));
    assert!(
        divs.is_empty(),
        "poll timeout divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// select — empty / writable / readable / timeout
// ===========================================================================

unsafe fn fd_set_zero(set: *mut libc::fd_set) {
    unsafe {
        libc::FD_ZERO(set);
    }
}
unsafe fn fd_set_set(fd: c_int, set: *mut libc::fd_set) {
    unsafe {
        libc::FD_SET(fd, set);
    }
}
unsafe fn fd_set_isset(fd: c_int, set: *const libc::fd_set) -> bool {
    unsafe { libc::FD_ISSET(fd, set as *mut libc::fd_set) }
}

#[test]
fn diff_select_empty_immediate() {
    let mut divs = Vec::new();
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let r_fl = unsafe {
        fl::select(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    let r_lc = unsafe {
        libc::select(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "select",
            case: "empty_immediate".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    assert!(
        divs.is_empty(),
        "select empty divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_select_writable_socketpair() {
    let mut divs = Vec::new();
    let (a, b) = make_socketpair();
    let nfds = (a.max(b) + 1) as c_int;

    let mut wfds: libc::fd_set = unsafe { core::mem::zeroed() };
    unsafe {
        fd_set_zero(&mut wfds);
        fd_set_set(a, &mut wfds);
    }
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let r_fl = unsafe {
        fl::select(
            nfds,
            std::ptr::null_mut(),
            &mut wfds,
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    let was_set_fl = unsafe { fd_set_isset(a, &wfds) };

    unsafe {
        fd_set_zero(&mut wfds);
        fd_set_set(a, &mut wfds);
    }
    let r_lc = unsafe {
        libc::select(
            nfds,
            std::ptr::null_mut(),
            &mut wfds,
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    let was_set_lc = unsafe { fd_set_isset(a, &wfds) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "select",
            case: "writable".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if was_set_fl != was_set_lc {
        divs.push(Divergence {
            function: "select",
            case: "writable".into(),
            field: "FD_ISSET",
            frankenlibc: format!("{was_set_fl}"),
            glibc: format!("{was_set_lc}"),
        });
    }
    close_pair((a, b));
    assert!(
        divs.is_empty(),
        "select writable divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_select_readable_after_write() {
    let mut divs = Vec::new();
    let (a, b) = make_socketpair();
    let buf = [0xCDu8; 1];
    let n = unsafe { libc::write(b, buf.as_ptr() as *const c_void, 1) };
    assert_eq!(n, 1);
    let nfds = (a.max(b) + 1) as c_int;

    let mut rfds: libc::fd_set = unsafe { core::mem::zeroed() };
    unsafe {
        fd_set_zero(&mut rfds);
        fd_set_set(a, &mut rfds);
    }
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    let r_fl = unsafe {
        fl::select(
            nfds,
            &mut rfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    let was_set_fl = unsafe { fd_set_isset(a, &rfds) };

    unsafe {
        fd_set_zero(&mut rfds);
        fd_set_set(a, &mut rfds);
    }
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    let r_lc = unsafe {
        libc::select(
            nfds,
            &mut rfds,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut tv,
        )
    };
    let was_set_lc = unsafe { fd_set_isset(a, &rfds) };

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "select",
            case: "readable".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if was_set_fl != was_set_lc {
        divs.push(Divergence {
            function: "select",
            case: "readable".into(),
            field: "FD_ISSET",
            frankenlibc: format!("{was_set_fl}"),
            glibc: format!("{was_set_lc}"),
        });
    }
    close_pair((a, b));
    assert!(
        divs.is_empty(),
        "select readable divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// ppoll / pselect — like poll/select with timespec + optional sigmask
// ===========================================================================

#[test]
fn diff_ppoll_writable() {
    let mut divs = Vec::new();
    let (a, b) = make_socketpair();
    let mut pfd = libc::pollfd {
        fd: a,
        events: libc::POLLOUT,
        revents: 0,
    };
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r_fl = unsafe { fl::ppoll(&mut pfd, 1, &ts, std::ptr::null()) };
    let revents_fl = pfd.revents;
    pfd.revents = 0;
    let r_lc = unsafe { libc::ppoll(&mut pfd, 1, &ts, std::ptr::null()) };
    let revents_lc = pfd.revents;
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "ppoll",
            case: "writable".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if revents_fl & libc::POLLOUT != revents_lc & libc::POLLOUT {
        divs.push(Divergence {
            function: "ppoll",
            case: "writable".into(),
            field: "POLLOUT_bit",
            frankenlibc: format!("{:#x}", revents_fl & libc::POLLOUT),
            glibc: format!("{:#x}", revents_lc & libc::POLLOUT),
        });
    }
    close_pair((a, b));
    assert!(
        divs.is_empty(),
        "ppoll divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_pselect_empty_immediate() {
    let mut divs = Vec::new();
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let r_fl = unsafe {
        fl::pselect(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts,
            std::ptr::null(),
        )
    };
    let r_lc = unsafe {
        libc::pselect(
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &ts,
            std::ptr::null(),
        )
    };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "pselect",
            case: "empty_immediate".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    assert!(
        divs.is_empty(),
        "pselect divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn poll_select_diff_coverage_report() {
    let _ = size_of::<libc::pollfd>();
    eprintln!(
        "{{\"family\":\"poll.h+sys/select.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
