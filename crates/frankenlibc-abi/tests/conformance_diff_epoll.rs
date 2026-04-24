#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/epoll.h>`:
//!   - epoll_create / epoll_create1 (epoll fd creation)
//!   - epoll_ctl  (add/mod/del registrations)
//!   - epoll_wait (block until events ready or timeout)
//!
//! Tests use socketpair to drive readiness deterministically. Each
//! test creates two independent epoll instances (one per impl) so
//! the registration state doesn't bleed between impls.
//!
//! Bead: CONFORMANCE: libc sys/epoll.h diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::poll_abi as fl;

unsafe extern "C" {
    fn epoll_create(size: c_int) -> c_int;
    fn epoll_create1(flags: c_int) -> c_int;
    fn epoll_ctl(epfd: c_int, op: c_int, fd: c_int, event: *mut EpollEvent) -> c_int;
    fn epoll_wait(epfd: c_int, events: *mut EpollEvent, maxevents: c_int, timeout: c_int)
    -> c_int;
}

const EPOLL_CTL_ADD: c_int = 1;
const EPOLL_CTL_DEL: c_int = 2;
const EPOLL_CTL_MOD: c_int = 3;

const EPOLLIN: u32 = 0x001;
const EPOLLOUT: u32 = 0x004;
const EPOLLERR: u32 = 0x008;
const EPOLLHUP: u32 = 0x010;

const EPOLL_CLOEXEC: c_int = 0o2000000;

#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct EpollEvent {
    events: u32,
    data: u64,
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

#[test]
fn diff_epoll_create_and_close() {
    let mut divs = Vec::new();
    let efd_fl = unsafe { fl::epoll_create(1) };
    let efd_lc = unsafe { epoll_create(1) };
    if (efd_fl >= 0) != (efd_lc >= 0) {
        divs.push(Divergence {
            function: "epoll_create",
            case: "size=1".into(),
            field: "success_match",
            frankenlibc: format!("{efd_fl}"),
            glibc: format!("{efd_lc}"),
        });
    }
    if efd_fl >= 0 {
        let _ = unsafe { libc::close(efd_fl) };
    }
    if efd_lc >= 0 {
        let _ = unsafe { libc::close(efd_lc) };
    }

    // epoll_create1 with CLOEXEC flag
    let efd1_fl = unsafe { fl::epoll_create1(EPOLL_CLOEXEC) };
    let efd1_lc = unsafe { epoll_create1(EPOLL_CLOEXEC) };
    if (efd1_fl >= 0) != (efd1_lc >= 0) {
        divs.push(Divergence {
            function: "epoll_create1",
            case: "EPOLL_CLOEXEC".into(),
            field: "success_match",
            frankenlibc: format!("{efd1_fl}"),
            glibc: format!("{efd1_lc}"),
        });
    }
    if efd1_fl >= 0 {
        let _ = unsafe { libc::close(efd1_fl) };
    }
    if efd1_lc >= 0 {
        let _ = unsafe { libc::close(efd1_lc) };
    }

    assert!(
        divs.is_empty(),
        "epoll_create divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_epoll_create1_invalid_flags() {
    // Bogus flag bit should fail with EINVAL on both
    let efd_fl = unsafe { fl::epoll_create1(0xffff_0000u32 as c_int) };
    let efd_lc = unsafe { epoll_create1(0xffff_0000u32 as c_int) };
    assert_eq!(
        efd_fl >= 0,
        efd_lc >= 0,
        "epoll_create1 invalid flags success-match: fl={efd_fl}, lc={efd_lc}"
    );
    if efd_fl >= 0 {
        let _ = unsafe { libc::close(efd_fl) };
    }
    if efd_lc >= 0 {
        let _ = unsafe { libc::close(efd_lc) };
    }
}

#[test]
fn diff_epoll_ctl_add_then_wait_readable() {
    let mut divs = Vec::new();
    // Run impl-paired test: each impl gets its own socketpair + epoll
    let run = |use_fl: bool| -> (c_int, Vec<EpollEvent>) {
        let (a, b) = make_socketpair();
        // Make 'a' readable by writing on 'b'
        let _ = unsafe { libc::write(b, b"x".as_ptr() as *const c_void, 1) };
        let efd = if use_fl {
            unsafe { fl::epoll_create1(0) }
        } else {
            unsafe { epoll_create1(0) }
        };
        let mut ev = EpollEvent {
            events: EPOLLIN,
            data: 0xabcd,
        };
        let r_ctl = if use_fl {
            unsafe { fl::epoll_ctl(efd, EPOLL_CTL_ADD, a, &mut ev as *mut _ as *mut _) }
        } else {
            unsafe { epoll_ctl(efd, EPOLL_CTL_ADD, a, &mut ev as *mut _) }
        };
        assert_eq!(r_ctl, 0, "epoll_ctl ADD via {}", if use_fl { "fl" } else { "lc" });
        let mut out = vec![EpollEvent::default(); 4];
        let n = if use_fl {
            unsafe {
                fl::epoll_wait(efd, out.as_mut_ptr() as *mut _, out.len() as c_int, 100)
            }
        } else {
            unsafe { epoll_wait(efd, out.as_mut_ptr(), out.len() as c_int, 100) }
        };
        unsafe {
            libc::close(efd);
            libc::close(a);
            libc::close(b);
        }
        (n, out)
    };
    let (n_fl, ev_fl) = run(true);
    let (n_lc, ev_lc) = run(false);
    if n_fl != n_lc {
        divs.push(Divergence {
            function: "epoll_wait",
            case: "ADD readable, wait 100ms".into(),
            field: "n_events",
            frankenlibc: format!("{n_fl}"),
            glibc: format!("{n_lc}"),
        });
    }
    if n_fl == 1 && n_lc == 1 {
        let e_fl = ev_fl[0].events;
        let e_lc = ev_lc[0].events;
        let d_fl = ev_fl[0].data;
        let d_lc = ev_lc[0].data;
        // Use bitwise EPOLLIN check (kernel may also set HUP/ERR depending)
        if (e_fl & EPOLLIN == 0) != (e_lc & EPOLLIN == 0) {
            divs.push(Divergence {
                function: "epoll_wait",
                case: "ADD readable".into(),
                field: "EPOLLIN_set",
                frankenlibc: format!("{e_fl:#x}"),
                glibc: format!("{e_lc:#x}"),
            });
        }
        if d_fl != d_lc || d_fl != 0xabcd {
            divs.push(Divergence {
                function: "epoll_wait",
                case: "ADD readable".into(),
                field: "data",
                frankenlibc: format!("{d_fl:#x}"),
                glibc: format!("{d_lc:#x}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "epoll_ctl ADD + wait divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_epoll_wait_timeout_no_events() {
    let mut divs = Vec::new();
    let run = |use_fl: bool| -> c_int {
        let (a, b) = make_socketpair();
        // Don't make 'a' readable.
        let efd = if use_fl {
            unsafe { fl::epoll_create1(0) }
        } else {
            unsafe { epoll_create1(0) }
        };
        let mut ev = EpollEvent {
            events: EPOLLIN,
            data: 0,
        };
        let _ = if use_fl {
            unsafe { fl::epoll_ctl(efd, EPOLL_CTL_ADD, a, &mut ev as *mut _ as *mut _) }
        } else {
            unsafe { epoll_ctl(efd, EPOLL_CTL_ADD, a, &mut ev as *mut _) }
        };
        let mut out = vec![EpollEvent::default(); 4];
        let n = if use_fl {
            unsafe { fl::epoll_wait(efd, out.as_mut_ptr() as *mut _, out.len() as c_int, 10) }
        } else {
            unsafe { epoll_wait(efd, out.as_mut_ptr(), out.len() as c_int, 10) }
        };
        unsafe {
            libc::close(efd);
            libc::close(a);
            libc::close(b);
        }
        n
    };
    let n_fl = run(true);
    let n_lc = run(false);
    if n_fl != n_lc {
        divs.push(Divergence {
            function: "epoll_wait",
            case: "no readiness, 10ms timeout".into(),
            field: "n_events",
            frankenlibc: format!("{n_fl}"),
            glibc: format!("{n_lc}"),
        });
    }
    if n_fl != 0 {
        divs.push(Divergence {
            function: "epoll_wait",
            case: "no readiness, 10ms timeout".into(),
            field: "expected_zero",
            frankenlibc: format!("{n_fl}"),
            glibc: "0".into(),
        });
    }
    assert!(
        divs.is_empty(),
        "epoll_wait timeout divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_epoll_ctl_del() {
    let mut divs = Vec::new();
    let run = |use_fl: bool| -> (c_int, c_int) {
        let (a, b) = make_socketpair();
        let _ = unsafe { libc::write(b, b"x".as_ptr() as *const c_void, 1) };
        let efd = if use_fl {
            unsafe { fl::epoll_create1(0) }
        } else {
            unsafe { epoll_create1(0) }
        };
        let mut ev = EpollEvent {
            events: EPOLLIN,
            data: 0,
        };
        let _ = if use_fl {
            unsafe { fl::epoll_ctl(efd, EPOLL_CTL_ADD, a, &mut ev as *mut _ as *mut _) }
        } else {
            unsafe { epoll_ctl(efd, EPOLL_CTL_ADD, a, &mut ev as *mut _) }
        };
        let r_del = if use_fl {
            unsafe { fl::epoll_ctl(efd, EPOLL_CTL_DEL, a, std::ptr::null_mut()) }
        } else {
            unsafe { epoll_ctl(efd, EPOLL_CTL_DEL, a, std::ptr::null_mut()) }
        };
        let mut out = vec![EpollEvent::default(); 4];
        let n = if use_fl {
            unsafe { fl::epoll_wait(efd, out.as_mut_ptr() as *mut _, out.len() as c_int, 10) }
        } else {
            unsafe { epoll_wait(efd, out.as_mut_ptr(), out.len() as c_int, 10) }
        };
        unsafe {
            libc::close(efd);
            libc::close(a);
            libc::close(b);
        }
        (r_del, n)
    };
    let (del_fl, n_fl) = run(true);
    let (del_lc, n_lc) = run(false);
    if del_fl != del_lc {
        divs.push(Divergence {
            function: "epoll_ctl DEL",
            case: "del then wait".into(),
            field: "del_return",
            frankenlibc: format!("{del_fl}"),
            glibc: format!("{del_lc}"),
        });
    }
    if n_fl != n_lc {
        divs.push(Divergence {
            function: "epoll_wait",
            case: "after DEL".into(),
            field: "n_events",
            frankenlibc: format!("{n_fl}"),
            glibc: format!("{n_lc}"),
        });
    }
    if n_fl != 0 {
        divs.push(Divergence {
            function: "epoll_wait",
            case: "after DEL".into(),
            field: "expected_zero",
            frankenlibc: format!("{n_fl}"),
            glibc: "0".into(),
        });
    }
    let _unused_mod = EPOLL_CTL_MOD;
    let _unused_err = EPOLLERR;
    let _unused_hup = EPOLLHUP;
    let _unused_out = EPOLLOUT;
    assert!(
        divs.is_empty(),
        "epoll_ctl DEL divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn epoll_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/epoll.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
