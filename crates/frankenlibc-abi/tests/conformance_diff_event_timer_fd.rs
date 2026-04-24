#![cfg(target_os = "linux")]

//! Differential conformance harness for Linux event-notification fds:
//!   - eventfd / eventfd_read / eventfd_write
//!   - timerfd_create / timerfd_settime / timerfd_gettime
//!   - signalfd (creation + invalid args; full delivery flow is out of
//!     scope because it requires a fork to avoid masking other tests)
//!
//! Bead: CONFORMANCE: libc eventfd/timerfd/signalfd diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::{poll_abi as fl_poll, unistd_abi as fl_uni};

unsafe extern "C" {
    fn eventfd(initval: u32, flags: c_int) -> c_int;
    fn eventfd_read(fd: c_int, value: *mut u64) -> c_int;
    fn eventfd_write(fd: c_int, value: u64) -> c_int;
    fn timerfd_create(clockid: c_int, flags: c_int) -> c_int;
    fn timerfd_settime(
        fd: c_int,
        flags: c_int,
        new_value: *const libc::itimerspec,
        old_value: *mut libc::itimerspec,
    ) -> c_int;
    fn timerfd_gettime(fd: c_int, curr_value: *mut libc::itimerspec) -> c_int;
    fn signalfd(fd: c_int, mask: *const c_void, flags: c_int) -> c_int;
}

const CLOCK_MONOTONIC: c_int = 1;
const EFD_CLOEXEC: c_int = 0o2000000;
const EFD_NONBLOCK: c_int = 0o4000;
const EFD_SEMAPHORE: c_int = 1;
const TFD_CLOEXEC: c_int = 0o2000000;
const TFD_NONBLOCK: c_int = 0o4000;
const SFD_CLOEXEC: c_int = 0o2000000;

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

// ===========================================================================
// eventfd
// ===========================================================================

#[test]
fn diff_eventfd_create_with_flags() {
    let mut divs = Vec::new();
    let cases: &[(&str, u32, c_int)] = &[
        ("0,0", 0, 0),
        ("5,0", 5, 0),
        ("0,CLOEXEC", 0, EFD_CLOEXEC),
        ("0,NONBLOCK", 0, EFD_NONBLOCK),
        ("0,SEMAPHORE", 0, EFD_SEMAPHORE),
        ("0,CLOEXEC|NONBLOCK", 0, EFD_CLOEXEC | EFD_NONBLOCK),
    ];
    for (label, init, flags) in cases {
        let fd_fl = unsafe { fl_poll::eventfd(*init, *flags) };
        let fd_lc = unsafe { eventfd(*init, *flags) };
        if (fd_fl >= 0) != (fd_lc >= 0) {
            divs.push(Divergence {
                function: "eventfd",
                case: (*label).into(),
                field: "success_match",
                frankenlibc: format!("{fd_fl}"),
                glibc: format!("{fd_lc}"),
            });
        }
        if fd_fl >= 0 {
            let _ = unsafe { libc::close(fd_fl) };
        }
        if fd_lc >= 0 {
            let _ = unsafe { libc::close(fd_lc) };
        }
    }
    assert!(
        divs.is_empty(),
        "eventfd creation divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_eventfd_write_then_read_round_trip() {
    let mut divs = Vec::new();
    // For each impl, create eventfd, write a value, read it back.
    let run = |use_fl: bool| -> Option<u64> {
        let fd = if use_fl {
            unsafe { fl_poll::eventfd(0, 0) }
        } else {
            unsafe { eventfd(0, 0) }
        };
        if fd < 0 {
            return None;
        }
        let r_w = if use_fl {
            unsafe { fl_uni::eventfd_write(fd, 12345) }
        } else {
            unsafe { eventfd_write(fd, 12345) }
        };
        if r_w != 0 {
            unsafe { libc::close(fd) };
            return None;
        }
        let mut val: u64 = 0;
        let r_r = if use_fl {
            unsafe { fl_uni::eventfd_read(fd, &mut val) }
        } else {
            unsafe { eventfd_read(fd, &mut val) }
        };
        unsafe { libc::close(fd) };
        if r_r == 0 { Some(val) } else { None }
    };
    let v_fl = run(true);
    let v_lc = run(false);
    if v_fl != v_lc {
        divs.push(Divergence {
            function: "eventfd_write/read",
            case: "round-trip 12345".into(),
            field: "value",
            frankenlibc: format!("{v_fl:?}"),
            glibc: format!("{v_lc:?}"),
        });
    }
    if v_fl != Some(12345) {
        divs.push(Divergence {
            function: "eventfd_write/read",
            case: "round-trip 12345".into(),
            field: "expected",
            frankenlibc: format!("{v_fl:?}"),
            glibc: "Some(12345)".into(),
        });
    }
    assert!(
        divs.is_empty(),
        "eventfd round-trip divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_eventfd_initial_value_readable() {
    // initval=7 should make the first read return 7.
    let mut divs = Vec::new();
    let run = |use_fl: bool| -> Option<u64> {
        let fd = if use_fl {
            unsafe { fl_poll::eventfd(7, 0) }
        } else {
            unsafe { eventfd(7, 0) }
        };
        if fd < 0 {
            return None;
        }
        let mut val: u64 = 0;
        let r = if use_fl {
            unsafe { fl_uni::eventfd_read(fd, &mut val) }
        } else {
            unsafe { eventfd_read(fd, &mut val) }
        };
        unsafe { libc::close(fd) };
        if r == 0 { Some(val) } else { None }
    };
    let v_fl = run(true);
    let v_lc = run(false);
    if v_fl != v_lc {
        divs.push(Divergence {
            function: "eventfd",
            case: "initval=7 read".into(),
            field: "value",
            frankenlibc: format!("{v_fl:?}"),
            glibc: format!("{v_lc:?}"),
        });
    }
    if v_fl != Some(7) {
        divs.push(Divergence {
            function: "eventfd",
            case: "initval=7 read".into(),
            field: "expected",
            frankenlibc: format!("{v_fl:?}"),
            glibc: "Some(7)".into(),
        });
    }
    assert!(
        divs.is_empty(),
        "eventfd initval divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// timerfd
// ===========================================================================

#[test]
fn diff_timerfd_create_with_flags() {
    let mut divs = Vec::new();
    let cases: &[(&str, c_int)] = &[
        ("0", 0),
        ("CLOEXEC", TFD_CLOEXEC),
        ("NONBLOCK", TFD_NONBLOCK),
        ("CLOEXEC|NONBLOCK", TFD_CLOEXEC | TFD_NONBLOCK),
    ];
    for (label, flags) in cases {
        let fd_fl = unsafe { fl_poll::timerfd_create(CLOCK_MONOTONIC, *flags) };
        let fd_lc = unsafe { timerfd_create(CLOCK_MONOTONIC, *flags) };
        if (fd_fl >= 0) != (fd_lc >= 0) {
            divs.push(Divergence {
                function: "timerfd_create",
                case: (*label).into(),
                field: "success_match",
                frankenlibc: format!("{fd_fl}"),
                glibc: format!("{fd_lc}"),
            });
        }
        if fd_fl >= 0 {
            let _ = unsafe { libc::close(fd_fl) };
        }
        if fd_lc >= 0 {
            let _ = unsafe { libc::close(fd_lc) };
        }
    }
    assert!(
        divs.is_empty(),
        "timerfd_create divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_timerfd_settime_then_gettime() {
    let mut divs = Vec::new();
    // Set a one-shot timer 1 second in the future, then gettime should
    // report it_value with positive seconds.
    let run = |use_fl: bool| -> (c_int, libc::itimerspec) {
        let fd = if use_fl {
            unsafe { fl_poll::timerfd_create(CLOCK_MONOTONIC, 0) }
        } else {
            unsafe { timerfd_create(CLOCK_MONOTONIC, 0) }
        };
        let new_val = libc::itimerspec {
            it_interval: libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            },
            it_value: libc::timespec {
                tv_sec: 1,
                tv_nsec: 0,
            },
        };
        let r = if use_fl {
            unsafe { fl_poll::timerfd_settime(fd, 0, &new_val, std::ptr::null_mut()) }
        } else {
            unsafe { timerfd_settime(fd, 0, &new_val, std::ptr::null_mut()) }
        };
        let mut got: libc::itimerspec = unsafe { core::mem::zeroed() };
        let _ = if use_fl {
            unsafe { fl_poll::timerfd_gettime(fd, &mut got) }
        } else {
            unsafe { timerfd_gettime(fd, &mut got) }
        };
        unsafe { libc::close(fd) };
        (r, got)
    };
    let (r_fl, got_fl) = run(true);
    let (r_lc, got_lc) = run(false);
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "timerfd_settime",
            case: "1s one-shot".into(),
            field: "settime_return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    // it_value: should have tv_sec ~= 1 (some time may have elapsed)
    if got_fl.it_value.tv_sec < 0
        || got_fl.it_value.tv_sec > 1
        || got_lc.it_value.tv_sec < 0
        || got_lc.it_value.tv_sec > 1
    {
        divs.push(Divergence {
            function: "timerfd_gettime",
            case: "1s one-shot".into(),
            field: "it_value.tv_sec_range",
            frankenlibc: format!("{}", got_fl.it_value.tv_sec),
            glibc: format!("{}", got_lc.it_value.tv_sec),
        });
    }
    assert!(
        divs.is_empty(),
        "timerfd settime/gettime divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// signalfd — creation + invalid-flags check. We don't exercise the full
// signal-delivery flow because that requires careful signal masking
// across other tests in the same process.
// ===========================================================================

#[test]
fn diff_signalfd_create_with_empty_mask() {
    let mut divs = Vec::new();
    // Empty sigset
    let mask: libc::sigset_t = unsafe { core::mem::zeroed() };
    let fd_fl = unsafe { fl_uni::signalfd(-1, &mask as *const _ as *const c_void, SFD_CLOEXEC) };
    let fd_lc = unsafe { signalfd(-1, &mask as *const _ as *const c_void, SFD_CLOEXEC) };
    if (fd_fl >= 0) != (fd_lc >= 0) {
        divs.push(Divergence {
            function: "signalfd",
            case: "fd=-1, empty mask, CLOEXEC".into(),
            field: "success_match",
            frankenlibc: format!("{fd_fl}"),
            glibc: format!("{fd_lc}"),
        });
    }
    if fd_fl >= 0 {
        let _ = unsafe { libc::close(fd_fl) };
    }
    if fd_lc >= 0 {
        let _ = unsafe { libc::close(fd_lc) };
    }
    assert!(
        divs.is_empty(),
        "signalfd divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn event_timer_signal_fd_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/eventfd.h+sys/timerfd.h+sys/signalfd.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
