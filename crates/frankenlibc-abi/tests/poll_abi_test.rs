#![cfg(target_os = "linux")]

//! Integration tests for I/O multiplexing ABI entrypoints.
//!
//! Covers: poll, ppoll, select, pselect, epoll_create/create1/ctl/wait/pwait,
//! eventfd, timerfd_create/settime/gettime, sched_yield, prctl.

use std::ffi::c_int;
use std::ptr;

use frankenlibc_abi::poll_abi::{epoll_create, epoll_create1, epoll_ctl, epoll_wait, poll};
use frankenlibc_abi::unistd_abi::close;

// ---------------------------------------------------------------------------
// Helper: create a pipe pair
// ---------------------------------------------------------------------------

fn pipe_pair() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    let rc = unsafe { frankenlibc_abi::io_abi::pipe(&mut fds as *mut c_int) };
    assert_eq!(rc, 0, "pipe() should succeed");
    (fds[0], fds[1])
}

// ---------------------------------------------------------------------------
// poll
// ---------------------------------------------------------------------------

#[test]
fn poll_timeout_no_events() {
    let (r, w) = pipe_pair();
    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    // Timeout=0 means non-blocking poll
    let rc = unsafe { poll(&mut pfd, 1, 0) };
    assert_eq!(rc, 0, "poll with timeout=0 and no data should return 0");
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn poll_detects_readable() {
    let (r, w) = pipe_pair();
    // Write a byte to make the read end readable
    let msg = b"x";
    unsafe { libc::write(w, msg.as_ptr() as *const _, 1) };

    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { poll(&mut pfd, 1, 100) };
    assert_eq!(rc, 1, "poll should detect 1 readable fd");
    assert_ne!(pfd.revents & libc::POLLIN, 0, "POLLIN should be set");
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn poll_empty_fds_timeout() {
    // poll with nfds=0 should just sleep for the timeout
    let rc = unsafe { poll(ptr::null_mut(), 0, 0) };
    assert_eq!(rc, 0, "poll with nfds=0 and timeout=0 should return 0");
}

// ---------------------------------------------------------------------------
// ppoll
// ---------------------------------------------------------------------------

#[test]
fn ppoll_timeout_zero() {
    use frankenlibc_abi::poll_abi::ppoll;
    let (r, w) = pipe_pair();
    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { ppoll(&mut pfd, 1, &ts, ptr::null()) };
    assert_eq!(rc, 0, "ppoll with zero timeout and no data should return 0");
    unsafe {
        close(r);
        close(w);
    }
}

// ---------------------------------------------------------------------------
// select
// ---------------------------------------------------------------------------

#[test]
fn select_timeout_zero() {
    use frankenlibc_abi::poll_abi::select;
    let (r, w) = pipe_pair();
    let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(r, &mut readfds) };
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let rc = unsafe {
        select(
            r + 1,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut tv,
        )
    };
    assert_eq!(
        rc, 0,
        "select with zero timeout and no data should return 0"
    );
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn select_detects_readable() {
    use frankenlibc_abi::poll_abi::select;
    let (r, w) = pipe_pair();
    let msg = b"y";
    unsafe { libc::write(w, msg.as_ptr() as *const _, 1) };

    let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(r, &mut readfds) };
    let mut tv = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    let rc = unsafe {
        select(
            r + 1,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut tv,
        )
    };
    assert_eq!(rc, 1, "select should detect 1 readable fd");
    assert!(unsafe { libc::FD_ISSET(r, &readfds) });
    unsafe {
        close(r);
        close(w);
    }
}

// ---------------------------------------------------------------------------
// epoll
// ---------------------------------------------------------------------------

#[test]
fn epoll_create_and_close() {
    let epfd = unsafe { epoll_create(1) };
    assert!(epfd >= 0, "epoll_create should return a valid fd");
    let rc = unsafe { close(epfd) };
    assert_eq!(rc, 0);
}

#[test]
fn epoll_create_invalid_size() {
    let epfd = unsafe { epoll_create(0) };
    assert_eq!(epfd, -1, "epoll_create(0) should fail");

    let epfd = unsafe { epoll_create(-1) };
    assert_eq!(epfd, -1, "epoll_create(-1) should fail");
}

#[test]
fn epoll_create1_basic() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0, "epoll_create1(0) should succeed");
    let rc = unsafe { close(epfd) };
    assert_eq!(rc, 0);
}

#[test]
fn epoll_create1_cloexec() {
    let epfd = unsafe { epoll_create1(libc::EPOLL_CLOEXEC) };
    assert!(epfd >= 0, "epoll_create1(EPOLL_CLOEXEC) should succeed");
    let rc = unsafe { close(epfd) };
    assert_eq!(rc, 0);
}

#[test]
fn epoll_ctl_add_and_wait() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);

    let (r, w) = pipe_pair();

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r as u64,
    };
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };
    assert_eq!(rc, 0, "epoll_ctl ADD should succeed");

    // No data yet — epoll_wait with timeout=0 should return 0
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 4, 0) };
    assert_eq!(n, 0, "epoll_wait should return 0 with no data");

    // Write data to trigger EPOLLIN
    let msg = b"z";
    unsafe { libc::write(w, msg.as_ptr() as *const _, 1) };

    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 4, 100) };
    assert_eq!(n, 1, "epoll_wait should detect 1 event");
    assert_ne!(events[0].events & libc::EPOLLIN as u32, 0);

    unsafe {
        close(r);
        close(w);
        close(epfd);
    }
}

#[test]
fn epoll_wait_null_events_fails() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let n = unsafe { epoll_wait(epfd, ptr::null_mut(), 4, 0) };
    assert_eq!(n, -1, "epoll_wait with null events should fail");
    unsafe { close(epfd) };
}

#[test]
fn epoll_wait_zero_maxevents_fails() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 0, 0) };
    assert_eq!(n, -1, "epoll_wait with maxevents=0 should fail");
    unsafe { close(epfd) };
}

// ---------------------------------------------------------------------------
// eventfd
// ---------------------------------------------------------------------------

#[test]
fn eventfd_basic() {
    use frankenlibc_abi::poll_abi::eventfd;
    let fd = unsafe { eventfd(0, 0) };
    assert!(fd >= 0, "eventfd should return a valid fd");

    // Write a value
    let val: u64 = 42;
    let written = unsafe { libc::write(fd, &val as *const u64 as *const _, 8) };
    assert_eq!(written, 8);

    // Read it back
    let mut read_val: u64 = 0;
    let n = unsafe { libc::read(fd, &mut read_val as *mut u64 as *mut _, 8) };
    assert_eq!(n, 8);
    assert_eq!(read_val, 42);

    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// timerfd
// ---------------------------------------------------------------------------

#[test]
fn timerfd_create_and_gettime() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_gettime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0, "timerfd_create should succeed");

    let mut curr: libc::itimerspec = unsafe { std::mem::zeroed() };
    let rc = unsafe { timerfd_gettime(fd, &mut curr) };
    assert_eq!(rc, 0, "timerfd_gettime should succeed");
    // Newly created timer should be disarmed (all zeros)
    assert_eq!(curr.it_value.tv_sec, 0);
    assert_eq!(curr.it_value.tv_nsec, 0);

    unsafe { close(fd) };
}

#[test]
fn timerfd_settime_and_gettime() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_gettime, timerfd_settime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0);

    // Arm a one-shot timer for 10 seconds (we won't wait for it)
    let new_val = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        },
    };
    let mut old_val: libc::itimerspec = unsafe { std::mem::zeroed() };
    let rc = unsafe { timerfd_settime(fd, 0, &new_val, &mut old_val) };
    assert_eq!(rc, 0, "timerfd_settime should succeed");

    // gettime should show time remaining
    let mut curr: libc::itimerspec = unsafe { std::mem::zeroed() };
    let rc = unsafe { timerfd_gettime(fd, &mut curr) };
    assert_eq!(rc, 0);
    assert!(curr.it_value.tv_sec > 0, "timer should still be armed");

    unsafe { close(fd) };
}

#[test]
fn timerfd_settime_null_fails() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_settime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0);

    let rc = unsafe { timerfd_settime(fd, 0, ptr::null(), ptr::null_mut()) };
    assert_eq!(rc, -1, "timerfd_settime with null new_value should fail");

    unsafe { close(fd) };
}

#[test]
fn timerfd_gettime_null_fails() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_gettime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0);

    let rc = unsafe { timerfd_gettime(fd, ptr::null_mut()) };
    assert_eq!(rc, -1, "timerfd_gettime with null should fail");

    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// sched_yield
// ---------------------------------------------------------------------------

#[test]
fn sched_yield_succeeds() {
    use frankenlibc_abi::poll_abi::sched_yield;
    let rc = unsafe { sched_yield() };
    assert_eq!(rc, 0, "sched_yield should succeed");
}

// ---------------------------------------------------------------------------
// poll — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn poll_detects_writable() {
    let (r, w) = pipe_pair();
    let mut pfd = libc::pollfd {
        fd: w,
        events: libc::POLLOUT,
        revents: 0,
    };
    let rc = unsafe { poll(&mut pfd, 1, 0) };
    assert_eq!(rc, 1, "pipe write end should be writable");
    assert_ne!(pfd.revents & libc::POLLOUT, 0, "POLLOUT should be set");
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn poll_multiple_fds() {
    let (r1, w1) = pipe_pair();
    let (r2, w2) = pipe_pair();
    // Write to pipe2 only
    unsafe { libc::write(w2, b"a".as_ptr() as *const _, 1) };

    let mut pfds = [
        libc::pollfd {
            fd: r1,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: r2,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let rc = unsafe { poll(pfds.as_mut_ptr(), 2, 100) };
    assert_eq!(rc, 1, "only one fd should be ready");
    assert_eq!(pfds[0].revents & libc::POLLIN, 0, "r1 should not be ready");
    assert_ne!(pfds[1].revents & libc::POLLIN, 0, "r2 should be ready");
    unsafe {
        close(r1);
        close(w1);
        close(r2);
        close(w2);
    }
}

#[test]
fn poll_closed_write_end_pollhup() {
    let (r, w) = pipe_pair();
    unsafe { close(w) };
    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { poll(&mut pfd, 1, 0) };
    assert!(rc >= 0);
    // When write end is closed, read end gets POLLHUP
    assert_ne!(
        pfd.revents & libc::POLLHUP,
        0,
        "POLLHUP should be set after close(write_end)"
    );
    unsafe { close(r) };
}

#[test]
fn poll_negative_fd_ignored() {
    // POSIX: negative fd values cause the pollfd entry to be ignored (revents=0)
    let mut pfd = libc::pollfd {
        fd: -1,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { poll(&mut pfd, 1, 0) };
    assert_eq!(rc, 0, "poll should skip negative fd");
    assert_eq!(pfd.revents, 0, "revents should be 0 for negative fd");
}

#[test]
fn poll_high_invalid_fd_pollnval() {
    // A non-negative fd that isn't open should get POLLNVAL
    let mut pfd = libc::pollfd {
        fd: 9999,
        events: libc::POLLIN,
        revents: 0,
    };
    let rc = unsafe { poll(&mut pfd, 1, 0) };
    assert_eq!(rc, 1, "poll should report 1 fd with event");
    assert_ne!(
        pfd.revents & libc::POLLNVAL,
        0,
        "POLLNVAL should be set for invalid fd"
    );
}

// ---------------------------------------------------------------------------
// ppoll — additional
// ---------------------------------------------------------------------------

#[test]
fn ppoll_detects_readable() {
    use frankenlibc_abi::poll_abi::ppoll;
    let (r, w) = pipe_pair();
    unsafe { libc::write(w, b"p".as_ptr() as *const _, 1) };

    let mut pfd = libc::pollfd {
        fd: r,
        events: libc::POLLIN,
        revents: 0,
    };
    let ts = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let rc = unsafe { ppoll(&mut pfd, 1, &ts, ptr::null()) };
    assert_eq!(rc, 1, "ppoll should detect readable fd");
    assert_ne!(pfd.revents & libc::POLLIN, 0);
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn ppoll_null_timeout_nfds_zero() {
    use frankenlibc_abi::poll_abi::ppoll;
    // null timeout + nfds=0: would block forever, but with 0 fds there's nothing to wait for
    // Use a zero timeout instead to avoid blocking
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { ppoll(ptr::null_mut(), 0, &ts, ptr::null()) };
    assert_eq!(rc, 0, "ppoll with nfds=0 and zero timeout should return 0");
}

// ---------------------------------------------------------------------------
// pselect
// ---------------------------------------------------------------------------

#[test]
fn pselect_timeout_zero() {
    use frankenlibc_abi::poll_abi::pselect;
    let (r, w) = pipe_pair();
    let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(r, &mut readfds) };
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe {
        pselect(
            r + 1,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            &ts,
            ptr::null(),
        )
    };
    assert_eq!(
        rc, 0,
        "pselect with zero timeout and no data should return 0"
    );
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn pselect_detects_readable() {
    use frankenlibc_abi::poll_abi::pselect;
    let (r, w) = pipe_pair();
    unsafe { libc::write(w, b"s".as_ptr() as *const _, 1) };

    let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(r, &mut readfds) };
    let ts = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let rc = unsafe {
        pselect(
            r + 1,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            &ts,
            ptr::null(),
        )
    };
    assert_eq!(rc, 1, "pselect should detect 1 readable fd");
    assert!(unsafe { libc::FD_ISSET(r, &readfds) });
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn pselect_with_null_sigmask() {
    use frankenlibc_abi::poll_abi::pselect;
    let (r, w) = pipe_pair();
    let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(r, &mut readfds) };
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // null sigmask is valid — doesn't change signal mask
    let rc = unsafe {
        pselect(
            r + 1,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            &ts,
            ptr::null(),
        )
    };
    assert_eq!(rc, 0);
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn pselect_write_fd_ready() {
    use frankenlibc_abi::poll_abi::pselect;
    let (r, w) = pipe_pair();
    let mut writefds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(w, &mut writefds) };
    let ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe {
        pselect(
            w + 1,
            ptr::null_mut(),
            &mut writefds,
            ptr::null_mut(),
            &ts,
            ptr::null(),
        )
    };
    assert_eq!(rc, 1, "pipe write end should be writable");
    assert!(unsafe { libc::FD_ISSET(w, &writefds) });
    unsafe {
        close(r);
        close(w);
    }
}

// ---------------------------------------------------------------------------
// select — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn select_write_fd_ready() {
    use frankenlibc_abi::poll_abi::select;
    let (r, w) = pipe_pair();
    let mut writefds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe { libc::FD_SET(w, &mut writefds) };
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let rc = unsafe {
        select(
            w + 1,
            ptr::null_mut(),
            &mut writefds,
            ptr::null_mut(),
            &mut tv,
        )
    };
    assert_eq!(rc, 1, "pipe write end should be writable");
    assert!(unsafe { libc::FD_ISSET(w, &writefds) });
    unsafe {
        close(r);
        close(w);
    }
}

#[test]
fn select_null_timeout_zero_nfds() {
    use frankenlibc_abi::poll_abi::select;
    // nfds=0, all fd_set null, zero timeout — should return immediately
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let rc = unsafe {
        select(
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut tv,
        )
    };
    assert_eq!(rc, 0, "select with nfds=0 should return 0");
}

#[test]
fn select_multiple_fds() {
    use frankenlibc_abi::poll_abi::select;
    let (r1, w1) = pipe_pair();
    let (r2, w2) = pipe_pair();
    unsafe { libc::write(w1, b"m".as_ptr() as *const _, 1) };

    let mut readfds: libc::fd_set = unsafe { std::mem::zeroed() };
    unsafe {
        libc::FD_SET(r1, &mut readfds);
        libc::FD_SET(r2, &mut readfds);
    }
    let nfds = std::cmp::max(r1, r2) + 1;
    let mut tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let rc = unsafe {
        select(
            nfds,
            &mut readfds,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut tv,
        )
    };
    assert_eq!(rc, 1, "only one fd should be readable");
    assert!(unsafe { libc::FD_ISSET(r1, &readfds) }, "r1 should be set");
    assert!(
        !unsafe { libc::FD_ISSET(r2, &readfds) },
        "r2 should not be set"
    );
    unsafe {
        close(r1);
        close(w1);
        close(r2);
        close(w2);
    }
}

// ---------------------------------------------------------------------------
// epoll — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn epoll_ctl_mod_event() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let (r, w) = pipe_pair();

    // Add for EPOLLIN
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r as u64,
    };
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };
    assert_eq!(rc, 0);

    // Modify to EPOLLOUT
    ev.events = libc::EPOLLOUT as u32;
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_MOD, r, &mut ev) };
    assert_eq!(rc, 0, "epoll_ctl MOD should succeed");

    unsafe {
        close(r);
        close(w);
        close(epfd);
    }
}

#[test]
fn epoll_ctl_del_event() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let (r, w) = pipe_pair();

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r as u64,
    };
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };
    assert_eq!(rc, 0);

    // Delete — event pointer can be null on Linux >= 2.6.9
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_DEL, r, ptr::null_mut()) };
    assert_eq!(rc, 0, "epoll_ctl DEL should succeed");

    // Verify fd is removed — write data and epoll_wait should return 0
    unsafe { libc::write(w, b"d".as_ptr() as *const _, 1) };
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 1, 0) };
    assert_eq!(n, 0, "deleted fd should not trigger events");

    unsafe {
        close(r);
        close(w);
        close(epfd);
    }
}

#[test]
fn epoll_ctl_add_duplicate_fails() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let (r, w) = pipe_pair();

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r as u64,
    };
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };
    assert_eq!(rc, 0);

    // Adding same fd again should fail with EEXIST
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };
    assert_eq!(rc, -1, "duplicate ADD should fail");

    unsafe {
        close(r);
        close(w);
        close(epfd);
    }
}

#[test]
fn epoll_multiple_fds() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let (r1, w1) = pipe_pair();
    let (r2, w2) = pipe_pair();

    let mut ev1 = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r1 as u64,
    };
    let mut ev2 = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r2 as u64,
    };
    unsafe {
        epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r1, &mut ev1);
        epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r2, &mut ev2);
    }

    // Write to both pipes
    unsafe {
        libc::write(w1, b"1".as_ptr() as *const _, 1);
        libc::write(w2, b"2".as_ptr() as *const _, 1);
    }

    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 4, 100) };
    assert_eq!(n, 2, "epoll_wait should return 2 events");

    unsafe {
        close(r1);
        close(w1);
        close(r2);
        close(w2);
        close(epfd);
    }
}

#[test]
fn epoll_edge_triggered() {
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let (r, w) = pipe_pair();

    let mut ev = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLET) as u32,
        u64: r as u64,
    };
    let rc = unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };
    assert_eq!(rc, 0);

    // Write data
    unsafe { libc::write(w, b"e".as_ptr() as *const _, 1) };

    // First wait should return the event
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 1, 100) };
    assert_eq!(n, 1, "first epoll_wait should return event");

    // Second wait without reading should return 0 (edge-triggered)
    let n = unsafe { epoll_wait(epfd, events.as_mut_ptr(), 1, 0) };
    assert_eq!(
        n, 0,
        "edge-triggered: second wait without read should return 0"
    );

    unsafe {
        close(r);
        close(w);
        close(epfd);
    }
}

// ---------------------------------------------------------------------------
// epoll_pwait
// ---------------------------------------------------------------------------

#[test]
fn epoll_pwait_basic() {
    use frankenlibc_abi::poll_abi::epoll_pwait;
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let (r, w) = pipe_pair();

    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: r as u64,
    };
    unsafe { epoll_ctl(epfd, libc::EPOLL_CTL_ADD, r, &mut ev) };

    // No data — should return 0
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = unsafe { epoll_pwait(epfd, events.as_mut_ptr(), 4, 0, ptr::null()) };
    assert_eq!(n, 0, "epoll_pwait with no data should return 0");

    // Write data
    unsafe { libc::write(w, b"w".as_ptr() as *const _, 1) };
    let n = unsafe { epoll_pwait(epfd, events.as_mut_ptr(), 4, 100, ptr::null()) };
    assert_eq!(n, 1, "epoll_pwait should detect 1 event");
    assert_ne!(events[0].events & libc::EPOLLIN as u32, 0);

    unsafe {
        close(r);
        close(w);
        close(epfd);
    }
}

#[test]
fn epoll_pwait_null_events_fails() {
    use frankenlibc_abi::poll_abi::epoll_pwait;
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let n = unsafe { epoll_pwait(epfd, ptr::null_mut(), 4, 0, ptr::null()) };
    assert_eq!(n, -1, "epoll_pwait with null events should fail");
    unsafe { close(epfd) };
}

#[test]
fn epoll_pwait_zero_maxevents_fails() {
    use frankenlibc_abi::poll_abi::epoll_pwait;
    let epfd = unsafe { epoll_create1(0) };
    assert!(epfd >= 0);
    let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
    let n = unsafe { epoll_pwait(epfd, events.as_mut_ptr(), 0, 0, ptr::null()) };
    assert_eq!(n, -1, "epoll_pwait with maxevents=0 should fail");
    unsafe { close(epfd) };
}

// ---------------------------------------------------------------------------
// eventfd — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn eventfd_nonblock() {
    use frankenlibc_abi::poll_abi::eventfd;
    let fd = unsafe { eventfd(0, libc::EFD_NONBLOCK) };
    assert!(fd >= 0, "eventfd(EFD_NONBLOCK) should succeed");

    // Read on empty nonblocking eventfd should fail with EAGAIN
    let mut val: u64 = 0;
    let n = unsafe { libc::read(fd, &mut val as *mut u64 as *mut _, 8) };
    assert_eq!(n, -1, "read on empty nonblock eventfd should fail");

    unsafe { close(fd) };
}

#[test]
fn eventfd_semaphore() {
    use frankenlibc_abi::poll_abi::eventfd;
    let fd = unsafe { eventfd(0, libc::EFD_SEMAPHORE | libc::EFD_NONBLOCK) };
    assert!(fd >= 0);

    // Write 3
    let val: u64 = 3;
    unsafe { libc::write(fd, &val as *const u64 as *const _, 8) };

    // In semaphore mode, each read returns 1 and decrements
    let mut read_val: u64 = 0;
    let n = unsafe { libc::read(fd, &mut read_val as *mut u64 as *mut _, 8) };
    assert_eq!(n, 8);
    assert_eq!(read_val, 1, "semaphore mode should return 1 per read");

    let n = unsafe { libc::read(fd, &mut read_val as *mut u64 as *mut _, 8) };
    assert_eq!(n, 8);
    assert_eq!(read_val, 1);

    let n = unsafe { libc::read(fd, &mut read_val as *mut u64 as *mut _, 8) };
    assert_eq!(n, 8);
    assert_eq!(read_val, 1);

    // Counter is now 0 — next read should fail (EAGAIN)
    let n = unsafe { libc::read(fd, &mut read_val as *mut u64 as *mut _, 8) };
    assert_eq!(n, -1, "read after draining semaphore should fail");

    unsafe { close(fd) };
}

#[test]
fn eventfd_accumulates_writes() {
    use frankenlibc_abi::poll_abi::eventfd;
    let fd = unsafe { eventfd(0, 0) };
    assert!(fd >= 0);

    let v1: u64 = 10;
    let v2: u64 = 20;
    unsafe {
        libc::write(fd, &v1 as *const u64 as *const _, 8);
        libc::write(fd, &v2 as *const u64 as *const _, 8);
    }

    let mut val: u64 = 0;
    let n = unsafe { libc::read(fd, &mut val as *mut u64 as *mut _, 8) };
    assert_eq!(n, 8);
    assert_eq!(val, 30, "eventfd should accumulate written values");

    unsafe { close(fd) };
}

#[test]
fn eventfd_initial_value() {
    use frankenlibc_abi::poll_abi::eventfd;
    let fd = unsafe { eventfd(7, libc::EFD_NONBLOCK) };
    assert!(fd >= 0);

    let mut val: u64 = 0;
    let n = unsafe { libc::read(fd, &mut val as *mut u64 as *mut _, 8) };
    assert_eq!(n, 8);
    assert_eq!(val, 7, "initial value should be readable");

    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// timerfd — additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn timerfd_disarm() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_gettime, timerfd_settime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0);

    // Arm
    let new_val = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        },
    };
    let mut old_val: libc::itimerspec = unsafe { std::mem::zeroed() };
    unsafe { timerfd_settime(fd, 0, &new_val, &mut old_val) };

    // Disarm (set it_value to zero)
    let disarm = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    };
    let rc = unsafe { timerfd_settime(fd, 0, &disarm, &mut old_val) };
    assert_eq!(rc, 0);
    // old_value should have had remaining time
    assert!(
        old_val.it_value.tv_sec > 0,
        "old timer should have had time remaining"
    );

    // Verify disarmed
    let mut curr: libc::itimerspec = unsafe { std::mem::zeroed() };
    unsafe { timerfd_gettime(fd, &mut curr) };
    assert_eq!(curr.it_value.tv_sec, 0);
    assert_eq!(curr.it_value.tv_nsec, 0);

    unsafe { close(fd) };
}

#[test]
fn timerfd_create_clock_realtime() {
    use frankenlibc_abi::poll_abi::timerfd_create;
    let fd = unsafe { timerfd_create(libc::CLOCK_REALTIME, 0) };
    assert!(fd >= 0, "timerfd_create(CLOCK_REALTIME) should succeed");
    unsafe { close(fd) };
}

#[test]
fn timerfd_create_with_cloexec() {
    use frankenlibc_abi::poll_abi::timerfd_create;
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_CLOEXEC) };
    assert!(fd >= 0, "timerfd_create with TFD_CLOEXEC should succeed");
    unsafe { close(fd) };
}

#[test]
fn timerfd_create_with_nonblock() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_gettime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK) };
    assert!(fd >= 0, "timerfd_create with TFD_NONBLOCK should succeed");

    // Read on disarmed nonblock timerfd should fail with EAGAIN
    let mut val: u64 = 0;
    let n = unsafe { libc::read(fd, &mut val as *mut u64 as *mut _, 8) };
    assert_eq!(n, -1, "read on disarmed nonblock timerfd should fail");

    // gettime should still work
    let mut curr: libc::itimerspec = unsafe { std::mem::zeroed() };
    let rc = unsafe { timerfd_gettime(fd, &mut curr) };
    assert_eq!(rc, 0);

    unsafe { close(fd) };
}

#[test]
fn timerfd_settime_returns_old_value() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_settime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0);

    // Set 10s timer
    let first = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 10,
            tv_nsec: 0,
        },
    };
    let mut old: libc::itimerspec = unsafe { std::mem::zeroed() };
    unsafe { timerfd_settime(fd, 0, &first, &mut old) };
    // Old should be zero (was disarmed)
    assert_eq!(old.it_value.tv_sec, 0);

    // Set 20s timer, old should reflect remaining of first
    let second = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 20,
            tv_nsec: 0,
        },
    };
    unsafe { timerfd_settime(fd, 0, &second, &mut old) };
    assert!(
        old.it_value.tv_sec > 0,
        "old value should have remaining time from first timer"
    );

    unsafe { close(fd) };
}

#[test]
fn timerfd_settime_null_old_value() {
    use frankenlibc_abi::poll_abi::{timerfd_create, timerfd_settime};
    let fd = unsafe { timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    assert!(fd >= 0);

    let new_val = libc::itimerspec {
        it_interval: libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        it_value: libc::timespec {
            tv_sec: 5,
            tv_nsec: 0,
        },
    };
    // null old_value is valid — just doesn't return the old setting
    let rc = unsafe { timerfd_settime(fd, 0, &new_val, ptr::null_mut()) };
    assert_eq!(rc, 0, "timerfd_settime with null old_value should succeed");

    unsafe { close(fd) };
}

// ---------------------------------------------------------------------------
// prctl
// ---------------------------------------------------------------------------

#[test]
fn prctl_get_name() {
    use frankenlibc_abi::poll_abi::prctl;
    let mut name = [0u8; 16];
    let rc = unsafe {
        prctl(
            libc::PR_GET_NAME,
            name.as_mut_ptr() as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    assert_eq!(rc, 0, "PR_GET_NAME should succeed");
    // Name should be a non-empty null-terminated string
    let len = name.iter().position(|&b| b == 0).unwrap_or(16);
    assert!(len > 0, "thread name should not be empty");
}

#[test]
fn prctl_set_and_get_name() {
    use frankenlibc_abi::poll_abi::prctl;
    let new_name = b"test_thread\0";
    let rc = unsafe {
        prctl(
            libc::PR_SET_NAME,
            new_name.as_ptr() as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    assert_eq!(rc, 0, "PR_SET_NAME should succeed");

    let mut got = [0u8; 16];
    unsafe {
        prctl(
            libc::PR_GET_NAME,
            got.as_mut_ptr() as libc::c_ulong,
            0,
            0,
            0,
        )
    };
    let got_str = std::str::from_utf8(&got[..11]).unwrap();
    assert_eq!(got_str, "test_thread");
}

#[test]
fn prctl_get_dumpable() {
    use frankenlibc_abi::poll_abi::prctl;
    let rc = unsafe { prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    // Returns 0 (not dumpable) or 1 (dumpable)
    assert!(
        rc == 0 || rc == 1,
        "PR_GET_DUMPABLE should return 0 or 1, got {rc}"
    );
}

#[test]
fn prctl_set_dumpable() {
    use frankenlibc_abi::poll_abi::prctl;
    // Save current
    let saved = unsafe { prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert!(saved >= 0);

    // Set to 1 (dumpable)
    let rc = unsafe { prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
    assert_eq!(rc, 0, "PR_SET_DUMPABLE should succeed");

    let current = unsafe { prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    assert_eq!(current, 1);

    // Restore
    unsafe { prctl(libc::PR_SET_DUMPABLE, saved as libc::c_ulong, 0, 0, 0) };
}

// ---------------------------------------------------------------------------
// sched_yield — additional
// ---------------------------------------------------------------------------

#[test]
fn sched_yield_multiple() {
    use frankenlibc_abi::poll_abi::sched_yield;
    // Yielding multiple times should always succeed
    for _ in 0..10 {
        let rc = unsafe { sched_yield() };
        assert_eq!(rc, 0);
    }
}
