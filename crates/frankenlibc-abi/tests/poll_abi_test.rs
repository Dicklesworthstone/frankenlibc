#![cfg(target_os = "linux")]

//! Integration tests for I/O multiplexing ABI entrypoints.
//!
//! Covers: poll, ppoll, select, epoll_create/create1/ctl/wait, eventfd,
//! timerfd_create/settime/gettime, sched_yield.

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
    let rc = unsafe { select(r + 1, &mut readfds, ptr::null_mut(), ptr::null_mut(), &mut tv) };
    assert_eq!(rc, 0, "select with zero timeout and no data should return 0");
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
    let rc = unsafe { select(r + 1, &mut readfds, ptr::null_mut(), ptr::null_mut(), &mut tv) };
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
