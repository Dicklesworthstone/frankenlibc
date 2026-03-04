#![cfg(target_os = "linux")]

//! Integration tests for `<termios.h>` ABI entrypoints.
//!
//! Tests cfget/cfset speed functions with in-memory termios structs.
//! Terminal I/O tests (tcgetattr, tcsetattr, etc.) require a real TTY
//! and are tested only when /dev/ptmx is available.

use frankenlibc_abi::termios_abi::{cfgetispeed, cfgetospeed, cfsetispeed, cfsetospeed};

// ---------------------------------------------------------------------------
// cfgetispeed / cfgetospeed
// ---------------------------------------------------------------------------

#[test]
fn cfgetispeed_extracts_baud() {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    t.c_cflag = libc::B9600;
    let speed = unsafe { cfgetispeed(&t) };
    assert_eq!(speed, libc::B9600, "cfgetispeed should extract B9600");
}

#[test]
fn cfgetospeed_extracts_baud() {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    t.c_cflag = libc::B115200;
    let speed = unsafe { cfgetospeed(&t) };
    assert_eq!(speed, libc::B115200, "cfgetospeed should extract B115200");
}

#[test]
fn cfgetispeed_null_returns_zero() {
    let speed = unsafe { cfgetispeed(std::ptr::null()) };
    assert_eq!(speed, 0, "cfgetispeed(null) should return 0");
}

#[test]
fn cfgetospeed_null_returns_zero() {
    let speed = unsafe { cfgetospeed(std::ptr::null()) };
    assert_eq!(speed, 0, "cfgetospeed(null) should return 0");
}

// ---------------------------------------------------------------------------
// cfsetispeed / cfsetospeed
// ---------------------------------------------------------------------------

#[test]
fn cfsetispeed_sets_baud() {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe { cfsetispeed(&mut t, libc::B19200) };
    assert_eq!(rc, 0, "cfsetispeed should succeed");
    let speed = unsafe { cfgetispeed(&t) };
    assert_eq!(speed, libc::B19200);
}

#[test]
fn cfsetospeed_sets_baud() {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe { cfsetospeed(&mut t, libc::B38400) };
    assert_eq!(rc, 0, "cfsetospeed should succeed");
    let speed = unsafe { cfgetospeed(&t) };
    assert_eq!(speed, libc::B38400);
}

#[test]
fn cfsetispeed_null_fails() {
    let rc = unsafe { cfsetispeed(std::ptr::null_mut(), libc::B9600) };
    assert_eq!(rc, -1, "cfsetispeed(null) should fail");
}

#[test]
fn cfsetospeed_null_fails() {
    let rc = unsafe { cfsetospeed(std::ptr::null_mut(), libc::B9600) };
    assert_eq!(rc, -1, "cfsetospeed(null) should fail");
}

#[test]
fn cfsetispeed_preserves_other_flags() {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // Set some non-baud flags
    t.c_cflag = libc::CS8 | libc::CLOCAL | libc::B9600;
    let rc = unsafe { cfsetispeed(&mut t, libc::B57600) };
    assert_eq!(rc, 0);
    // Baud should change
    let speed = unsafe { cfgetispeed(&t) };
    assert_eq!(speed, libc::B57600);
    // Non-baud flags should be preserved
    assert_ne!(t.c_cflag & libc::CS8, 0, "CS8 should be preserved");
    assert_ne!(t.c_cflag & libc::CLOCAL, 0, "CLOCAL should be preserved");
}

// ---------------------------------------------------------------------------
// tcgetattr / tcsetattr (requires a PTY)
// ---------------------------------------------------------------------------

/// Open a pseudoterminal master, returning its fd or None.
fn open_pty_master() -> Option<i32> {
    let fd = unsafe { libc::open(c"/dev/ptmx".as_ptr(), libc::O_RDWR | libc::O_NOCTTY) };
    if fd >= 0 {
        // Grant and unlock the slave side
        unsafe {
            libc::grantpt(fd);
            libc::unlockpt(fd);
        }
        Some(fd)
    } else {
        None
    }
}

#[test]
fn tcgetattr_on_pty() {
    use frankenlibc_abi::termios_abi::tcgetattr;
    if let Some(fd) = open_pty_master() {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { tcgetattr(fd, &mut t) };
        assert_eq!(rc, 0, "tcgetattr should succeed on a PTY");
        // The termios should have some reasonable values
        assert_ne!(t.c_cflag, 0, "c_cflag should be non-zero");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcgetattr_null_termios_fails() {
    use frankenlibc_abi::termios_abi::tcgetattr;
    if let Some(fd) = open_pty_master() {
        let rc = unsafe { tcgetattr(fd, std::ptr::null_mut()) };
        assert_eq!(rc, -1, "tcgetattr with null termios should fail");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcsetattr_roundtrip_on_pty() {
    use frankenlibc_abi::termios_abi::{tcgetattr, tcsetattr};
    if let Some(fd) = open_pty_master() {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { tcgetattr(fd, &mut t) };
        assert_eq!(rc, 0);

        // Set back the same attributes
        let rc = unsafe { tcsetattr(fd, 0, &t) }; // TCSANOW = 0
        assert_eq!(rc, 0, "tcsetattr should succeed with same attrs");

        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcsetattr_null_termios_fails() {
    use frankenlibc_abi::termios_abi::tcsetattr;
    if let Some(fd) = open_pty_master() {
        let rc = unsafe { tcsetattr(fd, 0, std::ptr::null()) };
        assert_eq!(rc, -1, "tcsetattr with null termios should fail");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}
