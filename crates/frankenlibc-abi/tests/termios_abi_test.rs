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

// ---------------------------------------------------------------------------
// cfsetispeed / cfsetospeed: more baud rates
// ---------------------------------------------------------------------------

#[test]
fn cfsetispeed_all_standard_rates() {
    let rates: &[u32] = &[
        libc::B0,
        libc::B50,
        libc::B75,
        libc::B110,
        libc::B134,
        libc::B150,
        libc::B200,
        libc::B300,
        libc::B600,
        libc::B1200,
        libc::B1800,
        libc::B2400,
        libc::B4800,
        libc::B9600,
        libc::B19200,
        libc::B38400,
    ];

    for &rate in rates {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { cfsetispeed(&mut t, rate) };
        assert_eq!(rc, 0, "cfsetispeed(B{rate}) should succeed");
        let got = unsafe { cfgetispeed(&t) };
        assert_eq!(got, rate, "cfgetispeed should return B{rate}");
    }
}

#[test]
fn cfsetospeed_high_rates() {
    let rates: &[u32] = &[
        libc::B57600,
        libc::B115200,
        libc::B230400,
        libc::B460800,
        libc::B500000,
        libc::B576000,
        libc::B921600,
        libc::B1000000,
    ];

    for &rate in rates {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { cfsetospeed(&mut t, rate) };
        assert_eq!(rc, 0, "cfsetospeed(B{rate}) should succeed");
        let got = unsafe { cfgetospeed(&t) };
        assert_eq!(got, rate, "cfgetospeed should return B{rate}");
    }
}

#[test]
fn cfset_input_output_independent() {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    unsafe { cfsetispeed(&mut t, libc::B9600) };
    unsafe { cfsetospeed(&mut t, libc::B115200) };

    // On Linux, c_cflag stores both and they may overlap,
    // but setting output should not corrupt prior flags
    let ospeed = unsafe { cfgetospeed(&t) };
    assert_eq!(ospeed, libc::B115200, "output speed should be B115200");
}

// ---------------------------------------------------------------------------
// tcdrain / tcflush / tcsendbreak / tcflow on PTY
// ---------------------------------------------------------------------------

#[test]
fn tcdrain_on_pty() {
    use frankenlibc_abi::termios_abi::tcdrain;
    if let Some(fd) = open_pty_master() {
        let rc = unsafe { tcdrain(fd) };
        assert_eq!(rc, 0, "tcdrain should succeed on PTY");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcdrain_bad_fd() {
    use frankenlibc_abi::termios_abi::tcdrain;
    let rc = unsafe { tcdrain(-1) };
    assert_eq!(rc, -1, "tcdrain on bad fd should fail");
}

#[test]
fn tcflush_on_pty() {
    use frankenlibc_abi::termios_abi::tcflush;
    if let Some(fd) = open_pty_master() {
        // TCIFLUSH=0, TCOFLUSH=1, TCIOFLUSH=2
        let rc = unsafe { tcflush(fd, libc::TCIFLUSH) };
        assert_eq!(rc, 0, "tcflush(TCIFLUSH) should succeed");

        let rc = unsafe { tcflush(fd, libc::TCOFLUSH) };
        assert_eq!(rc, 0, "tcflush(TCOFLUSH) should succeed");

        let rc = unsafe { tcflush(fd, libc::TCIOFLUSH) };
        assert_eq!(rc, 0, "tcflush(TCIOFLUSH) should succeed");

        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcflush_bad_fd() {
    use frankenlibc_abi::termios_abi::tcflush;
    let rc = unsafe { tcflush(-1, libc::TCIFLUSH) };
    assert_eq!(rc, -1, "tcflush on bad fd should fail");
}

#[test]
fn tcsendbreak_on_pty() {
    use frankenlibc_abi::termios_abi::tcsendbreak;
    if let Some(fd) = open_pty_master() {
        let rc = unsafe { tcsendbreak(fd, 0) };
        assert_eq!(rc, 0, "tcsendbreak should succeed on PTY");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcsendbreak_bad_fd() {
    use frankenlibc_abi::termios_abi::tcsendbreak;
    let rc = unsafe { tcsendbreak(-1, 0) };
    assert_eq!(rc, -1, "tcsendbreak on bad fd should fail");
}

#[test]
fn tcflow_on_pty() {
    use frankenlibc_abi::termios_abi::tcflow;
    if let Some(fd) = open_pty_master() {
        // TCOOFF=0, TCOON=1
        let rc = unsafe { tcflow(fd, libc::TCOOFF) };
        assert_eq!(rc, 0, "tcflow(TCOOFF) should succeed");

        let rc = unsafe { tcflow(fd, libc::TCOON) };
        assert_eq!(rc, 0, "tcflow(TCOON) should succeed");

        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcflow_bad_fd() {
    use frankenlibc_abi::termios_abi::tcflow;
    let rc = unsafe { tcflow(-1, libc::TCOON) };
    assert_eq!(rc, -1, "tcflow on bad fd should fail");
}

// ---------------------------------------------------------------------------
// tcgetattr on bad fd
// ---------------------------------------------------------------------------

#[test]
fn tcgetattr_bad_fd() {
    use frankenlibc_abi::termios_abi::tcgetattr;
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe { tcgetattr(-1, &mut t) };
    assert_eq!(rc, -1, "tcgetattr on bad fd should fail");
}

#[test]
fn tcsetattr_bad_fd() {
    use frankenlibc_abi::termios_abi::tcsetattr;
    let t: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe { tcsetattr(-1, 0, &t) };
    assert_eq!(rc, -1, "tcsetattr on bad fd should fail");
}

// ---------------------------------------------------------------------------
// tcsetattr with different optional_actions
// ---------------------------------------------------------------------------

#[test]
fn tcsetattr_tcsadrain_on_pty() {
    use frankenlibc_abi::termios_abi::{tcgetattr, tcsetattr};
    if let Some(fd) = open_pty_master() {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { tcgetattr(fd, &mut t) };
        let rc = unsafe { tcsetattr(fd, libc::TCSADRAIN, &t) };
        assert_eq!(rc, 0, "tcsetattr(TCSADRAIN) should succeed");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}

#[test]
fn tcsetattr_tcsaflush_on_pty() {
    use frankenlibc_abi::termios_abi::{tcgetattr, tcsetattr};
    if let Some(fd) = open_pty_master() {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        unsafe { tcgetattr(fd, &mut t) };
        let rc = unsafe { tcsetattr(fd, libc::TCSAFLUSH, &t) };
        assert_eq!(rc, 0, "tcsetattr(TCSAFLUSH) should succeed");
        unsafe { frankenlibc_abi::unistd_abi::close(fd) };
    }
}
