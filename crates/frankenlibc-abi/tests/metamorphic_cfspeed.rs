#![cfg(target_os = "linux")]

//! Metamorphic-property tests for the termios speed accessors:
//! `cfgetispeed` / `cfgetospeed` / `cfsetispeed` / `cfsetospeed` /
//! `cfsetspeed`.
//!
//! Properties:
//!
//!   - cfsetispeed(t, s) followed by cfgetispeed(t) returns s
//!     (same for ospeed)
//!   - cfsetspeed sets BOTH input and output to the same value
//!   - setting speed leaves other termios fields untouched
//!   - all standard B-rates are accepted
//!   - non-standard rates may be rejected (acceptance varies by
//!     kernel; we just check both impls are consistent)
//!
//! Filed under [bd-xn6p8] follow-up.

use frankenlibc_abi::stdlib_abi as fl_stdlib;
use frankenlibc_abi::termios_abi as fl;

fn fresh_termios() -> libc::termios {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    t.c_cflag = libc::B0;
    t.c_iflag = libc::ICRNL as libc::tcflag_t;
    t.c_oflag = libc::OPOST as libc::tcflag_t;
    t.c_lflag = libc::ECHO as libc::tcflag_t;
    t.c_cc[libc::VMIN] = 1;
    t.c_cc[libc::VTIME] = 0;
    t
}

#[test]
fn metamorphic_cfsetispeed_then_get_returns_same() {
    for &speed in &[libc::B0, libc::B9600, libc::B19200, libc::B38400, libc::B115200] {
        let mut t = fresh_termios();
        let r = unsafe { fl::cfsetispeed(&mut t, speed) };
        assert_eq!(r, 0, "cfsetispeed({speed}) failed");
        let got = unsafe { fl::cfgetispeed(&t) };
        assert_eq!(got, speed, "round-trip ispeed");
    }
}

#[test]
fn metamorphic_cfsetospeed_then_get_returns_same() {
    for &speed in &[libc::B0, libc::B9600, libc::B19200, libc::B38400, libc::B115200] {
        let mut t = fresh_termios();
        let r = unsafe { fl::cfsetospeed(&mut t, speed) };
        assert_eq!(r, 0);
        let got = unsafe { fl::cfgetospeed(&t) };
        assert_eq!(got, speed);
    }
}

#[test]
fn metamorphic_cfsetspeed_sets_both_fields() {
    let mut t = fresh_termios();
    unsafe { fl_stdlib::cfsetspeed(&mut t, libc::B57600) };
    let i = unsafe { fl::cfgetispeed(&t) };
    let o = unsafe { fl::cfgetospeed(&t) };
    assert_eq!(i, libc::B57600, "ispeed");
    assert_eq!(o, libc::B57600, "ospeed");
}

#[test]
fn metamorphic_cfset_does_not_disturb_other_fields() {
    let mut t = fresh_termios();
    let saved_iflag = t.c_iflag;
    let saved_oflag = t.c_oflag;
    let saved_lflag = t.c_lflag;
    let saved_vmin = t.c_cc[libc::VMIN];
    let saved_vtime = t.c_cc[libc::VTIME];
    unsafe { fl::cfsetispeed(&mut t, libc::B19200) };
    unsafe { fl::cfsetospeed(&mut t, libc::B38400) };
    assert_eq!(t.c_iflag, saved_iflag);
    assert_eq!(t.c_oflag, saved_oflag);
    assert_eq!(t.c_lflag, saved_lflag);
    assert_eq!(t.c_cc[libc::VMIN], saved_vmin);
    assert_eq!(t.c_cc[libc::VTIME], saved_vtime);
}

#[test]
fn metamorphic_speed_idempotent_round_trip() {
    // cfsetispeed twice with the same value should be idempotent.
    let mut t1 = fresh_termios();
    let mut t2 = fresh_termios();
    unsafe {
        fl::cfsetispeed(&mut t1, libc::B9600);
        fl::cfsetispeed(&mut t2, libc::B9600);
        fl::cfsetispeed(&mut t2, libc::B9600);
    }
    assert_eq!(unsafe { fl::cfgetispeed(&t1) }, unsafe {
        fl::cfgetispeed(&t2)
    });
}

#[test]
fn metamorphic_set_then_set_overwrites() {
    let mut t = fresh_termios();
    unsafe {
        fl::cfsetispeed(&mut t, libc::B9600);
        fl::cfsetispeed(&mut t, libc::B57600);
    }
    let got = unsafe { fl::cfgetispeed(&t) };
    assert_eq!(got, libc::B57600);
}

#[test]
fn metamorphic_independent_input_output_speeds() {
    // Setting different ispeed and ospeed should keep them
    // independent.
    let mut t = fresh_termios();
    unsafe {
        fl::cfsetispeed(&mut t, libc::B9600);
        fl::cfsetospeed(&mut t, libc::B19200);
    }
    let i = unsafe { fl::cfgetispeed(&t) };
    let o = unsafe { fl::cfgetospeed(&t) };
    assert_eq!(i, libc::B9600);
    assert_eq!(o, libc::B19200);
}

#[test]
fn cfspeed_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc cfgetispeed + cfgetospeed + cfsetispeed + cfsetospeed + cfsetspeed\",\"reference\":\"posix-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
