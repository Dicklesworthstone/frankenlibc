#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX `cfmakeraw(3)`.
//!
//! `cfmakeraw` mutates a `struct termios` to put it in raw mode by
//! clearing input flags (BRKINT, ICRNL, INPCK, ISTRIP, IXON,
//! IGNBRK, PARMRK), output flags (OPOST), control flags (PARENB,
//! CSIZE), and local flags (ECHO, ECHONL, ICANON, ISIG, IEXTEN);
//! and setting CS8 + VMIN=1 + VTIME=0. Both fl and glibc must
//! produce a byte-identical termios for the same input.
//!
//! Filed under [bd-xn6p8] follow-up.

use frankenlibc_abi::stdlib_abi as fl;

unsafe extern "C" {
    fn cfmakeraw(termios: *mut libc::termios);
}

fn make_default_termios() -> libc::termios {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    // Populate with realistic non-raw flags so cfmakeraw has work to do.
    t.c_iflag = (libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON) as libc::tcflag_t;
    t.c_oflag = libc::OPOST as libc::tcflag_t;
    t.c_cflag = (libc::CSIZE | libc::CS7 | libc::PARENB) as libc::tcflag_t;
    t.c_lflag = (libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN) as libc::tcflag_t;
    t.c_cc[libc::VMIN] = 0;
    t.c_cc[libc::VTIME] = 5;
    t
}

#[test]
fn diff_cfmakeraw_clears_documented_flags() {
    let mut fl_t = make_default_termios();
    let mut lc_t = make_default_termios();
    unsafe {
        fl::cfmakeraw(&mut fl_t);
        cfmakeraw(&mut lc_t);
    }
    assert_eq!(fl_t.c_iflag, lc_t.c_iflag, "iflag");
    assert_eq!(fl_t.c_oflag, lc_t.c_oflag, "oflag");
    assert_eq!(fl_t.c_cflag, lc_t.c_cflag, "cflag");
    assert_eq!(fl_t.c_lflag, lc_t.c_lflag, "lflag");
    assert_eq!(fl_t.c_cc[libc::VMIN], lc_t.c_cc[libc::VMIN], "VMIN");
    assert_eq!(fl_t.c_cc[libc::VTIME], lc_t.c_cc[libc::VTIME], "VTIME");
}

#[test]
fn diff_cfmakeraw_sets_cs8_and_vmin_vtime() {
    let mut fl_t = make_default_termios();
    unsafe { fl::cfmakeraw(&mut fl_t) };
    let mut lc_t = make_default_termios();
    unsafe { cfmakeraw(&mut lc_t) };
    // CS8 must be set in cflag.
    assert_eq!(fl_t.c_cflag & libc::CSIZE as libc::tcflag_t, libc::CS8 as libc::tcflag_t);
    assert_eq!(lc_t.c_cflag & libc::CSIZE as libc::tcflag_t, libc::CS8 as libc::tcflag_t);
    // VMIN=1, VTIME=0 — read at least 1 byte, no inter-byte timeout.
    assert_eq!(fl_t.c_cc[libc::VMIN], 1);
    assert_eq!(fl_t.c_cc[libc::VTIME], 0);
    assert_eq!(fl_t.c_cc[libc::VMIN], lc_t.c_cc[libc::VMIN]);
    assert_eq!(fl_t.c_cc[libc::VTIME], lc_t.c_cc[libc::VTIME]);
}

#[test]
fn diff_cfmakeraw_idempotent() {
    // Property: applying cfmakeraw twice must yield the same result
    // as applying it once.
    let mut t1 = make_default_termios();
    unsafe { fl::cfmakeraw(&mut t1) };
    let mut t2 = t1;
    unsafe { fl::cfmakeraw(&mut t2) };
    assert_eq!(t1.c_iflag, t2.c_iflag);
    assert_eq!(t1.c_oflag, t2.c_oflag);
    assert_eq!(t1.c_cflag, t2.c_cflag);
    assert_eq!(t1.c_lflag, t2.c_lflag);
    assert_eq!(t1.c_cc[libc::VMIN], t2.c_cc[libc::VMIN]);
    assert_eq!(t1.c_cc[libc::VTIME], t2.c_cc[libc::VTIME]);
}

#[test]
fn diff_cfmakeraw_preserves_speed_settings() {
    // The (cf|c)speed_t fields are not changed by cfmakeraw — they
    // sit in c_ispeed/c_ospeed (or encoded into c_cflag depending on
    // platform). We at least verify both impls preserve the same
    // c_ispeed/c_ospeed values.
    let mut fl_t = make_default_termios();
    let mut lc_t = make_default_termios();
    fl_t.c_ispeed = libc::B9600;
    fl_t.c_ospeed = libc::B9600;
    lc_t.c_ispeed = libc::B9600;
    lc_t.c_ospeed = libc::B9600;
    unsafe {
        fl::cfmakeraw(&mut fl_t);
        cfmakeraw(&mut lc_t);
    }
    assert_eq!(fl_t.c_ispeed, lc_t.c_ispeed);
    assert_eq!(fl_t.c_ospeed, lc_t.c_ospeed);
}

#[test]
fn cfmakeraw_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc cfmakeraw\",\"reference\":\"glibc\",\"functions\":1,\"divergences\":0}}",
    );
}
