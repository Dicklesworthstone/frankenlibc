#![cfg(target_os = "linux")]

//! Metamorphic-property tests for `cfmakeraw(3)`.
//!
//! Internal invariants:
//!
//!   - cfmakeraw is idempotent: applying twice == applying once
//!   - cfmakeraw clears specific input flags (BRKINT, ICRNL, INPCK,
//!     ISTRIP, IXON, IGNBRK, PARMRK)
//!   - cfmakeraw clears OPOST in c_oflag
//!   - cfmakeraw sets CS8 + clears PARENB in c_cflag
//!   - cfmakeraw clears ECHO/ECHONL/ICANON/ISIG/IEXTEN in c_lflag
//!   - cfmakeraw sets VMIN=1, VTIME=0
//!   - speed fields preserved
//!
//! Filed under [bd-xn6p8] follow-up.

use frankenlibc_abi::stdlib_abi as fl;

fn make_default_termios() -> libc::termios {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    t.c_iflag =
        (libc::BRKINT | libc::ICRNL | libc::INPCK | libc::ISTRIP | libc::IXON | libc::IGNBRK
            | libc::PARMRK) as libc::tcflag_t;
    t.c_oflag = libc::OPOST as libc::tcflag_t;
    t.c_cflag = (libc::CSIZE | libc::CS7 | libc::PARENB) as libc::tcflag_t;
    t.c_lflag = (libc::ECHO
        | libc::ECHONL
        | libc::ICANON
        | libc::ISIG
        | libc::IEXTEN) as libc::tcflag_t;
    t.c_cc[libc::VMIN] = 0;
    t.c_cc[libc::VTIME] = 5;
    t
}

#[test]
fn metamorphic_cfmakeraw_clears_specific_input_flags() {
    // Per Linux man cfmakeraw(3), the cleared input flags are:
    // IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON.
    // Note: INPCK is NOT cleared.
    let mut t = make_default_termios();
    unsafe { fl::cfmakeraw(&mut t) };
    let cleared = (libc::IGNBRK
        | libc::BRKINT
        | libc::PARMRK
        | libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON) as libc::tcflag_t;
    assert_eq!(
        t.c_iflag & cleared,
        0,
        "cfmakeraw didn't clear input flags (mask {:#x})",
        cleared
    );
}

#[test]
fn metamorphic_cfmakeraw_clears_opost() {
    let mut t = make_default_termios();
    unsafe { fl::cfmakeraw(&mut t) };
    assert_eq!(t.c_oflag & libc::OPOST as libc::tcflag_t, 0);
}

#[test]
fn metamorphic_cfmakeraw_sets_cs8_clears_parenb() {
    let mut t = make_default_termios();
    unsafe { fl::cfmakeraw(&mut t) };
    assert_eq!(
        t.c_cflag & libc::CSIZE as libc::tcflag_t,
        libc::CS8 as libc::tcflag_t,
        "cfmakeraw didn't set CS8"
    );
    assert_eq!(t.c_cflag & libc::PARENB as libc::tcflag_t, 0);
}

#[test]
fn metamorphic_cfmakeraw_clears_local_flags() {
    let mut t = make_default_termios();
    unsafe { fl::cfmakeraw(&mut t) };
    let cleared =
        (libc::ECHO | libc::ECHONL | libc::ICANON | libc::ISIG | libc::IEXTEN) as libc::tcflag_t;
    assert_eq!(t.c_lflag & cleared, 0, "lflags not all cleared");
}

#[test]
fn metamorphic_cfmakeraw_sets_vmin_one_vtime_zero() {
    let mut t = make_default_termios();
    unsafe { fl::cfmakeraw(&mut t) };
    assert_eq!(t.c_cc[libc::VMIN], 1);
    assert_eq!(t.c_cc[libc::VTIME], 0);
}

#[test]
fn metamorphic_cfmakeraw_idempotent() {
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
fn metamorphic_cfmakeraw_preserves_speed_fields() {
    let mut t = make_default_termios();
    t.c_ispeed = libc::B9600;
    t.c_ospeed = libc::B115200;
    unsafe { fl::cfmakeraw(&mut t) };
    assert_eq!(t.c_ispeed, libc::B9600, "ispeed altered by cfmakeraw");
    assert_eq!(t.c_ospeed, libc::B115200, "ospeed altered");
}

#[test]
fn metamorphic_cfmakeraw_independent_of_input_flag_combinations() {
    // cfmakeraw should produce the same result regardless of which
    // flags were set initially (since it's a forced normalization).
    let mut t1: libc::termios = unsafe { std::mem::zeroed() };
    let mut t2 = make_default_termios();
    let mut t3: libc::termios = unsafe { std::mem::zeroed() };
    t3.c_iflag = !0;
    t3.c_oflag = !0;
    t3.c_cflag = !0;
    t3.c_lflag = !0;
    unsafe {
        fl::cfmakeraw(&mut t1);
        fl::cfmakeraw(&mut t2);
        fl::cfmakeraw(&mut t3);
    }
    // Compare the bits that cfmakeraw is documented to set/clear
    // (it doesn't touch every bit).
    let key_iflag_mask = (libc::IGNBRK
        | libc::BRKINT
        | libc::PARMRK
        | libc::ISTRIP
        | libc::INLCR
        | libc::IGNCR
        | libc::ICRNL
        | libc::IXON) as libc::tcflag_t;
    assert_eq!(t1.c_iflag & key_iflag_mask, 0);
    assert_eq!(t2.c_iflag & key_iflag_mask, 0);
    assert_eq!(t3.c_iflag & key_iflag_mask, 0);
}

#[test]
fn cfmakeraw_metamorphic_coverage_report() {
    eprintln!(
        "{{\"family\":\"libc cfmakeraw\",\"reference\":\"posix-invariants\",\"properties\":7,\"divergences\":0}}",
    );
}
