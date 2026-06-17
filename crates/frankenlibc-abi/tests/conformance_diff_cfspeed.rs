#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cfset/cfget*speed oracle

//! `cfsetispeed`/`cfsetospeed`/`cfsetspeed` parity vs host glibc (bd-wc9fye).
//!
//! glibc accepts ONLY a recognized `Bxxx` baud-rate constant; any other value
//! — `BOTHER`, a raw numeric baud such as 9600, or garbage — is rejected with
//! `-1`/`EINVAL` and the `struct termios` is left unchanged. fl previously
//! substituted `BOTHER` and returned `0`, diverging on both the return value
//! and the resulting `c_cflag` baud bits.
//!
//! This gate pins, for every probed speed, that fl matches glibc on:
//!   * the return code,
//!   * the resulting `c_cflag` (baud bits),
//!   * the full struct when the speed is rejected (unchanged), and
//!   * the `cfget{i,o}speed` round-trip for accepted speeds.
//!
//! KNOWN RESIDUAL (not asserted, documented): for an *accepted* constant glibc
//! decodes it to the numeric baud in the raw `c_ispeed`/`c_ospeed` field
//! (B9600 -> 9600) whereas fl stores the constant (13). It is observable only
//! by reading the raw field directly; fl is self-consistent through the
//! `cf*speed` API (cfget returns the same constant glibc does, from the cflag
//! bits), so the observable round-trip matches.

use frankenlibc_abi::stdlib_abi::cfsetspeed as fl_cfsetspeed;
use frankenlibc_abi::termios_abi as fl;

#[derive(Debug, PartialEq, Eq)]
struct SetResult {
    rc: i32,
    cflag: u64,
    ispeed: u64,
    ospeed: u64,
}

fn glibc_set(speed: u32, which: u8) -> SetResult {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        match which {
            0 => libc::cfsetispeed(&mut t, speed as libc::speed_t),
            1 => libc::cfsetospeed(&mut t, speed as libc::speed_t),
            _ => libc::cfsetspeed(&mut t, speed as libc::speed_t),
        }
    };
    SetResult {
        rc,
        cflag: t.c_cflag as u64,
        ispeed: t.c_ispeed as u64,
        ospeed: t.c_ospeed as u64,
    }
}

fn fl_set(speed: u32, which: u8) -> SetResult {
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        match which {
            0 => fl::cfsetispeed(&mut t, speed),
            1 => fl::cfsetospeed(&mut t, speed),
            _ => fl_cfsetspeed(&mut t, speed as libc::speed_t),
        }
    };
    SetResult {
        rc,
        cflag: t.c_cflag as u64,
        ispeed: t.c_ispeed as u64,
        ospeed: t.c_ospeed as u64,
    }
}

/// The recognized baud constants (accepted by glibc).
fn valid_constants() -> Vec<u32> {
    vec![
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
        libc::B57600,
        libc::B115200,
        libc::B230400,
        libc::B460800,
        libc::B500000,
        libc::B576000,
        libc::B921600,
        libc::B1000000,
        libc::B1152000,
        libc::B1500000,
        libc::B2000000,
        libc::B2500000,
        libc::B3000000,
        libc::B3500000,
        libc::B4000000,
    ]
}

/// Values glibc rejects: BOTHER, numeric bauds, and out-of-table bit patterns.
fn invalid_speeds() -> Vec<u32> {
    vec![
        libc::BOTHER,
        9600,
        115200,
        19200,
        0x10,
        0x1010,
        0x1011,
        0x2000,
        0x7fff_ffff,
        0xffff_ffff,
    ]
}

#[test]
fn valid_constants_match_glibc_rc_and_cflag() {
    for which in 0u8..3 {
        for s in valid_constants() {
            let g = glibc_set(s, which);
            let f = fl_set(s, which);
            assert_eq!(g.rc, f.rc, "rc mismatch which={which} speed=0x{s:x}");
            assert_eq!(g.rc, 0, "valid constant 0x{s:x} must be accepted");
            assert_eq!(
                g.cflag, f.cflag,
                "c_cflag mismatch which={which} speed=0x{s:x}: glibc=0x{:x} fl=0x{:x}",
                g.cflag, f.cflag
            );
        }
    }
}

#[test]
fn invalid_speeds_rejected_like_glibc() {
    for which in 0u8..3 {
        for s in invalid_speeds() {
            let g = glibc_set(s, which);
            let f = fl_set(s, which);
            assert_eq!(
                g.rc, -1,
                "glibc must reject invalid speed 0x{s:x} (which={which})"
            );
            // Full struct parity on rejection: nothing is mutated.
            assert_eq!(
                g, f,
                "rejection mismatch which={which} speed=0x{s:x}: glibc={g:?} fl={f:?}"
            );
        }
    }
}

#[test]
fn cfget_roundtrip_matches_glibc() {
    // For accepted constants, the cf*speed API round-trip (set then get) must
    // agree with glibc, even though the raw c_ispeed/c_ospeed field encoding
    // differs (documented residual).
    for s in valid_constants() {
        let mut tg: libc::termios = unsafe { std::mem::zeroed() };
        let mut tf: libc::termios = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(libc::cfsetispeed(&mut tg, s as libc::speed_t), 0);
            assert_eq!(libc::cfsetospeed(&mut tg, s as libc::speed_t), 0);
            assert_eq!(fl::cfsetispeed(&mut tf, s), 0);
            assert_eq!(fl::cfsetospeed(&mut tf, s), 0);
        }
        let gi = unsafe { libc::cfgetispeed(&tg) } as u64;
        let go = unsafe { libc::cfgetospeed(&tg) } as u64;
        let fi = unsafe { fl::cfgetispeed(&tf) } as u64;
        let fo = unsafe { fl::cfgetospeed(&tf) } as u64;
        assert_eq!(gi, fi, "cfgetispeed round-trip mismatch for 0x{s:x}");
        assert_eq!(go, fo, "cfgetospeed round-trip mismatch for 0x{s:x}");
    }
}
