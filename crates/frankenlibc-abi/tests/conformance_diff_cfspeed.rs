#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc cfset/cfget*speed oracle

//! `cfsetispeed`/`cfsetospeed`/`cfsetspeed` parity vs host glibc.
//!
//! glibc has two ABIs here. The GLIBC_2.2.5 symbols take a legacy `Bxxx`
//! code (`B38400 == 017`) and reject anything else with EINVAL (bd-wc9fye).
//! glibc 2.42 made `speed_t` the plain baud number: its default
//! `cfsetispeed@@GLIBC_2.42` accepts ANY value, encodes a standard rate as its
//! CBAUD code in `c_cflag` and any other rate as BOTHER, and keeps the number
//! in `c_ispeed`/`c_ospeed` (measured on 2.43). Both oracles are resolved by
//! version with dlvsym, so the test exercises whichever the running glibc
//! has, independent of the glibc it was linked against.
//!
//! fl exports one unversioned symbol, so it serves both kinds of caller:
//! numeric rates get the 2.42 semantics, and a legacy code value (`01..=017`,
//! `010001..=010017`) selects the rate it names. `c_ispeed`/`c_ospeed` keep
//! the argument as passed, so `cfget*speed` returns what the same caller set.
//! Deliberate deviation, pinned below: glibc 2.42 reads those code values as
//! literal 1-15 / 4097-4111 baud BOTHER rates. Python's tty/termios tests
//! (cfsetispeed(t, 38400) under glibc 2.43) failed with EINVAL before this.

use std::ffi::{CStr, c_int};

use frankenlibc_abi::stdlib_abi::cfsetspeed as fl_cfsetspeed;
use frankenlibc_abi::termios_abi as fl;

type SetFn = unsafe extern "C" fn(*mut libc::termios, libc::speed_t) -> c_int;
type GetFn = unsafe extern "C" fn(*const libc::termios) -> libc::speed_t;

/// glibc's `name@version`, if the running glibc defines it.
fn versioned<T: Copy>(name: &CStr, version: &CStr) -> Option<T> {
    assert_eq!(size_of::<T>(), size_of::<*mut libc::c_void>());
    let sym = unsafe { libc::dlvsym(libc::RTLD_DEFAULT, name.as_ptr(), version.as_ptr()) };
    // SAFETY: T is the function-pointer type of that glibc symbol.
    (!sym.is_null()).then(|| unsafe { std::mem::transmute_copy(&sym) })
}

/// One glibc ABI's cfsetispeed, cfsetospeed, cfsetspeed.
struct Oracle([SetFn; 3]);

impl Oracle {
    fn of(version: &CStr) -> Option<Self> {
        Some(Self([
            versioned(c"cfsetispeed", version)?,
            versioned(c"cfsetospeed", version)?,
            versioned(c"cfsetspeed", version)?,
        ]))
    }

    fn set(&self, speed: u32, which: u8) -> SetResult {
        let mut t: libc::termios = unsafe { std::mem::zeroed() };
        let rc = unsafe { self.0[usize::from(which)](&mut t, speed) };
        SetResult::of(rc, &t)
    }
}

fn legacy() -> Oracle {
    Oracle::of(c"GLIBC_2.2.5").expect("every x86_64 glibc has the GLIBC_2.2.5 symbols")
}

fn numeric() -> Option<Oracle> {
    let oracle = Oracle::of(c"GLIBC_2.42");
    println!(
        "glibc 2.42 numeric-speed symbols present: {}",
        oracle.is_some()
    );
    oracle
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct SetResult {
    rc: i32,
    cflag: u64,
    ispeed: u64,
    ospeed: u64,
}

impl SetResult {
    fn of(rc: c_int, t: &libc::termios) -> Self {
        Self {
            rc,
            cflag: u64::from(t.c_cflag),
            ispeed: u64::from(t.c_ispeed),
            ospeed: u64::from(t.c_ospeed),
        }
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
    SetResult::of(rc, &t)
}

/// (standard rate, its legacy CBAUD code) -- the `libc` crate's `Bxxx`
/// constants are the legacy codes.
fn standard_rates() -> Vec<(u32, u32)> {
    vec![
        (0, libc::B0),
        (50, libc::B50),
        (75, libc::B75),
        (110, libc::B110),
        (134, libc::B134),
        (150, libc::B150),
        (200, libc::B200),
        (300, libc::B300),
        (600, libc::B600),
        (1200, libc::B1200),
        (1800, libc::B1800),
        (2400, libc::B2400),
        (4800, libc::B4800),
        (9600, libc::B9600),
        (19200, libc::B19200),
        (38400, libc::B38400),
        (57600, libc::B57600),
        (115200, libc::B115200),
        (230400, libc::B230400),
        (460800, libc::B460800),
        (500000, libc::B500000),
        (576000, libc::B576000),
        (921600, libc::B921600),
        (1000000, libc::B1000000),
        (1152000, libc::B1152000),
        (1500000, libc::B1500000),
        (2000000, libc::B2000000),
        (2500000, libc::B2500000),
        (3000000, libc::B3000000),
        (3500000, libc::B3500000),
        (4000000, libc::B4000000),
    ]
}

/// Rates with no CBAUD code: glibc 2.42 stores them as BOTHER.
const NONSTANDARD_RATES: [u32; 7] = [12345, 31250, 4096, 4112, 5000000, 0x7fff_ffff, 0xffff_ffff];

/// The struct glibc 2.42 produces from a zeroed termios (measured on 2.43):
/// the rate's code (or BOTHER) in the CBAUD and/or CIBAUD bits, the number
/// in c_ispeed and/or c_ospeed.
fn expected_numeric(rate: u32, code: u32, which: u8) -> SetResult {
    let (input, output) = match which {
        0 => (true, false),
        1 => (false, true),
        _ => (true, true),
    };
    SetResult {
        rc: 0,
        cflag: u64::from(if output { code } else { 0 })
            | u64::from(if input { code << 16 } else { 0 }),
        ispeed: if input { u64::from(rate) } else { 0 },
        ospeed: if output { u64::from(rate) } else { 0 },
    }
}

#[test]
fn numeric_rates_follow_glibc_2_42() {
    let numeric = numeric();
    let legacy = legacy();
    let cases = standard_rates()
        .into_iter()
        .chain(NONSTANDARD_RATES.iter().map(|&r| (r, libc::BOTHER)));
    let (mut compared, mut legacy_rejects) = (0, 0);
    for (rate, code) in cases {
        for which in 0u8..3 {
            let f = fl_set(rate, which);
            assert_eq!(
                f,
                expected_numeric(rate, code, which),
                "rate {rate} which={which}"
            );
            if let Some(numeric) = &numeric {
                assert_eq!(
                    numeric.set(rate, which),
                    f,
                    "glibc 2.42 parity: rate {rate} which={which}"
                );
                compared += 1;
            }
            // The legacy ABI rejects numeric rates; fl serves the 2.42 one.
            if rate > 0o10017 && legacy.set(rate, which).rc == -1 {
                legacy_rejects += 1;
            }
        }
    }
    println!("{compared} structs equal to glibc 2.42; legacy ABI rejected {legacy_rejects}");
    assert!(
        legacy_rejects > 0,
        "the legacy oracle is not the legacy ABI"
    );
}

#[test]
fn legacy_codes_select_the_rate_they_name() {
    let numeric = numeric();
    let legacy = legacy();
    for (rate, code) in standard_rates().into_iter().skip(1) {
        for which in 0u8..3 {
            let f = fl_set(code, which);
            let named = expected_numeric(rate, code, which);
            // The rate's code in the cflag; the argument itself kept as passed.
            let kept = |field: u64| if field == 0 { 0 } else { u64::from(code) };
            assert_eq!(
                f,
                SetResult {
                    ispeed: kept(named.ispeed),
                    ospeed: kept(named.ospeed),
                    ..named
                },
                "legacy code {code:#o} which={which}"
            );
            let g = legacy.set(code, which);
            assert_eq!(
                (g.rc, g.cflag),
                (f.rc, f.cflag),
                "legacy glibc {code:#o} which={which}"
            );
            if let Some(numeric) = &numeric {
                // The deliberate deviation: glibc 2.42 takes the value as a
                // literal BOTHER rate.
                assert_eq!(
                    numeric.set(code, which),
                    expected_numeric(code, libc::BOTHER, which),
                    "glibc 2.42 {code:#o}"
                );
            }
        }
    }
}

#[test]
fn cfget_returns_what_was_set() {
    let numeric_get: Option<[GetFn; 2]> = (|| {
        Some([
            versioned(c"cfgetispeed", c"GLIBC_2.42")?,
            versioned(c"cfgetospeed", c"GLIBC_2.42")?,
        ])
    })();
    let numeric = numeric();
    let values = standard_rates()
        .into_iter()
        .flat_map(|(rate, code)| [rate, code])
        .chain(NONSTANDARD_RATES);
    for s in values {
        let mut tf: libc::termios = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(fl::cfsetispeed(&mut tf, s), 0);
            assert_eq!(fl::cfsetospeed(&mut tf, s), 0);
            assert_eq!(fl::cfgetispeed(&tf), s, "cfgetispeed after {s}");
            assert_eq!(fl::cfgetospeed(&tf), s, "cfgetospeed after {s}");
        }
        let legacy_code = s != 0 && standard_rates().iter().any(|&(_, c)| c == s);
        if let (Some(numeric), Some([geti, geto])) = (&numeric, numeric_get)
            && !legacy_code
        {
            let mut tg: libc::termios = unsafe { std::mem::zeroed() };
            unsafe {
                numeric.0[0](&mut tg, s);
                numeric.0[1](&mut tg, s);
                assert_eq!((geti(&tg), geto(&tg)), (s, s), "glibc 2.42 get after {s}");
            }
        }
    }
}
