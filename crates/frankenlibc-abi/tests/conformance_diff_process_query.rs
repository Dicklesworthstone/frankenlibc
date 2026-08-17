#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-differential calls through dlsym

//! Three process/calendar queries, each compared against the host.
//!
//! Closes bd-rkusnh (`dysize` leap-year coverage), bd-jf0obh (`getpagesize`) and
//! bd-zrgrvy (`getgroups`). They are together because they share the same shape:
//! pure queries with no arguments to get wrong, where the only way to be wrong
//! is to disagree with glibc, and where a hand-written expectation would just be
//! a second implementation of the same rule.
//!
//! `dysize` is the one with a real rule behind it. glibc computes
//! `__isleap(year) ? 366 : 365` with
//! `((year) % 4 == 0 && ((year) % 100 != 0 || (year) % 400 == 0))`, and fl writes
//! the same rule the other way round as
//! `(year % 4 == 0 && year % 100 != 0) || year % 400 == 0`. Those are equivalent
//! for every year, including negative ones under C's truncating remainder — but
//! "I checked the algebra" is not evidence, so the years below include every
//! boundary that distinguishes the two forms if either is mistyped: century
//! years, 400-multiples, and negatives of each.

use std::ffi::{CStr, c_int};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr_optional;

fn host<T: Copy>(name: &CStr, fl: *const ()) -> Option<T> {
    // SAFETY: `name` is NUL-terminated and paired with fl's own definition, so a
    // symbol that resolved back to fl is rejected rather than compared with
    // itself.
    let addr = unsafe { host_addr_optional(name, fl) }?;
    // SAFETY: the resolved symbol has the C signature named by `T`.
    Some(unsafe { std::mem::transmute_copy::<usize, T>(&(addr as usize)) })
}

#[test]
fn dysize_matches_the_host_across_every_leap_boundary() {
    type Dysize = unsafe extern "C" fn(c_int) -> c_int;
    let fl = frankenlibc_abi::glibc_internal_abi::dysize as Dysize;
    let Some(glibc) = host::<Dysize>(c"dysize", fl as *const ()) else {
        panic!("host glibc does not export dysize; this gate needs an oracle");
    };

    // Every shape that separates the two spellings of the leap rule: ordinary
    // years, a leap year, century non-leaps, 400-multiples, the epoch edges, and
    // the negatives of each — C's `%` truncates toward zero, so a negative year
    // is where a mistyped rule diverges first.
    let years: &[c_int] = &[
        0, 1, 2, 3, 4, 99, 100, 101, 399, 400, 401, 1600, 1700, 1800, 1900, 1970, 1999, 2000,
        2001, 2004, 2100, 2200, 2300, 2400, -1, -4, -100, -400, -1900, -2000, i32::MIN + 1,
        i32::MAX,
    ];

    let mut compared = 0usize;
    for &y in years {
        // SAFETY: `dysize` reads only its argument.
        let (want, got) = unsafe { (glibc(y), fl(y)) };
        assert_eq!(got, want, "dysize({y}) returned {got}, host glibc returned {want}");
        compared += 1;
    }
    assert_eq!(compared, years.len(), "the loop skipped years");
    println!("compared {compared} dysize years against the host");
}

#[test]
fn getpagesize_matches_the_host() {
    type Getpagesize = unsafe extern "C" fn() -> c_int;
    let fl = frankenlibc_abi::unistd_abi::getpagesize as Getpagesize;
    let Some(glibc) = host::<Getpagesize>(c"getpagesize", fl as *const ()) else {
        panic!("host glibc does not export getpagesize; this gate needs an oracle");
    };

    // SAFETY: no arguments, no memory touched.
    let (want, got) = unsafe { (glibc(), fl()) };
    println!("getpagesize: host {want} fl {got}");
    assert_eq!(got, want, "getpagesize returned {got}, host glibc returned {want}");
    // A page size that is not a positive power of two would be wrong even if both
    // agreed, so the agreement is checked against reality too.
    assert!(
        want > 0 && (want as u32).is_power_of_two(),
        "host reported a page size of {want}, which is not a positive power of two"
    );
}

#[test]
fn getgroups_matches_the_host_in_count_and_contents() {
    type Getgroups = unsafe extern "C" fn(c_int, *mut libc::gid_t) -> c_int;
    let fl = frankenlibc_abi::unistd_abi::getgroups as Getgroups;
    let Some(glibc) = host::<Getgroups>(c"getgroups", fl as *const ()) else {
        panic!("host glibc does not export getgroups; this gate needs an oracle");
    };

    // size 0 is the "how many?" query and must not write through the pointer.
    // SAFETY: with size 0 neither implementation may touch `list`.
    let (want_n, got_n) = unsafe {
        (
            glibc(0, std::ptr::null_mut()),
            fl(0, std::ptr::null_mut()),
        )
    };
    println!("getgroups(0, NULL): host {want_n} fl {got_n}");
    assert_eq!(
        got_n, want_n,
        "getgroups(0, NULL) returned {got_n}, host glibc returned {want_n}"
    );
    assert!(
        want_n >= 0,
        "host getgroups(0, NULL) failed with {want_n}; this process has no group list to compare"
    );

    // Now the contents, in order. Both fill caller-owned buffers of the same size.
    let n = want_n as usize;
    let mut host_buf = vec![0 as libc::gid_t; n.max(1)];
    let mut fl_buf = vec![0 as libc::gid_t; n.max(1)];
    // SAFETY: each buffer holds at least `n` gids, which is what is requested.
    let (want_rc, got_rc) = unsafe {
        (
            glibc(n as c_int, host_buf.as_mut_ptr()),
            fl(n as c_int, fl_buf.as_mut_ptr()),
        )
    };
    assert_eq!(got_rc, want_rc, "getgroups({n}, buf) returned {got_rc}, host returned {want_rc}");
    assert_eq!(
        fl_buf[..n],
        host_buf[..n],
        "getgroups filled a different group list than the host"
    );

    // A size smaller than the real count is EINVAL — the one error path that is
    // not about permissions, and the one a caller sizing a buffer hits.
    if n > 0 {
        let mut small = vec![0 as libc::gid_t; 1];
        let errno_of = |rc: c_int| -> c_int {
            if rc >= 0 {
                0
            } else {
                std::io::Error::last_os_error().raw_os_error().unwrap_or_default()
            }
        };
        // SAFETY: the buffer holds one gid and one is requested.
        let want_rc = unsafe { glibc(1, small.as_mut_ptr()) };
        let want_e = errno_of(want_rc);
        // SAFETY: same.
        let got_rc = unsafe { fl(1, small.as_mut_ptr()) };
        let got_e = errno_of(got_rc);
        println!("getgroups(1, buf) with {n} groups: host rc={want_rc} errno={want_e} fl rc={got_rc} errno={got_e}");
        assert_eq!(
            (got_rc, got_e),
            (want_rc, want_e),
            "undersized getgroups: fl (rc={got_rc}, errno={got_e}), host (rc={want_rc}, errno={want_e})"
        );
    }
}
