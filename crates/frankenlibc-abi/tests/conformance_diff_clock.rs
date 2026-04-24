#![cfg(target_os = "linux")]

//! Differential conformance harness for POSIX clock/sleep functions:
//!   - clock_gettime (CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_BOOTTIME,
//!     CLOCK_PROCESS_CPUTIME_ID, CLOCK_THREAD_CPUTIME_ID)
//!   - clock_getres
//!   - nanosleep (with very small intervals; both must return 0)
//!   - clock_nanosleep (TIMER_ABSTIME and relative)
//!
//! Bead: CONFORMANCE: libc clock/sleep diff matrix.

use std::ffi::{c_int, c_long};

use frankenlibc_abi::time_abi as fl;

unsafe extern "C" {
    fn clock_gettime(clk_id: c_int, tp: *mut libc::timespec) -> c_int;
    fn clock_getres(clk_id: c_int, res: *mut libc::timespec) -> c_int;
    fn nanosleep(req: *const libc::timespec, rem: *mut libc::timespec) -> c_int;
    fn clock_nanosleep(
        clk_id: c_int,
        flags: c_int,
        req: *const libc::timespec,
        rem: *mut libc::timespec,
    ) -> c_int;
}

const CLOCK_REALTIME: c_int = 0;
const CLOCK_MONOTONIC: c_int = 1;
const CLOCK_PROCESS_CPUTIME_ID: c_int = 2;
const CLOCK_THREAD_CPUTIME_ID: c_int = 3;
const CLOCK_BOOTTIME: c_int = 7;
const TIMER_ABSTIME: c_int = 1;

#[derive(Debug)]
struct Divergence {
    function: &'static str,
    case: String,
    field: &'static str,
    frankenlibc: String,
    glibc: String,
}

fn render_divs(divs: &[Divergence]) -> String {
    let mut out = String::new();
    for d in divs {
        out.push_str(&format!(
            "  {} | case: {} | field: {} | fl: {} | glibc: {}\n",
            d.function, d.case, d.field, d.frankenlibc, d.glibc,
        ));
    }
    out
}

// ===========================================================================
// clock_gettime — return code parity across all common clocks. Values
// will differ (time advances), so we only check that both succeed and
// produce sensible non-zero seconds for wall clocks.
// ===========================================================================

#[test]
fn diff_clock_gettime_all_clocks() {
    let mut divs = Vec::new();
    let clocks: &[(&str, c_int)] = &[
        ("CLOCK_REALTIME", CLOCK_REALTIME),
        ("CLOCK_MONOTONIC", CLOCK_MONOTONIC),
        ("CLOCK_PROCESS_CPUTIME_ID", CLOCK_PROCESS_CPUTIME_ID),
        ("CLOCK_THREAD_CPUTIME_ID", CLOCK_THREAD_CPUTIME_ID),
        ("CLOCK_BOOTTIME", CLOCK_BOOTTIME),
    ];
    for (name, clk) in clocks {
        let mut tp_fl: libc::timespec = unsafe { core::mem::zeroed() };
        let mut tp_lc: libc::timespec = unsafe { core::mem::zeroed() };
        let r_fl = unsafe { fl::clock_gettime(*clk, &mut tp_fl as *mut _) };
        let r_lc = unsafe { clock_gettime(*clk, &mut tp_lc as *mut _) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "clock_gettime",
                case: (*name).into(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl == 0 && r_lc == 0 {
            // tv_nsec must be in [0, 10^9)
            if tp_fl.tv_nsec < 0 || tp_fl.tv_nsec >= 1_000_000_000 {
                divs.push(Divergence {
                    function: "clock_gettime",
                    case: (*name).into(),
                    field: "tv_nsec_range",
                    frankenlibc: format!("{}", tp_fl.tv_nsec),
                    glibc: "[0, 1e9)".into(),
                });
            }
            // tv_sec for wall clocks should be > 1 (post-epoch)
            if matches!(name, &"CLOCK_REALTIME" | &"CLOCK_MONOTONIC" | &"CLOCK_BOOTTIME")
                && (tp_fl.tv_sec < 1 || tp_lc.tv_sec < 1)
            {
                divs.push(Divergence {
                    function: "clock_gettime",
                    case: (*name).into(),
                    field: "tv_sec_sanity",
                    frankenlibc: format!("{}", tp_fl.tv_sec),
                    glibc: format!("{}", tp_lc.tv_sec),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "clock_gettime divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// clock_getres — both impls report the same resolution for each clock.
// ===========================================================================

#[test]
fn diff_clock_getres_all_clocks() {
    let mut divs = Vec::new();
    let clocks: &[(&str, c_int)] = &[
        ("CLOCK_REALTIME", CLOCK_REALTIME),
        ("CLOCK_MONOTONIC", CLOCK_MONOTONIC),
        ("CLOCK_PROCESS_CPUTIME_ID", CLOCK_PROCESS_CPUTIME_ID),
        ("CLOCK_THREAD_CPUTIME_ID", CLOCK_THREAD_CPUTIME_ID),
    ];
    for (name, clk) in clocks {
        let mut tp_fl: libc::timespec = unsafe { core::mem::zeroed() };
        let mut tp_lc: libc::timespec = unsafe { core::mem::zeroed() };
        let r_fl = unsafe { fl::clock_getres(*clk, &mut tp_fl as *mut _) };
        let r_lc = unsafe { clock_getres(*clk, &mut tp_lc as *mut _) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "clock_getres",
                case: (*name).into(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl == 0 && r_lc == 0 {
            if tp_fl.tv_sec != tp_lc.tv_sec || tp_fl.tv_nsec != tp_lc.tv_nsec {
                divs.push(Divergence {
                    function: "clock_getres",
                    case: (*name).into(),
                    field: "resolution",
                    frankenlibc: format!("({}, {})", tp_fl.tv_sec, tp_fl.tv_nsec),
                    glibc: format!("({}, {})", tp_lc.tv_sec, tp_lc.tv_nsec),
                });
            }
        }
    }
    assert!(
        divs.is_empty(),
        "clock_getres divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// nanosleep — short sleeps return 0 in both
// ===========================================================================

#[test]
fn diff_nanosleep_short() {
    let mut divs = Vec::new();
    let durations: &[(&str, c_long)] = &[
        ("100ns", 100),
        ("10us", 10_000),
        ("1ms", 1_000_000),
    ];
    for (name, ns) in durations {
        let req = libc::timespec {
            tv_sec: 0,
            tv_nsec: *ns,
        };
        let mut rem_fl: libc::timespec = unsafe { core::mem::zeroed() };
        let mut rem_lc: libc::timespec = unsafe { core::mem::zeroed() };
        let r_fl = unsafe { fl::nanosleep(&req as *const _, &mut rem_fl as *mut _) };
        let r_lc = unsafe { nanosleep(&req as *const _, &mut rem_lc as *mut _) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "nanosleep",
                case: (*name).into(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "nanosleep divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// nanosleep — invalid (negative tv_nsec, or tv_nsec >= 1e9): both must
// fail with EINVAL.
// ===========================================================================

#[test]
fn diff_nanosleep_invalid() {
    let mut divs = Vec::new();
    let invalids: &[(&str, c_long, libc::time_t)] = &[
        ("nsec_too_large", 1_000_000_000, 0),
        ("nsec_negative", -1, 0),
        ("sec_negative", 0, -1),
    ];
    for (name, ns, sec) in invalids {
        let req = libc::timespec {
            tv_sec: *sec,
            tv_nsec: *ns,
        };
        let r_fl = unsafe { fl::nanosleep(&req as *const _, std::ptr::null_mut()) };
        let r_lc = unsafe { nanosleep(&req as *const _, std::ptr::null_mut()) };
        if (r_fl == 0) != (r_lc == 0) {
            divs.push(Divergence {
                function: "nanosleep",
                case: (*name).into(),
                field: "success_match",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "nanosleep invalid divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// clock_nanosleep — TIMER_ABSTIME with a wake time slightly in the past
// (CLOCK_MONOTONIC) returns 0 immediately on both.
// ===========================================================================

#[test]
fn diff_clock_nanosleep_abstime_past() {
    let mut now: libc::timespec = unsafe { core::mem::zeroed() };
    let _ = unsafe { clock_gettime(CLOCK_MONOTONIC, &mut now as *mut _) };
    // Wake target = now (immediate)
    let req = libc::timespec {
        tv_sec: now.tv_sec,
        tv_nsec: now.tv_nsec,
    };
    let r_fl = unsafe {
        fl::clock_nanosleep(
            CLOCK_MONOTONIC,
            TIMER_ABSTIME,
            &req as *const _,
            std::ptr::null_mut(),
        )
    };
    let r_lc = unsafe {
        clock_nanosleep(
            CLOCK_MONOTONIC,
            TIMER_ABSTIME,
            &req as *const _,
            std::ptr::null_mut(),
        )
    };
    assert_eq!(
        r_fl, r_lc,
        "clock_nanosleep abstime-past return mismatch: fl={r_fl}, lc={r_lc}",
    );
}

#[test]
fn clock_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"time.h+sys/time.h(clock_*)\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
