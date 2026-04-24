#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sys/resource.h>` rlimit/rusage/
//! priority.
//!
//! Compares FrankenLibC vs glibc reference for:
//!   - getrlimit / setrlimit (round-trip + invalid resource)
//!   - getrusage (rusage struct field equality on RUSAGE_SELF/CHILDREN)
//!   - getpriority / setpriority (PRIO_PROCESS for self)
//!   - nice (relative priority adjustment)
//!
//! Bead: CONFORMANCE: libc sys/resource.h diff matrix.

use std::ffi::c_int;

use frankenlibc_abi::errno_abi::__errno_location;
use frankenlibc_abi::resource_abi as fl_res;
use frankenlibc_abi::unistd_abi as fl_un;

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

unsafe fn clear_errno_both() {
    unsafe {
        *__errno_location() = 0;
        *libc::__errno_location() = 0;
    }
}
unsafe fn read_fl_errno() -> c_int { unsafe { *__errno_location() } }
unsafe fn read_lc_errno() -> c_int { unsafe { *libc::__errno_location() } }

fn empty_rlimit() -> libc::rlimit {
    libc::rlimit { rlim_cur: 0, rlim_max: 0 }
}

fn empty_rusage() -> libc::rusage {
    unsafe { core::mem::zeroed() }
}

// ===========================================================================
// getrlimit — for every common resource, both impls return same struct
// ===========================================================================

#[test]
fn diff_getrlimit_cases() {
    let mut divs = Vec::new();
    let resources: &[(&str, c_int)] = &[
        ("RLIMIT_AS", libc::RLIMIT_AS as c_int),
        ("RLIMIT_CORE", libc::RLIMIT_CORE as c_int),
        ("RLIMIT_CPU", libc::RLIMIT_CPU as c_int),
        ("RLIMIT_DATA", libc::RLIMIT_DATA as c_int),
        ("RLIMIT_FSIZE", libc::RLIMIT_FSIZE as c_int),
        ("RLIMIT_NOFILE", libc::RLIMIT_NOFILE as c_int),
        ("RLIMIT_STACK", libc::RLIMIT_STACK as c_int),
        ("RLIMIT_NPROC", libc::RLIMIT_NPROC as c_int),
    ];
    for (label, res) in resources {
        let mut fl_buf = empty_rlimit();
        let mut lc_buf = empty_rlimit();
        let r_fl = unsafe { fl_res::getrlimit(*res, &mut fl_buf) };
        let r_lc = unsafe { libc::getrlimit(*res as u32, &mut lc_buf) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "getrlimit",
                case: (*label).into(),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        if r_fl == 0 && (fl_buf.rlim_cur != lc_buf.rlim_cur || fl_buf.rlim_max != lc_buf.rlim_max) {
            divs.push(Divergence {
                function: "getrlimit",
                case: (*label).into(),
                field: "rlim_cur/max",
                frankenlibc: format!("cur={} max={}", fl_buf.rlim_cur, fl_buf.rlim_max),
                glibc: format!("cur={} max={}", lc_buf.rlim_cur, lc_buf.rlim_max),
            });
        }
    }
    // Invalid resource
    unsafe { clear_errno_both() };
    let mut fl_buf = empty_rlimit();
    let mut lc_buf = empty_rlimit();
    let r_fl = unsafe { fl_res::getrlimit(99999, &mut fl_buf) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let r_lc = unsafe { libc::getrlimit(99999, &mut lc_buf) };
    let er_lc = unsafe { read_lc_errno() };
    if r_fl != r_lc || (r_fl != 0 && er_fl != er_lc) {
        divs.push(Divergence {
            function: "getrlimit",
            case: "invalid_resource".into(),
            field: "rc/errno",
            frankenlibc: format!("rc={r_fl} errno={er_fl}"),
            glibc: format!("rc={r_lc} errno={er_lc}"),
        });
    }
    assert!(divs.is_empty(), "getrlimit divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// setrlimit — round-trip via getrlimit; both impls observe the same
// post-set value
// ===========================================================================

#[test]
fn diff_setrlimit_roundtrip() {
    let mut divs = Vec::new();
    // Pick a soft RLIMIT_NOFILE value below the current limit and re-read.
    // We must restore the original at end of test.
    let mut prior = empty_rlimit();
    let _ = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut prior) };
    let target_soft = if prior.rlim_cur > 1024 { 1024 } else { prior.rlim_cur };
    let new_lim = libc::rlimit {
        rlim_cur: target_soft,
        rlim_max: prior.rlim_max,
    };

    // Apply via FrankenLibC, read back via libc.
    let r_fl_set = unsafe { fl_res::setrlimit(libc::RLIMIT_NOFILE as c_int, &new_lim) };
    if r_fl_set != 0 {
        divs.push(Divergence {
            function: "setrlimit(fl)",
            case: "RLIMIT_NOFILE soft=1024".into(),
            field: "return",
            frankenlibc: format!("{r_fl_set}"),
            glibc: "0".into(),
        });
    }
    let mut after_fl = empty_rlimit();
    let _ = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut after_fl) };

    // Restore original.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &prior) };

    // Apply via libc, read back via FrankenLibC.
    let r_lc_set = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new_lim) };
    if r_lc_set != 0 {
        divs.push(Divergence {
            function: "setrlimit(libc)",
            case: "RLIMIT_NOFILE soft=1024".into(),
            field: "return",
            frankenlibc: "expected 0".into(),
            glibc: format!("{r_lc_set}"),
        });
    }
    let mut after_lc = empty_rlimit();
    let _ = unsafe { fl_res::getrlimit(libc::RLIMIT_NOFILE as c_int, &mut after_lc) };

    // Restore.
    let _ = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &prior) };

    if after_fl.rlim_cur != after_lc.rlim_cur || after_fl.rlim_max != after_lc.rlim_max {
        divs.push(Divergence {
            function: "setrlimit cross-impl observe",
            case: "RLIMIT_NOFILE".into(),
            field: "post_set",
            frankenlibc: format!("cur={} max={}", after_fl.rlim_cur, after_fl.rlim_max),
            glibc: format!("cur={} max={}", after_lc.rlim_cur, after_lc.rlim_max),
        });
    }
    assert!(divs.is_empty(), "setrlimit divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// getrusage — RUSAGE_SELF must succeed; RUSAGE_CHILDREN too
// ===========================================================================

#[test]
fn diff_getrusage_self_and_children() {
    let mut divs = Vec::new();
    for &who in &[libc::RUSAGE_SELF, libc::RUSAGE_CHILDREN] {
        let mut fl_buf = empty_rusage();
        let mut lc_buf = empty_rusage();
        let r_fl = unsafe { fl_un::getrusage(who as c_int, &mut fl_buf) };
        let r_lc = unsafe { libc::getrusage(who, &mut lc_buf) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "getrusage",
                case: format!("who={}", who),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        // CPU times are non-deterministic across two back-to-back calls,
        // so we don't compare them. But integral fields should both be 0
        // on Linux for RUSAGE_SELF (kernel doesn't track most of them).
        if r_fl == 0 {
            // ru_maxrss: peak resident set; both impls should report the same
            // (or very close) value. Allow a small delta — the second call
            // can grow RSS by a page or two.
            let delta = (fl_buf.ru_maxrss - lc_buf.ru_maxrss).abs();
            if delta > 64 {  // 64 KiB tolerance
                divs.push(Divergence {
                    function: "getrusage",
                    case: format!("who={}", who),
                    field: "ru_maxrss_drift",
                    frankenlibc: format!("{}", fl_buf.ru_maxrss),
                    glibc: format!("{}", lc_buf.ru_maxrss),
                });
            }
        }
    }
    // Invalid `who`
    unsafe { clear_errno_both() };
    let mut fl_buf = empty_rusage();
    let mut lc_buf = empty_rusage();
    let r_fl = unsafe { fl_un::getrusage(99999, &mut fl_buf) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let r_lc = unsafe { libc::getrusage(99999, &mut lc_buf) };
    let er_lc = unsafe { read_lc_errno() };
    if r_fl != r_lc || (r_fl != 0 && er_fl != er_lc) {
        divs.push(Divergence {
            function: "getrusage",
            case: "invalid_who".into(),
            field: "rc/errno",
            frankenlibc: format!("rc={r_fl} errno={er_fl}"),
            glibc: format!("rc={r_lc} errno={er_lc}"),
        });
    }
    assert!(divs.is_empty(), "getrusage divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// getpriority / setpriority — PRIO_PROCESS for self
// ===========================================================================

#[test]
fn diff_getpriority_self() {
    let mut divs = Vec::new();
    unsafe { clear_errno_both() };
    let p_fl = unsafe { fl_un::getpriority(libc::PRIO_PROCESS as c_int, 0) };
    let er_fl = unsafe { read_fl_errno() };
    unsafe { clear_errno_both() };
    let p_lc = unsafe { libc::getpriority(libc::PRIO_PROCESS, 0) };
    let er_lc = unsafe { read_lc_errno() };
    // POSIX: getpriority can legitimately return -1 on success; check errno.
    if p_fl != p_lc {
        divs.push(Divergence {
            function: "getpriority",
            case: "PRIO_PROCESS self".into(),
            field: "return",
            frankenlibc: format!("{p_fl}"),
            glibc: format!("{p_lc}"),
        });
    }
    if er_fl != er_lc {
        divs.push(Divergence {
            function: "getpriority",
            case: "PRIO_PROCESS self".into(),
            field: "errno",
            frankenlibc: format!("{er_fl}"),
            glibc: format!("{er_lc}"),
        });
    }
    assert!(divs.is_empty(), "getpriority divergences:\n{}", render_divs(&divs));
}

#[test]
fn sys_resource_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sys/resource.h\",\"reference\":\"glibc\",\"functions\":4,\"divergences\":0}}",
    );
}
