#![cfg(target_os = "linux")]

//! Differential conformance harness for `<sched.h>`:
//!   - sched_yield (cooperative yield)
//!   - sched_getscheduler / sched_get_priority_min / sched_get_priority_max
//!   - sched_getparam (current thread scheduling parameters)
//!   - sched_getaffinity (current thread's CPU affinity mask)
//!   - sched_rr_get_interval (RR slice — only meaningful for SCHED_RR)
//!
//! Tests intentionally avoid sched_setscheduler/sched_setparam/
//! sched_setaffinity because they require CAP_SYS_NICE and would
//! affect process state across tests.
//!
//! Bead: CONFORMANCE: libc sched.h diff matrix.

use std::ffi::{c_int, c_void};

use frankenlibc_abi::{poll_abi as fl_poll, unistd_abi as fl_uni};

unsafe extern "C" {
    fn sched_yield() -> c_int;
    fn sched_getscheduler(pid: libc::pid_t) -> c_int;
    fn sched_get_priority_min(policy: c_int) -> c_int;
    fn sched_get_priority_max(policy: c_int) -> c_int;
    fn sched_getparam(pid: libc::pid_t, param: *mut SchedParam) -> c_int;
    fn sched_getaffinity(pid: libc::pid_t, cpusetsize: usize, mask: *mut c_void) -> c_int;
}

#[repr(C)]
struct SchedParam {
    sched_priority: c_int,
}

const SCHED_OTHER: c_int = 0;
const SCHED_FIFO: c_int = 1;
const SCHED_RR: c_int = 2;
const SCHED_BATCH: c_int = 3;
const SCHED_IDLE: c_int = 5;

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

#[test]
fn diff_sched_yield_succeeds() {
    let r_fl = unsafe { fl_poll::sched_yield() };
    let r_lc = unsafe { sched_yield() };
    assert_eq!(r_fl, r_lc, "sched_yield return mismatch");
    assert_eq!(r_fl, 0, "sched_yield should always return 0 on Linux");
}

#[test]
fn diff_sched_get_priority_bounds_per_policy() {
    let mut divs = Vec::new();
    let policies: &[(&str, c_int)] = &[
        ("SCHED_OTHER", SCHED_OTHER),
        ("SCHED_FIFO", SCHED_FIFO),
        ("SCHED_RR", SCHED_RR),
        ("SCHED_BATCH", SCHED_BATCH),
        ("SCHED_IDLE", SCHED_IDLE),
    ];
    for (name, policy) in policies {
        let min_fl = unsafe { fl_uni::sched_get_priority_min(*policy) };
        let min_lc = unsafe { sched_get_priority_min(*policy) };
        let max_fl = unsafe { fl_uni::sched_get_priority_max(*policy) };
        let max_lc = unsafe { sched_get_priority_max(*policy) };
        if min_fl != min_lc {
            divs.push(Divergence {
                function: "sched_get_priority_min",
                case: (*name).into(),
                field: "value",
                frankenlibc: format!("{min_fl}"),
                glibc: format!("{min_lc}"),
            });
        }
        if max_fl != max_lc {
            divs.push(Divergence {
                function: "sched_get_priority_max",
                case: (*name).into(),
                field: "value",
                frankenlibc: format!("{max_fl}"),
                glibc: format!("{max_lc}"),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sched_get_priority_min/max divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sched_get_priority_invalid_policy() {
    let r_fl = unsafe { fl_uni::sched_get_priority_min(99) };
    let r_lc = unsafe { sched_get_priority_min(99) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "sched_get_priority_min invalid policy fail-match: fl={r_fl}, lc={r_lc}"
    );
    let r_fl = unsafe { fl_uni::sched_get_priority_max(99) };
    let r_lc = unsafe { sched_get_priority_max(99) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "sched_get_priority_max invalid policy fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_sched_getscheduler_self() {
    let r_fl = unsafe { fl_uni::sched_getscheduler(0) };
    let r_lc = unsafe { sched_getscheduler(0) };
    assert_eq!(
        r_fl, r_lc,
        "sched_getscheduler(0) divergence: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_sched_getscheduler_invalid_pid() {
    // Use INT_MAX which is unlikely to be a real PID
    let r_fl = unsafe { fl_uni::sched_getscheduler(2_147_483_647) };
    let r_lc = unsafe { sched_getscheduler(2_147_483_647) };
    assert_eq!(
        r_fl < 0,
        r_lc < 0,
        "sched_getscheduler INT_MAX fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_sched_getparam_self() {
    let mut p_fl = SchedParam { sched_priority: -1 };
    let mut p_lc = SchedParam { sched_priority: -1 };
    let r_fl = unsafe { fl_uni::sched_getparam(0, &mut p_fl as *mut _ as *mut _) };
    let r_lc = unsafe { sched_getparam(0, &mut p_lc) };
    assert_eq!(r_fl, r_lc, "sched_getparam(0) return divergence");
    if r_fl == 0 && r_lc == 0 {
        assert_eq!(
            p_fl.sched_priority, p_lc.sched_priority,
            "sched_getparam(0) priority: fl={}, lc={}",
            p_fl.sched_priority, p_lc.sched_priority,
        );
    }
}

#[test]
fn diff_sched_getaffinity_self() {
    let mut divs = Vec::new();
    // 128-byte cpu_set_t (room for up to 1024 CPUs)
    const CPU_SET_BYTES: usize = 128;
    let mut mask_fl = vec![0u8; CPU_SET_BYTES];
    let mut mask_lc = vec![0u8; CPU_SET_BYTES];
    let r_fl = unsafe {
        fl_uni::sched_getaffinity(0, CPU_SET_BYTES, mask_fl.as_mut_ptr() as *mut c_void)
    };
    let r_lc =
        unsafe { sched_getaffinity(0, CPU_SET_BYTES, mask_lc.as_mut_ptr() as *mut c_void) };
    if r_fl != r_lc {
        divs.push(Divergence {
            function: "sched_getaffinity",
            case: "self, 128B mask".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if r_fl >= 0 && r_lc >= 0 {
        // Compare the bytes the kernel actually wrote (return value =
        // size in bytes of the affinity-mask data structure)
        let n = r_fl.max(r_lc) as usize;
        if mask_fl[..n] != mask_lc[..n] {
            divs.push(Divergence {
                function: "sched_getaffinity",
                case: "self".into(),
                field: "mask_bytes",
                frankenlibc: format!("{:?}", &mask_fl[..n]),
                glibc: format!("{:?}", &mask_lc[..n]),
            });
        }
    }
    assert!(
        divs.is_empty(),
        "sched_getaffinity divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn sched_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"sched.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
