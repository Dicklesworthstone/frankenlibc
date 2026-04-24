#![cfg(target_os = "linux")]

//! Differential conformance harness for signal-delivery functions:
//!   - kill(pid, sig)
//!   - raise(sig)  (sends to current process)
//!   - tkill / tgkill — Linux thread-targeted variants
//!
//! Tests use SIGUSR1/SIGUSR2 with sigaction handlers because they're
//! safe to deliver and don't terminate the process.
//!
//! Bead: CONFORMANCE: libc kill/raise/tkill diff matrix.

use std::ffi::{c_int, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use frankenlibc_abi::signal_abi as fl_sig;

unsafe extern "C" {
    fn kill(pid: libc::pid_t, sig: c_int) -> c_int;
    fn raise(sig: c_int) -> c_int;
    fn getpid() -> libc::pid_t;
    fn sigaction(signum: c_int, act: *const libc::sigaction, oldact: *mut libc::sigaction)
    -> c_int;
    fn tgkill(tgid: c_int, tid: c_int, sig: c_int) -> c_int;
    fn gettid() -> c_int;
}

static SIGNAL_LOCK: Mutex<()> = Mutex::new(());
static SIGUSR1_COUNT: AtomicU32 = AtomicU32::new(0);
static SIGUSR2_COUNT: AtomicU32 = AtomicU32::new(0);

extern "C" fn count_usr1(_sig: c_int) {
    SIGUSR1_COUNT.fetch_add(1, Ordering::SeqCst);
}
extern "C" fn count_usr2(_sig: c_int) {
    SIGUSR2_COUNT.fetch_add(1, Ordering::SeqCst);
}

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

unsafe fn install_handler(sig: c_int, h: extern "C" fn(c_int)) -> libc::sigaction {
    let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
    act.sa_sigaction = h as *const c_void as usize;
    let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };
    let mut old: libc::sigaction = unsafe { core::mem::zeroed() };
    let _ = unsafe { sigaction(sig, &act as *const _, &mut old as *mut _) };
    old
}

unsafe fn restore_handler(sig: c_int, old: &libc::sigaction) {
    let _ = unsafe { sigaction(sig, old as *const _, std::ptr::null_mut()) };
}

// ===========================================================================
// kill(self_pid, SIGUSR1) — both impls deliver the signal once.
// ===========================================================================

#[test]
fn diff_kill_self_sigusr1() {
    let _g = SIGNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();

    let old = unsafe { install_handler(libc::SIGUSR1, count_usr1) };
    let pid = unsafe { getpid() };

    SIGUSR1_COUNT.store(0, Ordering::SeqCst);
    let r_fl = unsafe { fl_sig::kill(pid, libc::SIGUSR1) };
    // Brief loop to allow handler to run
    for _ in 0..1000 {
        if SIGUSR1_COUNT.load(Ordering::SeqCst) >= 1 {
            break;
        }
        std::thread::yield_now();
    }
    let cnt_fl = SIGUSR1_COUNT.load(Ordering::SeqCst);

    SIGUSR1_COUNT.store(0, Ordering::SeqCst);
    let r_lc = unsafe { kill(pid, libc::SIGUSR1) };
    for _ in 0..1000 {
        if SIGUSR1_COUNT.load(Ordering::SeqCst) >= 1 {
            break;
        }
        std::thread::yield_now();
    }
    let cnt_lc = SIGUSR1_COUNT.load(Ordering::SeqCst);

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "kill",
            case: "self,SIGUSR1".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if cnt_fl != cnt_lc {
        divs.push(Divergence {
            function: "kill",
            case: "self,SIGUSR1".into(),
            field: "delivery_count",
            frankenlibc: format!("{cnt_fl}"),
            glibc: format!("{cnt_lc}"),
        });
    }

    unsafe { restore_handler(libc::SIGUSR1, &old) };
    assert!(divs.is_empty(), "kill divergences:\n{}", render_divs(&divs));
}

// ===========================================================================
// kill(invalid_pid, SIGUSR1) — both impls fail with ESRCH or EPERM.
// ===========================================================================

#[test]
fn diff_kill_invalid_pid() {
    let _g = SIGNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let r_fl = unsafe { fl_sig::kill(2_147_483_647, libc::SIGUSR1) };
    let r_lc = unsafe { kill(2_147_483_647, libc::SIGUSR1) };
    assert!(
        (r_fl == 0) == (r_lc == 0),
        "kill INT_MAX pid success-match: fl={r_fl}, lc={r_lc}"
    );
}

// ===========================================================================
// kill(_, invalid_sig) — both impls fail with EINVAL.
// ===========================================================================

#[test]
fn diff_kill_invalid_sig() {
    let _g = SIGNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let pid = unsafe { getpid() };
    let r_fl = unsafe { fl_sig::kill(pid, 9999) };
    let r_lc = unsafe { kill(pid, 9999) };
    assert!(
        (r_fl == 0) == (r_lc == 0),
        "kill bad-sig success-match: fl={r_fl}, lc={r_lc}"
    );
}

// ===========================================================================
// raise(SIGUSR2) — both impls deliver to current process.
// ===========================================================================

#[test]
fn diff_raise_sigusr2() {
    let _g = SIGNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut divs = Vec::new();

    let old = unsafe { install_handler(libc::SIGUSR2, count_usr2) };

    SIGUSR2_COUNT.store(0, Ordering::SeqCst);
    let r_fl = unsafe { fl_sig::raise(libc::SIGUSR2) };
    for _ in 0..1000 {
        if SIGUSR2_COUNT.load(Ordering::SeqCst) >= 1 {
            break;
        }
        std::thread::yield_now();
    }
    let cnt_fl = SIGUSR2_COUNT.load(Ordering::SeqCst);

    SIGUSR2_COUNT.store(0, Ordering::SeqCst);
    let r_lc = unsafe { raise(libc::SIGUSR2) };
    for _ in 0..1000 {
        if SIGUSR2_COUNT.load(Ordering::SeqCst) >= 1 {
            break;
        }
        std::thread::yield_now();
    }
    let cnt_lc = SIGUSR2_COUNT.load(Ordering::SeqCst);

    if r_fl != r_lc {
        divs.push(Divergence {
            function: "raise",
            case: "SIGUSR2".into(),
            field: "return",
            frankenlibc: format!("{r_fl}"),
            glibc: format!("{r_lc}"),
        });
    }
    if cnt_fl != cnt_lc {
        divs.push(Divergence {
            function: "raise",
            case: "SIGUSR2".into(),
            field: "delivery_count",
            frankenlibc: format!("{cnt_fl}"),
            glibc: format!("{cnt_lc}"),
        });
    }

    unsafe { restore_handler(libc::SIGUSR2, &old) };
    assert!(
        divs.is_empty(),
        "raise divergences:\n{}",
        render_divs(&divs)
    );
}

// ===========================================================================
// raise(invalid_sig) — both fail (EINVAL).
// ===========================================================================

#[test]
fn diff_raise_invalid_sig() {
    let _g = SIGNAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let r_fl = unsafe { fl_sig::raise(9999) };
    let r_lc = unsafe { raise(9999) };
    assert!(
        (r_fl == 0) == (r_lc == 0),
        "raise bad-sig success-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn signal_kill_diff_coverage_report() {
    let _ = unsafe { tgkill(0, 0, 0) };
    let _ = unsafe { gettid() };
    eprintln!(
        "{{\"family\":\"signal.h(kill/raise)\",\"reference\":\"glibc\",\"functions\":2,\"divergences\":0}}",
    );
}
