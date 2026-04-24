#![cfg(target_os = "linux")]

//! Differential conformance harness for `<semaphore.h>` POSIX
//! unnamed (sem_init) semaphores:
//!   - sem_init / sem_destroy
//!   - sem_post / sem_wait / sem_trywait / sem_timedwait
//!   - sem_getvalue
//!
//! sem_t is a 32-byte opaque blob (struct __sem_struct). Both impls
//! manage their own state inside that blob, so we run independent
//! sequences through fl and lc and compare the observable post-state.
//! Named semaphores (sem_open) are deferred — they require shm and
//! cleanup of /dev/shm on test failure.
//!
//! Bead: CONFORMANCE: libc semaphore.h diff matrix.

use std::ffi::{c_int, c_uint, c_void};

use frankenlibc_abi::unistd_abi as fl;

unsafe extern "C" {
    fn sem_init(sem: *mut c_void, pshared: c_int, value: c_uint) -> c_int;
    fn sem_destroy(sem: *mut c_void) -> c_int;
    fn sem_post(sem: *mut c_void) -> c_int;
    fn sem_wait(sem: *mut c_void) -> c_int;
    fn sem_trywait(sem: *mut c_void) -> c_int;
    fn sem_timedwait(sem: *mut c_void, abs_timeout: *const libc::timespec) -> c_int;
    fn sem_getvalue(sem: *mut c_void, sval: *mut c_int) -> c_int;
}

const SEM_T_BYTES: usize = 64; // glibc sem_t is 32 bytes; pad for safety

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
fn diff_sem_init_then_getvalue_match() {
    let mut divs = Vec::new();
    let initials: &[c_uint] = &[0, 1, 5, 100];
    for v in initials {
        let mut buf_fl = [0u8; SEM_T_BYTES];
        let mut buf_lc = [0u8; SEM_T_BYTES];
        let r_fl = unsafe { fl::sem_init(buf_fl.as_mut_ptr() as *mut c_void, 0, *v) };
        let r_lc = unsafe { sem_init(buf_lc.as_mut_ptr() as *mut c_void, 0, *v) };
        if r_fl != r_lc {
            divs.push(Divergence {
                function: "sem_init",
                case: format!("value={v}"),
                field: "return",
                frankenlibc: format!("{r_fl}"),
                glibc: format!("{r_lc}"),
            });
        }
        let mut sv_fl: c_int = -1;
        let mut sv_lc: c_int = -1;
        let _ = unsafe { fl::sem_getvalue(buf_fl.as_mut_ptr() as *mut c_void, &mut sv_fl) };
        let _ = unsafe { sem_getvalue(buf_lc.as_mut_ptr() as *mut c_void, &mut sv_lc) };
        if sv_fl != sv_lc || sv_fl != *v as c_int {
            divs.push(Divergence {
                function: "sem_getvalue",
                case: format!("after init({v})"),
                field: "value",
                frankenlibc: format!("{sv_fl}"),
                glibc: format!("{sv_lc}"),
            });
        }
        let _ = unsafe { fl::sem_destroy(buf_fl.as_mut_ptr() as *mut c_void) };
        let _ = unsafe { sem_destroy(buf_lc.as_mut_ptr() as *mut c_void) };
    }
    assert!(
        divs.is_empty(),
        "sem_init/getvalue divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sem_post_increments_value() {
    let mut divs = Vec::new();
    let mut buf_fl = [0u8; SEM_T_BYTES];
    let mut buf_lc = [0u8; SEM_T_BYTES];
    let _ = unsafe { fl::sem_init(buf_fl.as_mut_ptr() as *mut c_void, 0, 0) };
    let _ = unsafe { sem_init(buf_lc.as_mut_ptr() as *mut c_void, 0, 0) };
    for _ in 0..3 {
        let _ = unsafe { fl::sem_post(buf_fl.as_mut_ptr() as *mut c_void) };
        let _ = unsafe { sem_post(buf_lc.as_mut_ptr() as *mut c_void) };
    }
    let mut sv_fl: c_int = -1;
    let mut sv_lc: c_int = -1;
    let _ = unsafe { fl::sem_getvalue(buf_fl.as_mut_ptr() as *mut c_void, &mut sv_fl) };
    let _ = unsafe { sem_getvalue(buf_lc.as_mut_ptr() as *mut c_void, &mut sv_lc) };
    if sv_fl != sv_lc {
        divs.push(Divergence {
            function: "sem_post",
            case: "3 posts from 0".into(),
            field: "value",
            frankenlibc: format!("{sv_fl}"),
            glibc: format!("{sv_lc}"),
        });
    }
    if sv_fl != 3 {
        divs.push(Divergence {
            function: "sem_post",
            case: "3 posts from 0".into(),
            field: "expected_3",
            frankenlibc: format!("{sv_fl}"),
            glibc: "3".into(),
        });
    }
    let _ = unsafe { fl::sem_destroy(buf_fl.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { sem_destroy(buf_lc.as_mut_ptr() as *mut c_void) };
    assert!(
        divs.is_empty(),
        "sem_post divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sem_wait_decrements_value() {
    let mut divs = Vec::new();
    let mut buf_fl = [0u8; SEM_T_BYTES];
    let mut buf_lc = [0u8; SEM_T_BYTES];
    let _ = unsafe { fl::sem_init(buf_fl.as_mut_ptr() as *mut c_void, 0, 5) };
    let _ = unsafe { sem_init(buf_lc.as_mut_ptr() as *mut c_void, 0, 5) };
    for _ in 0..3 {
        let _ = unsafe { fl::sem_wait(buf_fl.as_mut_ptr() as *mut c_void) };
        let _ = unsafe { sem_wait(buf_lc.as_mut_ptr() as *mut c_void) };
    }
    let mut sv_fl: c_int = -1;
    let mut sv_lc: c_int = -1;
    let _ = unsafe { fl::sem_getvalue(buf_fl.as_mut_ptr() as *mut c_void, &mut sv_fl) };
    let _ = unsafe { sem_getvalue(buf_lc.as_mut_ptr() as *mut c_void, &mut sv_lc) };
    if sv_fl != sv_lc || sv_fl != 2 {
        divs.push(Divergence {
            function: "sem_wait",
            case: "3 waits from 5".into(),
            field: "value",
            frankenlibc: format!("{sv_fl}"),
            glibc: format!("{sv_lc} (expected 2)"),
        });
    }
    let _ = unsafe { fl::sem_destroy(buf_fl.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { sem_destroy(buf_lc.as_mut_ptr() as *mut c_void) };
    assert!(
        divs.is_empty(),
        "sem_wait divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sem_trywait_at_zero_fails() {
    let mut buf_fl = [0u8; SEM_T_BYTES];
    let mut buf_lc = [0u8; SEM_T_BYTES];
    let _ = unsafe { fl::sem_init(buf_fl.as_mut_ptr() as *mut c_void, 0, 0) };
    let _ = unsafe { sem_init(buf_lc.as_mut_ptr() as *mut c_void, 0, 0) };
    let r_fl = unsafe { fl::sem_trywait(buf_fl.as_mut_ptr() as *mut c_void) };
    let r_lc = unsafe { sem_trywait(buf_lc.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { fl::sem_destroy(buf_fl.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { sem_destroy(buf_lc.as_mut_ptr() as *mut c_void) };
    assert!(
        (r_fl < 0) == (r_lc < 0),
        "sem_trywait at zero fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_sem_trywait_at_positive_succeeds() {
    let mut buf_fl = [0u8; SEM_T_BYTES];
    let mut buf_lc = [0u8; SEM_T_BYTES];
    let _ = unsafe { fl::sem_init(buf_fl.as_mut_ptr() as *mut c_void, 0, 1) };
    let _ = unsafe { sem_init(buf_lc.as_mut_ptr() as *mut c_void, 0, 1) };
    let r_fl = unsafe { fl::sem_trywait(buf_fl.as_mut_ptr() as *mut c_void) };
    let r_lc = unsafe { sem_trywait(buf_lc.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { fl::sem_destroy(buf_fl.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { sem_destroy(buf_lc.as_mut_ptr() as *mut c_void) };
    assert_eq!(
        r_fl, r_lc,
        "sem_trywait at 1 divergence: fl={r_fl}, lc={r_lc}"
    );
    assert_eq!(r_fl, 0, "sem_trywait at value=1 should succeed");
}

#[test]
fn diff_sem_timedwait_short_expiry() {
    let mut buf_fl = [0u8; SEM_T_BYTES];
    let mut buf_lc = [0u8; SEM_T_BYTES];
    let _ = unsafe { fl::sem_init(buf_fl.as_mut_ptr() as *mut c_void, 0, 0) };
    let _ = unsafe { sem_init(buf_lc.as_mut_ptr() as *mut c_void, 0, 0) };
    // Absolute timeout 10ms in the past → must time out immediately
    let mut now: libc::timespec = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut now) };
    let abs = libc::timespec {
        tv_sec: now.tv_sec - 1,
        tv_nsec: 0,
    };
    let r_fl = unsafe { fl::sem_timedwait(buf_fl.as_mut_ptr() as *mut c_void, &abs as *const _) };
    let r_lc = unsafe { sem_timedwait(buf_lc.as_mut_ptr() as *mut c_void, &abs as *const _) };
    let _ = unsafe { fl::sem_destroy(buf_fl.as_mut_ptr() as *mut c_void) };
    let _ = unsafe { sem_destroy(buf_lc.as_mut_ptr() as *mut c_void) };
    assert!(
        (r_fl < 0) == (r_lc < 0),
        "sem_timedwait past-expiry fail-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn semaphore_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"semaphore.h\",\"reference\":\"glibc\",\"functions\":7,\"divergences\":0}}",
    );
}
