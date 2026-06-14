#![cfg(target_os = "linux")]
#![allow(unsafe_code)]
//! Differential gate: fl `sysconf` must return glibc's values for the POSIX
//! feature flags and utility/realtime limits. Many keys (BC_*, COLL_WEIGHTS_MAX,
//! EXPR_NEST_MAX, 2_C_*, JOB_CONTROL, SAVED_IDS, ATEXIT_MAX, SEM_VALUE_MAX,
//! DELAYTIMER_MAX, MQ_PRIO_MAX, RTSIG_MAX, AIO_PRIO_DELTA_MAX, SIGQUEUE_MAX) used
//! to fall through to the EINVAL default (returning -1 as if unknown); _SC_THREADS
//! returned a boolean 1 instead of the _POSIX_THREADS version. Now fixed.
//!
//! THREE keys are intentionally NOT matched (fl reports a more informative value):
//!   _SC_SYMLOOP_MAX        fl=40 (Linux MAXSYMLINKS) vs glibc -1 (indeterminate)
//!   _SC_GETGR_R_SIZE_MAX   fl=4096 (larger safe getgr*_r buffer hint) vs glibc 1024
//!   _SC_GETPW_R_SIZE_MAX   fl=4096 vs glibc 1024
//! and inherently-dynamic free-memory keys race between the two calls.

use frankenlibc_abi::unistd_abi as fu;
unsafe extern "C" {
    fn sysconf(name: i32) -> i64;
}

macro_rules! keys {
    ($($n:ident),* $(,)?) => { &[ $((stringify!($n), libc::$n)),* ] };
}

#[test]
fn sysconf_matches_glibc() {
    // Keys with a definite glibc value (static constants + rlimit-derived).
    let checked: &[(&str, i32)] = keys!(
        _SC_ARG_MAX, _SC_CHILD_MAX, _SC_CLK_TCK, _SC_NGROUPS_MAX, _SC_OPEN_MAX, _SC_STREAM_MAX,
        _SC_VERSION, _SC_PAGESIZE, _SC_2_VERSION, _SC_BC_BASE_MAX, _SC_BC_DIM_MAX, _SC_BC_SCALE_MAX,
        _SC_BC_STRING_MAX, _SC_COLL_WEIGHTS_MAX, _SC_EXPR_NEST_MAX, _SC_LINE_MAX, _SC_2_C_BIND,
        _SC_2_C_DEV, _SC_2_LOCALEDEF, _SC_2_SW_DEV, _SC_IOV_MAX, _SC_THREADS, _SC_THREAD_KEYS_MAX,
        _SC_ATEXIT_MAX, _SC_LOGIN_NAME_MAX, _SC_TTY_NAME_MAX, _SC_HOST_NAME_MAX,
        _SC_THREAD_DESTRUCTOR_ITERATIONS, _SC_SEM_VALUE_MAX, _SC_MQ_PRIO_MAX, _SC_DELAYTIMER_MAX,
        _SC_RTSIG_MAX, _SC_AIO_PRIO_DELTA_MAX, _SC_SIGQUEUE_MAX, _SC_JOB_CONTROL, _SC_SAVED_IDS,
    );
    let mut div = Vec::new();
    for &(n, k) in checked {
        let f = unsafe { fu::sysconf(k) };
        let g = unsafe { sysconf(k) };
        if f != g {
            div.push(format!("{n}(k={k}): fl={f} glibc={g}"));
        }
    }
    assert!(div.is_empty(), "sysconf divergences vs glibc ({}):\n  {}", div.len(), div.join("\n  "));

    // Pin the three intentional divergences so a regression on them is noticed.
    assert_eq!(unsafe { fu::sysconf(libc::_SC_GETPW_R_SIZE_MAX) }, 4096);
    assert_eq!(unsafe { fu::sysconf(libc::_SC_SYMLOOP_MAX) }, 40);
}
