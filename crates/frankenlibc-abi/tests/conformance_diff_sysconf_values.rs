#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sysconf oracle

//! Differential gate for sysconf() value parity vs host glibc (bd-ry5dsx).
//! Pins the run's sysconf fixes: _SC_SYMLOOP_MAX=-1, _SC_XOPEN_VERSION=700, the
//! X/Open feature flags, the POSIX thread/realtime option flags and the
//! _POSIX_* option-version flags (200809), GETPW/GETGR_R_SIZE_MAX=1024, and the
//! BC/COLL/EXPR utility limits — plus the already-correct standard limits.
//!
//! For each key in STABLE_KEYS (values that don't change during the test), fl's
//! sysconf MUST equal host glibc's, exactly. Volatile keys (free-memory pages)
//! are checked only for agreement of sign/availability. No mocks.

use std::ffi::c_int;

use frankenlibc_abi::unistd_abi::sysconf as fl_sysconf;

/// Keys whose sysconf value is a fixed constant or stable system property for
/// the duration of the test — fl must match glibc exactly.
fn stable_keys() -> Vec<(c_int, &'static str)> {
    vec![
        (libc::_SC_SYMLOOP_MAX, "_SC_SYMLOOP_MAX"),
        (libc::_SC_XOPEN_VERSION, "_SC_XOPEN_VERSION"),
        (libc::_SC_XOPEN_UNIX, "_SC_XOPEN_UNIX"),
        (libc::_SC_XOPEN_ENH_I18N, "_SC_XOPEN_ENH_I18N"),
        (libc::_SC_XOPEN_SHM, "_SC_XOPEN_SHM"),
        (libc::_SC_XOPEN_LEGACY, "_SC_XOPEN_LEGACY"),
        (libc::_SC_XOPEN_REALTIME, "_SC_XOPEN_REALTIME"),
        (
            libc::_SC_XOPEN_REALTIME_THREADS,
            "_SC_XOPEN_REALTIME_THREADS",
        ),
        (libc::_SC_XOPEN_XCU_VERSION, "_SC_XOPEN_XCU_VERSION"),
        (libc::_SC_REGEXP, "_SC_REGEXP"),
        (libc::_SC_SHELL, "_SC_SHELL"),
        // POSIX thread/realtime option flags (200809).
        (libc::_SC_THREAD_ATTR_STACKADDR, "_SC_THREAD_ATTR_STACKADDR"),
        (libc::_SC_THREAD_ATTR_STACKSIZE, "_SC_THREAD_ATTR_STACKSIZE"),
        (
            libc::_SC_THREAD_PRIORITY_SCHEDULING,
            "_SC_THREAD_PRIORITY_SCHEDULING",
        ),
        (libc::_SC_THREAD_PRIO_INHERIT, "_SC_THREAD_PRIO_INHERIT"),
        (libc::_SC_THREAD_PRIO_PROTECT, "_SC_THREAD_PRIO_PROTECT"),
        (libc::_SC_THREAD_PROCESS_SHARED, "_SC_THREAD_PROCESS_SHARED"),
        (libc::_SC_BARRIERS, "_SC_BARRIERS"),
        (libc::_SC_CLOCK_SELECTION, "_SC_CLOCK_SELECTION"),
        (libc::_SC_READER_WRITER_LOCKS, "_SC_READER_WRITER_LOCKS"),
        (libc::_SC_SPIN_LOCKS, "_SC_SPIN_LOCKS"),
        (libc::_SC_SPAWN, "_SC_SPAWN"),
        (libc::_SC_TIMEOUTS, "_SC_TIMEOUTS"),
        // _POSIX_* option-version flags (200809, not boolean 1).
        (libc::_SC_MONOTONIC_CLOCK, "_SC_MONOTONIC_CLOCK"),
        (libc::_SC_CPUTIME, "_SC_CPUTIME"),
        (libc::_SC_THREAD_CPUTIME, "_SC_THREAD_CPUTIME"),
        (libc::_SC_MAPPED_FILES, "_SC_MAPPED_FILES"),
        (libc::_SC_MEMLOCK, "_SC_MEMLOCK"),
        (libc::_SC_MEMLOCK_RANGE, "_SC_MEMLOCK_RANGE"),
        (libc::_SC_MEMORY_PROTECTION, "_SC_MEMORY_PROTECTION"),
        (libc::_SC_SEMAPHORES, "_SC_SEMAPHORES"),
        (libc::_SC_SHARED_MEMORY_OBJECTS, "_SC_SHARED_MEMORY_OBJECTS"),
        (libc::_SC_SYNCHRONIZED_IO, "_SC_SYNCHRONIZED_IO"),
        (libc::_SC_TIMERS, "_SC_TIMERS"),
        (libc::_SC_REALTIME_SIGNALS, "_SC_REALTIME_SIGNALS"),
        (libc::_SC_PRIORITY_SCHEDULING, "_SC_PRIORITY_SCHEDULING"),
        (libc::_SC_FSYNC, "_SC_FSYNC"),
        (libc::_SC_ASYNCHRONOUS_IO, "_SC_ASYNCHRONOUS_IO"),
        // Suggested NSS buffer sizes.
        (libc::_SC_GETPW_R_SIZE_MAX, "_SC_GETPW_R_SIZE_MAX"),
        (libc::_SC_GETGR_R_SIZE_MAX, "_SC_GETGR_R_SIZE_MAX"),
        // Utility limits.
        (libc::_SC_BC_BASE_MAX, "_SC_BC_BASE_MAX"),
        (libc::_SC_BC_DIM_MAX, "_SC_BC_DIM_MAX"),
        (libc::_SC_BC_SCALE_MAX, "_SC_BC_SCALE_MAX"),
        (libc::_SC_BC_STRING_MAX, "_SC_BC_STRING_MAX"),
        (libc::_SC_COLL_WEIGHTS_MAX, "_SC_COLL_WEIGHTS_MAX"),
        (libc::_SC_EXPR_NEST_MAX, "_SC_EXPR_NEST_MAX"),
        (libc::_SC_LINE_MAX, "_SC_LINE_MAX"),
        (libc::_SC_RE_DUP_MAX, "_SC_RE_DUP_MAX"),
        // Standard limits / counts (stable for the run).
        (libc::_SC_HOST_NAME_MAX, "_SC_HOST_NAME_MAX"),
        (libc::_SC_LOGIN_NAME_MAX, "_SC_LOGIN_NAME_MAX"),
        (libc::_SC_TTY_NAME_MAX, "_SC_TTY_NAME_MAX"),
        (libc::_SC_STREAM_MAX, "_SC_STREAM_MAX"),
        (libc::_SC_IOV_MAX, "_SC_IOV_MAX"),
        (libc::_SC_PAGESIZE, "_SC_PAGESIZE"),
        (libc::_SC_NGROUPS_MAX, "_SC_NGROUPS_MAX"),
        (libc::_SC_NPROCESSORS_ONLN, "_SC_NPROCESSORS_ONLN"),
        (libc::_SC_NPROCESSORS_CONF, "_SC_NPROCESSORS_CONF"),
        (libc::_SC_PHYS_PAGES, "_SC_PHYS_PAGES"),
        (libc::_SC_THREAD_KEYS_MAX, "_SC_THREAD_KEYS_MAX"),
        (
            libc::_SC_THREAD_DESTRUCTOR_ITERATIONS,
            "_SC_THREAD_DESTRUCTOR_ITERATIONS",
        ),
        (libc::_SC_THREADS, "_SC_THREADS"),
        (libc::_SC_VERSION, "_SC_VERSION"),
        (libc::_SC_2_VERSION, "_SC_2_VERSION"),
        (libc::_SC_JOB_CONTROL, "_SC_JOB_CONTROL"),
        (libc::_SC_SAVED_IDS, "_SC_SAVED_IDS"),
    ]
}

#[test]
fn sysconf_stable_values_match_glibc() {
    for (key, name) in stable_keys() {
        let g = unsafe { libc::sysconf(key) };
        let f = unsafe { fl_sysconf(key) };
        assert_eq!(f, g, "sysconf({name}): fl={f} glibc={g}");
    }
}

#[test]
fn sysconf_avphys_pages_agrees_in_magnitude() {
    // Free-RAM pages fluctuate between the two calls, so we don't assert exact
    // equality — only that both report a plausible, same-sign value (the fix
    // was MemAvailable -> MemFree; MemAvailable would be much larger, but here
    // we just guard against -1/0 vs a real count divergence).
    let g = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
    let f = unsafe { fl_sysconf(libc::_SC_AVPHYS_PAGES) };
    assert!(g > 0, "glibc _SC_AVPHYS_PAGES should be positive");
    assert!(f > 0, "fl _SC_AVPHYS_PAGES should be positive (MemFree)");
    // Both derive from free RAM; allow a 4x window for fluctuation/estimate.
    let lo = g / 4;
    let hi = g.saturating_mul(4);
    assert!(
        f >= lo && f <= hi,
        "fl _SC_AVPHYS_PAGES {f} not within [{lo},{hi}] of glibc {g}"
    );
}

#[test]
fn sysconf_invalid_key_is_einval() {
    // A clearly-invalid sysconf name returns -1 (both impls).
    let bogus: c_int = 0x7fff_fff0;
    let g = unsafe { libc::sysconf(bogus) };
    let f = unsafe { fl_sysconf(bogus) };
    assert_eq!(g, -1, "glibc rejects bogus key");
    assert_eq!(f, g, "fl bogus-key return must match glibc");
}
