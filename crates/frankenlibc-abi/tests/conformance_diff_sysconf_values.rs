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
        // These are POSIX option-version values, not boolean capability flags.
        // Keep the sibling of _SC_THREADS in this independently-maintained
        // stable-values gate: a return of `1` is a real regression even though
        // it is non-negative.
        (libc::_SC_THREAD_SAFE_FUNCTIONS, "_SC_THREAD_SAFE_FUNCTIONS"),
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
fn sysconf_avphys_pages_tracks_free_ram_not_the_available_estimate() {
    // THIS REPLACES A 4x-WINDOW MAGNITUDE CHECK THAT WAS BOTH VACUOUS AND
    // FLAKY, and the two faults had one cause: it compared fl against a second
    // reading of glibc and accepted anything within 4x.
    //
    //   VACUOUS -- fl answered /proc/meminfo MemAvailable while glibc reports
    //     the raw free RAM from sysinfo(2). Measured on the worker that ran
    //     this gate green: MemFree 431648 pages against MemAvailable 1676548,
    //     a ratio of 3.88x, INSIDE the 4x window. So the gate passed over a
    //     live 3.88x over-report. Its own comment claimed to pin "the fix was
    //     MemAvailable -> MemFree"; that fix (bd-l18p7s) had landed on
    //     get_avphys_pages only, and sysconf still read the other field.
    //   FLAKY -- on a worker whose page cache pushed the ratio to 5.29x the
    //     same gate failed, so one permanent defect presented as an
    //     intermittent RED that depended on which host drew the run.
    //
    // The replacement does NOT key on the MemFree/MemAvailable ratio. A first
    // version did, and a negative control caught it failing outright on a
    // cold-cache worker (ratio 1.38x) where it could not discriminate -- a gate
    // that REDs on correct code because of the host's page cache is the same
    // trap in a new costume. Instead fl is bracketed against the incumbent
    // itself, which is host-independent: both sides read one kernel counter, so
    // they agree to within its drift across two adjacent calls, and a value
    // taken from any other source is tens of percent away.
    let free_pages = meminfo_pages("MemFree:");
    let available_pages = meminfo_pages("MemAvailable:");

    let g_first = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
    assert!(
        g_first > 0,
        "host premise: glibc _SC_AVPHYS_PAGES must be positive, got {g_first}"
    );
    println!("AVPHYS: glibc={g_first} MemFree={free_pages:?} MemAvailable={available_pages:?}");

    // Both fl entry points are judged, because glibc implements
    // sysconf(_SC_AVPHYS_PAGES) by CALLING get_avphys_pages. Fixing one and not
    // the other is precisely how the divergence above survived: the direct
    // function had a bracketing test in stdlib_abi_test and the selector had
    // none, so only the untested door was wrong.
    for (label, probe) in [
        (
            "sysconf(_SC_AVPHYS_PAGES)",
            (|| unsafe { fl_sysconf(libc::_SC_AVPHYS_PAGES) }) as fn() -> libc::c_long,
        ),
        (
            "get_avphys_pages()",
            // Wrapped rather than named directly: it is an `extern "C" fn`,
            // which does not coerce to a Rust `fn` pointer.
            (|| frankenlibc_abi::stdlib_abi::get_avphys_pages()) as fn() -> libc::c_long,
        ),
    ] {
        assert_brackets_host_free_ram(label, probe, free_pages, available_pages);
    }
}

/// Assert an fl probe reports the same kernel counter glibc does.
///
/// BRACKETING, not equality: free RAM moves, so the host is sampled either side
/// of fl's call and fl must land between those samples. Drift across two
/// adjacent library calls is far smaller than the gap to any other candidate
/// source -- MemAvailable ran 1.38x to 5.29x above free RAM across the workers
/// measured -- so this separates "same counter, sampled a moment apart" from
/// "different counter" without needing to know which host it is running on.
/// Non-monotonic jitter inside a single window is retried, the same shape the
/// get_avphys_pages arm in stdlib_abi_test already uses.
fn assert_brackets_host_free_ram(
    label: &str,
    probe: fn() -> libc::c_long,
    free_pages: Option<i64>,
    available_pages: Option<i64>,
) {
    // Absorbs unit rounding only; the counter itself is compared by bracket.
    const SLACK: libc::c_long = 64;
    let mut attempts = Vec::new();
    for _ in 0..8 {
        let before = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
        let observed = probe();
        let after = unsafe { libc::sysconf(libc::_SC_AVPHYS_PAGES) };
        let (lo, hi) = (before.min(after), before.max(after));
        if observed >= lo - SLACK && observed <= hi + SLACK {
            return;
        }
        attempts.push(format!("host [{lo},{hi}] fl {observed}"));
    }
    panic!(
        "fl {label} never landed inside the host's own free-RAM window in 8 attempts.\n           {}\n  For reference on this host: MemFree {free_pages:?} pages, MemAvailable          {available_pages:?} pages. An fl value near MemAvailable means it is reporting the          kernel's reclaimable-cache ESTIMATE where glibc reports raw free RAM (sysinfo(2)          freeram), which over-states free memory by the size of the page cache.",
        attempts.join("\n  ")
    )
}

/// Read a `/proc/meminfo` field and convert its kB figure to pages.
///
/// Diagnostic only -- nothing is asserted against it. glibc does not read this
/// file for these selectors (emptying it under bwrap leaves glibc answering
/// correctly), so it is reported to make a failure legible, not to define the
/// expected value.
fn meminfo_pages(field: &str) -> Option<i64> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            let kb: i64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb.checked_mul(1024)? / page_size);
        }
    }
    None
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
