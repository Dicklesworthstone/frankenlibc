#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc syslog oracle; redirects process fd 2

//! Differential gate for the setlogmask() priority filter (bd-c7cs3h).
//!
//! glibc drops a message whose level bit is clear in the current mask:
//!
//!     if ((LOG_MASK (LOG_PRI (pri)) & LogMask) == 0)
//!       return;
//!
//! fl stored the mask in `setlogmask()` but `syslog_send()` never read it, so
//! every message was emitted regardless. That was fixed once, in dc6bdb4e0
//! (2026-06-18), and then SILENTLY DELETED on 2026-06-26 by e634aff2a — a
//! commit about wordexp `${...}` expansion, which had nothing to do with
//! syslog. Nothing noticed for six weeks, because the only setlogmask test in
//! the repo (bd-22qdtd's, commit 3376bed21) checks the set/query round-trip and
//! never calls syslog(). A stored-but-unread mask passes it perfectly.
//!
//! This file is the arm that regression needed.
//!
//! Observing the filter without a syslog daemon: `openlog` with LOG_PERROR
//! makes both impls write the message to stderr as well as to /dev/log, so
//! "was it emitted" is visible on a captured fd 2 and needs no socket. The
//! comparison is deliberately on WHETHER each priority produced output, not on
//! the bytes of the line: line formatting (ident, pid, timestamp) is a separate
//! concern from filtering, and asserting it here would make this gate fail for
//! reasons that are not the bug it exists to catch.

use std::ffi::{CString, c_char, c_int, c_void};
use std::io::Read;
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

unsafe extern "C" {
    fn openlog(ident: *const c_char, option: c_int, facility: c_int);
    fn closelog();
    fn setlogmask(mask: c_int) -> c_int;
    fn syslog(priority: c_int, fmt: *const c_char, ...);
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

/// Serialises the whole openlog/setlogmask/syslog/closelog window: these are
/// process-global and the harness runs tests in parallel threads.
static SYSLOG_LOCK: Mutex<()> = Mutex::new(());

const LOG_PERROR: c_int = 0x20;
const LOG_USER: c_int = 1 << 3;

const LOG_EMERG: c_int = 0;
const LOG_ERR: c_int = 3;
const LOG_DEBUG: c_int = 7;

/// `LOG_MASK(pri)` / `LOG_UPTO(pri)` from <syslog.h>.
fn log_mask(pri: c_int) -> c_int {
    1 << pri
}
fn log_upto(pri: c_int) -> c_int {
    (1 << (pri + 1)) - 1
}

fn capture<F: FnOnce()>(f: F) -> Vec<u8> {
    let mut fds = [0i32; 2];
    unsafe { libc::pipe(fds.as_mut_ptr()) };
    let saved = unsafe { libc::dup(2) };
    unsafe { libc::dup2(fds[1], 2) };
    f();
    unsafe { libc::fflush(std::ptr::null_mut()) };
    unsafe {
        libc::dup2(saved, 2);
        libc::close(saved);
        libc::close(fds[1]);
    }
    let mut out = Vec::new();
    let mut file = unsafe { std::fs::File::from_raw_fd(fds[0]) };
    let _ = file.read_to_end(&mut out);
    out
}

/// The two implementations under comparison, as a uniform set of entry points.
struct Impl {
    name: &'static str,
    openlog: unsafe fn(*const c_char, c_int, c_int),
    closelog: unsafe fn(),
    setlogmask: unsafe fn(c_int) -> c_int,
    syslog1: unsafe fn(c_int, *const c_char),
}

/// glibc is reached through the `extern "C"` declarations above. Assert they are
/// NOT fl's own symbols: in a release test build `no_mangle` is active and these
/// would bind to fl, silently comparing fl against itself.
fn glibc_impl() -> Impl {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        for (sym, fl_addr) in [
            (c"openlog", frankenlibc_abi::unistd_abi::openlog as *const () as usize),
            (c"setlogmask", frankenlibc_abi::unistd_abi::setlogmask as *const () as usize),
        ] {
            let s = dlsym(h, sym.as_ptr());
            assert!(!s.is_null(), "dlsym({sym:?}) failed");
            assert_ne!(
                s as usize, fl_addr,
                "{sym:?} resolved to fl's own symbol — the arms are not distinct"
            );
        }
    }
    Impl {
        name: "glibc",
        openlog: |i, o, f| unsafe { openlog(i, o, f) },
        closelog: || unsafe { closelog() },
        setlogmask: |m| unsafe { setlogmask(m) },
        syslog1: |p, f| unsafe { syslog(p, f) },
    }
}

fn fl_impl() -> Impl {
    Impl {
        name: "fl",
        openlog: |i, o, f| unsafe { frankenlibc_abi::unistd_abi::openlog(i, o, f) },
        closelog: || unsafe { frankenlibc_abi::unistd_abi::closelog() },
        setlogmask: |m| unsafe { frankenlibc_abi::unistd_abi::setlogmask(m) },
        syslog1: |p, f| unsafe { frankenlibc_abi::unistd_abi::syslog(p, f) },
    }
}

/// For each priority 0..=7 under `mask`, did the implementation emit anything?
///
/// Restores the previous mask and closes the log before returning, so one arm
/// cannot leak a mask into the next.
fn emitted_by_priority(imp: &Impl, mask: c_int) -> [bool; 8] {
    let ident = CString::new("fltest").unwrap();
    let fmt = CString::new("m").unwrap();
    let mut out = [false; 8];

    unsafe { (imp.openlog)(ident.as_ptr(), LOG_PERROR, LOG_USER) };
    let prev = unsafe { (imp.setlogmask)(mask) };
    for (pri, slot) in out.iter_mut().enumerate() {
        let captured = capture(|| unsafe { (imp.syslog1)(pri as c_int, fmt.as_ptr()) });
        *slot = !captured.is_empty();
    }
    unsafe {
        (imp.setlogmask)(prev);
        (imp.closelog)();
    }
    out
}

fn check(mask: c_int, label: &str, expected: [bool; 8]) {
    let g = emitted_by_priority(&glibc_impl(), mask);
    let f = emitted_by_priority(&fl_impl(), mask);
    assert_eq!(
        f, g,
        "{label} (mask {mask:#x}): emitted-by-priority differs; fl={f:?} glibc={g:?}"
    );
    // Assert what the ORACLE produced, not only that the arms agree: if BOTH
    // impls stopped filtering — which is exactly the state this gate exists to
    // catch — the equality above would still hold.
    assert_eq!(
        g, expected,
        "{label} (mask {mask:#x}): glibc did not filter as <syslog.h> specifies; got {g:?}"
    );
}

#[test]
fn syslog_honors_log_upto_err() {
    let _guard = SYSLOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // LOG_UPTO(LOG_ERR) admits EMERG..ERR (0..=3) and drops WARNING..DEBUG.
    check(
        log_upto(LOG_ERR),
        "LOG_UPTO(LOG_ERR)",
        [true, true, true, true, false, false, false, false],
    );
}

#[test]
fn syslog_honors_a_single_priority_mask() {
    let _guard = SYSLOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A non-contiguous mask: only DEBUG passes. Catches an implementation that
    // treated the mask as a threshold ("<= level") rather than a bitmask, which
    // LOG_UPTO alone cannot distinguish.
    let mut expected = [false; 8];
    expected[LOG_DEBUG as usize] = true;
    check(log_mask(LOG_DEBUG), "LOG_MASK(LOG_DEBUG) only", expected);

    // Two non-adjacent bits, for the same reason.
    let mut expected = [false; 8];
    expected[LOG_EMERG as usize] = true;
    expected[LOG_ERR as usize] = true;
    check(
        log_mask(LOG_EMERG) | log_mask(LOG_ERR),
        "LOG_MASK(EMERG)|LOG_MASK(ERR)",
        expected,
    );
}

#[test]
fn syslog_emits_every_priority_under_the_default_mask() {
    let _guard = SYSLOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // NEGATIVE CONTROL for the arms above. With every bit set, nothing may be
    // filtered. Without this, an implementation that dropped ALL messages —
    // or a harness whose capture never saw anything — would satisfy every
    // suppression assertion above.
    check(log_upto(LOG_DEBUG), "LOG_UPTO(LOG_DEBUG) (all bits)", [true; 8]);
}

#[test]
fn a_filtered_message_is_dropped_not_merely_unprinted() {
    // The mask must gate the message itself, not just the LOG_PERROR echo: a
    // filtered call has to produce no output even when LOG_PERROR is off and
    // regardless of whether a syslog socket is reachable. Stated separately
    // because an implementation that filtered only inside the LOG_PERROR branch
    // would pass every arm above while still sending filtered records to the
    // daemon.
    let _guard = SYSLOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let ident = CString::new("fltest").unwrap();
    let fmt = CString::new("m").unwrap();

    let imp = fl_impl();
    unsafe { (imp.openlog)(ident.as_ptr(), LOG_PERROR, LOG_USER) };
    let prev = unsafe { (imp.setlogmask)(log_upto(LOG_ERR)) };

    let admitted = capture(|| unsafe { (imp.syslog1)(LOG_ERR, fmt.as_ptr()) });
    let filtered = capture(|| unsafe { (imp.syslog1)(LOG_DEBUG, fmt.as_ptr()) });

    unsafe {
        (imp.setlogmask)(prev);
        (imp.closelog)();
    }

    assert!(
        !admitted.is_empty(),
        "LOG_ERR is inside LOG_UPTO(LOG_ERR) and must be emitted"
    );
    assert!(
        filtered.is_empty(),
        "LOG_DEBUG is outside LOG_UPTO(LOG_ERR) and must be dropped, got {:?}",
        String::from_utf8_lossy(&filtered)
    );
}

#[test]
fn setlogmask_round_trip_still_matches_glibc() {
    // The pre-existing bd-22qdtd property, kept alongside the filter arms so the
    // relationship is visible: this passes on a stored-but-never-read mask,
    // which is precisely why it did not catch the regression above.
    let _guard = SYSLOG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let g = glibc_impl();
    let f = fl_impl();

    let seq = |imp: &Impl| -> (c_int, c_int, c_int) {
        let default = unsafe { (imp.setlogmask)(0) }; // 0 queries without changing
        let prev = unsafe { (imp.setlogmask)(log_upto(LOG_ERR)) };
        let now = unsafe { (imp.setlogmask)(0) };
        unsafe { (imp.setlogmask)(prev) };
        (default, prev, now)
    };

    let gs = seq(&g);
    let fs = seq(&f);
    assert_eq!(
        fs, gs,
        "setlogmask (default, prev, new) round-trip: fl={fs:?} glibc={gs:?}"
    );
    assert_eq!(
        gs.2,
        log_upto(LOG_ERR),
        "a query after setting must report the mask just installed"
    );
}
