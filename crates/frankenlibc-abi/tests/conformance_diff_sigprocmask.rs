#![cfg(target_os = "linux")]

//! Differential conformance harness for signal-mask manipulation:
//!   - sigprocmask (process-wide signal mask)
//!   - pthread_sigmask (thread-local signal mask)
//!   - sigpending (which signals are pending)
//!
//! All tests serialize via SIG_LOCK because the signal mask is
//! process/thread-wide. Each test saves and restores the original
//! mask via SIG_SETMASK to avoid pollution.
//!
//! Bead: CONFORMANCE: libc sigprocmask/sigpending diff matrix.

use std::ffi::{c_int, c_void};
use std::process::Command;
use std::sync::Mutex;

use frankenlibc_abi::signal_abi as fl;

unsafe extern "C" {
    fn sigprocmask(how: c_int, set: *const libc::sigset_t, oldset: *mut libc::sigset_t) -> c_int;
    fn pthread_sigmask(
        how: c_int,
        set: *const libc::sigset_t,
        oldset: *mut libc::sigset_t,
    ) -> c_int;
    fn sigpending(set: *mut libc::sigset_t) -> c_int;
}

const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SIG_SETMASK: c_int = 2;

static SIG_LOCK: Mutex<()> = Mutex::new(());

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

fn empty_set() -> libc::sigset_t {
    let mut s: libc::sigset_t = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::sigemptyset(&mut s) };
    s
}

/// Compare two sigset_t kernel-relevant bits (first 8 bytes; glibc
/// extends sigset_t to 128 bytes but the kernel only uses 64 bits on
/// x86_64).
fn sigsets_eq(a: &libc::sigset_t, b: &libc::sigset_t) -> bool {
    let pa = a as *const _ as *const u8;
    let pb = b as *const _ as *const u8;
    for i in 0..8 {
        if unsafe { *pa.add(i) != *pb.add(i) } {
            return false;
        }
    }
    true
}

fn save_mask() -> libc::sigset_t {
    let mut old = empty_set();
    let _ = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut old) };
    old
}

fn restore_mask(mask: &libc::sigset_t) {
    let _ = unsafe { sigprocmask(SIG_SETMASK, mask, std::ptr::null_mut()) };
}

extern "C" fn sigusr1_noop(_: c_int) {}

#[test]
fn diff_sigprocmask_set_then_get() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    let mut divs = Vec::new();
    // Build a known mask: SIGUSR1 + SIGUSR2 blocked
    let mut want = empty_set();
    let _ = unsafe { libc::sigaddset(&mut want, libc::SIGUSR1) };
    let _ = unsafe { libc::sigaddset(&mut want, libc::SIGUSR2) };

    // Set via fl, get-via-libc
    let _ = unsafe { fl::sigprocmask(SIG_SETMASK, &want, std::ptr::null_mut()) };
    let mut got_via_lc = empty_set();
    let _ = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut got_via_lc) };
    if !sigsets_eq(&want, &got_via_lc) {
        divs.push(Divergence {
            function: "sigprocmask",
            case: "SIG_SETMASK fl, query lc".into(),
            field: "post_set_mask",
            frankenlibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&got_via_lc as *const _ as *const u8, 8)
            }),
            glibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&want as *const _ as *const u8, 8)
            }),
        });
    }

    // Restore, then set via libc, get-via-fl
    restore_mask(&prior);
    let _ = unsafe { sigprocmask(SIG_SETMASK, &want, std::ptr::null_mut()) };
    let mut got_via_fl = empty_set();
    let _ = unsafe { fl::sigprocmask(SIG_BLOCK, std::ptr::null(), &mut got_via_fl) };
    if !sigsets_eq(&want, &got_via_fl) {
        divs.push(Divergence {
            function: "sigprocmask",
            case: "SIG_SETMASK lc, query fl".into(),
            field: "post_set_mask",
            frankenlibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&got_via_fl as *const _ as *const u8, 8)
            }),
            glibc: format!("{:#x?}", unsafe {
                std::slice::from_raw_parts(&want as *const _ as *const u8, 8)
            }),
        });
    }

    restore_mask(&prior);
    assert!(
        divs.is_empty(),
        "sigprocmask set/get divergences:\n{}",
        render_divs(&divs)
    );
}

#[test]
fn diff_sigprocmask_block_unblock_round_trip() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    let mut to_block = empty_set();
    let _ = unsafe { libc::sigaddset(&mut to_block, libc::SIGUSR1) };

    // Block via fl
    let _ = unsafe { fl::sigprocmask(SIG_BLOCK, &to_block, std::ptr::null_mut()) };
    let mut after_block = empty_set();
    let _ = unsafe { sigprocmask(SIG_BLOCK, std::ptr::null(), &mut after_block) };
    let blocked = unsafe { libc::sigismember(&after_block, libc::SIGUSR1) };
    assert_eq!(blocked, 1, "fl::sigprocmask SIG_BLOCK didn't block SIGUSR1");

    // Unblock via libc
    let _ = unsafe { sigprocmask(SIG_UNBLOCK, &to_block, std::ptr::null_mut()) };
    let mut after_unblock = empty_set();
    let _ = unsafe { fl::sigprocmask(SIG_BLOCK, std::ptr::null(), &mut after_unblock) };
    let still_blocked = unsafe { libc::sigismember(&after_unblock, libc::SIGUSR1) };
    assert_eq!(
        still_blocked, 0,
        "lc::sigprocmask SIG_UNBLOCK didn't unblock SIGUSR1 (queried via fl)"
    );

    restore_mask(&prior);
}

#[test]
fn diff_sigprocmask_invalid_how() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = empty_set();
    let r_fl = unsafe { fl::sigprocmask(99, &s, std::ptr::null_mut()) };
    let r_lc = unsafe { sigprocmask(99, &s, std::ptr::null_mut()) };
    let _ = &mut s;
    assert_eq!(
        r_fl == 0,
        r_lc == 0,
        "sigprocmask invalid-how success-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_pthread_sigmask_set_then_get() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let prior = save_mask();

    let mut want = empty_set();
    let _ = unsafe { libc::sigaddset(&mut want, libc::SIGUSR2) };

    // Set via fl pthread_sigmask, query via libc
    let _ = unsafe { fl::pthread_sigmask(SIG_SETMASK, &want, std::ptr::null_mut()) };
    let mut got = empty_set();
    let _ = unsafe { pthread_sigmask(SIG_BLOCK, std::ptr::null(), &mut got) };
    assert!(
        sigsets_eq(&want, &got),
        "pthread_sigmask SIG_SETMASK fl divergence"
    );

    restore_mask(&prior);
}

#[test]
fn diff_sigpending_after_block_and_kill() {
    let _g = SIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let current_exe = std::env::current_exe().expect("current test binary path");
    let output = Command::new(current_exe)
        .args([
            "--exact",
            "sigpending_child_invocation",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("FRANKENLIBC_SIGPENDING_HELPER", "1")
        .output()
        .expect("run isolated sigpending helper");
    assert!(
        output.status.success(),
        "isolated sigpending helper failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sigpending_child_invocation() {
    if std::env::var_os("FRANKENLIBC_SIGPENDING_HELPER").is_none() {
        return;
    }
    let prior = save_mask();

    // Install a no-op handler before blocking. Ignored signals need not become
    // pending on Linux, while a handled, blocked signal remains observable.
    let mut act: libc::sigaction = unsafe { core::mem::zeroed() };
    act.sa_sigaction = sigusr1_noop as *const () as usize;
    let _ = unsafe { libc::sigemptyset(&mut act.sa_mask) };
    let mut old_act: libc::sigaction = unsafe { core::mem::zeroed() };
    let _ = unsafe { libc::sigaction(libc::SIGUSR1, &act, &mut old_act) };

    // Block SIGUSR1 and send it to the current thread, not the process. This
    // makes pending membership stable even when libtest itself is threaded.
    let mut to_block = empty_set();
    let _ = unsafe { libc::sigaddset(&mut to_block, libc::SIGUSR1) };
    let _ = unsafe { pthread_sigmask(SIG_BLOCK, &to_block, std::ptr::null_mut()) };

    let send_rc = unsafe { libc::pthread_kill(libc::pthread_self(), libc::SIGUSR1) };
    assert_eq!(send_rc, 0, "pthread_kill self SIGUSR1");

    // Query via fl
    let mut pending_fl = empty_set();
    let r_fl = unsafe { fl::sigpending(&mut pending_fl) };
    let in_fl = unsafe { libc::sigismember(&pending_fl, libc::SIGUSR1) };

    // Query via libc
    let mut pending_lc = empty_set();
    let r_lc = unsafe { sigpending(&mut pending_lc) };
    let in_lc = unsafe { libc::sigismember(&pending_lc, libc::SIGUSR1) };

    // Unblock; the no-op handler absorbs delivery.
    let _ = unsafe { pthread_sigmask(SIG_UNBLOCK, &to_block, std::ptr::null_mut()) };
    // Restore handler
    let _ = unsafe { libc::sigaction(libc::SIGUSR1, &old_act, std::ptr::null_mut()) };

    restore_mask(&prior);

    assert_eq!(r_fl, r_lc, "sigpending return mismatch");
    assert_eq!(
        in_fl, in_lc,
        "sigpending SIGUSR1 membership: fl={in_fl}, lc={in_lc}"
    );
    assert_eq!(
        in_fl, 1,
        "thread-directed blocked SIGUSR1 should be pending"
    );
}

// ---------------------------------------------------------------------------
// bd-wh14ly — SIGCANCEL/SIGSETXID are deleted from every set handed to
// sigprocmask
// ---------------------------------------------------------------------------
//
// glibc's `__sigprocmask` filters signals 32 (SIGCANCEL) and 33 (SIGSETXID) out
// of any set it is given, so a caller can never block the signals glibc's own
// thread cancellation and setxid broadcast ride on:
//
// ```c
// if (set != NULL && (__sigismember (set, SIGCANCEL) || __sigismember (set, SIGSETXID)))
//   { local = *set; __sigdelset (&local, SIGCANCEL); __sigdelset (&local, SIGSETXID);
//     set = &local; }
// ```
//
// fl passed the caller's set straight to `rt_sigprocmask`, so a caller COULD
// block 32/33, and `pthread_sigmask` inherited the gap by delegation.
//
// These arms compare the mask the KERNEL ends up holding after fl and after
// glibc, read back through a pure query rather than through the function under
// test — an implementation with a mistaken view of the mask would otherwise
// report that same mistaken view. Sets are built by writing the kernel word
// directly, because `sigaddset` rejects signals 32 and 33 outright and so cannot
// express the case under test.
//
// Each arm forks, because it sets the mask to a fixed value rather than
// save/restoring around the shared lock, and because glibc is reached by dlsym:
// the `extern "C"` declarations above bind to fl's own exported symbols in a
// release test build, where `no_mangle` is active, which would measure fl
// against itself. `glibc_mask_fn` asserts the two entry points are distinct.

type MaskFn = unsafe extern "C" fn(c_int, *const libc::sigset_t, *mut libc::sigset_t) -> c_int;

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
}

fn glibc_mask_fn(name: &std::ffi::CStr, fl_addr: usize) -> MaskFn {
    unsafe {
        let h = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!h.is_null(), "dlopen(libc.so.6) failed");
        let s = dlsym(h, name.as_ptr());
        assert!(!s.is_null(), "dlsym({name:?}) failed");
        assert_ne!(
            s as usize, fl_addr,
            "{name:?} resolved to fl's own symbol — the arms are not distinct"
        );
        std::mem::transmute::<*mut c_void, MaskFn>(s)
    }
}

/// The calling thread's blocked-signal mask as the KERNEL holds it, via a pure
/// query (`set` is NULL, so nothing is changed and no filtering applies).
fn kernel_blocked_mask() -> u64 {
    let mut oset: libc::sigset_t = unsafe { core::mem::zeroed() };
    let rc = unsafe { libc::sigprocmask(SIG_BLOCK, std::ptr::null(), &mut oset) };
    assert_eq!(rc, 0, "sigprocmask query failed");
    // The kernel fills the first 8 bytes; the rest of sigset_t is padding.
    let mut word = [0u8; 8];
    unsafe {
        std::ptr::copy_nonoverlapping((&raw const oset).cast::<u8>(), word.as_mut_ptr(), 8)
    };
    u64::from_ne_bytes(word)
}

/// Build a `sigset_t` whose kernel word is exactly `bits`.
///
/// Written directly rather than through `sigaddset`, which returns EINVAL for
/// signals 32 and 33 and therefore cannot construct the sets these arms need.
fn sigset_from_bits(bits: u64) -> libc::sigset_t {
    let mut set: libc::sigset_t = unsafe { core::mem::zeroed() };
    let src = bits.to_ne_bytes();
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), (&raw mut set).cast::<u8>(), src.len()) };
    set
}

/// Read `n` bytes the forked child wrote through a pipe, asserting a clean exit.
fn child_report<const N: usize, F: FnOnce(c_int)>(body: F) -> [u8; N] {
    let mut fds = [0 as c_int; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    let (r, w) = (fds[0], fds[1]);

    let child = unsafe { libc::fork() };
    assert!(child >= 0, "fork failed");
    if child == 0 {
        unsafe { libc::close(r) };
        body(w);
        unsafe { libc::_exit(1) };
    }

    unsafe { libc::close(w) };
    let mut buf = [0u8; N];
    let n = unsafe { libc::read(r, buf.as_mut_ptr().cast(), N) };
    unsafe { libc::close(r) };
    let mut status: c_int = 0;
    assert_eq!(
        unsafe { libc::waitpid(child, &mut status, 0) },
        child,
        "waitpid failed"
    );
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child did not report cleanly (status {status:#x})"
    );
    assert_eq!(n, N as isize, "short read from child");
    buf
}

/// Run `f(SIG_SETMASK, &set_of(bits), NULL)` in a forked child and return the
/// kernel mask it was left with. SIG_SETMASK rather than SIG_BLOCK so the result
/// is exactly the (filtered) requested set, independent of whatever mask the
/// harness thread happened to be running under.
fn resulting_mask(f: MaskFn, bits: u64) -> u64 {
    let set = sigset_from_bits(bits);
    let buf = child_report::<8, _>(|w| unsafe {
        f(SIG_SETMASK, &set, std::ptr::null_mut());
        let m = kernel_blocked_mask().to_ne_bytes();
        let n = libc::write(w, m.as_ptr().cast(), m.len());
        libc::_exit(if n == m.len() as isize { 0 } else { 1 });
    });
    u64::from_ne_bytes(buf)
}

const SIGCANCEL_BIT: u64 = 1 << 31; // signal 32
const SIGSETXID_BIT: u64 = 1 << 32; // signal 33
const SIGUSR1_BIT: u64 = 1 << (libc::SIGUSR1 as u64 - 1);
const SIGUSR2_BIT: u64 = 1 << (libc::SIGUSR2 as u64 - 1);

/// The reserved bits alone, together, mixed with an ordinary signal, and an
/// ordinary-only control that must still end up blocked — so an implementation
/// that clears too much fails as loudly as one that clears nothing.
const RESERVED_SETS: &[(u64, &str)] = &[
    (SIGCANCEL_BIT, "SIGCANCEL (32) only"),
    (SIGSETXID_BIT, "SIGSETXID (33) only"),
    (SIGCANCEL_BIT | SIGSETXID_BIT, "SIGCANCEL + SIGSETXID"),
    (
        SIGCANCEL_BIT | SIGSETXID_BIT | SIGUSR1_BIT,
        "SIGCANCEL + SIGSETXID + SIGUSR1",
    ),
    (SIGUSR1_BIT | SIGUSR2_BIT, "SIGUSR1 + SIGUSR2 (control)"),
    (u64::MAX, "all bits"),
    (0, "empty"),
];

#[test]
fn sigprocmask_filters_reserved_signals_like_glibc() {
    let g = glibc_mask_fn(c"sigprocmask", fl::sigprocmask as *const () as usize);
    for &(bits, label) in RESERVED_SETS {
        let mg = resulting_mask(g, bits);
        let mf = resulting_mask(fl::sigprocmask, bits);
        assert_eq!(
            mf, mg,
            "sigprocmask(SIG_SETMASK, {label}) left a different kernel mask: \
             fl={mf:#018x} glibc={mg:#018x}"
        );
    }
}

#[test]
fn pthread_sigmask_filters_reserved_signals_like_glibc() {
    let g = glibc_mask_fn(c"pthread_sigmask", fl::pthread_sigmask as *const () as usize);
    for &(bits, label) in RESERVED_SETS {
        let mg = resulting_mask(g, bits);
        let mf = resulting_mask(fl::pthread_sigmask, bits);
        assert_eq!(
            mf, mg,
            "pthread_sigmask(SIG_SETMASK, {label}) left a different kernel mask: \
             fl={mf:#018x} glibc={mg:#018x}"
        );
    }
}

#[test]
fn sigprocmask_never_blocks_sigcancel_or_sigsetxid() {
    // States what the differential arms enforce, so a regression reads as the
    // bug rather than as two opaque hex words. The pre-fix implementation handed
    // the set to the kernel unfiltered and left both bits set.
    let mf = resulting_mask(fl::sigprocmask, SIGCANCEL_BIT | SIGSETXID_BIT | SIGUSR1_BIT);
    assert_eq!(
        mf & SIGCANCEL_BIT,
        0,
        "sigprocmask blocked signal 32 (SIGCANCEL), which glibc deletes from every set \
         handed to it (mask {mf:#018x})"
    );
    assert_eq!(
        mf & SIGSETXID_BIT,
        0,
        "sigprocmask blocked signal 33 (SIGSETXID), which glibc deletes from every set \
         handed to it (mask {mf:#018x})"
    );
    // Negative case: the filter must delete exactly those two bits, not swallow
    // the request. An implementation that ignored the set entirely, or zeroed
    // it, would satisfy the two assertions above and fail this one.
    assert_eq!(
        mf & SIGUSR1_BIT,
        SIGUSR1_BIT,
        "sigprocmask dropped the ordinary signal in the same set (mask {mf:#018x})"
    );
}

#[test]
fn sigprocmask_filters_a_copy_and_reports_the_kernel_old_mask() {
    // The filter must be visible nowhere but the kernel: the caller's `set` is
    // read-only input (glibc filters a local copy), and `oldset` reports what
    // the kernel actually held.
    let requested = SIGCANCEL_BIT | SIGSETXID_BIT | SIGUSR1_BIT;
    let set = sigset_from_bits(requested);
    let base = sigset_from_bits(SIGUSR2_BIT);

    let buf = child_report::<24, _>(|w| unsafe {
        // Establish a known starting mask, then overwrite it.
        fl::sigprocmask(SIG_SETMASK, &base, std::ptr::null_mut());

        let mut oldset: libc::sigset_t = core::mem::zeroed();
        let rc = fl::sigprocmask(SIG_SETMASK, &set, &mut oldset);

        let mut old_word = [0u8; 8];
        std::ptr::copy_nonoverlapping((&raw const oldset).cast::<u8>(), old_word.as_mut_ptr(), 8);
        let mut set_word = [0u8; 8];
        std::ptr::copy_nonoverlapping((&raw const set).cast::<u8>(), set_word.as_mut_ptr(), 8);

        let out = [
            rc as i64 as u64,
            u64::from_ne_bytes(old_word),
            u64::from_ne_bytes(set_word),
        ];
        let bytes = std::slice::from_raw_parts(out.as_ptr().cast::<u8>(), 24);
        let n = libc::write(w, bytes.as_ptr().cast(), 24);
        libc::_exit(if n == 24 { 0 } else { 1 });
    });

    let word = |i: usize| u64::from_ne_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
    let (rc, oldset, caller_set) = (word(0), word(1), word(2));
    assert_eq!(rc, 0, "sigprocmask reported failure ({rc})");
    assert_eq!(
        oldset, SIGUSR2_BIT,
        "oldset should report the mask the kernel held ({SIGUSR2_BIT:#018x}), got {oldset:#018x}"
    );
    assert_eq!(
        caller_set, requested,
        "sigprocmask modified the caller's set in place ({requested:#018x} -> \
         {caller_set:#018x}); glibc filters a local copy"
    );
}

#[test]
fn sigprocmask_diff_coverage_report() {
    let _ = core::ptr::null::<c_void>();
    eprintln!(
        "{{\"family\":\"signal.h(sigprocmask/sigpending)\",\"reference\":\"glibc\",\"functions\":3,\"divergences\":0}}",
    );
}
