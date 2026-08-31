#![cfg(all(target_os = "linux", target_arch = "x86_64"))]
#![allow(unsafe_code)] // raw syscall oracle + live glibc oracle

//! `uselib` and `__profile_frequency`.
//!
//! bd-ib5u39 and bd-qnys38: neither had differential coverage. They are gated
//! together because they need DIFFERENT oracles, and the reason is the point.
//!
//! ## `uselib` has no glibc oracle at all
//!
//! Modern glibc no longer exports a `uselib` wrapper — `dlsym` finds nothing.
//! So the oracle here is the KERNEL, reached through `syscall(SYS_uselib, ..)`.
//! Measured on Linux 6.17:
//!
//! ```text
//!   uselib(NULL)              -1, ENOSYS
//!   uselib("/nonexistent.so") -1, ENOSYS
//!   uselib("/lib")            -1, ENOSYS
//! ```
//!
//! ENOSYS for EVERY argument, including a valid-looking path: the syscall is
//! compiled out, so it fails before it can inspect anything. An arm that only
//! tried a bad path would pass an implementation that validated the argument
//! first and returned EFAULT or ENOENT.
//!
//! This is the third disguise from bd-v0388t seen from the other side: not "the
//! oracle might be fl", but "the oracle does not exist", which a link-time
//! `extern "C" { fn uselib(..) }` would not have revealed — it would simply have
//! bound to fl's own export and compared fl against itself.
//!
//! ## `__profile_frequency` must agree with `sysconf`
//!
//! Measured: `__profile_frequency() == sysconf(_SC_CLK_TCK) == 100`, and
//! `sprofil` reports its period as `{0, 1000000/f} = {0, 10000}`. fl used to
//! hardcode the 100; it now derives it, so the two cannot drift apart.

use std::ffi::{c_char, c_int, c_long, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::{host_addr, host_fn};

/// `long syscall(long number, ...)`, matching glibc's declaration.
type SyscallFn = unsafe extern "C" fn(c_long, ...) -> c_long;

/// `int *__errno_location(void)`.
type ErrnoLocationFn = unsafe extern "C" fn() -> *mut c_int;

/// Host glibc's `syscall`, proven not to be fl's own export.
fn host_syscall() -> SyscallFn {
    // SAFETY: the resolved address is glibc's `syscall`, declared
    // `long syscall(long, ...)`; fl's own export is handed over so a collapsed
    // oracle aborts instead of comparing fl against itself.
    unsafe {
        let addr = host_addr(
            c"syscall",
            frankenlibc_abi::unistd_abi::syscall as SyscallFn as *const (),
        );
        std::mem::transmute::<*mut c_void, SyscallFn>(addr)
    }
}

/// Host glibc's `__errno_location`, proven not to be fl's own export.
///
/// `kernel_uselib` is the raw-kernel arm of this gate and both of its halves —
/// the call and the errno read — were link-time references. fl exports `syscall`
/// AND `__errno_location` under
/// `#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]`, so in a release test
/// binary the linker prefers fl's definitions for both: the arm calls fl's
/// syscall wrapper and then reads fl's errno slot, and the comparison becomes
/// fl against fl. Debug hides it because the attribute is off there.
///
/// This gate happens to pass in release today, so unlike bsd_stubs,
/// c_locale_codec and locale_categories this conversion is prophylactic rather
/// than bug-fixing — recorded plainly so nobody reads it as a fix. The three
/// that WERE broken had the identical shape (bd-g1sjty).
fn host_errno_location() -> ErrnoLocationFn {
    // SAFETY: the resolved address is glibc's `__errno_location`, declared
    // `int *__errno_location(void)`; fl's own export is the collapse guard.
    unsafe {
        let addr = host_addr(
            c"__errno_location",
            frankenlibc_abi::errno_abi::__errno_location as ErrnoLocationFn as *const (),
        );
        std::mem::transmute::<*mut c_void, ErrnoLocationFn>(addr)
    }
}

/// x86_64 `__NR_uselib`.
const SYS_USELIB: c_long = 134;

/// `(return, errno)` from the raw kernel syscall.
fn kernel_uselib(path: *const c_char) -> (c_long, c_int) {
    // SAFETY: `uselib` takes one pointer; a NULL or dangling path is exactly
    // what is under test, and the kernel validates it.
    unsafe {
        let host_errno = host_errno_location();
        *host_errno() = 0;
        let rc = host_syscall()(SYS_USELIB, path);
        (rc, *host_errno())
    }
}

/// `(return, errno)` from fl's wrapper.
fn fl_uselib(path: *const c_char) -> (c_int, c_int) {
    // SAFETY: same contract; fl forwards to the same syscall.
    unsafe {
        *frankenlibc_abi::errno_abi::__errno_location() = 0;
        let rc = frankenlibc_abi::glibc_internal_abi::uselib(path);
        (rc, *frankenlibc_abi::errno_abi::__errno_location())
    }
}

#[test]
fn uselib_matches_the_kernel_for_every_argument_shape() {
    let cases: &[(*const c_char, &str)] = &[
        (std::ptr::null(), "NULL"),
        (c"/nonexistent.so".as_ptr(), "missing path"),
        (c"/lib".as_ptr(), "a directory"),
    ];

    for (path, label) in cases {
        let (kernel_rc, kernel_errno) = kernel_uselib(*path);
        assert_eq!(
            (kernel_rc, kernel_errno),
            (-1, libc::ENOSYS),
            "the kernel no longer answers ENOSYS for uselib({label}); this gate's \
             premise is that the syscall is compiled out"
        );

        let (fl_rc, fl_errno) = fl_uselib(*path);
        assert_eq!(
            (c_long::from(fl_rc), fl_errno),
            (kernel_rc, kernel_errno),
            "uselib({label}): fl ({fl_rc}, {fl_errno}) kernel ({kernel_rc}, {kernel_errno})"
        );
    }
}

/// glibc really has stopped exporting it, which is why the oracle above is the
/// kernel. If this ever fails, a wrapper came back and the gate should compare
/// against it instead.
#[test]
fn glibc_does_not_export_a_uselib_wrapper() {
    // SAFETY: dlopen/dlsym with NUL-terminated names; the handle is process-lived.
    let found = unsafe {
        let handle = libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!handle.is_null(), "libc.so.6 must be loadable");
        !libc::dlsym(handle, c"uselib".as_ptr()).is_null()
    };
    assert!(
        !found,
        "glibc exports uselib again — this gate uses the raw syscall as its \
         oracle precisely because it did not, and should now be compared \
         against the wrapper (bd-ib5u39)"
    );
}

type ProfileFrequencyFn = unsafe extern "C" fn() -> c_int;
type SysconfFn = unsafe extern "C" fn(c_int) -> c_long;

#[test]
fn profile_frequency_matches_glibc_and_its_own_sysconf() {
    // SAFETY: `int __profile_frequency(void)`, fl's own export as the guard.
    let host_freq: ProfileFrequencyFn = unsafe {
        host_fn(
            c"__profile_frequency",
            frankenlibc_abi::glibc_internal_abi::__profile_frequency as *const (),
        )
    };
    // SAFETY: `long sysconf(int)`.
    let host_sysconf: SysconfFn = unsafe {
        host_fn(
            c"sysconf",
            frankenlibc_abi::unistd_abi::sysconf as *const (),
        )
    };

    // SAFETY: no arguments / a scalar selector.
    let (fl_f, host_f) = unsafe {
        (
            frankenlibc_abi::glibc_internal_abi::__profile_frequency(),
            host_freq(),
        )
    };
    assert_eq!(fl_f, host_f, "__profile_frequency");

    // SAFETY: scalar selector.
    let (fl_ticks, host_ticks) = unsafe {
        (
            frankenlibc_abi::unistd_abi::sysconf(libc::_SC_CLK_TCK),
            host_sysconf(libc::_SC_CLK_TCK),
        )
    };
    assert_eq!(fl_ticks, host_ticks, "sysconf(_SC_CLK_TCK)");

    // The relation, not just the values: fl derives one from the other, so a
    // change to sysconf that left __profile_frequency behind must fail here.
    assert_eq!(
        c_long::from(fl_f),
        fl_ticks,
        "__profile_frequency must equal sysconf(_SC_CLK_TCK) — it is DERIVED \
         from it, and hardcoding either would let the two drift (bd-qnys38)"
    );
    assert!(
        fl_f > 0,
        "a non-positive frequency divides by zero in callers"
    );
}

/// `sprofil` reports its sampling period as `{0, 1000000 / frequency}`, so the
/// two must stay consistent. Pinned because the period is what a caller sees.
#[test]
fn sprofil_period_is_derived_from_the_frequency() {
    // SAFETY: no arguments.
    let freq = unsafe { frankenlibc_abi::glibc_internal_abi::__profile_frequency() };
    assert!(freq > 0);
    let mut period = libc::timeval {
        tv_sec: -1,
        tv_usec: -1,
    };
    // SAFETY: a NULL profp with profcnt 0 is the query form; `tvp` is a live
    // local of the right size.
    let rc = unsafe {
        frankenlibc_abi::glibc_internal_abi::sprofil(
            std::ptr::null_mut(),
            0,
            (&mut period as *mut libc::timeval).cast::<c_void>(),
            0,
        )
    };
    assert_eq!(rc, 0, "sprofil query form must succeed");
    assert_eq!(period.tv_sec, 0, "the period is sub-second");
    assert_eq!(
        period.tv_usec as i64,
        1_000_000 / i64::from(freq),
        "sprofil's reported period must follow __profile_frequency"
    );
}
