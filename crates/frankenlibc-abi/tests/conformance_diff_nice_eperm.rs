//! Differential gate: nice() reports a permission failure as EPERM (POSIX),
//! matching glibc — not the kernel's raw EACCES.
//!
//! The kernel's setpriority returns EACCES when an unprivileged process tries to
//! lower its nice value; POSIX nice() specifies EPERM, and glibc remaps
//! EACCES -> EPERM. fl previously surfaced the raw EACCES.
//!
//! We attempt a large negative nice increment (lowering the nice value, which an
//! unprivileged process may not do) through glibc's nice() and fl's, and require
//! the same rc and errno. If the process is privileged (root / CAP_SYS_NICE /
//! permissive RLIMIT_NICE) the call succeeds and the remap path can't be
//! exercised — we then only require parity on the success and skip the errno
//! check. fl's set_abi_errno mirrors into the host libc errno slot, so both are
//! read via libc::__errno_location.
#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use frankenlibc_abi::unistd_abi as fl;

fn cur_nice() -> i32 {
    unsafe {
        *libc::__errno_location() = 0;
        libc::getpriority(libc::PRIO_PROCESS, 0)
    }
}

fn restore(n: i32) {
    unsafe {
        libc::setpriority(libc::PRIO_PROCESS, 0, n);
    }
}

#[test]
fn nice_permission_failure_is_eperm_like_glibc() {
    let base = cur_nice();

    // glibc reference.
    unsafe { *libc::__errno_location() = 0 };
    let g_rc = unsafe { libc::nice(-40) };
    let g_errno = unsafe { *libc::__errno_location() };
    restore(base);

    // fl.
    unsafe { *libc::__errno_location() = 0 };
    let f_rc = unsafe { fl::nice(-40) };
    let f_errno = unsafe { *libc::__errno_location() };
    restore(base);

    if g_rc == -1 && g_errno != 0 {
        // Permission path exercised — this is the bug-relevant case.
        assert_eq!(g_errno, libc::EPERM, "glibc nice should map permission failure to EPERM");
        assert_eq!(f_rc, -1, "fl nice should also fail (rc): glibc=-1 fl={f_rc}");
        assert_eq!(
            f_errno, libc::EPERM,
            "fl nice errno should be EPERM (was EACCES={} before the fix)",
            libc::EACCES
        );
    } else {
        // Privileged: nice succeeded; the remap can't be reached. Require parity.
        assert_eq!(
            f_rc, g_rc,
            "nice(-40) succeeded under glibc (privileged) but fl rc diverged: glibc={g_rc} fl={f_rc}"
        );
        eprintln!("nice(-40) succeeded (privileged env); EACCES->EPERM remap not exercised");
    }
}
