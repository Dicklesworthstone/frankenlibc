#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc seteuid/setegid oracle

//! Gate for seteuid/setegid vs live host glibc (bd-nb3egy, and the EINVAL half
//! originally filed as bd-40ymct).
//!
//! Two separable defects, so two kinds of assertion:
//!
//! 1. `(uid_t)-1` rejection. glibc rejects `(uid_t)-1` / `(gid_t)-1` with
//!    EINVAL; fl routed through setreuid/setregid, which read -1 as "no change"
//!    and returned 0. Directly observable from the return value and errno.
//!
//! 2. Which syscall is issued. glibc issues `setresuid(-1, euid, -1)`; fl issued
//!    `setreuid(-1, euid)`, which additionally moves the saved-set-user-ID to the
//!    new euid whenever it differs from the old real UID — destroying the
//!    caller's ability to regain a dropped privilege. That difference is
//!    invisible to an unprivileged test (it cannot move an ID at all), so it is
//!    gated by tracing the syscall the call actually issues.
//!
//! glibc is reached by dlsym, and every arm asserts its glibc entry point is at
//! a different address from fl's, so the gate cannot degrade into fl-vs-fl.
//! No mocks. All cases here change no credentials, so they are safe in-process.

use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn dlopen(filename: *const i8, flag: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const i8) -> *mut c_void;
    fn __errno_location() -> *mut c_int;
}

/// `seteuid`/`setegid` share this shape (uid_t and gid_t are both u32).
type SetEffectiveIdFn = unsafe extern "C" fn(u32) -> c_int;

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

/// Resolve a symbol from the live host glibc, asserting it is not fl's own.
fn glibc_sym(name: &std::ffi::CStr, fl_addr: usize) -> SetEffectiveIdFn {
    unsafe {
        let handle = dlopen(c"libc.so.6".as_ptr(), 2 /* RTLD_NOW */);
        assert!(!handle.is_null(), "dlopen(libc.so.6) failed");
        let sym = dlsym(handle, name.as_ptr());
        assert!(!sym.is_null(), "dlsym({name:?}) failed");
        assert_ne!(
            sym as usize, fl_addr,
            "{name:?} resolved to fl's own symbol — the two arms are not distinct"
        );
        std::mem::transmute::<*mut c_void, SetEffectiveIdFn>(sym)
    }
}

fn glibc_seteuid() -> SetEffectiveIdFn {
    glibc_sym(
        c"seteuid",
        frankenlibc_abi::unistd_abi::seteuid as *const () as usize,
    )
}

fn glibc_setegid() -> SetEffectiveIdFn {
    glibc_sym(
        c"setegid",
        frankenlibc_abi::unistd_abi::setegid as *const () as usize,
    )
}

#[test]
fn seteuid_minus_one_is_einval_like_glibc() {
    let g_fn = glibc_seteuid();
    let bad = libc::uid_t::MAX; // (uid_t)-1
    unsafe { *__errno_location() = 0 };
    let g = unsafe { g_fn(bad) };
    let g_err = errno();
    unsafe { *__errno_location() = 0 };
    let f = unsafe { frankenlibc_abi::unistd_abi::seteuid(bad) };
    let f_err = errno();
    assert_eq!(f, g, "seteuid(-1) rc: fl={f} glibc={g}");
    assert_eq!(g, -1, "glibc seteuid(-1) must fail");
    assert_eq!(f_err, g_err, "seteuid(-1) errno: fl={f_err} glibc={g_err}");
    assert_eq!(
        g_err,
        libc::EINVAL,
        "glibc seteuid(-1) errno must be EINVAL"
    );
}

#[test]
fn setegid_minus_one_is_einval_like_glibc() {
    let g_fn = glibc_setegid();
    let bad = libc::gid_t::MAX; // (gid_t)-1
    unsafe { *__errno_location() = 0 };
    let g = unsafe { g_fn(bad) };
    let g_err = errno();
    unsafe { *__errno_location() = 0 };
    let f = unsafe { frankenlibc_abi::unistd_abi::setegid(bad) };
    let f_err = errno();
    assert_eq!(f, g, "setegid(-1) rc: fl={f} glibc={g}");
    assert_eq!(g, -1, "glibc setegid(-1) must fail");
    assert_eq!(f_err, g_err, "setegid(-1) errno: fl={f_err} glibc={g_err}");
    assert_eq!(
        g_err,
        libc::EINVAL,
        "glibc setegid(-1) errno must be EINVAL"
    );
}

#[test]
fn seteuid_to_current_euid_succeeds() {
    // Setting the effective uid to its current value is a no-op that must
    // succeed (no privilege needed), in both impls.
    let g_fn = glibc_seteuid();
    let cur = unsafe { libc::geteuid() };
    let f = unsafe { frankenlibc_abi::unistd_abi::seteuid(cur) };
    assert_eq!(f, 0, "fl seteuid(current euid) should succeed");
    let g = unsafe { g_fn(cur) };
    assert_eq!(g, 0, "glibc seteuid(current euid) should succeed");
}

/// Traces which credential syscall a call actually issues.
///
/// The saved-set-ID half of bd-nb3egy cannot be observed from return values by
/// an unprivileged process: it may only set an effective ID to one it already
/// holds, and the kernel leaves the saved ID alone in exactly that case. So we
/// observe the request instead of its effect. x86_64 only — this reads the
/// syscall number and argument registers directly.
#[cfg(target_arch = "x86_64")]
mod issued_syscall {
    use std::ffi::{c_int, c_long, c_void};

    const PTRACE_TRACEME: c_int = 0;
    const PTRACE_KILL: c_int = 8;
    const PTRACE_GETREGS: c_int = 12;
    const PTRACE_SYSCALL: c_int = 24;
    const SIGSTOP: c_int = 19;
    /// x86_64 leaves -ENOSYS in rax at a syscall-ENTRY stop; at the matching
    /// exit stop rax holds the result. Only entry stops carry intact arguments.
    const ENTRY_RAX: u64 = -(libc::ENOSYS as i64) as u64;

    unsafe extern "C" {
        fn fork() -> c_int;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn raise(sig: c_int) -> c_int;
        fn ptrace(request: c_int, pid: c_int, addr: *mut c_void, data: *mut c_void) -> c_long;
        fn _exit(code: c_int) -> !;
    }

    /// A credential syscall as the kernel receives it. Arguments are truncated
    /// to 32 bits because uid_t/gid_t are 32-bit: glibc passes -1 widened from
    /// `long` (0xffff_ffff_ffff_ffff) and fl passes `u32::MAX` (0x0000_0000_ffff_ffff),
    /// which are the same request — the kernel reads only the low half.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Issued {
        pub nr: c_long,
        pub args: [u32; 3],
    }

    fn is_credential_syscall(nr: c_long) -> bool {
        nr == libc::SYS_setuid
            || nr == libc::SYS_setreuid
            || nr == libc::SYS_setresuid
            || nr == libc::SYS_setgid
            || nr == libc::SYS_setregid
            || nr == libc::SYS_setresgid
    }

    fn stopped(status: c_int) -> bool {
        (status & 0xff) == 0x7f
    }

    /// Run `call` in a forked child under ptrace and report the first credential
    /// syscall it issues, or `None` if ptrace is restricted (yama/container).
    ///
    /// The child is single-threaded (fork drops the other threads), which also
    /// keeps glibc on its plain-syscall path instead of the nptl setxid
    /// broadcast, so the trace shows the request itself.
    pub fn observe(call: impl FnOnce()) -> Option<Issued> {
        let null = std::ptr::null_mut::<c_void>();
        unsafe {
            let child = fork();
            assert!(child >= 0, "fork failed");
            if child == 0 {
                // Child: opt into tracing, stop so the parent can attach to the
                // syscall stream, then make the one call under test.
                if ptrace(PTRACE_TRACEME, 0, null, null) != 0 {
                    _exit(2);
                }
                raise(SIGSTOP);
                call();
                _exit(0);
            }

            let mut status: c_int = 0;
            if waitpid(child, &mut status, 0) != child || !stopped(status) {
                ptrace(PTRACE_KILL, child, null, null);
                let _ = waitpid(child, &mut status, 0);
                return None;
            }

            let mut found = None;
            loop {
                if ptrace(PTRACE_SYSCALL, child, null, null) != 0 {
                    break;
                }
                if waitpid(child, &mut status, 0) != child || !stopped(status) {
                    break; // child exited or died before issuing one
                }
                let mut regs: libc::user_regs_struct = std::mem::zeroed();
                if ptrace(
                    PTRACE_GETREGS,
                    child,
                    null,
                    (&raw mut regs).cast::<c_void>(),
                ) != 0
                {
                    break;
                }
                let nr = regs.orig_rax as c_long;
                if regs.rax == ENTRY_RAX && is_credential_syscall(nr) {
                    found = Some(Issued {
                        nr,
                        args: [regs.rdi as u32, regs.rsi as u32, regs.rdx as u32],
                    });
                    break;
                }
            }

            ptrace(PTRACE_KILL, child, null, null);
            let _ = waitpid(child, &mut status, 0);
            found
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn seteuid_issues_setresuid_leaving_saved_uid_alone() {
    let g_fn = glibc_seteuid();
    let cur = unsafe { libc::geteuid() };

    let Some(g) = issued_syscall::observe(|| {
        unsafe { g_fn(cur) };
    }) else {
        eprintln!("ptrace restricted; skipping");
        return;
    };
    let f = issued_syscall::observe(|| {
        unsafe { frankenlibc_abi::unistd_abi::seteuid(cur) };
    })
    .expect("ptrace worked for the glibc arm, so it must work for fl's");

    assert_eq!(
        g.nr,
        libc::SYS_setresuid,
        "glibc seteuid must issue setresuid, got nr={}",
        g.nr
    );
    assert_eq!(
        g.args,
        [u32::MAX, cur, u32::MAX],
        "glibc seteuid must issue setresuid(-1, euid, -1)"
    );
    assert_eq!(
        f, g,
        "seteuid issued syscall: fl={f:?} glibc={g:?} — setreuid(-1, euid) would \
         also move the saved-set-user-ID"
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn setegid_issues_setresgid_leaving_saved_gid_alone() {
    let g_fn = glibc_setegid();
    let cur = unsafe { libc::getegid() };

    let Some(g) = issued_syscall::observe(|| {
        unsafe { g_fn(cur) };
    }) else {
        eprintln!("ptrace restricted; skipping");
        return;
    };
    let f = issued_syscall::observe(|| {
        unsafe { frankenlibc_abi::unistd_abi::setegid(cur) };
    })
    .expect("ptrace worked for the glibc arm, so it must work for fl's");

    assert_eq!(
        g.nr,
        libc::SYS_setresgid,
        "glibc setegid must issue setresgid, got nr={}",
        g.nr
    );
    assert_eq!(
        g.args,
        [u32::MAX, cur, u32::MAX],
        "glibc setegid must issue setresgid(-1, egid, -1)"
    );
    assert_eq!(
        f, g,
        "setegid issued syscall: fl={f:?} glibc={g:?} — setregid(-1, egid) would \
         also move the saved-set-group-ID"
    );
}
