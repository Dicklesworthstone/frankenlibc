//! ABI layer for process control functions.
//!
//! Provides the POSIX process-control surface: fork, _exit, execve, execvp,
//! waitpid, wait. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::Process`.

use std::ffi::{c_char, c_int, c_void};
use std::os::raw::c_long;
use std::os::unix::ffi::OsStrExt;

use frankenlibc_core::process;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

unsafe fn path_bytes_from_env_vector(mut envp: *const *mut c_char) -> Vec<u8> {
    if envp.is_null() {
        // SAFETY: reading the process-global `environ` pointer is valid here.
        envp = unsafe { environ as *const *mut c_char };
    }

    while !envp.is_null() {
        // SAFETY: `envp` points to a NULL-terminated environment vector.
        let entry = unsafe { *envp };
        if entry.is_null() {
            break;
        }
        // SAFETY: each environment entry is a valid NUL-terminated string.
        let env_slice = unsafe { std::ffi::CStr::from_ptr(entry) }.to_bytes();
        if let Some(path_value) = env_slice.strip_prefix(b"PATH=") {
            return path_value.to_vec();
        }
        // SAFETY: advancing within a NULL-terminated environment vector.
        envp = unsafe { envp.add(1) };
    }

    b"/bin:/usr/bin".to_vec()
}

#[inline]
fn last_host_errno(default_errno: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(default_errno)
}

unsafe fn execvp_via_execve(file: *const c_char, argv: *const *const c_char) -> c_int {
    if file.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let file_bytes = unsafe { std::ffi::CStr::from_ptr(file) }.to_bytes();
    if file_bytes.is_empty() {
        unsafe { set_abi_errno(libc::ENOENT) };
        return -1;
    }

    if file_bytes.contains(&b'/') {
        let rc = unsafe { libc::syscall(libc::SYS_execve as c_long, file, argv, environ) } as c_int;
        if rc < 0 {
            unsafe { set_abi_errno(last_host_errno(libc::ENOENT)) };
        }
        return rc;
    }

    let path =
        std::env::var_os("PATH").unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin"));
    let path_bytes = path.as_os_str().as_bytes();

    let mut saw_eacces = false;

    for dir in path_bytes.split(|b| *b == b':') {
        let dir = if dir.is_empty() { b"." as &[u8] } else { dir };
        let mut candidate = Vec::with_capacity(dir.len() + 1 + file_bytes.len() + 1);
        candidate.extend_from_slice(dir);
        candidate.push(b'/');
        candidate.extend_from_slice(file_bytes);
        candidate.push(0);

        let _rc = unsafe {
            libc::syscall(
                libc::SYS_execve as c_long,
                candidate.as_ptr().cast::<c_char>(),
                argv,
                environ,
            ) as c_int
        };
        // execve only returns on failure (rc == -1); on success the process is replaced.

        let err = last_host_errno(libc::ENOENT);
        match err {
            libc::ENOENT | libc::ENOTDIR => {}
            libc::EACCES => {
                saw_eacces = true;
            }
            _ => {
                unsafe { set_abi_errno(err) };
                return -1;
            }
        }
    }

    unsafe {
        set_abi_errno(if saw_eacces {
            libc::EACCES
        } else {
            libc::ENOENT
        });
    }
    -1
}

// ---------------------------------------------------------------------------
// fork
// ---------------------------------------------------------------------------

/// POSIX `fork` — create a child process.
///
/// Calls registered `pthread_atfork` handlers and prepares the membrane
/// pipeline before the clone syscall, then runs child/parent cleanup
/// handlers afterward. This prevents mutex corruption and stale state
/// in the child process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fork() -> libc::pid_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 50, true);
        unsafe { set_abi_errno(libc::EAGAIN) };
        return -1;
    }

    // Run atfork prepare handlers (acquire locks in parent before fork).
    crate::pthread_abi::run_atfork_prepare();
    let _pipeline_guard =
        crate::membrane_state::try_global_pipeline().map(|pipeline| pipeline.atfork_prepare());

    let rc = unsafe { libc::syscall(libc::SYS_clone as c_long, libc::SIGCHLD, 0, 0, 0, 0) };
    let pid = rc as libc::pid_t;

    drop(_pipeline_guard);

    if pid == 0 {
        // Child: run child handlers to reinitialize state.
        crate::pthread_abi::run_atfork_child();
    } else if pid > 0 {
        // Parent: run parent handlers to release locks.
        crate::pthread_abi::run_atfork_parent();
    }

    let adverse = pid < 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(libc::EAGAIN)) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 50, adverse);
    pid
}

// ---------------------------------------------------------------------------
// _exit
// ---------------------------------------------------------------------------

/// POSIX `_exit` — terminate the calling process immediately.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _exit(status: c_int) -> ! {
    let (mode, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, false, false, 0);

    let clamped = if mode.heals_enabled() {
        let c = process::clamp_exit_status(status);
        if c != status {
            global_healing_policy().record(&HealingAction::ClampSize {
                requested: status as usize,
                clamped: c as usize,
            });
        }
        c
    } else {
        status
    };

    runtime_policy::observe(ApiFamily::Process, decision.profile, 5, false);
    unsafe { libc::syscall(libc::SYS_exit_group as c_long, clamped) };
    // If exit_group returns, fall back to SYS_exit and keep retrying.
    unsafe { libc::syscall(libc::SYS_exit as c_long, clamped) };
    loop {
        unsafe { libc::syscall(libc::SYS_exit as c_long, clamped) };
    }
}

// ---------------------------------------------------------------------------
// execve
// ---------------------------------------------------------------------------

/// POSIX `execve` — execute a program.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execve(
    pathname: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if pathname.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, pathname as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_execve as c_long, pathname, argv, envp) as c_int };

    // execve only returns on failure.
    let e = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::ENOENT);
    unsafe { set_abi_errno(e) };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
    rc
}

// ---------------------------------------------------------------------------
// execvp
// ---------------------------------------------------------------------------

/// POSIX `execvp` — execute a file, searching PATH.
///
/// Performs PATH search and dispatches via raw `execve` syscalls.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execvp(file: *const c_char, argv: *const *const c_char) -> c_int {
    if file.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, file as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
        unsafe { set_abi_errno(libc::EPERM) };
        return -1;
    }

    let rc = unsafe { execvp_via_execve(file, argv) };

    // execvp only returns on failure.
    runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
    rc
}

// ---------------------------------------------------------------------------
// waitpid
// ---------------------------------------------------------------------------

/// POSIX `waitpid` — wait for a child process to change state.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn waitpid(
    pid: libc::pid_t,
    wstatus: *mut c_int,
    options: c_int,
) -> libc::pid_t {
    let (mode, decision) =
        runtime_policy::decide(ApiFamily::Process, wstatus as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    // Sanitize options in hardened mode.
    let opts = if mode.heals_enabled() && !process::valid_wait_options(options) {
        let sanitized = process::sanitize_wait_options(options);
        global_healing_policy().record(&HealingAction::ClampSize {
            requested: options as usize,
            clamped: sanitized as usize,
        });
        sanitized
    } else {
        options
    };

    let rc = unsafe {
        libc::syscall(
            libc::SYS_wait4 as c_long,
            pid,
            wstatus,
            opts,
            std::ptr::null::<c_void>(),
        ) as libc::pid_t
    };

    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(libc::ECHILD)) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 30, adverse);
    rc
}

// ---------------------------------------------------------------------------
// wait
// ---------------------------------------------------------------------------

/// POSIX `wait` — equivalent to `waitpid(-1, wstatus, 0)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wait(wstatus: *mut c_int) -> libc::pid_t {
    unsafe { waitpid(-1, wstatus, 0) }
}

// ---------------------------------------------------------------------------
// wait3
// ---------------------------------------------------------------------------

/// BSD `wait3` — wait for any child with resource usage.
///
/// Equivalent to `wait4(-1, wstatus, options, rusage)`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wait3(
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut libc::rusage,
) -> libc::pid_t {
    unsafe { wait4(-1, wstatus, options, rusage) }
}

// ---------------------------------------------------------------------------
// wait4
// ---------------------------------------------------------------------------

/// BSD `wait4` — wait for a specific child with resource usage.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn wait4(
    pid: libc::pid_t,
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut libc::rusage,
) -> libc::pid_t {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, wstatus as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let rc = unsafe {
        libc::syscall(libc::SYS_wait4 as c_long, pid, wstatus, options, rusage) as libc::pid_t
    };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(libc::ECHILD)) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 30, adverse);
    rc
}

// ---------------------------------------------------------------------------
// waitid
// ---------------------------------------------------------------------------

/// POSIX `waitid` — wait for a child process to change state (extended).
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn waitid(
    idtype: c_int,
    id: libc::id_t,
    infop: *mut libc::siginfo_t,
    options: c_int,
) -> c_int {
    let (_, decision) =
        runtime_policy::decide(ApiFamily::Process, infop as usize, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
        unsafe { set_abi_errno(libc::EINVAL) };
        return -1;
    }

    let rc = unsafe {
        libc::syscall(
            libc::SYS_waitid as c_long,
            idtype,
            id,
            infop,
            options,
            std::ptr::null_mut::<c_void>(), // rusage (5th arg)
        ) as c_int
    };
    let adverse = rc < 0;
    if adverse {
        unsafe { set_abi_errno(last_host_errno(libc::ECHILD)) };
    }
    runtime_policy::observe(ApiFamily::Process, decision.profile, 30, adverse);
    rc
}

// ---------------------------------------------------------------------------
// vfork
// ---------------------------------------------------------------------------

/// BSD/POSIX `vfork` — on modern Linux, identical to `fork`.
///
/// POSIX.1-2008 removed vfork; glibc maps it to fork. We do the same.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn vfork() -> libc::pid_t {
    unsafe { fork() }
}

// ---------------------------------------------------------------------------
// execvpe — native implementation (PATH search + custom environment)
// ---------------------------------------------------------------------------

/// GNU `execvpe` — execute a file with PATH search and custom environment.
///
/// Like `execvp` but uses `envp` instead of the inherited environment.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if file.is_null() || argv.is_null() {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }

    let (file_len, terminated) = unsafe {
        crate::util::scan_c_string(file, crate::malloc_abi::known_remaining(file as usize))
    };
    if !terminated {
        unsafe { set_abi_errno(libc::EFAULT) };
        return -1;
    }
    let file_bytes = unsafe { std::slice::from_raw_parts(file as *const u8, file_len) };
    if file_bytes.is_empty() {
        unsafe { set_abi_errno(libc::ENOENT) };
        return -1;
    }

    // If file contains '/', execute directly without PATH search.
    if file_bytes.contains(&b'/') {
        let rc = unsafe { libc::syscall(libc::SYS_execve as c_long, file, argv, envp) } as c_int;
        if rc < 0 {
            unsafe { set_abi_errno(last_host_errno(libc::ENOENT)) };
        }
        return rc;
    }

    // Search PATH for the executable.
    let path =
        std::env::var_os("PATH").unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin"));
    let path_bytes = path.as_os_str().as_bytes();

    let mut saw_eacces = false;

    for dir in path_bytes.split(|b| *b == b':') {
        let dir = if dir.is_empty() { b"." as &[u8] } else { dir };
        let mut candidate = Vec::with_capacity(dir.len() + 1 + file_bytes.len() + 1);
        candidate.extend_from_slice(dir);
        candidate.push(b'/');
        candidate.extend_from_slice(file_bytes);
        candidate.push(0);

        let rc = unsafe {
            libc::syscall(
                libc::SYS_execve as c_long,
                candidate.as_ptr().cast::<c_char>(),
                argv,
                envp,
            ) as c_int
        };
        if rc == 0 {
            return rc;
        }

        let err = last_host_errno(libc::ENOENT);
        match err {
            libc::ENOENT | libc::ENOTDIR => {}
            libc::EACCES => {
                saw_eacces = true;
            }
            _ => {
                unsafe { set_abi_errno(err) };
                return -1;
            }
        }
    }

    unsafe {
        set_abi_errno(if saw_eacces {
            libc::EACCES
        } else {
            libc::ENOENT
        });
    }
    -1
}

// ---------------------------------------------------------------------------
// posix_spawn family — Implemented (native fork+exec)
// ---------------------------------------------------------------------------
//
// Native POSIX posix_spawn implementation using fork()+execve()/execvp().
// File actions and spawn attributes use heap-allocated internal representations
// stored behind the opaque pointer the caller provides.
//
// The opaque posix_spawn_file_actions_t and posix_spawnattr_t must be at least
// pointer-sized. We store a `Box<T>` pointer in the first 8 bytes.

/// Internal file action kinds.
enum SpawnFileAction {
    Close(c_int),
    CloseFrom(c_int),
    Dup2 {
        oldfd: c_int,
        newfd: c_int,
    },
    Open {
        fd: c_int,
        path: Vec<u8>,
        oflag: c_int,
        mode: libc::mode_t,
    },
    Chdir {
        path: Vec<u8>,
    },
    Fchdir(c_int),
    TcSetPgrp(c_int),
}

/// Internal file actions list, heap-allocated.
struct SpawnFileActions {
    actions: Vec<SpawnFileAction>,
}

/// Internal spawn attributes (flags + signal masks, etc.)
struct SpawnAttrs {
    flags: libc::c_short,
    pgroup: libc::pid_t,
    sigdefault: u64, // signal set bitmask
    sigmask: u64,
    schedpolicy: c_int,
    schedparam_priority: c_int,
    cgroup_fd: c_int,
    has_cgroup: bool,
}

/// Magic value to tag our internal pointers.
const SPAWN_FA_MAGIC: u64 = 0x4652_414e_4b46_4131; // "FRANKFA1"
const SPAWN_AT_MAGIC: u64 = 0x4652_414e_4b41_5431; // "FRANKAT1"

/// Layout of opaque posix_spawn_file_actions_t (we use first 16 bytes):
///   [0..8]  magic
///   [8..16] pointer to Box<SpawnFileActions>
const FA_MAGIC_OFF: usize = 0;
const FA_PTR_OFF: usize = 8;

/// Layout of opaque posix_spawnattr_t (same pattern):
const AT_MAGIC_OFF: usize = 0;
const AT_PTR_OFF: usize = 8;

/// POSIX `posix_spawn_file_actions_init` — initialize file actions object.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_init(file_actions: *mut c_void) -> c_int {
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    let fa = Box::new(SpawnFileActions {
        actions: Vec::new(),
    });
    let raw = Box::into_raw(fa);
    let p = file_actions as *mut u8;
    unsafe {
        *(p.add(FA_MAGIC_OFF) as *mut u64) = SPAWN_FA_MAGIC;
        *(p.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) = raw;
    }
    0
}

/// POSIX `posix_spawn_file_actions_destroy` — free file actions object.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_destroy(file_actions: *mut c_void) -> c_int {
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    let p = file_actions as *mut u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *const *mut SpawnFileActions) };
    if !raw.is_null() {
        // SAFETY: we allocated this with Box::into_raw in init
        let _ = unsafe { Box::from_raw(raw) };
    }
    unsafe {
        *(p.add(FA_MAGIC_OFF) as *mut u64) = 0;
        *(p.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) = std::ptr::null_mut();
    }
    0
}

/// POSIX `posix_spawnattr_init` — initialize spawn attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_init(attrp: *mut c_void) -> c_int {
    if attrp.is_null() {
        return libc::EINVAL;
    }
    let attr = Box::new(SpawnAttrs {
        flags: 0,
        pgroup: 0,
        sigdefault: 0,
        sigmask: 0,
        schedpolicy: 0,
        schedparam_priority: 0,
        cgroup_fd: -1,
        has_cgroup: false,
    });
    let raw = Box::into_raw(attr);
    let p = attrp as *mut u8;
    unsafe {
        *(p.add(AT_MAGIC_OFF) as *mut u64) = SPAWN_AT_MAGIC;
        *(p.add(AT_PTR_OFF) as *mut *mut SpawnAttrs) = raw;
    }
    0
}

/// POSIX `posix_spawnattr_destroy` — free spawn attributes.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_destroy(attrp: *mut c_void) -> c_int {
    if attrp.is_null() {
        return libc::EINVAL;
    }
    let p = attrp as *mut u8;
    let magic = unsafe { *(p.add(AT_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_AT_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p.add(AT_PTR_OFF) as *const *mut SpawnAttrs) };
    if !raw.is_null() {
        // SAFETY: we allocated this with Box::into_raw in init
        let _ = unsafe { Box::from_raw(raw) };
    }
    unsafe {
        *(p.add(AT_MAGIC_OFF) as *mut u64) = 0;
        *(p.add(AT_PTR_OFF) as *mut *mut SpawnAttrs) = std::ptr::null_mut();
    }
    0
}

/// Read spawn attrs from opaque pointer. Returns None if null or not initialized.
unsafe fn read_spawn_attrs(attrp: *const c_void) -> Option<&'static SpawnAttrs> {
    if attrp.is_null() {
        return None;
    }
    let p = attrp as *const u8;
    let magic = unsafe { *(p.add(AT_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_AT_MAGIC {
        return None;
    }
    let raw = unsafe { *(p.add(AT_PTR_OFF) as *const *const SpawnAttrs) };
    if raw.is_null() {
        return None;
    }
    Some(unsafe { &*raw })
}

/// Get mutable spawn attrs from opaque pointer.
unsafe fn read_spawn_attrs_mut(attrp: *mut c_void) -> Option<&'static mut SpawnAttrs> {
    if attrp.is_null() {
        return None;
    }
    let p = attrp as *mut u8;
    let magic = unsafe { *(p.add(AT_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_AT_MAGIC {
        return None;
    }
    let raw = unsafe { *(p.add(AT_PTR_OFF) as *const *mut SpawnAttrs) };
    if raw.is_null() {
        return None;
    }
    Some(unsafe { &mut *raw })
}

// ===========================================================================
// posix_spawnattr accessors
// ===========================================================================

/// `posix_spawnattr_getflags` — get spawn attribute flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getflags(
    attrp: *const c_void,
    flags: *mut libc::c_short,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if flags.is_null() {
        return libc::EINVAL;
    }
    unsafe { *flags = attr.flags };
    0
}

/// `posix_spawnattr_setflags` — set spawn attribute flags.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setflags(
    attrp: *mut c_void,
    flags: libc::c_short,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    attr.flags = flags;
    0
}

/// `posix_spawnattr_getsigdefault` — get default signal set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigdefault(
    attrp: *const c_void,
    sigdefault: *mut libc::sigset_t,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if sigdefault.is_null() {
        return libc::EINVAL;
    }
    // Store our u64 bitmask into sigset_t
    unsafe {
        libc::sigemptyset(sigdefault);
        for sig in 1..=63 {
            if attr.sigdefault & (1u64 << sig) != 0 {
                libc::sigaddset(sigdefault, sig);
            }
        }
    }
    0
}

/// `posix_spawnattr_setsigdefault` — set default signal set.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigdefault(
    attrp: *mut c_void,
    sigdefault: *const libc::sigset_t,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    if sigdefault.is_null() {
        return libc::EINVAL;
    }
    let mut mask = 0u64;
    for sig in 1..=63 {
        if unsafe { libc::sigismember(sigdefault, sig) } == 1 {
            mask |= 1u64 << sig;
        }
    }
    attr.sigdefault = mask;
    0
}

/// `posix_spawnattr_getsigmask` — get signal mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getsigmask(
    attrp: *const c_void,
    sigmask: *mut libc::sigset_t,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if sigmask.is_null() {
        return libc::EINVAL;
    }
    unsafe {
        libc::sigemptyset(sigmask);
        for sig in 1..=63 {
            if attr.sigmask & (1u64 << sig) != 0 {
                libc::sigaddset(sigmask, sig);
            }
        }
    }
    0
}

/// `posix_spawnattr_setsigmask` — set signal mask.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setsigmask(
    attrp: *mut c_void,
    sigmask: *const libc::sigset_t,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    if sigmask.is_null() {
        return libc::EINVAL;
    }
    let mut mask = 0u64;
    for sig in 1..=63 {
        if unsafe { libc::sigismember(sigmask, sig) } == 1 {
            mask |= 1u64 << sig;
        }
    }
    attr.sigmask = mask;
    0
}

/// `posix_spawnattr_getpgroup` — get process group.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getpgroup(
    attrp: *const c_void,
    pgroup: *mut libc::pid_t,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if pgroup.is_null() {
        return libc::EINVAL;
    }
    unsafe { *pgroup = attr.pgroup };
    0
}

/// `posix_spawnattr_setpgroup` — set process group.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setpgroup(
    attrp: *mut c_void,
    pgroup: libc::pid_t,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    attr.pgroup = pgroup;
    0
}

/// `posix_spawnattr_getschedparam` — get scheduling parameters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedparam(
    attrp: *const c_void,
    schedparam: *mut libc::sched_param,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if schedparam.is_null() {
        return libc::EINVAL;
    }
    unsafe {
        (*schedparam).sched_priority = attr.schedparam_priority;
    }
    0
}

/// `posix_spawnattr_setschedparam` — set scheduling parameters.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedparam(
    attrp: *mut c_void,
    schedparam: *const libc::sched_param,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    if schedparam.is_null() {
        return libc::EINVAL;
    }
    attr.schedparam_priority = unsafe { (*schedparam).sched_priority };
    0
}

/// `posix_spawnattr_getschedpolicy` — get scheduling policy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_getschedpolicy(
    attrp: *const c_void,
    schedpolicy: *mut c_int,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if schedpolicy.is_null() {
        return libc::EINVAL;
    }
    unsafe { *schedpolicy = attr.schedpolicy };
    0
}

/// `posix_spawnattr_setschedpolicy` — set scheduling policy.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnattr_setschedpolicy(
    attrp: *mut c_void,
    schedpolicy: c_int,
) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    attr.schedpolicy = schedpolicy;
    0
}

/// Read file actions from opaque pointer. Returns None if null or not initialized.
unsafe fn read_file_actions(fa_ptr: *const c_void) -> Option<&'static SpawnFileActions> {
    if fa_ptr.is_null() {
        return None;
    }
    let p = fa_ptr as *const u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return None;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *const *const SpawnFileActions) };
    if raw.is_null() {
        return None;
    }
    // SAFETY: pointer is valid and was allocated by init
    Some(unsafe { &*raw })
}

unsafe fn read_file_actions_mut(fa_ptr: *mut c_void) -> Option<&'static mut SpawnFileActions> {
    if fa_ptr.is_null() {
        return None;
    }
    let p = fa_ptr as *mut u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return None;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *const *mut SpawnFileActions) };
    if raw.is_null() {
        return None;
    }
    Some(unsafe { &mut *raw })
}

/// Apply spawn attributes in the child process.
/// Returns 0 on success, errno on failure.
unsafe fn apply_spawn_attrs(attr: &SpawnAttrs) -> c_int {
    let flags = attr.flags as c_int;

    if flags & libc::POSIX_SPAWN_SETPGROUP != 0 {
        let rc = unsafe { libc::syscall(libc::SYS_setpgid, 0, attr.pgroup) };
        if rc < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
        }
    }

    if flags & libc::POSIX_SPAWN_SETSIGMASK != 0 {
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&mut sigset) };
        for sig in 1..=63 {
            if attr.sigmask & (1u64 << sig) != 0 {
                unsafe { libc::sigaddset(&mut sigset, sig) };
            }
        }
        let rc = unsafe {
            libc::syscall(
                libc::SYS_rt_sigprocmask,
                libc::SIG_SETMASK,
                &sigset as *const libc::sigset_t,
                std::ptr::null_mut::<libc::sigset_t>(),
                8, // kernel _NSIG / 8 (NOT sizeof(sigset_t))
            )
        };
        if rc < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
        }
    }

    if flags & libc::POSIX_SPAWN_SETSIGDEF != 0 {
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = libc::SIG_DFL;
        for sig in 1..=63 {
            if attr.sigdefault & (1u64 << sig) != 0 {
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_rt_sigaction,
                        sig,
                        &act as *const libc::sigaction,
                        std::ptr::null_mut::<libc::sigaction>(),
                        8, // kernel _NSIG / 8 (NOT sizeof(sigset_t))
                    )
                };
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL);
                }
            }
        }
    }

    // Process setscheduler / setparam if requested
    if flags & libc::POSIX_SPAWN_SETSCHEDULER != 0 {
        let param = libc::sched_param {
            sched_priority: attr.schedparam_priority,
        };
        let rc = unsafe {
            libc::syscall(
                libc::SYS_sched_setscheduler,
                0,
                attr.schedpolicy,
                &param as *const _,
            )
        };
        if rc < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
        }
    } else if flags & libc::POSIX_SPAWN_SETSCHEDPARAM != 0 {
        let param = libc::sched_param {
            sched_priority: attr.schedparam_priority,
        };
        let rc = unsafe { libc::syscall(libc::SYS_sched_setparam, 0, &param as *const _) };
        if rc < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
        }
    }

    if flags & libc::POSIX_SPAWN_RESETIDS != 0 {
        let egid = unsafe { libc::syscall(libc::SYS_getegid) };
        let euid = unsafe { libc::syscall(libc::SYS_geteuid) };
        let rc1 = unsafe { libc::syscall(libc::SYS_setgid, egid) };
        let rc2 = unsafe { libc::syscall(libc::SYS_setuid, euid) };
        if rc1 < 0 || rc2 < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EINVAL);
        }
    }

    if attr.has_cgroup {
        let cgroup_name = b"cgroup.procs\0";
        let fd = unsafe {
            libc::syscall(
                libc::SYS_openat,
                attr.cgroup_fd,
                cgroup_name.as_ptr().cast::<c_char>(),
                libc::O_WRONLY,
                0,
            )
        } as c_int;
        if fd < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EBADF);
        }

        let current = b"0";
        let write_rc = unsafe {
            libc::syscall(
                libc::SYS_write,
                fd,
                current.as_ptr().cast::<c_void>(),
                current.len(),
            )
        };
        let close_rc = unsafe { libc::syscall(libc::SYS_close, fd) };
        if write_rc < 0 || close_rc < 0 {
            return std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
        }
    }

    0
}

/// Apply file actions in the child process (between fork and exec).
/// Returns 0 on success, errno on failure.
unsafe fn apply_file_actions(fa: &SpawnFileActions) -> c_int {
    for action in &fa.actions {
        match action {
            SpawnFileAction::Close(fd) => {
                let rc = unsafe { libc::syscall(libc::SYS_close, *fd) };
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EBADF);
                }
            }
            SpawnFileAction::Dup2 { oldfd, newfd } => {
                let rc = unsafe { libc::syscall(libc::SYS_dup2, *oldfd, *newfd) };
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EBADF);
                }
            }
            SpawnFileAction::Open {
                fd,
                path,
                oflag,
                mode,
            } => {
                let rc = unsafe {
                    libc::syscall(
                        libc::SYS_openat,
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        *oflag,
                        *mode,
                    )
                } as c_int;
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::ENOENT);
                }
                if rc != *fd {
                    let dup_rc = unsafe { libc::syscall(libc::SYS_dup2, rc, *fd) };
                    unsafe { libc::syscall(libc::SYS_close, rc) };
                    if dup_rc < 0 {
                        return std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(libc::EBADF);
                    }
                }
            }
            SpawnFileAction::CloseFrom(from) => {
                let rc =
                    unsafe { libc::syscall(libc::SYS_close_range, *from, u32::MAX, 0) } as c_int;
                if rc < 0 {
                    let err = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EINVAL);
                    if err != libc::ENOSYS {
                        return err;
                    }

                    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
                    let end = if max_fd > 0 { max_fd as c_int } else { 1024 };
                    for fd in *from..end {
                        let _ = unsafe { libc::syscall(libc::SYS_close, fd) };
                    }
                }
            }
            SpawnFileAction::Chdir { path } => {
                let rc = unsafe { libc::syscall(libc::SYS_chdir, path.as_ptr()) };
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::ENOENT);
                }
            }
            SpawnFileAction::Fchdir(fd) => {
                let rc = unsafe { libc::syscall(libc::SYS_fchdir, *fd) };
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::EBADF);
                }
            }
            SpawnFileAction::TcSetPgrp(fd) => {
                const TIOCSPGRP: std::os::raw::c_ulong = 0x5410;
                let pgrp = unsafe { libc::syscall(libc::SYS_getpgrp) as libc::pid_t };
                let rc = unsafe {
                    libc::syscall(libc::SYS_ioctl, *fd, TIOCSPGRP, &pgrp as *const libc::pid_t)
                } as c_int;
                if rc < 0 {
                    return std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(libc::ENOTTY);
                }
            }
        }
    }
    0
}

#[inline]
unsafe fn child_spawn_fail(err_fd: c_int, err: c_int) -> ! {
    let mut to_write = err;
    let mut written = 0usize;
    while written < std::mem::size_of::<c_int>() {
        let ptr = (&mut to_write as *mut c_int as *mut u8).wrapping_add(written);
        let rc = unsafe {
            libc::syscall(
                libc::SYS_write as c_long,
                err_fd,
                ptr.cast::<c_void>(),
                std::mem::size_of::<c_int>() - written,
            )
        };
        if rc <= 0 {
            break;
        }
        written += rc as usize;
    }
    unsafe { libc::syscall(libc::SYS_exit_group as c_long, 127) };
    // If exit_group returns, keep attempting SYS_exit to avoid panicking in child context.
    loop {
        unsafe { libc::syscall(libc::SYS_exit as c_long, 127) };
    }
}

/// Core posix_spawn implementation shared between posix_spawn and posix_spawnp.
/// `search_path` controls whether PATH search is done (posix_spawnp).
unsafe fn posix_spawn_impl(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    search_path: bool,
) -> c_int {
    if path.is_null() || argv.is_null() {
        return libc::EINVAL;
    }

    let (path_len, terminated) = unsafe {
        crate::util::scan_c_string(path, crate::malloc_abi::known_remaining(path as usize))
    };
    if !terminated {
        return libc::EFAULT;
    }
    let path_slice = unsafe { std::slice::from_raw_parts(path as *const u8, path_len) };
    let file_cstr = unsafe {
        std::ffi::CStr::from_bytes_with_nul_unchecked(std::slice::from_raw_parts(
            path as *const u8,
            path_len + 1,
        ))
    };

    // Prepare candidate paths in the parent process to avoid allocations in the
    // child process after fork, which is not async-signal safe and can deadlock
    // if another thread held an allocator lock during clone().
    let mut candidate_paths: Vec<std::ffi::CString> = Vec::new();

    if search_path {
        let file_bytes = path_slice;

        if file_bytes.contains(&b'/') {
            candidate_paths.push(std::ffi::CString::from(file_cstr));
        } else {
            let owned_path = unsafe { path_bytes_from_env_vector(envp) };
            let path_bytes = owned_path.as_slice();
            for dir in path_bytes.split(|b| *b == b':') {
                let mut full = dir.to_vec();
                if !full.ends_with(b"/") && !full.is_empty() {
                    full.push(b'/');
                }
                full.extend_from_slice(file_bytes);
                if let Ok(c) = std::ffi::CString::new(full) {
                    candidate_paths.push(c);
                }
            }
            if candidate_paths.is_empty()
                && let Ok(c) = std::ffi::CString::new(file_bytes)
            {
                candidate_paths.push(c);
            }
        }
    }

    // Create an array of raw pointers that the child process can iterate over safely.
    let candidate_ptrs: Vec<*const c_char> = if search_path {
        candidate_paths.iter().map(|c| c.as_ptr()).collect()
    } else {
        vec![path]
    };

    // Use an error-report pipe so the child can report pre-exec failure errno.
    // `O_CLOEXEC` ensures successful exec closes the write end and the parent
    // observes EOF as success.
    let mut err_pipe = [-1_i32; 2];
    let pipe_rc = unsafe {
        libc::syscall(
            libc::SYS_pipe2 as c_long,
            err_pipe.as_mut_ptr(),
            libc::O_CLOEXEC,
        )
    } as c_int;
    if pipe_rc < 0 {
        return last_host_errno(libc::EAGAIN);
    }

    // Fork using clone syscall (minimal flags = just SIGCHLD for basic fork)
    let child_pid =
        unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) } as libc::pid_t;

    if child_pid < 0 {
        unsafe {
            libc::syscall(libc::SYS_close as c_long, err_pipe[0]);
            libc::syscall(libc::SYS_close as c_long, err_pipe[1]);
        }
        return std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EAGAIN);
    }

    if child_pid == 0 {
        // --- Child process ---
        unsafe {
            libc::syscall(libc::SYS_close as c_long, err_pipe[0]);
        }

        // Apply spawn attributes if provided
        if let Some(attr) = unsafe { read_spawn_attrs(attrp) } {
            let err = unsafe { apply_spawn_attrs(attr) };
            if err != 0 {
                unsafe { child_spawn_fail(err_pipe[1], err) };
            }
        }

        // Apply file actions if provided
        if let Some(fa) = unsafe { read_file_actions(file_actions) } {
            let err = unsafe { apply_file_actions(fa) };
            if err != 0 {
                unsafe { child_spawn_fail(err_pipe[1], err) };
            }
        }

        // Execute the program
        let env = if envp.is_null() {
            unsafe { environ as *const *mut c_char }
        } else {
            envp
        };

        // Try execve for each candidate path. Iterating a Vec is just reading
        // memory (slice) and does not allocate, so it is async-signal safe.
        let mut saw_eacces = false;
        let mut final_err = libc::ENOENT;
        for &cand_path in candidate_ptrs.iter() {
            unsafe { libc::syscall(libc::SYS_execve, cand_path, argv, env) };
            let err = last_host_errno(libc::ENOENT);
            match err {
                libc::ENOENT | libc::ENOTDIR => {}
                libc::EACCES => {
                    saw_eacces = true;
                }
                _ => {
                    final_err = err;
                    break;
                }
            }
        }

        if saw_eacces {
            final_err = libc::EACCES;
        }
        unsafe { child_spawn_fail(err_pipe[1], final_err) };
    }

    // --- Parent process ---
    unsafe {
        libc::syscall(libc::SYS_close as c_long, err_pipe[1]);
    }
    let mut child_err: c_int = 0;
    let mut bytes_read = 0usize;
    while bytes_read < std::mem::size_of::<c_int>() {
        let ptr = (&mut child_err as *mut c_int as *mut u8).wrapping_add(bytes_read);
        let rc = unsafe {
            libc::syscall(
                libc::SYS_read as c_long,
                err_pipe[0],
                ptr.cast::<c_void>(),
                std::mem::size_of::<c_int>() - bytes_read,
            )
        } as isize;
        if rc == 0 {
            break; // EOF => exec succeeded.
        }
        if rc < 0 {
            let err = last_host_errno(libc::EIO);
            if err == libc::EINTR {
                continue;
            }
            child_err = err;
            bytes_read = std::mem::size_of::<c_int>();
            break;
        }
        bytes_read += rc as usize;
    }
    unsafe {
        libc::syscall(libc::SYS_close as c_long, err_pipe[0]);
    }

    if bytes_read > 0 {
        unsafe {
            libc::syscall(
                libc::SYS_wait4 as c_long,
                child_pid,
                std::ptr::null_mut::<c_int>(),
                0,
                std::ptr::null_mut::<c_void>(),
            );
        }
        if child_err == 0 { libc::EIO } else { child_err }
    } else {
        if !pid.is_null() {
            unsafe { *pid = child_pid };
        }
        0
    }
}

/// POSIX `posix_spawn` — spawn a new process from a file path.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { posix_spawn_impl(pid, path, file_actions, attrp, argv, envp, false) }
}

/// POSIX `posix_spawnp` — spawn a new process, searching PATH.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { posix_spawn_impl(pid, file, file_actions, attrp, argv, envp, true) }
}

/// POSIX `posix_spawn_file_actions_addclose` — add a close action.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(
    file_actions: *mut c_void,
    fd: c_int,
) -> c_int {
    if file_actions.is_null() || fd < 0 {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    fa.actions.push(SpawnFileAction::Close(fd));
    0
}

/// POSIX `posix_spawn_file_actions_adddup2` — add a dup2 action.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_adddup2(
    file_actions: *mut c_void,
    oldfd: c_int,
    newfd: c_int,
) -> c_int {
    if file_actions.is_null() || oldfd < 0 || newfd < 0 {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    fa.actions.push(SpawnFileAction::Dup2 { oldfd, newfd });
    0
}

/// POSIX `posix_spawn_file_actions_addopen` — add an open action.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addopen(
    file_actions: *mut c_void,
    fd: c_int,
    path: *const c_char,
    oflag: c_int,
    mode: libc::mode_t,
) -> c_int {
    if file_actions.is_null() || fd < 0 || path.is_null() {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    let (path_len, terminated) = unsafe {
        crate::util::scan_c_string(path, crate::malloc_abi::known_remaining(path as usize))
    };
    if !terminated {
        return libc::EINVAL;
    }
    let path_bytes = unsafe { std::slice::from_raw_parts(path as *const u8, path_len) };
    let mut vec_bytes = path_bytes.to_vec();
    vec_bytes.push(0); // NUL terminate for later syscall
    fa.actions.push(SpawnFileAction::Open {
        fd,
        path: vec_bytes,
        oflag,
        mode,
    });
    0
}

// ---------------------------------------------------------------------------
// posix_spawn_file_actions_addchdir_np — Implemented (glibc 2.29+)
// ---------------------------------------------------------------------------

/// GNU extension `posix_spawn_file_actions_addchdir_np` — add a chdir action.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addchdir_np(
    file_actions: *mut c_void,
    path: *const c_char,
) -> c_int {
    if file_actions.is_null() || path.is_null() {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    let (path_len, terminated) = unsafe {
        crate::util::scan_c_string(path, crate::malloc_abi::known_remaining(path as usize))
    };
    if !terminated {
        return libc::EINVAL;
    }
    let path_bytes = unsafe { std::slice::from_raw_parts(path as *const u8, path_len) };
    let mut vec_bytes = path_bytes.to_vec();
    vec_bytes.push(0); // NUL terminate
    fa.actions.push(SpawnFileAction::Chdir { path: vec_bytes });
    0
}

// ---------------------------------------------------------------------------
// posix_spawn_file_actions_addfchdir_np — Implemented (glibc 2.29+)
// ---------------------------------------------------------------------------

/// GNU extension `posix_spawn_file_actions_addfchdir_np` — add an fchdir action.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addfchdir_np(
    file_actions: *mut c_void,
    fd: c_int,
) -> c_int {
    if file_actions.is_null() || fd < 0 {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    fa.actions.push(SpawnFileAction::Fchdir(fd));
    0
}

pub unsafe fn posix_spawn_file_actions_addclosefrom_np_impl(
    file_actions: *mut c_void,
    from: c_int,
) -> c_int {
    if file_actions.is_null() || from < 0 {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    fa.actions.push(SpawnFileAction::CloseFrom(from));
    0
}

pub unsafe fn posix_spawn_file_actions_addtcsetpgrp_np_impl(
    file_actions: *mut c_void,
    fd: c_int,
) -> c_int {
    if file_actions.is_null() || fd < 0 {
        return libc::EINVAL;
    }
    let Some(fa) = (unsafe { read_file_actions_mut(file_actions) }) else {
        return libc::EINVAL;
    };
    fa.actions.push(SpawnFileAction::TcSetPgrp(fd));
    0
}

pub unsafe fn posix_spawnattr_getcgroup_np_impl(attrp: *const c_void, cgroup: *mut c_int) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs(attrp) }) else {
        return libc::EINVAL;
    };
    if cgroup.is_null() {
        return libc::EINVAL;
    }
    unsafe {
        *cgroup = if attr.has_cgroup { attr.cgroup_fd } else { -1 };
    }
    0
}

pub unsafe fn posix_spawnattr_setcgroup_np_impl(attrp: *mut c_void, cgroup: c_int) -> c_int {
    let Some(attr) = (unsafe { read_spawn_attrs_mut(attrp) }) else {
        return libc::EINVAL;
    };
    if cgroup < 0 {
        return libc::EINVAL;
    }
    attr.cgroup_fd = cgroup;
    attr.has_cgroup = true;
    0
}
