//! ABI layer for process control functions.
//!
//! Provides the POSIX process-control surface: fork, _exit, execve, execvp,
//! waitpid, wait. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::Process`.

use std::ffi::{c_char, c_int, c_void};
use std::os::unix::ffi::OsStrExt;

use frankenlibc_core::process;
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::runtime_policy;

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

unsafe fn path_bytes_from_env_vector(envp: *const *mut c_char) -> Vec<u8> {
    // If a caller-supplied envp was provided, walk it directly: that array
    // is owned by the caller, not by libc's mutable environ table, so
    // ENVIRON_LOCK does not apply.
    if !envp.is_null() {
        return unsafe { walk_env_for_path(envp) };
    }
    // Walking the process-global `environ` requires ENVIRON_LOCK to avoid
    // UAFing on a concurrent setenv realloc — same defense class as the
    // native_getenv / clearenv fixes. (REVIEW round 4.)
    crate::stdlib_abi::with_environ_locked(|envp| unsafe {
        walk_env_for_path(envp as *const *mut c_char)
    })
}

unsafe fn walk_env_for_path(mut envp: *const *mut c_char) -> Vec<u8> {
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
        // execve only returns on failure
        let err = unsafe {
            raw_syscall::sys_execve(
                file as *const u8,
                argv as *const *const u8,
                environ as *const *const u8,
            )
        }
        .err()
        .unwrap_or(libc::ENOENT);
        unsafe { set_abi_errno(err) };
        return -1;
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

        // execve only returns on failure; on success the process is replaced.
        let err = unsafe {
            raw_syscall::sys_execve(
                candidate.as_ptr(),
                argv as *const *const u8,
                environ as *const *const u8,
            )
        }
        .err()
        .unwrap_or(libc::ENOENT);
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
    // Acquire ENVIRON_LOCK before fork so the child does not inherit a held
    // state from another parent thread mid-setenv. Without this, the child's
    // first getenv/setenv after fork would deadlock waiting for a lock that
    // no thread can ever release in the new address space. Mirrors the
    // pipeline atfork pattern. (REVIEW round 4: fork-after-setenv deadlock.)
    let _environ_guard = crate::stdlib_abi::ENVIRON_LOCK.lock();

    let pid = match raw_syscall::sys_clone_fork(libc::SIGCHLD as usize) {
        Ok(p) => p,
        Err(e) => {
            // Drop guards in failure path before returning so the parent
            // can resume normal env operations.
            drop(_environ_guard);
            drop(_pipeline_guard);
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 50, true);
            return -1;
        }
    };

    // Both parent and child release their copies of these guards. The
    // parking_lot mutex state lives inline in the static; the guard's Drop
    // releases the lock owned by the current thread on each side of fork.
    drop(_environ_guard);
    drop(_pipeline_guard);

    if pid == 0 {
        // Child: run child handlers to reinitialize state.
        crate::pthread_abi::run_atfork_child();
    } else {
        // Parent: run parent handlers to release locks.
        crate::pthread_abi::run_atfork_parent();
    }

    runtime_policy::observe(ApiFamily::Process, decision.profile, 50, false);
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
    raw_syscall::sys_exit_group(clamped)
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

    // execve only returns on failure.
    let e = unsafe {
        raw_syscall::sys_execve(
            pathname as *const u8,
            argv as *const *const u8,
            envp as *const *const u8,
        )
    }
    .err()
    .unwrap_or(libc::ENOENT);
    unsafe { set_abi_errno(e) };
    runtime_policy::observe(ApiFamily::Process, decision.profile, 40, true);
    -1
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

    let rc = unsafe { raw_syscall::sys_wait4(pid, wstatus, opts, std::ptr::null_mut()) };

    match rc {
        Ok(child_pid) => {
            runtime_policy::observe(ApiFamily::Process, decision.profile, 30, false);
            child_pid
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
            -1
        }
    }
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

    let rc = unsafe { raw_syscall::sys_wait4(pid, wstatus, options, rusage as *mut u8) };

    match rc {
        Ok(child_pid) => {
            runtime_policy::observe(ApiFamily::Process, decision.profile, 30, false);
            child_pid
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
            -1
        }
    }
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
        raw_syscall::sys_waitid(
            idtype,
            id,
            infop as *mut u8,
            options,
            std::ptr::null_mut(), // rusage (5th arg)
        )
    };

    match rc {
        Ok(()) => {
            runtime_policy::observe(ApiFamily::Process, decision.profile, 30, false);
            0
        }
        Err(e) => {
            unsafe { set_abi_errno(e) };
            runtime_policy::observe(ApiFamily::Process, decision.profile, 30, true);
            -1
        }
    }
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
        // execve only returns on failure
        let err = unsafe {
            raw_syscall::sys_execve(
                file as *const u8,
                argv as *const *const u8,
                envp as *const *const u8,
            )
        }
        .err()
        .unwrap_or(libc::ENOENT);
        unsafe { set_abi_errno(err) };
        return -1;
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

        // execve only returns on failure; on success the process is replaced.
        let err = unsafe {
            raw_syscall::sys_execve(
                candidate.as_ptr(),
                argv as *const *const u8,
                envp as *const *const u8,
            )
        }
        .err()
        .unwrap_or(libc::ENOENT);
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
        crate::signal_abi::sigemptyset(sigdefault);
        for sig in 1..=63 {
            if attr.sigdefault & (1u64 << sig) != 0 {
                crate::signal_abi::sigaddset(sigdefault, sig);
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
        if unsafe { crate::signal_abi::sigismember(sigdefault, sig) } == 1 {
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
        crate::signal_abi::sigemptyset(sigmask);
        for sig in 1..=63 {
            if attr.sigmask & (1u64 << sig) != 0 {
                crate::signal_abi::sigaddset(sigmask, sig);
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
        if unsafe { crate::signal_abi::sigismember(sigmask, sig) } == 1 {
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

    if flags & libc::POSIX_SPAWN_SETPGROUP != 0
        && let Err(e) = raw_syscall::sys_setpgid(0, attr.pgroup)
    {
        return e;
    }

    if flags & libc::POSIX_SPAWN_SETSIGMASK != 0 {
        let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { crate::signal_abi::sigemptyset(&mut sigset) };
        for sig in 1..=63 {
            if attr.sigmask & (1u64 << sig) != 0 {
                unsafe { crate::signal_abi::sigaddset(&mut sigset, sig) };
            }
        }
        if let Err(e) = unsafe {
            raw_syscall::sys_rt_sigprocmask(
                libc::SIG_SETMASK,
                &sigset as *const libc::sigset_t as *const u8,
                std::ptr::null_mut(),
                8, // kernel _NSIG / 8 (NOT sizeof(sigset_t))
            )
        } {
            return e;
        }
    }

    if flags & libc::POSIX_SPAWN_SETSIGDEF != 0 {
        let mut act: libc::sigaction = unsafe { std::mem::zeroed() };
        act.sa_sigaction = libc::SIG_DFL;
        for sig in 1..=63 {
            if attr.sigdefault & (1u64 << sig) != 0
                && let Err(e) = unsafe {
                    raw_syscall::sys_rt_sigaction(
                        sig,
                        &act as *const libc::sigaction as *const u8,
                        std::ptr::null_mut(),
                        8, // kernel _NSIG / 8 (NOT sizeof(sigset_t))
                    )
                }
            {
                return e;
            }
        }
    }

    // Process setscheduler / setparam if requested
    if flags & libc::POSIX_SPAWN_SETSCHEDULER != 0 {
        let param = libc::sched_param {
            sched_priority: attr.schedparam_priority,
        };
        if let Err(e) = unsafe {
            raw_syscall::sys_sched_setscheduler(
                0,
                attr.schedpolicy,
                &param as *const _ as *const u8,
            )
        } {
            return e;
        }
    } else if flags & libc::POSIX_SPAWN_SETSCHEDPARAM != 0 {
        let param = libc::sched_param {
            sched_priority: attr.schedparam_priority,
        };
        if let Err(e) =
            unsafe { raw_syscall::sys_sched_setparam(0, &param as *const _ as *const u8) }
        {
            return e;
        }
    }

    if flags & libc::POSIX_SPAWN_RESETIDS != 0 {
        let egid = raw_syscall::sys_getegid();
        let euid = raw_syscall::sys_geteuid();
        if let Err(e) = raw_syscall::sys_setgid(egid) {
            return e;
        }
        if let Err(e) = raw_syscall::sys_setuid(euid) {
            return e;
        }
    }

    if attr.has_cgroup {
        let cgroup_name = b"cgroup.procs\0";
        let fd = match unsafe {
            raw_syscall::sys_openat(attr.cgroup_fd, cgroup_name.as_ptr(), libc::O_WRONLY, 0)
        } {
            Ok(f) => f,
            Err(e) => return e,
        };

        let current = b"0";
        let write_res = unsafe { raw_syscall::sys_write(fd, current.as_ptr(), current.len()) };
        let close_res = raw_syscall::sys_close(fd);
        if write_res.is_err() || close_res.is_err() {
            return write_res.err().or(close_res.err()).unwrap_or(libc::EIO);
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
                if let Err(e) = raw_syscall::sys_close(*fd) {
                    return e;
                }
            }
            SpawnFileAction::Dup2 { oldfd, newfd } => {
                if let Err(e) = raw_syscall::sys_dup2(*oldfd, *newfd) {
                    return e;
                }
            }
            SpawnFileAction::Open {
                fd,
                path,
                oflag,
                mode,
            } => {
                let opened_fd = match unsafe {
                    raw_syscall::sys_openat(libc::AT_FDCWD, path.as_ptr(), *oflag, *mode)
                } {
                    Ok(f) => f,
                    Err(e) => return e,
                };
                if opened_fd != *fd {
                    if let Err(e) = raw_syscall::sys_dup2(opened_fd, *fd) {
                        let _ = raw_syscall::sys_close(opened_fd);
                        return e;
                    }
                    let _ = raw_syscall::sys_close(opened_fd);
                }
            }
            SpawnFileAction::CloseFrom(from) => {
                if let Err(e) = raw_syscall::sys_close_range(*from as u32, u32::MAX, 0) {
                    if e != libc::ENOSYS {
                        return e;
                    }
                    // Fallback for older kernels without close_range
                    let max_fd = unsafe { crate::unistd_abi::sysconf(libc::_SC_OPEN_MAX) };
                    let end = if max_fd > 0 { max_fd as c_int } else { 1024 };
                    for fd in *from..end {
                        let _ = raw_syscall::sys_close(fd);
                    }
                }
            }
            SpawnFileAction::Chdir { path } => {
                if let Err(e) = unsafe { raw_syscall::sys_chdir(path.as_ptr()) } {
                    return e;
                }
            }
            SpawnFileAction::Fchdir(fd) => {
                if let Err(e) = raw_syscall::sys_fchdir(*fd) {
                    return e;
                }
            }
            SpawnFileAction::TcSetPgrp(fd) => {
                const TIOCSPGRP: usize = 0x5410;
                let pgrp = raw_syscall::sys_getpgrp();
                if let Err(e) =
                    unsafe { raw_syscall::sys_ioctl(*fd, TIOCSPGRP, &pgrp as *const i32 as usize) }
                {
                    return e;
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
        let rc =
            unsafe { raw_syscall::sys_write(err_fd, ptr, std::mem::size_of::<c_int>() - written) };
        match rc {
            Ok(n) if n > 0 => written += n,
            _ => break,
        }
    }
    raw_syscall::sys_exit_group(127)
}

/// Core posix_spawn implementation shared between posix_spawn and posix_spawnp.
/// `search_path` controls whether PATH search is done (posix_spawnp).
struct SpawnRequest {
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    search_path: bool,
    pidfd_out: *mut c_int,
}

unsafe fn posix_spawn_impl(request: SpawnRequest) -> c_int {
    let SpawnRequest {
        pid,
        path,
        file_actions,
        attrp,
        argv,
        envp,
        search_path,
        pidfd_out,
    } = request;

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
    if let Err(e) = unsafe { raw_syscall::sys_pipe2(err_pipe.as_mut_ptr(), libc::O_CLOEXEC) } {
        return e;
    }

    let mut child_pidfd = -1_i32;
    let want_pidfd = !pidfd_out.is_null();

    let child_pid = if want_pidfd {
        let args = raw_syscall::CloneArgs {
            flags: raw_syscall::CLONE_PIDFD,
            pidfd: (&mut child_pidfd as *mut i32).cast::<()>() as u64,
            exit_signal: libc::SIGCHLD as u64,
            ..raw_syscall::CloneArgs::default()
        };

        // Use clone3(CLONE_PIDFD) so the parent receives a pidfd in the same
        // kernel operation that creates the child. Calling pidfd_open(child_pid)
        // after a separate spawn has a PID-reuse race for very short-lived
        // children.
        match unsafe {
            raw_syscall::sys_clone3(&args, std::mem::size_of::<raw_syscall::CloneArgs>())
        } {
            Ok(pid) => pid,
            Err(e) => {
                let _ = raw_syscall::sys_close(err_pipe[0]);
                let _ = raw_syscall::sys_close(err_pipe[1]);
                return e;
            }
        }
    } else {
        // Fork using clone syscall (minimal flags = just SIGCHLD for basic fork)
        match raw_syscall::sys_clone_fork(libc::SIGCHLD as usize) {
            Ok(pid) => pid,
            Err(e) => {
                let _ = raw_syscall::sys_close(err_pipe[0]);
                let _ = raw_syscall::sys_close(err_pipe[1]);
                return e;
            }
        }
    };

    if child_pid == 0 {
        // --- Child process ---
        let _ = raw_syscall::sys_close(err_pipe[0]);

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
            // execve only returns on error
            let err = unsafe {
                raw_syscall::sys_execve(
                    cand_path as *const u8,
                    argv as *const *const u8,
                    env as *const *const u8,
                )
            }
            .err()
            .unwrap_or(libc::ENOENT);
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
    let _ = raw_syscall::sys_close(err_pipe[1]);
    let mut child_err: c_int = 0;
    let mut bytes_read = 0usize;
    while bytes_read < std::mem::size_of::<c_int>() {
        let ptr = (&mut child_err as *mut c_int as *mut u8).wrapping_add(bytes_read);
        match unsafe {
            raw_syscall::sys_read(err_pipe[0], ptr, std::mem::size_of::<c_int>() - bytes_read)
        } {
            Ok(0) => break, // EOF => exec succeeded.
            Ok(n) => bytes_read += n,
            Err(libc::EINTR) => continue,
            Err(e) => {
                child_err = e;
                bytes_read = std::mem::size_of::<c_int>();
                break;
            }
        }
    }
    let _ = raw_syscall::sys_close(err_pipe[0]);

    if bytes_read > 0 {
        if child_pidfd >= 0 {
            let _ = raw_syscall::sys_close(child_pidfd);
        }
        let _ = unsafe {
            raw_syscall::sys_wait4(child_pid, std::ptr::null_mut(), 0, std::ptr::null_mut())
        };
        if want_pidfd {
            unsafe { *pidfd_out = -1 };
        }
        if child_err == 0 { libc::EIO } else { child_err }
    } else {
        if !pid.is_null() {
            unsafe { *pid = child_pid };
        }
        if want_pidfd {
            unsafe { *pidfd_out = child_pidfd };
        }
        0
    }
}

/// GNU `pidfd_spawn`/`pidfd_spawnp` implementation shared by the ABI aliases.
///
/// Unlike `posix_spawn` followed by `pidfd_open`, this uses
/// `clone3(CLONE_PIDFD)` so the process handle is allocated atomically with
/// child creation.
pub(crate) unsafe fn pidfd_spawn_impl(
    pidfd: *mut c_int,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    search_path: bool,
) -> c_int {
    if pidfd.is_null() {
        return libc::EINVAL;
    }
    unsafe { *pidfd = -1 };
    unsafe {
        posix_spawn_impl(SpawnRequest {
            pid: std::ptr::null_mut(),
            path,
            file_actions,
            attrp,
            argv,
            envp,
            search_path,
            pidfd_out: pidfd,
        })
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
    unsafe {
        posix_spawn_impl(SpawnRequest {
            pid,
            path,
            file_actions,
            attrp,
            argv,
            envp,
            search_path: false,
            pidfd_out: std::ptr::null_mut(),
        })
    }
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
    unsafe {
        posix_spawn_impl(SpawnRequest {
            pid,
            path: file,
            file_actions,
            attrp,
            argv,
            envp,
            search_path: true,
            pidfd_out: std::ptr::null_mut(),
        })
    }
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
