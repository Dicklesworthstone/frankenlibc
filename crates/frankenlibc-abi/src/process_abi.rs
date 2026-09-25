//! ABI layer for process control functions.
//!
//! Provides the POSIX process-control surface: fork, _exit, execve, execvp,
//! waitpid, wait. All functions route through the membrane RuntimeMathKernel
//! under `ApiFamily::Process`.

#[path = "spawn_protocol.rs"]
mod spawn_protocol;

use std::ffi::{c_char, c_int, c_void};

use frankenlibc_core::process;
use frankenlibc_core::syscall as raw_syscall;
use frankenlibc_membrane::heal::{HealingAction, global_healing_policy};
use frankenlibc_membrane::runtime_math::{ApiFamily, MembraneAction};

use crate::errno_abi::set_abi_errno;
use crate::malloc_abi::known_remaining;
use crate::runtime_policy;
use crate::util::scan_c_string;

/// Read a user-supplied C string pointer with a known-region bound so a
/// non-NUL-terminated argument cannot walk arbitrary process memory through
/// `CStr::from_ptr`. (REVIEW round 5: same defense class as bd-z4k96.)
#[inline]
unsafe fn read_bounded_cstr(ptr: *const c_char) -> Option<Vec<u8>> {
    if ptr.is_null() {
        return None;
    }
    let (len, terminated) = unsafe { scan_c_string(ptr, known_remaining(ptr as usize)) };
    if !terminated {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, len) };
    Some(bytes.to_vec())
}

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
        // Caller-provided envp entries can be malformed. Bound scans for tracked
        // allocations so an unterminated entry cannot bleed into adjacent memory.
        if let Some(env_slice) = unsafe { read_bounded_cstr(entry) }
            && let Some(path_value) = env_slice.strip_prefix(b"PATH=")
        {
            return path_value.to_vec();
        }
        // SAFETY: advancing within a NULL-terminated environment vector.
        envp = unsafe { envp.add(1) };
    }

    b"/bin:/usr/bin".to_vec()
}

/// ENOEXEC fallback for the searching exec family, NOT execve or posix_spawnp.
/// Pass the script filename and argv[1..] as individual arguments. A command
/// string would reinterpret spaces, substitutions and shell metacharacters.
/// Returns errno only: successful exec never returns to this address space.
unsafe fn exec_through_shell(
    path: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let slots = known_remaining(argv as usize)
        .map(|bytes| bytes / std::mem::size_of::<*const c_char>());
    let mut argc = 0usize;
    loop {
        if slots.is_some_and(|slots| argc >= slots) {
            return libc::EFAULT;
        }
        if argc >= c_int::MAX as usize - 1 {
            return libc::E2BIG;
        }
        // SAFETY: caller supplies a NULL-terminated vector; tracked extents
        // are checked before each read, including the terminating slot.
        if unsafe { *argv.add(argc) }.is_null() {
            break;
        }
        argc += 1;
    }

    let mut shell_argv: Vec<*const c_char> = Vec::new();
    // Even argv == {NULL} needs shell, script, NULL. Do not read argv[1]
    // in that case (the terminator may be the last word of a readable page).
    if shell_argv.try_reserve_exact(argc.max(1) + 2).is_err() {
        return libc::ENOMEM;
    }
    shell_argv.push(c"/bin/sh".as_ptr());
    shell_argv.push(path);
    for index in 1..argc {
        // SAFETY: the first pass checked all of these vector slots.
        shell_argv.push(unsafe { *argv.add(index) });
    }
    shell_argv.push(std::ptr::null());
    // SAFETY: the pointer vector is terminated and lives until exec returns;
    // path, argument strings and envp retain their caller-owned lifetimes.
    unsafe {
        raw_syscall::sys_execve(
            c"/bin/sh".as_ptr().cast(),
            shell_argv.as_ptr().cast(),
            envp.cast(),
        )
    }
    .err()
    .unwrap_or(libc::EIO)
}

/// Shared native execvp/execvpe search. Return the final errno without host
/// delegation. PATH always belongs to the caller; envp belongs to the new
/// image, including the implicit shell. Shell-launch failures are terminal.
unsafe fn execvpe_error(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    if file.is_null() || argv.is_null() {
        return libc::EFAULT;
    }
    let (file_len, terminated) = unsafe { scan_c_string(file, known_remaining(file as usize)) };
    if !terminated {
        return libc::EFAULT;
    }
    if file_len == 0 {
        return libc::ENOENT;
    }
    // SAFETY: the bounded scan established this readable byte range.
    let file_bytes = unsafe { std::slice::from_raw_parts(file.cast::<u8>(), file_len) };
    let attempt = |path: *const c_char| {
        // SAFETY: all candidates are terminated and the caller's argument
        // and environment vectors remain valid throughout the operation.
        unsafe { raw_syscall::sys_execve(path.cast(), argv.cast(), envp.cast()) }
            .err()
            .unwrap_or(libc::EIO)
    };
    if file_bytes.contains(&b'/') {
        let error = attempt(file);
        return if error == libc::ENOEXEC {
            unsafe { exec_through_shell(file, argv, envp) }
        } else {
            error
        };
    }

    // Bound per-candidate storage without allocating for every PATH entry.
    // glibc's searching exec bounds bare names at Linux NAME_MAX (255).
    // A pathname containing '/' is deliberately left to the kernel above.
    const EXEC_NAME_MAX: usize = 255;
    if file_len > EXEC_NAME_MAX {
        return libc::ENAMETOOLONG;
    }
    let path = unsafe { path_bytes_from_env_vector(std::ptr::null()) };
    let mut candidate = [0u8; libc::PATH_MAX as usize + EXEC_NAME_MAX + 1];
    let mut saw_eacces = false;
    let mut last_error = libc::ENOENT;
    for directory in path.split(|byte| *byte == b':') {
        // Like glibc, skip an unrepresentably long search component rather
        // than letting it hide a usable executable in a later component.
        if directory.len() >= libc::PATH_MAX as usize {
            continue;
        }
        let mut length = directory.len();
        candidate[..length].copy_from_slice(directory);
        if length != 0 {
            candidate[length] = b'/';
            length += 1;
        }
        // Empty PATH entries use the bare filename, not './file': the script
        // sees the same $0 as glibc's fallback, including leading/trailing ':'.
        candidate[length..length + file_len].copy_from_slice(file_bytes);
        candidate[length + file_len] = 0;
        let candidate_ptr = candidate.as_ptr().cast::<c_char>();
        let error = attempt(candidate_ptr);
        if error == libc::ENOEXEC {
            // Do not continue PATH search if /bin/sh itself fails to exec.
            return unsafe { exec_through_shell(candidate_ptr, argv, envp) };
        }
        last_error = error;
        match error {
            libc::EACCES => saw_eacces = true,
            libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT => {}
            // E2BIG, ENOMEM, ELOOP, ETXTBSY, etc. must not be hidden by an
            // earlier EACCES or retried as if the executable were missing.
            _ => return error,
        }
    }
    if saw_eacces { libc::EACCES } else { last_error }
}

unsafe fn execvp_via_execve(file: *const c_char, argv: *const *const c_char) -> c_int {
    let error = unsafe { execvpe_error(file, argv, environ as *const *const c_char) };
    unsafe { set_abi_errno(error) };
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
    // Stdio before the arena shards: normal code takes stdio locks and then
    // allocates, and in hardened mode the registry's first use allocates.
    let stdio_guard = crate::stdio_abi::stdio_fork_prepare();
    let _pipeline_guard =
        crate::membrane_state::try_global_pipeline().map(|pipeline| pipeline.atfork_prepare());
    // Acquire ENVIRON_LOCK before fork so the child does not inherit a held
    // state from another parent thread mid-setenv. Without this, the child's
    // first getenv/setenv after fork would deadlock waiting for a lock that
    // no thread can ever release in the new address space. Mirrors the
    // pipeline atfork pattern. (REVIEW round 4: fork-after-setenv deadlock.)
    let parent_tid = crate::util::AbiReentrantMutex::<()>::current_owner_tid();
    let _environ_guard = crate::stdlib_abi::ENVIRON_LOCK.lock();
    // Taken last and released first: nothing between here and the drop below
    // may allocate or free.
    let malloc_guard = crate::malloc_abi::malloc_fork_prepare();

    let pid = raw_syscall::sys_clone_fork(libc::SIGCHLD as usize);
    drop(malloc_guard);
    if pid == Ok(0) {
        // Membrane locks held by other parent threads are orphaned now.
        frankenlibc_membrane::util::note_fork_child();
    }
    let pid = match pid {
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

    // Both parent and child release their copies of these guards. The ABI lock
    // state lives inline in the static; the guard's Drop releases the lock
    // owned by the current thread on each side of fork. The child's thread has
    // a new TID, so ownership must be handed to it first or the drop is a
    // silent no-op and the lock stays held forever (bd-rc0923-epic-eeuy4f.5).
    if pid == 0 {
        // SAFETY: freshly forked child (single thread); parent_tid was read
        // by the forking thread before the clone.
        unsafe { crate::stdlib_abi::ENVIRON_LOCK.adopt_in_fork_child(parent_tid) };
    }
    drop(_environ_guard);
    drop(_pipeline_guard);
    // After the arena guard is gone: the child side allocates.
    if pid == 0 {
        stdio_guard.release_in_child();
    } else {
        stdio_guard.release_in_parent();
    }

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

/// C99 `_Exit(status)` — capital-E spelling of POSIX `_exit`.
/// Identical contract: terminate the calling process immediately
/// without running atexit handlers, flushing stdio, or invoking
/// signal handlers. Forwards to `_exit`.
///
/// # Safety
///
/// Same as `_exit`: terminates the process; the caller does not
/// return.
#[allow(non_snake_case)]
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn _Exit(status: c_int) -> ! {
    unsafe { _exit(status) }
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
pub unsafe extern "C-unwind" fn waitpid(
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
        crate::pthread_abi::at_cancellation_point(|| {
            raw_syscall::sys_wait4(pid, wstatus, opts, std::ptr::null_mut())
        })
    };

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
pub unsafe extern "C-unwind" fn wait(wstatus: *mut c_int) -> libc::pid_t {
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
pub unsafe extern "C-unwind" fn wait4(
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
        crate::pthread_abi::at_cancellation_point(|| {
            raw_syscall::sys_wait4(pid, wstatus, options, rusage as *mut u8)
        })
    };

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
pub unsafe extern "C-unwind" fn waitid(
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
        crate::pthread_abi::at_cancellation_point(|| {
            raw_syscall::sys_waitid(
                idtype,
                id,
                infop as *mut u8,
                options,
                std::ptr::null_mut(), // rusage (5th arg)
            )
        })
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

/// glibc reserved-namespace alias for [`wait3`].
///
/// # Safety
///
/// Same as [`wait3`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wait3(
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut libc::rusage,
) -> libc::pid_t {
    unsafe { wait3(wstatus, options, rusage) }
}

/// glibc reserved-namespace alias for [`wait4`].
///
/// # Safety
///
/// Same as [`wait4`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __wait4(
    pid: libc::pid_t,
    wstatus: *mut c_int,
    options: c_int,
    rusage: *mut libc::rusage,
) -> libc::pid_t {
    unsafe { wait4(pid, wstatus, options, rusage) }
}

/// glibc reserved-namespace alias for [`waitid`].
///
/// # Safety
///
/// Same as [`waitid`].
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn __waitid(
    idtype: c_int,
    id: libc::id_t,
    infop: *mut libc::siginfo_t,
    options: c_int,
) -> c_int {
    unsafe { waitid(idtype, id, infop, options) }
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
/// PATH search still uses the caller's environment, not `envp`.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn execvpe(
    file: *const c_char,
    argv: *const *const c_char,
    envp: *const *const c_char,
) -> c_int {
    let error = unsafe { execvpe_error(file, argv, envp) };
    unsafe { set_abi_errno(error) };
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
    // glibc rejects any bits outside the known flag set with EINVAL. ALL_FLAGS
    // (0x1FF) = RESETIDS|SETPGROUP|SETSIGDEF|SETSIGMASK|SETSCHEDPARAM|
    // SETSCHEDULER|USEVFORK|SETSID|SETCGROUP. fl previously stored any value.
    // bd-lkvixl.
    const ALL_FLAGS: libc::c_short = 0x1FF;
    if flags & !ALL_FLAGS != 0 {
        return libc::EINVAL;
    }
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
    // Store the kernel bit layout: signal N occupies bit N-1, including 64.
    unsafe {
        std::ptr::write_bytes(sigdefault, 0, 1);
        std::ptr::write_unaligned(sigdefault.cast::<u64>(), attr.sigdefault);
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
    // Linux consumes the first 64 signal bits; do not drop SIGRTMAX.
    attr.sigdefault = unsafe { std::ptr::read_unaligned(sigdefault.cast::<u64>()) };
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
    // Store the kernel bit layout: signal N occupies bit N-1, including 64.
    unsafe {
        std::ptr::write_bytes(sigmask, 0, 1);
        std::ptr::write_unaligned(sigmask.cast::<u64>(), attr.sigmask);
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
    // Linux consumes the first 64 signal bits; do not drop SIGRTMAX.
    attr.sigmask = unsafe { std::ptr::read_unaligned(sigmask.cast::<u64>()) };
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

    // The child trampoline has reset dispositions with every signal blocked.
    // Keep SETSID before SETPGROUP and scheduling before the effective-ID drop.
    // The requested/inherited signal mask is installed only after file actions,
    // immediately before exec; no inherited application handler can run here.

    // POSIX_SPAWN_SETSID (glibc >= 2.26, value 0x80; not exposed by the libc
    // crate): the child starts a new session. glibc applies it FIRST, before
    // SETPGROUP (setsid makes the child a session+group leader, and a later
    // SETPGROUP can still move it). fl ignored the flag entirely, so the child
    // stayed in the parent's session. bd-h0ht3b.
    const POSIX_SPAWN_SETSID: c_int = 0x80;
    if flags & POSIX_SPAWN_SETSID != 0
        && let Err(e) = raw_syscall::sys_setsid()
    {
        return e;
    }

    if flags & libc::POSIX_SPAWN_SETPGROUP != 0
        && let Err(e) = raw_syscall::sys_setpgid(0, attr.pgroup)
    {
        return e;
    }

    // Signal dispositions were reset by the raw child trampoline. All
    // blockable signals remain blocked until file actions have completed.

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

    if flags & libc::POSIX_SPAWN_RESETIDS != 0
        && let Err(error) = spawn_protocol::reset_effective_ids()
    {
        return error;
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
unsafe fn apply_file_actions(fa: &SpawnFileActions, error_fd: c_int) -> c_int {
    for action in &fa.actions {
        match action {
            SpawnFileAction::Close(fd) => {
                if let Err(e) = spawn_protocol::close_for_spawn(*fd) {
                    return e;
                }
            }
            SpawnFileAction::Dup2 { oldfd, newfd } => {
                if let Err(e) = spawn_protocol::duplicate_for_spawn(*oldfd, *newfd) {
                    return e;
                }
            }
            SpawnFileAction::Open {
                fd,
                path,
                oflag,
                mode,
            } => {
                // An open action closes its destination before opening. This
                // also makes that descriptor slot available under fd pressure.
                let _ = raw_syscall::sys_close(*fd);
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
                if let Err(e) = spawn_protocol::close_from(*from, error_fd) {
                    return e;
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
    spawn_protocol::child_fail(err_fd, err)
}

/// Everything the spawn child reads. It lives in the parent's frame, which a
/// `CLONE_VM | CLONE_VFORK` child shares (read-only, by convention) until it
/// execs or exits; the parent is suspended until then.
struct SpawnChildContext<'a> {
    spawn_attrs: Option<&'static SpawnAttrs>,
    spawn_actions: Option<&'static SpawnFileActions>,
    candidate_ptrs: &'a [*const c_char],
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    is_path_search: bool,
    original_mask: u64,
    err_fd: c_int,
}

/// The spawn child: apply attributes and file actions, then exec. Raw
/// syscalls only (see `spawn_protocol`); never returns.
unsafe extern "C" fn spawn_child_main(ctx: *const SpawnChildContext<'_>) -> ! {
    // SAFETY: the parent keeps the context alive and unmodified until this
    // child execs or exits.
    let ctx = unsafe { &*ctx };
    let err_fd = ctx.err_fd;

    let defaults = ctx
        .spawn_attrs
        .filter(|attr| c_int::from(attr.flags) & libc::POSIX_SPAWN_SETSIGDEF != 0)
        .map_or(0, |attr| attr.sigdefault);
    if let Err(error) = spawn_protocol::reset_child_signals(defaults) {
        unsafe { child_spawn_fail(err_fd, error) };
    }

    // Apply spawn attributes if provided
    if let Some(attr) = ctx.spawn_attrs {
        let err = unsafe { apply_spawn_attrs(attr) };
        if err != 0 {
            unsafe { child_spawn_fail(err_fd, err) };
        }
    }

    // Apply file actions if provided
    if let Some(fa) = ctx.spawn_actions {
        let err = unsafe { apply_file_actions(fa, err_fd) };
        if err != 0 {
            unsafe { child_spawn_fail(err_fd, err) };
        }
    }

    // Execute the program
    let env = if ctx.envp.is_null() {
        unsafe { environ as *const *mut c_char }
    } else {
        ctx.envp
    };

    let final_mask = ctx
        .spawn_attrs
        .filter(|attr| c_int::from(attr.flags) & libc::POSIX_SPAWN_SETSIGMASK != 0)
        .map_or(ctx.original_mask, |attr| attr.sigmask);
    if let Err(error) = spawn_protocol::install_signal_mask(final_mask) {
        unsafe { child_spawn_fail(err_fd, error) };
    }

    // Try execve for each candidate path; reading the slice does not allocate.
    let mut saw_eacces = false;
    let mut final_err = libc::ENOENT;
    for &cand_path in ctx.candidate_ptrs.iter() {
        // execve only returns on error
        let err = unsafe {
            raw_syscall::sys_execve(
                cand_path as *const u8,
                ctx.argv as *const *const u8,
                env as *const *const u8,
            )
        }
        .err()
        .unwrap_or(libc::ENOENT);
        // Without a PATH search, preserve the syscall's exact errno
        // (in particular ENOTDIR), rather than folding it into ENOENT.
        if !ctx.is_path_search {
            unsafe { child_spawn_fail(err_fd, err) };
        }
        match err {
            libc::ENOENT | libc::ENOTDIR | libc::ESTALE | libc::ENODEV | libc::ETIMEDOUT => {}
            libc::EACCES => {
                saw_eacces = true;
            }
            // A terminal error (notably ENOEXEC) wins over an earlier
            // EACCES. posix_spawnp must not run an implicit shell here.
            _ => unsafe { child_spawn_fail(err_fd, err) },
        }
    }

    if saw_eacces {
        final_err = libc::EACCES;
    }
    unsafe { child_spawn_fail(err_fd, final_err) };
}

/// Stack for a `CLONE_VM` spawn child.
const SPAWN_CHILD_STACK_SIZE: usize = 64 * 1024;

/// Create the spawn child with `clone3(CLONE_VM | CLONE_VFORK | extra_flags)`
/// on its own stack, running `spawn_child_main(ctx)`; returns the child pid in
/// the parent once the child has exec'd or exited.
///
/// A full fork copied the parent's page tables for every spawn, although
/// the child only execs: posix_spawn of /bin/true ran ~4.6 ms vs glibc's
/// ~1.3 ms, which uses this same vfork-style clone
/// (bd-rc0923-epic-eeuy4f.25). The child must run on a separate stack: in
/// the parent's frame it would overwrite stack slots the compiler assumes
/// only the parent path uses.
#[cfg(target_arch = "x86_64")]
unsafe fn clone_spawn_child(
    ctx: &SpawnChildContext<'_>,
    extra_flags: u64,
    pidfd: *mut c_int,
) -> Result<c_int, c_int> {
    const CLONE_VM: u64 = 0x0000_0100;
    const CLONE_VFORK: u64 = 0x0000_4000;
    // SAFETY: fresh anonymous mapping, unmapped below once the child is gone.
    let stack = unsafe {
        raw_syscall::sys_mmap(
            std::ptr::null_mut(),
            SPAWN_CHILD_STACK_SIZE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_STACK,
            -1,
            0,
        )
    }?;
    let args = raw_syscall::CloneArgs {
        flags: CLONE_VM | CLONE_VFORK | extra_flags,
        pidfd: pidfd as u64,
        exit_signal: libc::SIGCHLD as u64,
        stack: stack as u64,
        stack_size: SPAWN_CHILD_STACK_SIZE as u64,
        ..raw_syscall::CloneArgs::default()
    };
    let ret: isize;
    // SAFETY: clone3 with a new stack: the child resumes after `syscall` with
    // rsp at the (16-byte aligned) top of `stack`, and calls
    // `spawn_child_main(ctx)`, which never returns. The parent sees the pid
    // (or -errno) in rax once the child has exec'd or exited (CLONE_VFORK).
    unsafe {
        core::arch::asm!(
            "syscall",
            "test rax, rax",
            "jnz 2f",
            "xor ebp, ebp",
            "mov rdi, r12",
            "call r13",
            "ud2",
            "2:",
            inlateout("rax") libc::SYS_clone3 as isize => ret,
            in("rdi") &args as *const raw_syscall::CloneArgs,
            in("rsi") std::mem::size_of::<raw_syscall::CloneArgs>(),
            in("r12") ctx as *const SpawnChildContext<'_>,
            in("r13") spawn_child_main as usize,
            lateout("rcx") _,
            lateout("r11") _,
        );
    }
    // SAFETY: the child no longer runs on this stack (exec'd or exited).
    let _ = unsafe { raw_syscall::sys_munmap(stack, SPAWN_CHILD_STACK_SIZE) };
    if (-4095..0).contains(&ret) {
        Err((-ret) as c_int)
    } else {
        Ok(ret as c_int)
    }
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

    // Validate optional handles in the parent. A non-null invalid object must
    // not silently turn into an empty action list/default attributes.
    let spawn_attrs = if attrp.is_null() {
        None
    } else {
        match unsafe { read_spawn_attrs(attrp) } {
            Some(value) => Some(value),
            None => return libc::EINVAL,
        }
    };
    let spawn_actions = if file_actions.is_null() {
        None
    } else {
        match unsafe { read_file_actions(file_actions) } {
            Some(value) => Some(value),
            None => return libc::EINVAL,
        }
    };

    let (path_len, terminated) = unsafe {
        crate::util::scan_c_string(path, crate::malloc_abi::known_remaining(path as usize))
    };
    if !terminated {
        return libc::EFAULT;
    }
    let path_slice = unsafe { std::slice::from_raw_parts(path as *const u8, path_len) };
    if path_slice.is_empty() {
        return libc::ENOENT;
    }
    let is_path_search = search_path && !path_slice.contains(&b'/');
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
            // PATH comes from the caller's environment, not the environment
            // vector that will be installed in the newly executed program.
            let owned_path = unsafe { path_bytes_from_env_vector(std::ptr::null()) };
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

    // The pipe must not become an implicit source/destination in user actions.
    // closefrom is handled separately by excluding this private descriptor.
    if let Err(error) = spawn_protocol::reserve_error_fd(&mut err_pipe[1], |fd| {
        spawn_attrs.is_some_and(|attr| attr.has_cgroup && attr.cgroup_fd == fd)
            || spawn_actions.is_some_and(|fa| fa.actions.iter().any(|action| match action {
                SpawnFileAction::Close(value)
                | SpawnFileAction::Fchdir(value)
                | SpawnFileAction::TcSetPgrp(value) => *value == fd,
                SpawnFileAction::Dup2 { oldfd, newfd } => *oldfd == fd || *newfd == fd,
                SpawnFileAction::Open { fd: destination, .. } => *destination == fd,
                SpawnFileAction::CloseFrom(_) | SpawnFileAction::Chdir { .. } => false,
            }))
    }) {
        let _ = raw_syscall::sys_close(err_pipe[0]);
        let _ = raw_syscall::sys_close(err_pipe[1]);
        return error;
    }

    let signal_guard = match spawn_protocol::SignalMaskGuard::block_all() {
        Ok(guard) => guard,
        Err(error) => {
            let _ = raw_syscall::sys_close(err_pipe[0]);
            let _ = raw_syscall::sys_close(err_pipe[1]);
            return error;
        }
    };
    let mut child_pidfd = -1_i32;
    let want_pidfd = !pidfd_out.is_null();

    let child_context = SpawnChildContext {
        spawn_attrs,
        spawn_actions,
        candidate_ptrs: &candidate_ptrs,
        argv,
        envp,
        is_path_search,
        original_mask: signal_guard.original,
        err_fd: err_pipe[1],
    };
    // Use clone3(CLONE_PIDFD) when a pidfd is wanted, so the parent receives
    // it in the same kernel operation that creates the child: pidfd_open
    // after the fact has a PID-reuse race for very short-lived children.
    let extra_flags = if want_pidfd {
        raw_syscall::CLONE_PIDFD
    } else {
        0
    };

    #[cfg(target_arch = "x86_64")]
    let spawned = unsafe { clone_spawn_child(&child_context, extra_flags, &mut child_pidfd) };
    #[cfg(not(target_arch = "x86_64"))]
    let spawned = {
        let result = if want_pidfd {
            let args = raw_syscall::CloneArgs {
                flags: extra_flags,
                pidfd: (&mut child_pidfd as *mut i32).cast::<()>() as u64,
                exit_signal: libc::SIGCHLD as u64,
                ..raw_syscall::CloneArgs::default()
            };
            unsafe { raw_syscall::sys_clone3(&args, std::mem::size_of::<raw_syscall::CloneArgs>()) }
        } else {
            raw_syscall::sys_clone_fork(libc::SIGCHLD as usize)
        };
        if result == Ok(0) {
            // --- Child process (full fork) ---
            let _ = raw_syscall::sys_close(err_pipe[0]);
            unsafe { spawn_child_main(&child_context) };
        }
        result
    };
    let child_pid = match spawned {
        Ok(pid) => pid,
        Err(e) => {
            let _ = raw_syscall::sys_close(err_pipe[0]);
            let _ = raw_syscall::sys_close(err_pipe[1]);
            return e;
        }
    };

    // --- Parent process ---
    // The child does not share this address space. Restore the calling thread's
    // mask now, not after potentially blocking in the error-pipe read.
    drop(signal_guard);
    let _ = raw_syscall::sys_close(err_pipe[1]);
    let child_status = spawn_protocol::read_child_error(err_pipe[0]);
    let _ = raw_syscall::sys_close(err_pipe[0]);

    match child_status {
        Ok(None) => {
            if !pid.is_null() {
                unsafe { *pid = child_pid };
            }
            if want_pidfd {
                unsafe { *pidfd_out = child_pidfd };
            }
            0
        }
        Ok(Some(error)) | Err(error) => {
            if child_pidfd >= 0 {
                let _ = raw_syscall::sys_close(child_pidfd);
            }
            spawn_protocol::reap_failed_child(child_pid);
            if want_pidfd {
                unsafe { *pidfd_out = -1 };
            }
            error
        }
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
/// glibc's file-descriptor validity test for the file-action adders.
///
/// Every adder that takes an fd opens with, in effect,
/// `if (fd < 0 || fd >= __sysconf (_SC_OPEN_MAX)) return EBADF;`. Both halves
/// matter and fl only had the first: measured against live glibc 2.42 on a host
/// whose `_SC_OPEN_MAX` is 1048576,
///
/// ```text
///   addclose(-1)        -> EBADF      addclose(1000000)   -> 0
///   addclose(1048575)   -> 0          addclose(1048576)   -> EBADF
///   addclose(INT_MAX)   -> EBADF
/// ```
///
/// so the bound is the RLIMIT, not `INT_MAX` and not a constant — which is why
/// the gate derives its probe values from `sysconf` at runtime instead of
/// hardcoding one. `addfchdir_np` is the deliberate exception: glibc does not
/// validate there at all (see its own comment). bd-r1cvsg.
fn spawn_valid_fd(fd: c_int) -> bool {
    if fd < 0 {
        return false;
    }
    // SAFETY: sysconf takes an int and has no pointer arguments.
    let open_max = unsafe { crate::unistd_abi::sysconf(libc::_SC_OPEN_MAX) };
    // A negative sysconf means "no determinate limit"; glibc's comparison then
    // cannot reject, so neither do we.
    open_max < 0 || (fd as i64) < open_max as i64
}

#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn posix_spawn_file_actions_addclose(
    file_actions: *mut c_void,
    fd: c_int,
) -> c_int {
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    if !spawn_valid_fd(fd) {
        return libc::EBADF;
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
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    if !spawn_valid_fd(oldfd) || !spawn_valid_fd(newfd) {
        return libc::EBADF; // glibc: fd < 0 || fd >= _SC_OPEN_MAX. bd-r1cvsg.
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
    if file_actions.is_null() || path.is_null() {
        return libc::EINVAL;
    }
    if !spawn_valid_fd(fd) {
        return libc::EBADF; // glibc: fd < 0 || fd >= _SC_OPEN_MAX. bd-r1cvsg.
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
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    // NO fd validation here, deliberately. Unlike every other adder, glibc's
    // addfchdir_np never calls the validity test, so it accepts -1, INT_MIN and
    // INT_MAX alike and returns 0; a bad fd surfaces at spawn time instead. fl
    // used to reject fd < 0 with EBADF here, which the bd-r1cvsg fix introduced
    // by applying the rule uniformly. Measured against live glibc 2.42:
    //   addfchdir_np(-1) -> 0   addfchdir_np(INT_MIN) -> 0   addfchdir_np(INT_MAX) -> 0
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
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    if !spawn_valid_fd(from) {
        return libc::EBADF; // glibc addclosefrom_np: same validity test. bd-r1cvsg.
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
    if file_actions.is_null() {
        return libc::EINVAL;
    }
    if !spawn_valid_fd(fd) {
        return libc::EBADF; // glibc: fd < 0 || fd >= _SC_OPEN_MAX. bd-r1cvsg.
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
