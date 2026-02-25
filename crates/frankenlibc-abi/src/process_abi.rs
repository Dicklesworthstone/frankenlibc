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

use crate::runtime_policy;

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

#[inline]
unsafe fn set_abi_errno(val: c_int) {
    let p = unsafe { super::errno_abi::__errno_location() };
    unsafe { *p = val };
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
        return unsafe { libc::syscall(libc::SYS_execve as c_long, file, argv, environ) } as c_int;
    }

    let path =
        std::env::var_os("PATH").unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin"));
    let path_bytes = path.as_os_str().as_bytes();

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
        if err != libc::ENOENT && err != libc::ENOTDIR {
            return -1;
        }
    }

    unsafe { set_abi_errno(libc::ENOENT) };
    -1
}

// ---------------------------------------------------------------------------
// fork
// ---------------------------------------------------------------------------

/// POSIX `fork` — create a child process.
#[cfg_attr(not(debug_assertions), unsafe(no_mangle))]
pub unsafe extern "C" fn fork() -> libc::pid_t {
    let (_, decision) = runtime_policy::decide(ApiFamily::Process, 0, 0, true, false, 0);
    if matches!(decision.action, MembraneAction::Deny) {
        runtime_policy::observe(ApiFamily::Process, decision.profile, 50, true);
        unsafe { set_abi_errno(libc::EAGAIN) };
        return -1;
    }

    let rc = unsafe { libc::syscall(libc::SYS_clone as c_long, libc::SIGCHLD, 0, 0, 0, 0) };
    let pid = rc as libc::pid_t;
    let adverse = pid < 0;
    if adverse {
        unsafe { set_abi_errno(libc::EAGAIN) };
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
    // SAFETY: `SYS_exit_group` does not return on Linux; `_exit` is a diverging API.
    unsafe { core::hint::unreachable_unchecked() }
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

    let rc =
        unsafe { libc::syscall(libc::SYS_waitid as c_long, idtype, id, infop, options) as c_int };
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

    let file_bytes = unsafe { std::ffi::CStr::from_ptr(file) }.to_bytes();
    if file_bytes.is_empty() {
        unsafe { set_abi_errno(libc::ENOENT) };
        return -1;
    }

    // If file contains '/', execute directly without PATH search.
    if file_bytes.contains(&b'/') {
        return unsafe { libc::syscall(libc::SYS_execve as c_long, file, argv, envp) as c_int };
    }

    // Search PATH for the executable.
    let path =
        std::env::var_os("PATH").unwrap_or_else(|| std::ffi::OsString::from("/bin:/usr/bin"));
    let path_bytes = path.as_os_str().as_bytes();

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
        if err != libc::ENOENT && err != libc::ENOTDIR {
            return -1;
        }
    }

    unsafe { set_abi_errno(libc::ENOENT) };
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
}

/// Internal file actions list, heap-allocated.
struct SpawnFileActions {
    actions: Vec<SpawnFileAction>,
}

/// Internal spawn attributes (flags + signal masks, etc.)
#[allow(dead_code)]
struct SpawnAttrs {
    flags: libc::c_short,
    pgroup: libc::pid_t,
    sigdefault: u64, // signal set bitmask
    sigmask: u64,
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
        }
    }
    0
}

/// Core posix_spawn implementation shared between posix_spawn and posix_spawnp.
/// `search_path` controls whether PATH search is done (posix_spawnp).
unsafe fn posix_spawn_impl(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const c_void,
    _attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
    search_path: bool,
) -> c_int {
    if path.is_null() || argv.is_null() {
        return libc::EINVAL;
    }

    // Fork using clone syscall (minimal flags = just SIGCHLD for basic fork)
    let child_pid =
        unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) } as libc::pid_t;

    if child_pid < 0 {
        return std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EAGAIN);
    }

    if child_pid == 0 {
        // --- Child process ---

        // Apply file actions if provided
        if let Some(fa) = unsafe { read_file_actions(file_actions) } {
            let err = unsafe { apply_file_actions(fa) };
            if err != 0 {
                unsafe { libc::syscall(libc::SYS_exit_group, 127) };
                unreachable!();
            }
        }

        // Execute the program
        let env = if envp.is_null() {
            unsafe { environ as *const *mut c_char }
        } else {
            envp
        };

        if search_path {
            // Use execvpe-like behavior: search PATH
            let file_cstr = unsafe { std::ffi::CStr::from_ptr(path) };
            let file_bytes = file_cstr.to_bytes();

            if file_bytes.contains(&b'/') {
                // Contains slash — use directly
                unsafe { libc::syscall(libc::SYS_execve, path, argv, env) };
            } else {
                // Search PATH
                let path_env =
                    std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
                for dir in path_env.split(':') {
                    let mut full = dir.as_bytes().to_vec();
                    full.push(b'/');
                    full.extend_from_slice(file_bytes);
                    full.push(0);
                    unsafe {
                        libc::syscall(libc::SYS_execve, full.as_ptr(), argv, env);
                    }
                    // If execve returns, try next PATH entry
                }
            }
        } else {
            unsafe { libc::syscall(libc::SYS_execve, path, argv, env) };
        }

        // If we get here, exec failed
        unsafe { libc::syscall(libc::SYS_exit_group, 127) };
        unreachable!();
    }

    // --- Parent process ---
    if !pid.is_null() {
        unsafe { *pid = child_pid };
    }
    0
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
    let p = file_actions as *mut u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) };
    if raw.is_null() {
        return libc::EINVAL;
    }
    let fa = unsafe { &mut *raw };
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
    let p = file_actions as *mut u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) };
    if raw.is_null() {
        return libc::EINVAL;
    }
    let fa = unsafe { &mut *raw };
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
    let p_fa = file_actions as *mut u8;
    let magic = unsafe { *(p_fa.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p_fa.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) };
    if raw.is_null() {
        return libc::EINVAL;
    }
    let path_cstr = unsafe { std::ffi::CStr::from_ptr(path) };
    let mut path_bytes = path_cstr.to_bytes().to_vec();
    path_bytes.push(0); // NUL terminate for later syscall
    let fa = unsafe { &mut *raw };
    fa.actions.push(SpawnFileAction::Open {
        fd,
        path: path_bytes,
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
    let p = file_actions as *mut u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) };
    if raw.is_null() {
        return libc::EINVAL;
    }
    let path_cstr = unsafe { std::ffi::CStr::from_ptr(path) };
    let mut path_bytes = path_cstr.to_bytes().to_vec();
    path_bytes.push(0); // NUL terminate
    let fa = unsafe { &mut *raw };
    fa.actions.push(SpawnFileAction::Chdir { path: path_bytes });
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
    let p = file_actions as *mut u8;
    let magic = unsafe { *(p.add(FA_MAGIC_OFF) as *const u64) };
    if magic != SPAWN_FA_MAGIC {
        return libc::EINVAL;
    }
    let raw = unsafe { *(p.add(FA_PTR_OFF) as *mut *mut SpawnFileActions) };
    if raw.is_null() {
        return libc::EINVAL;
    }
    let fa = unsafe { &mut *raw };
    fa.actions.push(SpawnFileAction::Fchdir(fd));
    0
}
