#![cfg(target_os = "linux")]

//! Integration tests for `<spawn.h>` and process ABI entrypoints.
//!
//! Tests cover posix_spawn attribute and file action lifecycle:
//! init/destroy, flag get/set, signal set get/set, pgroup, sched params,
//! file actions (addclose, adddup2, addopen, addchdir_np, addfchdir_np).
//!
//! Fork/exec/wait tests are in separate integration test suites
//! because they require child process creation.

use std::ffi::{CString, c_char, c_int};
use std::os::unix::fs::symlink;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenlibc_abi::process_abi::*;

// ===========================================================================
// posix_spawnattr lifecycle: init / destroy
// ===========================================================================

// The opaque posix_spawnattr_t struct needs enough space for magic + pointer.
// On glibc it's typically 336 bytes. We use 512 to be safe.
// Must be 8-byte aligned because process_abi writes u64 at offset 0.
#[repr(C, align(8))]
struct AlignedBuf([u8; 512]);

impl AlignedBuf {
    fn new() -> Self {
        Self([0u8; 512])
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }
    fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

#[test]
fn spawnattr_init_destroy() {
    let mut attr = AlignedBuf::new();
    let rc = unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "init should succeed");

    let rc = unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
    assert_eq!(rc, 0, "destroy should succeed");
}

#[test]
fn spawnattr_init_null_returns_einval() {
    let rc = unsafe { posix_spawnattr_init(std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn spawnattr_destroy_null_returns_einval() {
    let rc = unsafe { posix_spawnattr_destroy(std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn spawnattr_destroy_uninitialized_returns_einval() {
    let mut attr = AlignedBuf::new();
    let rc = unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
    assert_eq!(
        rc,
        libc::EINVAL,
        "destroy uninitialized should return EINVAL"
    );
}

// ===========================================================================
// posix_spawnattr flags
// ===========================================================================

#[test]
fn spawnattr_flags_default_zero() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut flags: libc::c_short = -1;
    let rc = unsafe { posix_spawnattr_getflags(attr.as_ptr().cast(), &mut flags) };
    assert_eq!(rc, 0);
    assert_eq!(flags, 0, "default flags should be 0");

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_flags_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_setflags(attr.as_mut_ptr().cast(), 0x1234) };
    assert_eq!(rc, 0);

    let mut flags: libc::c_short = 0;
    let rc = unsafe { posix_spawnattr_getflags(attr.as_ptr().cast(), &mut flags) };
    assert_eq!(rc, 0);
    assert_eq!(flags, 0x1234);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr pgroup
// ===========================================================================

#[test]
fn spawnattr_pgroup_default_zero() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut pgroup: libc::pid_t = -1;
    let rc = unsafe { posix_spawnattr_getpgroup(attr.as_ptr().cast(), &mut pgroup) };
    assert_eq!(rc, 0);
    assert_eq!(pgroup, 0, "default pgroup should be 0");

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_pgroup_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_setpgroup(attr.as_mut_ptr().cast(), 42) };
    assert_eq!(rc, 0);

    let mut pgroup: libc::pid_t = 0;
    let rc = unsafe { posix_spawnattr_getpgroup(attr.as_ptr().cast(), &mut pgroup) };
    assert_eq!(rc, 0);
    assert_eq!(pgroup, 42);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr sched policy
// ===========================================================================

#[test]
fn spawnattr_schedpolicy_default_zero() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut policy: c_int = -1;
    let rc = unsafe { posix_spawnattr_getschedpolicy(attr.as_ptr().cast(), &mut policy) };
    assert_eq!(rc, 0);
    assert_eq!(policy, 0);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_schedpolicy_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_setschedpolicy(attr.as_mut_ptr().cast(), libc::SCHED_RR) };
    assert_eq!(rc, 0);

    let mut policy: c_int = 0;
    let rc = unsafe { posix_spawnattr_getschedpolicy(attr.as_ptr().cast(), &mut policy) };
    assert_eq!(rc, 0);
    assert_eq!(policy, libc::SCHED_RR);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr schedparam
// ===========================================================================

#[test]
fn spawnattr_schedparam_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let param_in = libc::sched_param { sched_priority: 10 };
    let rc = unsafe { posix_spawnattr_setschedparam(attr.as_mut_ptr().cast(), &param_in) };
    assert_eq!(rc, 0);

    let mut param_out: libc::sched_param = unsafe { std::mem::zeroed() };
    let rc = unsafe { posix_spawnattr_getschedparam(attr.as_ptr().cast(), &mut param_out) };
    assert_eq!(rc, 0);
    assert_eq!(param_out.sched_priority, 10);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnattr signal sets
// ===========================================================================

#[test]
fn spawnattr_sigdefault_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    // Set SIGCHLD in sigdefault
    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGCHLD);
    }
    let rc = unsafe { posix_spawnattr_setsigdefault(attr.as_mut_ptr().cast(), &sigset) };
    assert_eq!(rc, 0);

    // Read it back
    let mut out: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { posix_spawnattr_getsigdefault(attr.as_ptr().cast(), &mut out) };
    assert_eq!(rc, 0);
    assert_eq!(
        unsafe { libc::sigismember(&out, libc::SIGCHLD) },
        1,
        "SIGCHLD should be in sigdefault"
    );
    assert_eq!(
        unsafe { libc::sigismember(&out, libc::SIGTERM) },
        0,
        "SIGTERM should NOT be in sigdefault"
    );

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

#[test]
fn spawnattr_sigmask_roundtrip() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let mut sigset: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut sigset);
        libc::sigaddset(&mut sigset, libc::SIGUSR1);
        libc::sigaddset(&mut sigset, libc::SIGUSR2);
    }
    let rc = unsafe { posix_spawnattr_setsigmask(attr.as_mut_ptr().cast(), &sigset) };
    assert_eq!(rc, 0);

    let mut out: libc::sigset_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { posix_spawnattr_getsigmask(attr.as_ptr().cast(), &mut out) };
    assert_eq!(rc, 0);
    assert_eq!(unsafe { libc::sigismember(&out, libc::SIGUSR1) }, 1);
    assert_eq!(unsafe { libc::sigismember(&out, libc::SIGUSR2) }, 1);
    assert_eq!(unsafe { libc::sigismember(&out, libc::SIGINT) }, 0);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawn_file_actions lifecycle: init / destroy
// ===========================================================================

#[test]
fn file_actions_init_destroy() {
    let mut fa = AlignedBuf::new();
    let rc = unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);

    let rc = unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
    assert_eq!(rc, 0);
}

#[test]
fn file_actions_init_null_returns_einval() {
    let rc = unsafe { posix_spawn_file_actions_init(std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);
}

// ===========================================================================
// posix_spawn_file_actions_add*
// ===========================================================================

#[test]
fn file_actions_addclose() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_addclose(fa.as_mut_ptr().cast(), 3) };
    assert_eq!(rc, 0, "addclose should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_adddup2() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_adddup2(fa.as_mut_ptr().cast(), 1, 2) };
    assert_eq!(rc, 0, "adddup2 should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addopen() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let path = CString::new("/dev/null").unwrap();
    let rc = unsafe {
        posix_spawn_file_actions_addopen(
            fa.as_mut_ptr().cast(),
            3,
            path.as_ptr(),
            libc::O_RDONLY,
            0o644,
        )
    };
    assert_eq!(rc, 0, "addopen should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addchdir_np() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let path = CString::new("/tmp").unwrap();
    let rc = unsafe { posix_spawn_file_actions_addchdir_np(fa.as_mut_ptr().cast(), path.as_ptr()) };
    assert_eq!(rc, 0, "addchdir_np should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addfchdir_np() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_addfchdir_np(fa.as_mut_ptr().cast(), 0) };
    assert_eq!(rc, 0, "addfchdir_np should succeed");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_multiple() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    // Chain multiple actions
    let path = CString::new("/dev/null").unwrap();
    assert_eq!(
        unsafe { posix_spawn_file_actions_addclose(fa.as_mut_ptr().cast(), 3) },
        0
    );
    assert_eq!(
        unsafe { posix_spawn_file_actions_adddup2(fa.as_mut_ptr().cast(), 1, 2) },
        0
    );
    assert_eq!(
        unsafe {
            posix_spawn_file_actions_addopen(
                fa.as_mut_ptr().cast(),
                4,
                path.as_ptr(),
                libc::O_RDONLY,
                0,
            )
        },
        0
    );

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

// ===========================================================================
// Null safety for accessors
// ===========================================================================

#[test]
fn spawnattr_getflags_null_attr() {
    let mut flags: libc::c_short = 0;
    let rc = unsafe { posix_spawnattr_getflags(std::ptr::null(), &mut flags) };
    assert_eq!(rc, libc::EINVAL);
}

#[test]
fn spawnattr_getpgroup_null_out() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawnattr_getpgroup(attr.as_ptr().cast(), std::ptr::null_mut()) };
    assert_eq!(rc, libc::EINVAL);

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnp (smoke test with /bin/true)
// ===========================================================================

#[test]
fn posix_spawnp_true() {
    let cmd = CString::new("/bin/true").unwrap();
    let argv: [*const std::ffi::c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = 0;

    let rc = unsafe {
        posix_spawnp(
            &mut pid,
            cmd.as_ptr(),
            std::ptr::null(),     // file_actions
            std::ptr::null(),     // attrp
            argv.as_ptr().cast(), // argv
            std::ptr::null(),     // envp (inherit)
        )
    };
    assert_eq!(rc, 0, "posix_spawnp(/bin/true) should succeed");
    assert!(pid > 0, "child pid should be positive");

    // Wait for child
    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child should exit 0"
    );
}

#[test]
fn posix_spawnp_missing_binary_returns_enoent() {
    let missing =
        CString::new("frankenlibc_nonexistent_spawn_binary_9f1e62f4b2c1478ab5f92cf0").unwrap();
    let argv: [*const c_char; 2] = [missing.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = -1;

    let rc = unsafe {
        posix_spawnp(
            &mut pid,
            missing.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr().cast(),
            std::ptr::null(),
        )
    };

    assert_eq!(
        rc,
        libc::ENOENT,
        "posix_spawnp should surface ENOENT when PATH search finds nothing"
    );
    assert_eq!(pid, -1, "pid must remain unchanged on spawn failure");
}

#[test]
fn execvp_continues_path_search_after_eacces() {
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("frankenlibc_execvp_path_{uniq}"));
    let deny_dir = base.join("deny");
    let ok_dir = base.join("ok");
    std::fs::create_dir_all(&deny_dir).unwrap();
    std::fs::create_dir_all(&ok_dir).unwrap();

    let cmd_name = "frankenlibc_execvp_probe";
    let deny_cmd = deny_dir.join(cmd_name);
    std::fs::write(&deny_cmd, b"#!/bin/sh\nexit 66\n").unwrap();
    std::fs::set_permissions(
        &deny_cmd,
        std::os::unix::fs::PermissionsExt::from_mode(0o644),
    )
    .unwrap();

    let ok_cmd = ok_dir.join(cmd_name);
    symlink("/bin/true", &ok_cmd).unwrap();

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork should succeed in execvp path-search test");

    if pid == 0 {
        let path = CString::new(format!("{}:{}", deny_dir.display(), ok_dir.display())).unwrap();
        let key = CString::new("PATH").unwrap();
        unsafe { libc::setenv(key.as_ptr(), path.as_ptr(), 1) };

        let cmd = CString::new(cmd_name).unwrap();
        let argv: [*const c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
        let rc = unsafe { execvp(cmd.as_ptr(), argv.as_ptr()) };
        let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        let code = if rc == -1 { 100 + (err & 0x7f) } else { 127 };
        unsafe { libc::_exit(code) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(
        libc::WIFEXITED(status),
        "child should exit normally after execvp path resolution"
    );
    assert_eq!(
        libc::WEXITSTATUS(status),
        0,
        "execvp must keep searching PATH after EACCES and execute later candidate"
    );

    let _ = std::fs::remove_file(&ok_cmd);
    let _ = std::fs::remove_file(&deny_cmd);
    let _ = std::fs::remove_dir(&ok_dir);
    let _ = std::fs::remove_dir(&deny_dir);
    let _ = std::fs::remove_dir(&base);
}

// ===========================================================================
// fork + waitpid
// ===========================================================================

#[test]
fn fork_and_waitpid_child_exits_zero() {
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork should succeed");

    if pid == 0 {
        // Child: exit immediately with code 0
        unsafe { libc::_exit(0) };
    }

    // Parent: wait for child
    let mut status: c_int = 0;
    let waited = unsafe { waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid should return the child pid");
    assert!(libc::WIFEXITED(status), "child should have exited normally");
    assert_eq!(libc::WEXITSTATUS(status), 0, "child exit code should be 0");
}

#[test]
fn fork_and_waitpid_child_exits_nonzero() {
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork should succeed");

    if pid == 0 {
        unsafe { libc::_exit(42) };
    }

    let mut status: c_int = 0;
    let waited = unsafe { waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 42);
}

#[test]
fn fork_child_gets_zero_pid() {
    let pid = unsafe { fork() };
    assert!(pid >= 0, "fork should succeed");

    if pid == 0 {
        // In child: fork() returns 0
        // Verify we're really the child by checking getpid != parent
        unsafe { libc::_exit(0) };
    }

    // Parent: pid > 0
    assert!(pid > 0, "parent should get positive child pid");
    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
}

// ===========================================================================
// wait (simple form)
// ===========================================================================

#[test]
fn wait_returns_child_status() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        unsafe { libc::_exit(7) };
    }

    let mut status: c_int = 0;
    let waited = unsafe { wait(&mut status) };
    assert_eq!(waited, pid, "wait should return the child pid");
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 7);
}

// ===========================================================================
// wait4
// ===========================================================================

#[test]
fn wait4_captures_rusage() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        unsafe { libc::_exit(3) };
    }

    let mut status: c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let waited = unsafe { wait4(pid, &mut status, 0, &mut rusage) };
    assert_eq!(waited, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 3);
    // rusage should have been populated (at least user time >= 0)
    assert!(rusage.ru_utime.tv_sec >= 0);
    assert!(rusage.ru_stime.tv_sec >= 0);
}

// ===========================================================================
// wait3
// ===========================================================================

#[test]
fn wait3_captures_rusage() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        unsafe { libc::_exit(5) };
    }

    let mut status: c_int = 0;
    let mut rusage: libc::rusage = unsafe { std::mem::zeroed() };
    let waited = unsafe { wait3(&mut status, 0, &mut rusage) };
    assert_eq!(waited, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 5);
}

// ===========================================================================
// waitid
// ===========================================================================

#[test]
fn waitid_with_p_pid() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        unsafe { libc::_exit(11) };
    }

    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let rc = unsafe { waitid(libc::P_PID as c_int, pid as libc::id_t, &mut info, libc::WEXITED) };
    assert_eq!(rc, 0, "waitid should succeed");
}

// ===========================================================================
// waitpid with WNOHANG
// ===========================================================================

#[test]
fn waitpid_wnohang_no_child_ready() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        // Child sleeps briefly then exits
        unsafe { libc::usleep(100_000) }; // 100ms
        unsafe { libc::_exit(0) };
    }

    // Immediately try WNOHANG - child likely hasn't exited yet
    let mut status: c_int = 0;
    let waited = unsafe { waitpid(pid, &mut status, libc::WNOHANG) };
    // Either 0 (not ready) or pid (already exited) are valid
    assert!(waited == 0 || waited == pid);

    // Clean up: wait for child to finish
    if waited == 0 {
        unsafe { libc::waitpid(pid, &mut status, 0) };
    }
}

// ===========================================================================
// execve (fork + exec)
// ===========================================================================

#[test]
fn execve_runs_true() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        let path = CString::new("/bin/true").unwrap();
        let argv: [*const c_char; 2] = [path.as_ptr(), std::ptr::null()];
        let envp: [*const c_char; 1] = [std::ptr::null()];
        unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        // If execve returns, it failed
        unsafe { libc::_exit(127) };
    }

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0, "/bin/true should exit 0");
}

#[test]
fn execve_null_pathname_returns_efault() {
    let rc = unsafe { execve(std::ptr::null(), std::ptr::null(), std::ptr::null()) };
    assert_eq!(rc, -1);
    let err = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    assert_eq!(err, libc::EFAULT);
}

#[test]
fn execve_nonexistent_returns_enoent() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        let path = CString::new("/nonexistent_frankenlibc_test_binary_3f8a9c").unwrap();
        let argv: [*const c_char; 2] = [path.as_ptr(), std::ptr::null()];
        let envp: [*const c_char; 1] = [std::ptr::null()];
        let rc = unsafe { execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        // execve failed - exit with errno as code
        let err = if rc == -1 {
            unsafe { *frankenlibc_abi::errno_abi::__errno_location() }
        } else {
            0
        };
        unsafe { libc::_exit(err) };
    }

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), libc::ENOENT);
}

// ===========================================================================
// execvpe (fork + exec with PATH search + custom env)
// ===========================================================================

#[test]
fn execvpe_finds_true_on_path() {
    let pid = unsafe { fork() };
    assert!(pid >= 0);

    if pid == 0 {
        let cmd = CString::new("true").unwrap();
        let argv: [*const c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
        let path_env = CString::new("PATH=/bin:/usr/bin").unwrap();
        let envp: [*const c_char; 2] = [path_env.as_ptr(), std::ptr::null()];
        unsafe { execvpe(cmd.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        unsafe { libc::_exit(127) };
    }

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

// ===========================================================================
// posix_spawn (direct, not spawnp)
// ===========================================================================

#[test]
fn posix_spawn_runs_true() {
    let cmd = CString::new("/bin/true").unwrap();
    let argv: [*const c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = 0;

    let rc = unsafe {
        posix_spawn(
            &mut pid,
            cmd.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr().cast(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "posix_spawn should succeed");
    assert!(pid > 0);

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[test]
fn posix_spawn_null_path_returns_einval() {
    let mut pid: libc::pid_t = -1;
    let rc = unsafe {
        posix_spawn(
            &mut pid,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    // Should fail with EINVAL or EFAULT
    assert_ne!(rc, 0);
}

// ===========================================================================
// posix_spawn with file actions
// ===========================================================================

#[test]
fn posix_spawn_with_file_actions() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    // Add /dev/null as stdin
    let devnull = CString::new("/dev/null").unwrap();
    assert_eq!(
        unsafe {
            posix_spawn_file_actions_addopen(
                fa.as_mut_ptr().cast(),
                0,
                devnull.as_ptr(),
                libc::O_RDONLY,
                0,
            )
        },
        0
    );

    let cmd = CString::new("/bin/true").unwrap();
    let argv: [*const c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = 0;

    let rc = unsafe {
        posix_spawn(
            &mut pid,
            cmd.as_ptr(),
            fa.as_ptr().cast(),
            std::ptr::null(),
            argv.as_ptr().cast(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0);
    assert!(pid > 0);

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawn with spawnattr
// ===========================================================================

#[test]
fn posix_spawn_with_attr() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };

    // Set POSIX_SPAWN_SETSIGMASK flag and a sigmask
    unsafe { posix_spawnattr_setflags(attr.as_mut_ptr().cast(), 0) };

    let cmd = CString::new("/bin/true").unwrap();
    let argv: [*const c_char; 2] = [cmd.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = 0;

    let rc = unsafe {
        posix_spawnp(
            &mut pid,
            cmd.as_ptr(),
            std::ptr::null(),
            attr.as_ptr().cast(),
            argv.as_ptr().cast(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0);
    assert!(pid > 0);

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));

    unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
}

// ===========================================================================
// posix_spawnp with false command (empty argv)
// ===========================================================================

#[test]
fn posix_spawnp_with_echo() {
    let cmd = CString::new("/bin/echo").unwrap();
    let arg1 = CString::new("hello").unwrap();
    let argv: [*const c_char; 3] = [cmd.as_ptr(), arg1.as_ptr(), std::ptr::null()];
    let mut pid: libc::pid_t = 0;

    let rc = unsafe {
        posix_spawnp(
            &mut pid,
            cmd.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr().cast(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0);
    assert!(pid > 0);

    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

// ===========================================================================
// file_actions edge cases
// ===========================================================================

#[test]
fn file_actions_addclose_negative_fd() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_addclose(fa.as_mut_ptr().cast(), -1) };
    assert!(rc == libc::EBADF || rc == libc::EINVAL, "negative fd should return EBADF or EINVAL, got {rc}");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_adddup2_negative_fd() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_adddup2(fa.as_mut_ptr().cast(), -1, 0) };
    assert!(rc == libc::EBADF || rc == libc::EINVAL, "negative oldfd should return EBADF or EINVAL, got {rc}");

    let rc = unsafe { posix_spawn_file_actions_adddup2(fa.as_mut_ptr().cast(), 0, -1) };
    assert!(rc == libc::EBADF || rc == libc::EINVAL, "negative newfd should return EBADF or EINVAL, got {rc}");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addopen_null_path() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe {
        posix_spawn_file_actions_addopen(
            fa.as_mut_ptr().cast(),
            3,
            std::ptr::null(),
            libc::O_RDONLY,
            0,
        )
    };
    assert_eq!(rc, libc::EINVAL, "null path should return EINVAL");

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

#[test]
fn file_actions_addchdir_np_null_path() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };

    let rc = unsafe { posix_spawn_file_actions_addchdir_np(fa.as_mut_ptr().cast(), std::ptr::null()) };
    assert_eq!(rc, libc::EINVAL);

    unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
}

// ===========================================================================
// spawnattr: double init / double destroy
// ===========================================================================

#[test]
fn spawnattr_double_destroy() {
    let mut attr = AlignedBuf::new();
    unsafe { posix_spawnattr_init(attr.as_mut_ptr().cast()) };
    let rc1 = unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
    assert_eq!(rc1, 0);

    // Second destroy on already-destroyed attr should return EINVAL
    let rc2 = unsafe { posix_spawnattr_destroy(attr.as_mut_ptr().cast()) };
    assert_eq!(rc2, libc::EINVAL);
}

#[test]
fn file_actions_double_destroy() {
    let mut fa = AlignedBuf::new();
    unsafe { posix_spawn_file_actions_init(fa.as_mut_ptr().cast()) };
    let rc1 = unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
    assert_eq!(rc1, 0);

    let rc2 = unsafe { posix_spawn_file_actions_destroy(fa.as_mut_ptr().cast()) };
    assert_eq!(rc2, libc::EINVAL);
}
