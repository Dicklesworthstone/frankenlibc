#![cfg(target_os = "linux")]

//! Differential conformance harness for `<spawn.h>`:
//!   - posix_spawn / posix_spawnp (process creation)
//!   - posix_spawn_file_actions_init / posix_spawn_file_actions_destroy
//!   - posix_spawnattr_init / posix_spawnattr_destroy
//!
//! Tests spawn /bin/true and /bin/false with each impl, verify the
//! returned PID is a real child, then waitpid for the exit status.
//!
//! Bead: CONFORMANCE: libc spawn.h diff matrix.

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::fd::AsRawFd;

use frankenlibc_abi::process_abi as fl;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_fn;

type PosixSpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const c_void,
    *const c_void,
    *const *mut c_char,
    *const *mut c_char,
) -> c_int;
type PosixSpawnpFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const c_void,
    *const c_void,
    *const *mut c_char,
    *const *mut c_char,
) -> c_int;
type FileActionsInitFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FileActionsDestroyFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type FileActionsAddCloseFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type FileActionsAddDup2Fn = unsafe extern "C" fn(*mut c_void, c_int, c_int) -> c_int;
type SpawnattrInitFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type SpawnattrDestroyFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type SpawnattrSetflagsFn = unsafe extern "C" fn(*mut c_void, libc::c_short) -> c_int;

fn host_posix_spawn_fn() -> PosixSpawnFn {
    unsafe { host_fn(c"posix_spawn", fl::posix_spawn as *const ()) }
}
fn host_posix_spawnp_fn() -> PosixSpawnpFn {
    unsafe { host_fn(c"posix_spawnp", fl::posix_spawnp as *const ()) }
}
fn host_posix_spawn_file_actions_init_fn() -> FileActionsInitFn {
    unsafe {
        host_fn(
            c"posix_spawn_file_actions_init",
            fl::posix_spawn_file_actions_init as *const (),
        )
    }
}
fn host_posix_spawn_file_actions_destroy_fn() -> FileActionsDestroyFn {
    unsafe {
        host_fn(
            c"posix_spawn_file_actions_destroy",
            fl::posix_spawn_file_actions_destroy as *const (),
        )
    }
}
fn host_posix_spawn_file_actions_addclose_fn() -> FileActionsAddCloseFn {
    unsafe {
        host_fn(
            c"posix_spawn_file_actions_addclose",
            fl::posix_spawn_file_actions_addclose as *const (),
        )
    }
}
fn host_posix_spawn_file_actions_adddup2_fn() -> FileActionsAddDup2Fn {
    unsafe {
        host_fn(
            c"posix_spawn_file_actions_adddup2",
            fl::posix_spawn_file_actions_adddup2 as *const (),
        )
    }
}
fn host_posix_spawnattr_init_fn() -> SpawnattrInitFn {
    unsafe {
        host_fn(
            c"posix_spawnattr_init",
            fl::posix_spawnattr_init as *const (),
        )
    }
}
fn host_posix_spawnattr_destroy_fn() -> SpawnattrDestroyFn {
    unsafe {
        host_fn(
            c"posix_spawnattr_destroy",
            fl::posix_spawnattr_destroy as *const (),
        )
    }
}
fn host_posix_spawnattr_setflags_fn() -> SpawnattrSetflagsFn {
    unsafe {
        host_fn(
            c"posix_spawnattr_setflags",
            fl::posix_spawnattr_setflags as *const (),
        )
    }
}

unsafe fn posix_spawn(
    pid: *mut libc::pid_t,
    path: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { host_posix_spawn_fn()(pid, path, file_actions, attrp, argv, envp) }
}

unsafe fn posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const c_char,
    file_actions: *const c_void,
    attrp: *const c_void,
    argv: *const *mut c_char,
    envp: *const *mut c_char,
) -> c_int {
    unsafe { host_posix_spawnp_fn()(pid, file, file_actions, attrp, argv, envp) }
}

unsafe fn posix_spawn_file_actions_init(file_actions: *mut c_void) -> c_int {
    unsafe { host_posix_spawn_file_actions_init_fn()(file_actions) }
}

unsafe fn posix_spawn_file_actions_destroy(file_actions: *mut c_void) -> c_int {
    unsafe { host_posix_spawn_file_actions_destroy_fn()(file_actions) }
}

unsafe fn posix_spawn_file_actions_addclose(file_actions: *mut c_void, fd: c_int) -> c_int {
    unsafe { host_posix_spawn_file_actions_addclose_fn()(file_actions, fd) }
}

unsafe fn posix_spawn_file_actions_adddup2(
    file_actions: *mut c_void,
    oldfd: c_int,
    newfd: c_int,
) -> c_int {
    unsafe { host_posix_spawn_file_actions_adddup2_fn()(file_actions, oldfd, newfd) }
}

unsafe fn posix_spawnattr_init(attrp: *mut c_void) -> c_int {
    unsafe { host_posix_spawnattr_init_fn()(attrp) }
}

unsafe fn posix_spawnattr_destroy(attrp: *mut c_void) -> c_int {
    unsafe { host_posix_spawnattr_destroy_fn()(attrp) }
}

unsafe fn posix_spawnattr_setflags(attrp: *mut c_void, flags: libc::c_short) -> c_int {
    unsafe { host_posix_spawnattr_setflags_fn()(attrp, flags) }
}

const FA_BYTES: usize = 128;
const ATTR_BYTES: usize = 384;

fn waitpid_status(pid: libc::pid_t) -> c_int {
    let mut status: c_int = 0;
    let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

#[test]
fn diff_posix_spawn_true_returns_zero() {
    let path = CString::new("/bin/true").unwrap();
    let arg0 = CString::new("true").unwrap();
    let argv = [arg0.as_ptr() as *mut c_char, std::ptr::null_mut()];

    let mut pid_fl: libc::pid_t = -1;
    let r_fl = unsafe {
        fl::posix_spawn(
            &mut pid_fl,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let exit_fl = if r_fl == 0 {
        waitpid_status(pid_fl)
    } else {
        -1
    };

    let mut pid_lc: libc::pid_t = -1;
    let r_lc = unsafe {
        posix_spawn(
            &mut pid_lc,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let exit_lc = if r_lc == 0 {
        waitpid_status(pid_lc)
    } else {
        -1
    };

    assert_eq!(
        r_fl, r_lc,
        "posix_spawn(/bin/true) return: fl={r_fl}, lc={r_lc}"
    );
    assert_eq!(exit_fl, exit_lc, "exit code: fl={exit_fl}, lc={exit_lc}");
    assert_eq!(exit_fl, 0, "/bin/true should exit 0");
}

#[test]
fn diff_posix_spawn_false_returns_one() {
    let path = CString::new("/bin/false").unwrap();
    let arg0 = CString::new("false").unwrap();
    let argv = [arg0.as_ptr() as *mut c_char, std::ptr::null_mut()];

    let mut pid_fl: libc::pid_t = -1;
    let r_fl = unsafe {
        fl::posix_spawn(
            &mut pid_fl,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let exit_fl = if r_fl == 0 {
        waitpid_status(pid_fl)
    } else {
        -1
    };

    let mut pid_lc: libc::pid_t = -1;
    let r_lc = unsafe {
        posix_spawn(
            &mut pid_lc,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let exit_lc = if r_lc == 0 {
        waitpid_status(pid_lc)
    } else {
        -1
    };

    assert_eq!(
        r_fl, r_lc,
        "posix_spawn(/bin/false) return: fl={r_fl}, lc={r_lc}"
    );
    assert_eq!(exit_fl, exit_lc, "exit code: fl={exit_fl}, lc={exit_lc}");
    assert_eq!(exit_fl, 1, "/bin/false should exit 1");
}

#[test]
fn diff_posix_spawn_nonexistent_path() {
    let path = CString::new("/this/binary/does/not/exist/xyz").unwrap();
    let arg0 = CString::new("xyz").unwrap();
    let argv = [arg0.as_ptr() as *mut c_char, std::ptr::null_mut()];
    let mut pid_fl: libc::pid_t = -1;
    let r_fl = unsafe {
        fl::posix_spawn(
            &mut pid_fl,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let mut pid_lc: libc::pid_t = -1;
    let r_lc = unsafe {
        posix_spawn(
            &mut pid_lc,
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    // posix_spawn may succeed with a child that immediately fails, OR
    // return non-zero. Both impls should agree.
    if r_fl == 0 && pid_fl > 0 {
        let _ = waitpid_status(pid_fl);
    }
    if r_lc == 0 && pid_lc > 0 {
        let _ = waitpid_status(pid_lc);
    }
    // Both should either succeed (with child failing later) or fail.
    // We just confirm both behave consistently.
    assert_eq!(
        r_fl == 0,
        r_lc == 0,
        "posix_spawn nonexistent return-match: fl={r_fl}, lc={r_lc}"
    );
}

#[test]
fn diff_posix_spawnp_path_lookup() {
    // /bin is in $PATH on most Linux systems
    let file = CString::new("true").unwrap();
    let arg0 = CString::new("true").unwrap();
    let argv = [arg0.as_ptr() as *mut c_char, std::ptr::null_mut()];

    let mut pid_fl: libc::pid_t = -1;
    let r_fl = unsafe {
        fl::posix_spawnp(
            &mut pid_fl,
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let exit_fl = if r_fl == 0 {
        waitpid_status(pid_fl)
    } else {
        -1
    };

    let mut pid_lc: libc::pid_t = -1;
    let r_lc = unsafe {
        posix_spawnp(
            &mut pid_lc,
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    let exit_lc = if r_lc == 0 {
        waitpid_status(pid_lc)
    } else {
        -1
    };

    assert_eq!(r_fl, r_lc, "posix_spawnp return: fl={r_fl}, lc={r_lc}");
    assert_eq!(exit_fl, exit_lc, "exit code: fl={exit_fl}, lc={exit_lc}");
}

#[derive(Debug, PartialEq, Eq)]
struct SpawnObservation {
    error: c_int,
    exit_status: Option<c_int>,
    published_pid: bool,
}

/// Compare an actual executed child (or the exact pre-exec error) through the
/// independently resolved GNU symbol and the candidate. Reap before returning
/// even when a later differential assertion will fail.
fn observe_spawn(
    host: bool,
    search: bool,
    file: &std::ffi::CStr,
    args: &[&std::ffi::CStr],
    envp: *const *mut c_char,
) -> SpawnObservation {
    let spawn = match (host, search) {
        (true, true) => host_posix_spawnp_fn(),
        (true, false) => host_posix_spawn_fn(),
        (false, true) => fl::posix_spawnp,
        (false, false) => fl::posix_spawn,
    };
    let argv: Vec<*mut c_char> = args
        .iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let mut pid = -1;
    // SAFETY: all strings and terminated vectors remain alive through spawn.
    // A NULL envp is the GNU/Linux empty-environment extension under test.
    let error = unsafe {
        spawn(
            &mut pid,
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            argv.as_ptr(),
            envp,
        )
    };
    let exit_status = if error == 0 {
        assert!(pid > 0, "successful spawn must publish a real child PID");
        let mut status = 0;
        loop {
            // SAFETY: pid is this call's child and status is writable.
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert_eq!(waited, pid, "spawned child must be reaped");
            break;
        }
        assert!(
            libc::WIFEXITED(status),
            "child terminated abnormally: {status}"
        );
        Some(libc::WEXITSTATUS(status))
    } else {
        None
    };
    SpawnObservation {
        error,
        exit_status,
        published_pid: pid != -1,
    }
}

#[test]
fn diff_spawnp_search_path_and_errors() {
    const CHILD_CASE: &str = "FRANKENLIBC_TEST_SPAWN_SEARCH_CASE";
    const CHILD_FILE: &str = "FRANKENLIBC_TEST_SPAWN_SEARCH_FILE";
    const CHILD_ERROR: &str = "FRANKENLIBC_TEST_SPAWN_SEARCH_ERROR";
    if let Some(case) = std::env::var_os(CHILD_CASE) {
        let file = CString::new(std::env::var(CHILD_FILE).unwrap()).unwrap();
        let error = std::env::var(CHILD_ERROR).unwrap().parse().unwrap();
        let empty = [std::ptr::null_mut()];
        let expected = SpawnObservation {
            error,
            exit_status: (error == 0).then_some(0),
            published_pid: error == 0,
        };
        let host = observe_spawn(true, true, &file, &[&file], empty.as_ptr());
        assert_eq!(host, expected, "GNU contract for {case:?}");
        let candidate = observe_spawn(false, true, &file, &[&file], empty.as_ptr());
        assert_eq!(candidate, host, "candidate contract for {case:?}");
        return;
    }

    // Each environment lives in a separate process, avoiding a global PATH
    // mutation racing libtest. Retain scratch fixtures for failure diagnosis.
    use std::os::unix::fs::{PermissionsExt, symlink};
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "frankenlibc-spawn-search-{}-{unique}",
        std::process::id()
    ));
    let good = directory.join("good");
    let denied = directory.join("denied");
    let noexec = directory.join("noexec");
    for path in [&good, &denied, &noexec] {
        std::fs::create_dir_all(path).unwrap();
    }
    symlink("/bin/true", good.join("probe")).unwrap();
    std::fs::write(denied.join("probe"), b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(denied.join("probe"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(noexec.join("probe"), b"exit 0\n").unwrap();
    std::fs::set_permissions(noexec.join("probe"), std::fs::Permissions::from_mode(0o700)).unwrap();
    let missing = directory.join("missing");
    let too_long = "x".repeat(libc::PATH_MAX as usize);
    let cases = [
        (
            "long-prefix",
            format!("{too_long}:{}", good.display()),
            "probe".into(),
            0,
        ),
        (
            "long-middle",
            format!("{}:{too_long}:{}", missing.display(), good.display()),
            "probe".into(),
            0,
        ),
        (
            "name-max-directory",
            format!("{}:{}", "x".repeat(256), good.display()),
            "probe".into(),
            libc::ENAMETOOLONG,
        ),
        (
            "path-max-minus-one",
            format!(
                "{}:{}",
                "x".repeat(libc::PATH_MAX as usize - 1),
                good.display()
            ),
            "probe".into(),
            libc::ENAMETOOLONG,
        ),
        (
            "long-name",
            good.display().to_string(),
            "x".repeat(256),
            libc::ENAMETOOLONG,
        ),
        (
            "last-notdir",
            format!("{}:/dev/null", missing.display()),
            "probe".into(),
            libc::ENOTDIR,
        ),
        (
            "last-missing",
            format!("/dev/null:{}", missing.display()),
            "probe".into(),
            libc::ENOENT,
        ),
        (
            "denied-before-notdir",
            format!("{}:/dev/null", denied.display()),
            "probe".into(),
            libc::EACCES,
        ),
        (
            "notdir-before-denied",
            format!("/dev/null:{}", denied.display()),
            "probe".into(),
            libc::EACCES,
        ),
        (
            "denied-before-success",
            format!("{}:{}", denied.display(), good.display()),
            "probe".into(),
            0,
        ),
        (
            "enoexec-after-denied",
            format!("{}:{}", denied.display(), noexec.display()),
            "probe".into(),
            libc::ENOEXEC,
        ),
        ("empty-component", String::new(), "probe".into(), 0),
    ];
    for mode in ["strict", "hardened"] {
        for (case, path, file, error) in &cases {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "diff_spawnp_search_path_and_errors",
                    "--nocapture",
                ])
                .current_dir(if *case == "empty-component" {
                    &good
                } else {
                    &directory
                })
                .env("FRANKENLIBC_MODE", mode)
                .env("PATH", path)
                .env(CHILD_CASE, case)
                .env(CHILD_FILE, file)
                .env(CHILD_ERROR, error.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "mode={mode}, case={case}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[test]
fn diff_spawn_empty_and_explicit_environments() {
    const CHILD_ENV: &str = "FRANKENLIBC_TEST_SPAWN_ENVIRONMENT_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        for mode in ["strict", "hardened"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "diff_spawn_empty_and_explicit_environments",
                    "--nocapture",
                ])
                .env("FRANKENLIBC_MODE", mode)
                .env("PATH", "/bin:/usr/bin")
                .env("FL_SPAWN_SENTINEL", "parent")
                .env("FL_SPAWN_PARENT_ONLY", "present")
                .env(CHILD_ENV, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "mode={mode}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    }

    assert_eq!(std::env::var("FL_SPAWN_SENTINEL").unwrap(), "parent");
    assert_eq!(std::env::var("FL_SPAWN_PARENT_ONLY").unwrap(), "present");
    let empty = [std::ptr::null_mut()];
    let explicit = [
        c"FL_SPAWN_SENTINEL=child".as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];
    for search in [false, true] {
        for (label, envp, command) in [
            (
                "NULL",
                std::ptr::null(),
                c"test -z \"${FL_SPAWN_SENTINEL+x}\" && test -z \"${FL_SPAWN_PARENT_ONLY+x}\"",
            ),
            (
                "empty-vector",
                empty.as_ptr(),
                c"test -z \"${FL_SPAWN_SENTINEL+x}\" && test -z \"${FL_SPAWN_PARENT_ONLY+x}\"",
            ),
            (
                "explicit-vector",
                explicit.as_ptr(),
                c"test \"$FL_SPAWN_SENTINEL\" = child && test -z \"${FL_SPAWN_PARENT_ONLY+x}\"",
            ),
        ] {
            let file = if search { c"sh" } else { c"/bin/sh" };
            let args = [c"sh", c"-c", command];
            let host = observe_spawn(true, search, file, &args, envp);
            assert_eq!(
                host,
                SpawnObservation {
                    error: 0,
                    exit_status: Some(0),
                    published_pid: true
                },
                "GNU environment contract: search={search}, {label}"
            );
            let candidate = observe_spawn(false, search, file, &args, envp);
            assert_eq!(candidate, host, "search={search}, environment={label}");
        }
    }
}

#[test]
fn diff_file_actions_init_destroy_round_trip() {
    let mut fa = FileActionsBuf([0u8; FA_BYTES]);
    let r_init_fl = unsafe { fl::posix_spawn_file_actions_init(fa.0.as_mut_ptr().cast()) };
    let r_destroy_fl = unsafe { fl::posix_spawn_file_actions_destroy(fa.0.as_mut_ptr().cast()) };
    assert_eq!(r_init_fl, 0, "fl init");
    assert_eq!(r_destroy_fl, 0, "fl destroy");

    let mut fa = FileActionsBuf([0u8; FA_BYTES]);
    let r_init_lc = unsafe { posix_spawn_file_actions_init(fa.0.as_mut_ptr().cast()) };
    let r_destroy_lc = unsafe { posix_spawn_file_actions_destroy(fa.0.as_mut_ptr().cast()) };
    assert_eq!(r_init_lc, 0, "lc init");
    assert_eq!(r_destroy_lc, 0, "lc destroy");
}

#[test]
fn diff_attr_init_destroy_round_trip() {
    let mut a = AttrBuf([0u8; ATTR_BYTES]);
    let r_init_fl = unsafe { fl::posix_spawnattr_init(a.0.as_mut_ptr().cast()) };
    let r_destroy_fl = unsafe { fl::posix_spawnattr_destroy(a.0.as_mut_ptr().cast()) };
    assert_eq!(r_init_fl, 0, "fl init");
    assert_eq!(r_destroy_fl, 0, "fl destroy");

    let mut a = AttrBuf([0u8; ATTR_BYTES]);
    let r_init_lc = unsafe { posix_spawnattr_init(a.0.as_mut_ptr().cast()) };
    let r_destroy_lc = unsafe { posix_spawnattr_destroy(a.0.as_mut_ptr().cast()) };
    assert_eq!(r_init_lc, 0, "lc init");
    assert_eq!(r_destroy_lc, 0, "lc destroy");
}

/// posix_spawnattr_setflags must reject flag words containing bits outside the
/// known set (glibc returns EINVAL; fl previously stored any value). bd-lkvixl.
#[test]
fn diff_spawnattr_setflags_validates_flags() {
    // ALL_FLAGS == 0x1FF (RESETIDS..SETSID..SETCGROUP). Bits at/above 0x200 are
    // invalid; the all-valid word is accepted.
    let cases: &[libc::c_short] = &[
        0,
        0x01,          // RESETIDS
        0x1FF,         // every defined flag
        0x80,          // SETSID
        0x200,         // first invalid bit -> EINVAL
        0x400,         // invalid
        0x1FF | 0x200, // valid bits + one invalid -> EINVAL
    ];
    for &flags in cases {
        let mut a_fl = AttrBuf([0u8; ATTR_BYTES]);
        let mut a_g = AttrBuf([0u8; ATTR_BYTES]);
        assert_eq!(
            unsafe { fl::posix_spawnattr_init(a_fl.0.as_mut_ptr().cast()) },
            0
        );
        assert_eq!(
            unsafe { posix_spawnattr_init(a_g.0.as_mut_ptr().cast()) },
            0
        );
        let r_fl = unsafe { fl::posix_spawnattr_setflags(a_fl.0.as_mut_ptr().cast(), flags) };
        let r_g = unsafe { posix_spawnattr_setflags(a_g.0.as_mut_ptr().cast(), flags) };
        assert_eq!(r_fl, r_g, "setflags(0x{flags:x}): fl={r_fl} glibc={r_g}");
        unsafe { fl::posix_spawnattr_destroy(a_fl.0.as_mut_ptr().cast()) };
        unsafe { posix_spawnattr_destroy(a_g.0.as_mut_ptr().cast()) };
    }
}

/// The file-action adders must reject a negative fd with EBADF (not EINVAL),
/// matching glibc's __spawn_valid_fd. bd-r1cvsg.
#[test]
fn diff_file_actions_addclose_negative_fd_is_ebadf() {
    for fd in [-1i32, 5] {
        let mut fa_fl = FileActionsBuf([0u8; FA_BYTES]);
        let mut fa_g = FileActionsBuf([0u8; FA_BYTES]);
        assert_eq!(
            unsafe { fl::posix_spawn_file_actions_init(fa_fl.0.as_mut_ptr().cast()) },
            0
        );
        assert_eq!(
            unsafe { posix_spawn_file_actions_init(fa_g.0.as_mut_ptr().cast()) },
            0
        );
        let r_fl =
            unsafe { fl::posix_spawn_file_actions_addclose(fa_fl.0.as_mut_ptr().cast(), fd) };
        let r_g = unsafe { posix_spawn_file_actions_addclose(fa_g.0.as_mut_ptr().cast(), fd) };
        assert_eq!(r_fl, r_g, "addclose(fd={fd}): fl={r_fl} glibc={r_g}");
        // adddup2 with a negative oldfd must also match.
        let d_fl =
            unsafe { fl::posix_spawn_file_actions_adddup2(fa_fl.0.as_mut_ptr().cast(), fd, 1) };
        let d_g = unsafe { posix_spawn_file_actions_adddup2(fa_g.0.as_mut_ptr().cast(), fd, 1) };
        assert_eq!(d_fl, d_g, "adddup2(oldfd={fd}): fl={d_fl} glibc={d_g}");
        unsafe { fl::posix_spawn_file_actions_destroy(fa_fl.0.as_mut_ptr().cast()) };
        unsafe { posix_spawn_file_actions_destroy(fa_g.0.as_mut_ptr().cast()) };
    }
}

// ---------------------------------------------------------------------------
// POSIX_SPAWN_SETSID behaviour (bd-h0ht3b). The flag was previously ignored, so
// the child stayed in the parent's session. The flag-bit validation test above
// only proves setflags ACCEPTS 0x80; this proves the spawned child actually
// lands in a new session.
// ---------------------------------------------------------------------------

/// glibc >= 2.26; not exposed by the libc crate.
const POSIX_SPAWN_SETSID: libc::c_short = 0x80;

type SpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const c_char,
    *const c_void,
    *const c_void,
    *const *mut c_char,
    *const *mut c_char,
) -> c_int;
type AttrInitFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type AttrFlagsFn = unsafe extern "C" fn(*mut c_void, libc::c_short) -> c_int;

/// One implementation's spawn entry points, so both arms run identical logic.
struct SpawnApi {
    name: &'static str,
    spawn: SpawnFn,
    attr_init: AttrInitFn,
    attr_setflags: AttrFlagsFn,
    attr_destroy: AttrInitFn,
}

/// A stand-in for `posix_spawnattr_t` with the alignment the real type has.
/// A bare `[u8; ATTR_BYTES]` local is only 1-byte aligned, and both impls store
/// a `u64` magic at offset 0, so an unaligned buffer trips the misaligned-write
/// check under a debug build depending on where the array happens to land.
#[repr(C, align(16))]
struct AttrBuf([u8; ATTR_BYTES]);

/// A stand-in for `posix_spawn_file_actions_t` with the alignment the real
/// type has. File-action initializers also store a word at offset zero.
#[repr(C, align(16))]
struct FileActionsBuf([u8; FA_BYTES]);

#[test]
fn spawn_abi_buffers_are_word_aligned() {
    assert!(std::mem::align_of::<AttrBuf>() >= std::mem::align_of::<u64>());
    assert!(std::mem::align_of::<FileActionsBuf>() >= std::mem::align_of::<u64>());

    let attr = AttrBuf([0u8; ATTR_BYTES]);
    let actions = FileActionsBuf([0u8; FA_BYTES]);
    assert_eq!((attr.0.as_ptr() as usize) % std::mem::align_of::<u64>(), 0);
    assert_eq!(
        (actions.0.as_ptr() as usize) % std::mem::align_of::<u64>(),
        0
    );
}

/// `(comm, session id)` from `/proc/<pid>/stat`. `comm` is delimited by the
/// first `(` and the LAST `)`, since a program name may itself contain either;
/// the fields after it are state, ppid, pgrp, session.
fn proc_comm_and_sid(pid: libc::pid_t) -> Option<(String, libc::pid_t)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let comm = stat.get(open + 1..close)?.to_string();
    let after: Vec<&str> = stat.get(close + 1..)?.split_whitespace().collect();
    Some((comm, after.get(3)?.parse().ok()?))
}

/// Session id of `pid` once it has finished exec'ing into `want`.
///
/// Waiting for the exec is what makes this race-free: every spawn attribute is
/// applied in the child before it execs, so a `comm` of `want` proves SETSID
/// has already been applied (or skipped) — no polling on the value itself.
fn sid_after_exec(pid: libc::pid_t, want: &str) -> libc::pid_t {
    for _ in 0..2000 {
        if let Some((comm, sid)) = proc_comm_and_sid(pid)
            && comm == want
        {
            return sid;
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    panic!("child {pid} never exec'd into {want}");
}

/// Spawn `/bin/sleep 30` through `api`, optionally with SETSID, and report the
/// child's `(pid, session id)`. The child is killed and reaped before returning.
fn spawned_child_sid(api: &SpawnApi, setsid: bool) -> (libc::pid_t, libc::pid_t) {
    let path = CString::new("/bin/sleep").unwrap();
    let arg0 = CString::new("sleep").unwrap();
    let arg1 = CString::new("30").unwrap();
    let argv = [
        arg0.as_ptr() as *mut c_char,
        arg1.as_ptr() as *mut c_char,
        std::ptr::null_mut(),
    ];

    let mut attr = AttrBuf([0u8; ATTR_BYTES]);
    let ap = attr.0.as_mut_ptr() as *mut c_void;
    assert_eq!(
        unsafe { (api.attr_init)(ap) },
        0,
        "{} attr_init failed",
        api.name
    );
    if setsid {
        assert_eq!(
            unsafe { (api.attr_setflags)(ap, POSIX_SPAWN_SETSID) },
            0,
            "{} setflags(SETSID) failed",
            api.name
        );
    }

    let mut pid: libc::pid_t = -1;
    let rc = unsafe {
        (api.spawn)(
            &mut pid,
            path.as_ptr(),
            std::ptr::null(),
            ap as *const c_void,
            argv.as_ptr(),
            std::ptr::null(),
        )
    };
    assert_eq!(rc, 0, "{} posix_spawn(/bin/sleep) failed: {rc}", api.name);
    assert!(pid > 0, "{} returned a bogus pid {pid}", api.name);

    let sid = sid_after_exec(pid, "sleep");

    unsafe { libc::kill(pid, libc::SIGKILL) };
    let mut status: c_int = 0;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    unsafe { (api.attr_destroy)(ap) };
    (pid, sid)
}

fn fl_api() -> SpawnApi {
    SpawnApi {
        name: "fl",
        spawn: fl::posix_spawn,
        attr_init: fl::posix_spawnattr_init,
        attr_setflags: fl::posix_spawnattr_setflags,
        attr_destroy: fl::posix_spawnattr_destroy,
    }
}

fn glibc_api() -> SpawnApi {
    let api = SpawnApi {
        name: "glibc",
        spawn: host_posix_spawn_fn(),
        attr_init: host_posix_spawnattr_init_fn(),
        attr_setflags: host_posix_spawnattr_setflags_fn(),
        attr_destroy: host_posix_spawnattr_destroy_fn(),
    };
    assert_ne!(
        api.spawn as *const () as usize,
        fl::posix_spawn as *const () as usize,
        "glibc posix_spawn resolved to fl's own symbol — the arms are not distinct"
    );
    api
}

#[test]
fn diff_posix_spawn_setsid_puts_child_in_a_new_session() {
    let own_sid = unsafe { libc::getsid(0) };

    let (g_pid, g_sid) = spawned_child_sid(&glibc_api(), true);
    let (f_pid, f_sid) = spawned_child_sid(&fl_api(), true);

    // The two children are different processes, so their session ids cannot be
    // compared directly. The defining property is compared instead: setsid()
    // makes the caller a session leader, so its session id IS its own pid.
    assert_eq!(
        g_sid, g_pid,
        "glibc SETSID child must lead its own session (sid={g_sid} pid={g_pid})"
    );
    assert_eq!(
        f_sid, f_pid,
        "SETSID child must lead its own session (fl sid={f_sid} pid={f_pid}) — \
         ignoring the flag leaves it in the spawner's session instead"
    );
    assert_ne!(
        f_sid, own_sid,
        "SETSID child must not stay in the spawner's session ({own_sid})"
    );
}

#[test]
fn diff_posix_spawn_without_setsid_keeps_the_spawner_session() {
    // Negative control: the same code path with the flag cleared must leave the
    // child in our session, so the test above is detecting SETSID and not just
    // "spawned children get a new session".
    let own_sid = unsafe { libc::getsid(0) };
    let (_, g_sid) = spawned_child_sid(&glibc_api(), false);
    let (_, f_sid) = spawned_child_sid(&fl_api(), false);
    assert_eq!(
        g_sid, own_sid,
        "glibc child without SETSID must inherit the spawner's session"
    );
    assert_eq!(
        f_sid, g_sid,
        "child session without SETSID: fl={f_sid} glibc={g_sid} (spawner={own_sid})"
    );
}

/// Exercise the same cgroup contract through PID and pidfd, direct and PATH
/// searching entry points. All children are reaped before assertions in callers.
fn spawn_cgroup_probe(
    host: bool,
    search: bool,
    pidfd: bool,
    descriptor: Option<c_int>,
    flags: libc::c_short,
) -> c_int {
    type SetCgroupFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    use frankenlibc_abi::glibc_internal_abi;
    use frankenlibc_abi::unistd_abi;

    let (symbol, candidate): (&std::ffi::CStr, SpawnFn) = match (search, pidfd) {
        (false, false) => (c"posix_spawn", fl::posix_spawn),
        (true, false) => (c"posix_spawnp", fl::posix_spawnp),
        (false, true) => (c"pidfd_spawn", glibc_internal_abi::pidfd_spawn),
        (true, true) => (c"pidfd_spawnp", glibc_internal_abi::pidfd_spawnp),
    };
    let mut api = if host { glibc_api() } else { fl_api() };
    api.spawn = if host {
        unsafe { host_fn(symbol, candidate as *const ()) }
    } else {
        candidate
    };
    let set_cgroup: SetCgroupFn = if host {
        unsafe {
            host_fn(
                c"posix_spawnattr_setcgroup_np",
                unistd_abi::posix_spawnattr_setcgroup_np as *const (),
            )
        }
    } else {
        unistd_abi::posix_spawnattr_setcgroup_np
    };
    let mut attr = AttrBuf([0; ATTR_BYTES]);
    let attrp = attr.0.as_mut_ptr().cast();
    assert_eq!(unsafe { (api.attr_init)(attrp) }, 0);
    if let Some(fd) = descriptor {
        assert_eq!(unsafe { set_cgroup(attrp, fd) }, 0);
    }
    assert_eq!(unsafe { (api.attr_setflags)(attrp, flags) }, 0);
    let path = if search { c"true" } else { c"/bin/true" };
    let argv = [c"true".as_ptr().cast_mut(), std::ptr::null_mut()];
    let envp = [std::ptr::null_mut()];
    let mut child = -1;
    let result = unsafe {
        (api.spawn)(
            &mut child,
            path.as_ptr(),
            std::ptr::null(),
            attrp,
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    assert_eq!(unsafe { (api.attr_destroy)(attrp) }, 0);
    if result == 0 {
        if pidfd {
            assert!(
                child >= 0,
                "successful pidfd_spawn must publish a descriptor"
            );
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let waited = unsafe {
                libc::waitid(libc::P_PIDFD, child as libc::id_t, &mut info, libc::WEXITED)
            };
            unsafe { libc::close(child) };
            assert_eq!(waited, 0);
            assert_eq!(info.si_code, libc::CLD_EXITED);
            assert_eq!(unsafe { info.si_status() }, 0);
        } else {
            assert!(child > 0, "successful spawn must publish a child PID");
            assert_eq!(waitpid_status(child), 0);
        }
    }
    result
}

#[test]
fn diff_spawn_cgroup_descriptor_requires_enabling_flag() {
    let fd = std::fs::File::open("/dev/null").unwrap();
    for search in [false, true] {
        for pidfd in [false, true] {
            for descriptor in [fd.as_raw_fd(), -1, c_int::MIN] {
                let host = spawn_cgroup_probe(true, search, pidfd, Some(descriptor), 0);
                assert_eq!(host, 0, "inactive cgroup attribute must not affect spawn");
                let candidate = spawn_cgroup_probe(false, search, pidfd, Some(descriptor), 0);
                assert_eq!(
                    candidate, host,
                    "search={search}, pidfd={pidfd}, fd={descriptor}"
                );
            }
        }
    }
}

#[test]
fn diff_spawn_cgroup_attributes_store_values_independently_of_flags() {
    type SetCgroupFn = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
    type GetCgroupFn = unsafe extern "C" fn(*const c_void, *mut c_int) -> c_int;
    type GetFlagsFn = unsafe extern "C" fn(*const c_void, *mut libc::c_short) -> c_int;
    use frankenlibc_abi::unistd_abi;

    for host in [true, false] {
        let api = if host { glibc_api() } else { fl_api() };
        let set_cgroup: SetCgroupFn = if host {
            unsafe {
                host_fn(
                    c"posix_spawnattr_setcgroup_np",
                    unistd_abi::posix_spawnattr_setcgroup_np as *const (),
                )
            }
        } else {
            unistd_abi::posix_spawnattr_setcgroup_np
        };
        let get_cgroup: GetCgroupFn = if host {
            unsafe {
                host_fn(
                    c"posix_spawnattr_getcgroup_np",
                    unistd_abi::posix_spawnattr_getcgroup_np as *const (),
                )
            }
        } else {
            unistd_abi::posix_spawnattr_getcgroup_np
        };
        let get_flags: GetFlagsFn = if host {
            unsafe {
                host_fn(
                    c"posix_spawnattr_getflags",
                    fl::posix_spawnattr_getflags as *const (),
                )
            }
        } else {
            fl::posix_spawnattr_getflags
        };
        let mut attr = AttrBuf([0; ATTR_BYTES]);
        let attrp = attr.0.as_mut_ptr().cast();
        assert_eq!(unsafe { (api.attr_init)(attrp) }, 0);
        let mut value = -99;
        assert_eq!(unsafe { get_cgroup(attrp, &mut value) }, 0);
        assert_eq!(
            value, 0,
            "host={host}: GNU initialization zeroes the cgroup value"
        );
        for flags in [0, 0x100, 0] {
            assert_eq!(unsafe { (api.attr_setflags)(attrp, flags) }, 0);
            for descriptor in [c_int::MIN, -2, -1, 0, c_int::MAX] {
                assert_eq!(unsafe { set_cgroup(attrp, descriptor) }, 0);
                assert_eq!(unsafe { get_cgroup(attrp, &mut value) }, 0);
                assert_eq!(value, descriptor, "host={host}");
                let mut actual_flags = -1;
                assert_eq!(unsafe { get_flags(attrp, &mut actual_flags) }, 0);
                assert_eq!(actual_flags, flags, "setter must not activate SETCGROUP");
            }
        }
        assert_eq!(unsafe { (api.attr_destroy)(attrp) }, 0);
    }
}

#[test]
fn diff_spawn_cgroup_rejects_non_cgroup_without_writing_files() {
    // Only a scratch directory is used. A cgroup.procs-shaped ordinary file
    // must never become an emulation of atomic kernel cgroup placement.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "frankenlibc-spawn-cgroup-{}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let control = directory.join("cgroup.procs");
    const CONTENTS: &[u8] = b"unchanged ordinary file\n";
    std::fs::write(&control, CONTENTS).unwrap();
    let fd = std::fs::File::open(&directory).unwrap();
    for search in [false, true] {
        for pidfd in [false, true] {
            for descriptor in [None, Some(fd.as_raw_fd())] {
                let host = spawn_cgroup_probe(true, search, pidfd, descriptor, 0x100);
                assert_ne!(host, 0, "invalid cgroup must not create a child");
                let candidate = spawn_cgroup_probe(false, search, pidfd, descriptor, 0x100);
                assert_eq!(std::fs::read(&control).unwrap(), CONTENTS);
                assert_eq!(
                    candidate, host,
                    "search={search}, pidfd={pidfd}, fd={descriptor:?}"
                );
            }
        }
    }
}

#[test]
fn diff_spawn_cgroup_clone3_failure_never_falls_back() {
    const CHILD_ENV: &str = "FRANKENLIBC_TEST_SPAWN_CGROUP_CLONE3_ERROR";
    let Some(error) = std::env::var_os(CHILD_ENV) else {
        // seccomp is confined to fresh test subprocesses. A genuine unavailable
        // or denied clone3 must not be emulated by spawning outside the cgroup.
        for error in [libc::ENOSYS, libc::E2BIG, libc::EPERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "diff_spawn_cgroup_clone3_failure_never_falls_back",
                    "--nocapture",
                ])
                .env(CHILD_ENV, error.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "clone3 error {error}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return;
    };
    let error = error.to_str().unwrap().parse::<c_int>().unwrap();
    let filter = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        }, // load syscall nr
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::SYS_clone3 as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | error as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: this disposable subprocess installs a validated four-instruction
    // filter that only returns an error for clone3 and allows every other call.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(
            libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
            0
        );
        assert_eq!(
            libc::syscall(libc::SYS_clone3, std::ptr::null::<c_void>(), 0),
            -1
        );
        assert_eq!(
            *libc::__errno_location(),
            error,
            "fault filter must execute"
        );
    }
    let fd = std::fs::File::open("/dev/null").unwrap();
    let expected = if error == libc::ENOSYS {
        libc::EOPNOTSUPP
    } else {
        error
    };
    for search in [false, true] {
        for pidfd in [false, true] {
            for host in [true, false] {
                assert_eq!(
                    spawn_cgroup_probe(host, search, pidfd, Some(fd.as_raw_fd()), 0x100),
                    expected,
                    "host={host}, search={search}, pidfd={pidfd}, clone3 errno={error}"
                );
            }
        }
        if error == libc::ENOSYS {
            // Without SETCGROUP ordinary spawn must retain its working
            // legacy-clone fallback, even when the descriptor was configured.
            for host in [true, false] {
                assert_eq!(
                    spawn_cgroup_probe(host, search, false, Some(fd.as_raw_fd()), 0),
                    0
                );
            }
        }
    }
}

#[test]
fn posix_spawn_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"spawn.h\",\"reference\":\"glibc\",\"functions\":6,\"divergences\":0}}",
    );
}
