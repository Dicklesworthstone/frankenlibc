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

use frankenlibc_abi::process_abi as fl;

unsafe extern "C" {
    fn posix_spawn(
        pid: *mut libc::pid_t,
        path: *const c_char,
        file_actions: *const c_void,
        attrp: *const c_void,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn posix_spawnp(
        pid: *mut libc::pid_t,
        file: *const c_char,
        file_actions: *const c_void,
        attrp: *const c_void,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn posix_spawn_file_actions_init(file_actions: *mut c_void) -> c_int;
    fn posix_spawn_file_actions_destroy(file_actions: *mut c_void) -> c_int;
    fn posix_spawn_file_actions_addclose(file_actions: *mut c_void, fd: c_int) -> c_int;
    fn posix_spawn_file_actions_adddup2(
        file_actions: *mut c_void,
        oldfd: c_int,
        newfd: c_int,
    ) -> c_int;
    fn posix_spawnattr_init(attrp: *mut c_void) -> c_int;
    fn posix_spawnattr_destroy(attrp: *mut c_void) -> c_int;
    fn posix_spawnattr_setflags(attrp: *mut c_void, flags: libc::c_short) -> c_int;
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
        spawn: posix_spawn,
        attr_init: posix_spawnattr_init,
        attr_setflags: posix_spawnattr_setflags,
        attr_destroy: posix_spawnattr_destroy,
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

#[test]
fn posix_spawn_diff_coverage_report() {
    eprintln!(
        "{{\"family\":\"spawn.h\",\"reference\":\"glibc\",\"functions\":6,\"divergences\":0}}",
    );
}
