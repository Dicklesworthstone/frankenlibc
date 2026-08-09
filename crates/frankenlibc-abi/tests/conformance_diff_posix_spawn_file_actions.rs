#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc posix_spawn_file_actions oracle (no spawning)

//! Differential gate for file-descriptor validation in the
//! `posix_spawn_file_actions_add*` adders (bd-r1cvsg). No process is spawned:
//! every arm only builds a file-actions object and compares return codes
//! against host glibc. No mocks.
//!
//! ## The rule, measured rather than assumed
//!
//! The bead was filed as "fl returns EINVAL for fd<0, glibc returns EBADF".
//! Probing live glibc 2.42 showed the rule is wider than that in one direction
//! and narrower in another, and the shipped fix got both wrong:
//!
//! * There is an UPPER bound as well as a lower one. Each adder rejects
//!   `fd < 0 || fd >= sysconf(_SC_OPEN_MAX)`. fl checked only `fd < 0`, so it
//!   accepted `INT_MAX` where glibc returns EBADF. The bound is the RLIMIT, so
//!   it is host-dependent — on the machine this was written on `_SC_OPEN_MAX`
//!   is 1048576 and `addclose(1000000)` succeeds while `addclose(1048576)`
//!   fails. That is exactly why the probe values below are computed at
//!   runtime; a hardcoded constant would pass here and fail on a host with a
//!   different limit.
//!
//! * `addfchdir_np` is the exception: glibc never applies the test there, and
//!   returns 0 for -1, INT_MIN and INT_MAX alike. The bd-r1cvsg fix applied
//!   the rule uniformly and so introduced a divergence on that one function.
//!
//! Both halves are asserted below, and both fl and glibc are driven through
//! the same table so neither can drift alone.

use std::ffi::{CString, c_char, c_int, c_void};

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn posix_spawn_file_actions_init(fa: *mut c_void) -> c_int;
        pub fn posix_spawn_file_actions_destroy(fa: *mut c_void) -> c_int;
        pub fn posix_spawn_file_actions_addclose(fa: *mut c_void, fd: c_int) -> c_int;
        pub fn posix_spawn_file_actions_adddup2(fa: *mut c_void, o: c_int, n: c_int) -> c_int;
        pub fn posix_spawn_file_actions_addopen(
            fa: *mut c_void,
            fd: c_int,
            path: *const c_char,
            oflag: c_int,
            mode: libc::mode_t,
        ) -> c_int;
        pub fn posix_spawn_file_actions_addfchdir_np(fa: *mut c_void, fd: c_int) -> c_int;
        pub fn posix_spawn_file_actions_addclosefrom_np(fa: *mut c_void, from: c_int) -> c_int;
        pub fn posix_spawn_file_actions_addtcsetpgrp_np(fa: *mut c_void, fd: c_int) -> c_int;
        pub fn sysconf(name: c_int) -> i64;
    }
}

/// fl splits this family across two modules: the core adders live in
/// `process_abi`, while the two `_np` extras are exported from `unistd_abi` as
/// thin wrappers over `*_impl`. Re-exported here so both sides of the diff can
/// be driven through one identical macro.
mod fl {
    pub use frankenlibc_abi::process_abi::{
        posix_spawn_file_actions_addclose, posix_spawn_file_actions_adddup2,
        posix_spawn_file_actions_addfchdir_np, posix_spawn_file_actions_addopen,
        posix_spawn_file_actions_destroy, posix_spawn_file_actions_init,
    };
    pub use frankenlibc_abi::unistd_abi::{
        posix_spawn_file_actions_addclosefrom_np, posix_spawn_file_actions_addtcsetpgrp_np,
    };
}

/// `_SC_OPEN_MAX` from the host, the bound glibc's adders compare against.
fn open_max() -> i64 {
    let m = unsafe { g::sysconf(libc::_SC_OPEN_MAX) };
    assert!(
        m > 1,
        "host _SC_OPEN_MAX is {m}; this gate needs a determinate limit to probe the boundary"
    );
    m
}

/// Which adder to drive. Each takes exactly one fd under test.
#[derive(Clone, Copy, Debug)]
enum Adder {
    Close,
    Dup2Old,
    Dup2New,
    Open,
    FchdirNp,
    ClosefromNp,
    TcsetpgrpNp,
}

const VALIDATING: &[Adder] = &[
    Adder::Close,
    Adder::Dup2Old,
    Adder::Dup2New,
    Adder::Open,
    Adder::ClosefromNp,
    Adder::TcsetpgrpNp,
];

/// A file-actions object big enough for either implementation, correctly
/// aligned. `posix_spawn_file_actions_t` is 80 bytes on glibc x86-64; the
/// generous size plus `u64` alignment keeps this clear of the misaligned
/// scratch-buffer problem tracked as bd-f7pjdt.
#[repr(align(8))]
struct FaBuf([u8; 1024]);

impl FaBuf {
    fn new() -> Self {
        Self([0u8; 1024])
    }
    fn ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}

macro_rules! drive {
    ($m:ident, $adder:expr, $fd:expr) => {{
        let mut buf = FaBuf::new();
        let p = buf.ptr();
        let path = CString::new("/tmp/fl-spawn-fa-probe").unwrap();
        unsafe {
            assert_eq!(
                $m::posix_spawn_file_actions_init(p),
                0,
                "file_actions_init should succeed"
            );
            let rc = match $adder {
                Adder::Close => $m::posix_spawn_file_actions_addclose(p, $fd),
                Adder::Dup2Old => $m::posix_spawn_file_actions_adddup2(p, $fd, 3),
                Adder::Dup2New => $m::posix_spawn_file_actions_adddup2(p, 3, $fd),
                Adder::Open => {
                    $m::posix_spawn_file_actions_addopen(p, $fd, path.as_ptr(), 0, 0)
                }
                Adder::FchdirNp => $m::posix_spawn_file_actions_addfchdir_np(p, $fd),
                Adder::ClosefromNp => $m::posix_spawn_file_actions_addclosefrom_np(p, $fd),
                Adder::TcsetpgrpNp => $m::posix_spawn_file_actions_addtcsetpgrp_np(p, $fd),
            };
            $m::posix_spawn_file_actions_destroy(p);
            rc
        }
    }};
}

/// fl must match glibc's return code for every (adder, fd) pair.
#[test]
fn file_action_adders_match_glibc_fd_validation() {
    let max = open_max();
    // Values chosen around the two boundaries glibc actually uses. `max` and
    // `max - 1` straddle the upper bound; INT_MAX is above any RLIMIT and
    // catches an implementation that only checks the lower one.
    let fds: Vec<c_int> = vec![
        0,
        3,
        (max - 1) as c_int,
        max as c_int,
        c_int::MAX,
        -1,
        -2,
        c_int::MIN,
    ];

    let mut compared = 0usize;
    for &adder in VALIDATING.iter().chain(&[Adder::FchdirNp]) {
        for &fd in &fds {
            let gr = drive!(g, adder, fd);
            let fr = drive!(fl, adder, fd);
            assert_eq!(
                fr, gr,
                "{adder:?} with fd={fd}: fl returned {fr}, glibc {gr} \
                 (_SC_OPEN_MAX={max})"
            );
            compared += 1;
        }
    }
    assert_eq!(compared, 56, "adder x fd table drifted");
}

/// Reference assertion for the validating adders, so the differential above
/// cannot pass by fl and glibc regressing together.
#[test]
fn validating_adders_reject_out_of_range_fds() {
    let max = open_max();
    for &adder in VALIDATING {
        assert_eq!(drive!(g, adder, 3), 0, "{adder:?}: fd 3 is valid");
        assert_eq!(
            drive!(g, adder, (max - 1) as c_int),
            0,
            "{adder:?}: the last in-range fd is valid"
        );
        for &bad in &[-1, c_int::MIN, c_int::MAX] {
            assert_eq!(
                drive!(g, adder, bad),
                libc::EBADF,
                "{adder:?}: glibc should reject fd={bad} with EBADF"
            );
        }
        assert_eq!(
            drive!(g, adder, max as c_int),
            libc::EBADF,
            "{adder:?}: glibc should reject fd == _SC_OPEN_MAX with EBADF"
        );
    }
}

/// `addfchdir_np` is the documented exception: glibc applies no validity test,
/// so every fd is accepted. Pinning this stops a future "make it consistent"
/// change from re-introducing the divergence the bd-r1cvsg fix created.
#[test]
fn addfchdir_np_does_not_validate_the_fd() {
    for &fd in &[-1, c_int::MIN, c_int::MAX, 0, 3] {
        assert_eq!(
            drive!(g, Adder::FchdirNp, fd),
            0,
            "glibc addfchdir_np should accept fd={fd} without validating it"
        );
        assert_eq!(
            drive!(fl, Adder::FchdirNp, fd),
            0,
            "fl addfchdir_np should accept fd={fd}, matching glibc"
        );
    }
}
