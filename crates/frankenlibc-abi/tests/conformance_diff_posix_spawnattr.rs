#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc posix_spawnattr oracle (no spawning)

//! Differential gate for the posix_spawnattr getter/setter round-trips
//! (bd-2uqsly). conformance_diff_posix_spawn.rs exercises spawn *behavior*, but
//! the attribute getters (getflags/getpgroup/getsigmask/getsigdefault/
//! getschedparam/getschedpolicy) had no round-trip gate. Each impl inits its own
//! attr object, sets each attribute, reads it back, and the recovered values are
//! compared vs glibc. No process is spawned. No mocks.

use std::ffi::{c_int, c_short, c_void};
use std::mem::MaybeUninit;

const FLAGS: c_short = 0x3F; // RESETIDS|SETPGROUP|SETSIGDEF|SETSIGMASK|SETSCHEDPARAM|SETSCHEDULER
const PGRP: i32 = 4321;
const SCHED_FIFO: c_int = 1;
const PRIO: c_int = 7;

mod g {
    use super::*;
    unsafe extern "C" {
        pub fn posix_spawnattr_init(a: *mut c_void) -> c_int;
        pub fn posix_spawnattr_destroy(a: *mut c_void) -> c_int;
        pub fn posix_spawnattr_setflags(a: *mut c_void, f: c_short) -> c_int;
        pub fn posix_spawnattr_getflags(a: *const c_void, f: *mut c_short) -> c_int;
        pub fn posix_spawnattr_setpgroup(a: *mut c_void, p: i32) -> c_int;
        pub fn posix_spawnattr_getpgroup(a: *const c_void, p: *mut i32) -> c_int;
        pub fn posix_spawnattr_setsigmask(a: *mut c_void, s: *const libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_getsigmask(a: *const c_void, s: *mut libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_setsigdefault(a: *mut c_void, s: *const libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_getsigdefault(a: *const c_void, s: *mut libc::sigset_t) -> c_int;
        pub fn posix_spawnattr_setschedpolicy(a: *mut c_void, p: c_int) -> c_int;
        pub fn posix_spawnattr_getschedpolicy(a: *const c_void, p: *mut c_int) -> c_int;
        pub fn posix_spawnattr_setschedparam(a: *mut c_void, p: *const libc::sched_param) -> c_int;
        pub fn posix_spawnattr_getschedparam(a: *const c_void, p: *mut libc::sched_param) -> c_int;
    }
}
use frankenlibc_abi::process_abi as fl;

fn mkset(sig: c_int) -> libc::sigset_t {
    unsafe {
        let mut s = MaybeUninit::<libc::sigset_t>::zeroed();
        libc::sigemptyset(s.as_mut_ptr());
        libc::sigaddset(s.as_mut_ptr(), sig);
        s.assume_init()
    }
}

/// (flags, pgroup, mask_has_usr1, def_has_usr2, policy, prio); rcs must all be 0.
type R = (c_short, i32, i32, i32, c_int, c_int, [c_int; 7]);

macro_rules! round_trip {
    ($m:ident) => {{
        unsafe {
            let mut attr = MaybeUninit::<libc::posix_spawnattr_t>::zeroed();
            let a = attr.as_mut_ptr() as *mut c_void;
            let ac = attr.as_ptr() as *const c_void;
            let mut rc = [0i32; 7];
            rc[0] = $m::posix_spawnattr_init(a);
            rc[1] = $m::posix_spawnattr_setflags(a, FLAGS);
            let mut flags: c_short = 0;
            $m::posix_spawnattr_getflags(ac, &mut flags);
            rc[2] = $m::posix_spawnattr_setpgroup(a, PGRP);
            let mut pgrp: i32 = -1;
            $m::posix_spawnattr_getpgroup(ac, &mut pgrp);
            let smask = mkset(libc::SIGUSR1);
            rc[3] = $m::posix_spawnattr_setsigmask(a, &smask);
            let mut omask = MaybeUninit::<libc::sigset_t>::zeroed();
            $m::posix_spawnattr_getsigmask(ac, omask.as_mut_ptr());
            let mhas = libc::sigismember(omask.as_ptr(), libc::SIGUSR1);
            let sdef = mkset(libc::SIGUSR2);
            rc[4] = $m::posix_spawnattr_setsigdefault(a, &sdef);
            let mut odef = MaybeUninit::<libc::sigset_t>::zeroed();
            $m::posix_spawnattr_getsigdefault(ac, odef.as_mut_ptr());
            let dhas = libc::sigismember(odef.as_ptr(), libc::SIGUSR2);
            rc[5] = $m::posix_spawnattr_setschedpolicy(a, SCHED_FIFO);
            let mut pol: c_int = -1;
            $m::posix_spawnattr_getschedpolicy(ac, &mut pol);
            let sp = libc::sched_param {
                sched_priority: PRIO,
            };
            rc[6] = $m::posix_spawnattr_setschedparam(a, &sp);
            let mut osp = MaybeUninit::<libc::sched_param>::zeroed();
            $m::posix_spawnattr_getschedparam(ac, osp.as_mut_ptr());
            let prio = osp.assume_init().sched_priority;
            $m::posix_spawnattr_destroy(a);
            (flags, pgrp, mhas, dhas, pol, prio, rc)
        }
    }};
}

/// Flag words fed to `posix_spawnattr_setflags`: every individually valid bit,
/// their union, then words carrying a bit outside the set.
///
/// glibc's accepted set is `ALL_FLAGS = 0x1FF` — RESETIDS|SETPGROUP|SETSIGDEF|
/// SETSIGMASK|SETSCHEDPARAM|SETSCHEDULER|USEVFORK|SETSID|SETCGROUP. Probed
/// against the live host (glibc 2.42) before being asserted here: 0x000..0x1FF
/// all return 0, and 0x200 / 0x400 / 0x1000 / 0x4000 / 0xFFFF / 0x8000 / 0x2FF
/// all return EINVAL(22) — including 0x2FF, which is a VALID word with one
/// extra bit, so the rule is `flags & !ALL_FLAGS`, not a range check.
const FLAG_WORDS: &[c_short] = &[
    0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x100, 0x1FF, // accepted
    0x200, 0x400, 0x1000, 0x4000, -1, -32768, 0x2FF, // rejected
];

/// Sentinel pre-loaded into the attr before each probe, so a rejected call is
/// distinguishable from one that stored the bad value.
const SENTINEL: c_short = 0x1FF;

/// `(setflags rc, flags read back afterwards)` for one candidate word.
fn setflags_probe(
    init: unsafe extern "C" fn(*mut c_void) -> c_int,
    destroy: unsafe extern "C" fn(*mut c_void) -> c_int,
    set: unsafe extern "C" fn(*mut c_void, c_short) -> c_int,
    get: unsafe extern "C" fn(*const c_void, *mut c_short) -> c_int,
    word: c_short,
) -> (c_int, c_short) {
    unsafe {
        let mut attr = MaybeUninit::<libc::posix_spawnattr_t>::zeroed();
        let a = attr.as_mut_ptr() as *mut c_void;
        let ac = attr.as_ptr() as *const c_void;
        assert_eq!(init(a), 0, "posix_spawnattr_init should succeed");
        assert_eq!(set(a, SENTINEL), 0, "sentinel is a valid flag word");
        let rc = set(a, word);
        let mut after: c_short = 0;
        get(ac, &mut after);
        destroy(a);
        (rc, after)
    }
}

/// bd-lkvixl: `posix_spawnattr_setflags` must reject any bit outside
/// `ALL_FLAGS` with EINVAL, and must leave the attribute UNCHANGED when it
/// does. fl used to store whatever it was given.
///
/// The "unchanged" half matters as much as the errno: a caller that ignores
/// the return value would otherwise carry a bogus flag word into
/// `posix_spawn`, which is exactly where an unknown bit does damage. Asserting
/// only the errno would let an implementation return EINVAL *after* writing.
#[test]
fn posix_spawnattr_setflags_rejects_unknown_bits_like_glibc() {
    let mut checked_accept = 0usize;
    let mut checked_reject = 0usize;
    for &word in FLAG_WORDS {
        let g = setflags_probe(
            g::posix_spawnattr_init,
            g::posix_spawnattr_destroy,
            g::posix_spawnattr_setflags,
            g::posix_spawnattr_getflags,
            word,
        );
        let f = setflags_probe(
            fl::posix_spawnattr_init,
            fl::posix_spawnattr_destroy,
            fl::posix_spawnattr_setflags,
            fl::posix_spawnattr_getflags,
            word,
        );
        assert_eq!(
            f, g,
            "setflags(0x{:04X}): fl returned {f:?}, glibc {g:?} (rc, flags-after)",
            word as u16
        );

        // Independent reference check, so the arm cannot pass by fl and glibc
        // regressing together.
        const ALL_FLAGS: c_short = 0x1FF;
        if word & !ALL_FLAGS == 0 {
            assert_eq!(
                g,
                (0, word),
                "glibc should accept 0x{:04X} and store it",
                word as u16
            );
            checked_accept += 1;
        } else {
            assert_eq!(
                g,
                (libc::EINVAL, SENTINEL),
                "glibc should reject 0x{:04X} with EINVAL and leave the attr alone",
                word as u16
            );
            checked_reject += 1;
        }
    }
    assert_eq!(
        (checked_accept, checked_reject),
        (11, 7),
        "flag-word table drifted; both halves must stay covered"
    );
}

#[test]
fn posix_spawnattr_round_trips_match_glibc() {
    let g: R = round_trip!(g);
    let f: R = round_trip!(fl);
    assert_eq!(f, g, "posix_spawnattr round-trips: fl={f:?} glibc={g:?}");
    assert_eq!(
        (g.0, g.1, g.2, g.3, g.4, g.5),
        (FLAGS, PGRP, 1, 1, SCHED_FIFO, PRIO),
        "glibc reference values"
    );
    assert_eq!(g.6, [0; 7], "glibc: all setters/init/destroy return 0");
}
