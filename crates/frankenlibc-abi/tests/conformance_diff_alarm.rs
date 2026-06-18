#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc alarm oracle; manipulates this process's ITIMER_REAL

//! Differential gate for alarm() (bd-6sywp3). alarm(seconds) arms ITIMER_REAL
//! and returns the number of seconds REMAINING from a previously scheduled
//! alarm (rounded UP — ceil of the sub-second remainder), or 0 if none; a 0
//! argument cancels. fl and glibc share the one process timer, so each impl
//! runs its own self-contained sequence (always ending in alarm(0) to cancel —
//! no SIGALRM ever fires). The remaining-seconds returns are compared. The
//! operations are microseconds apart, so the ceil values are stable (100, 30).
//! No mocks.

unsafe extern "C" {
    fn alarm(seconds: u32) -> u32;
}

/// Clear any prior alarm, then [alarm(100), alarm(30), alarm(0)] returns.
fn glibc_seq() -> [u32; 3] {
    unsafe {
        alarm(0);
        let a = alarm(100); // no prior -> 0
        let b = alarm(30); // remaining of the 100s timer -> 100 (ceil)
        let c = alarm(0); // remaining of the 30s timer -> 30 (ceil), cancels
        [a, b, c]
    }
}
fn fl_seq() -> [u32; 3] {
    unsafe {
        frankenlibc_abi::unistd_abi::alarm(0);
        let a = frankenlibc_abi::unistd_abi::alarm(100);
        let b = frankenlibc_abi::unistd_abi::alarm(30);
        let c = frankenlibc_abi::unistd_abi::alarm(0);
        [a, b, c]
    }
}

#[test]
fn alarm_remaining_sequence_matches_glibc() {
    let g = glibc_seq();
    let f = fl_seq();
    // Safety net: ensure no alarm is left pending regardless of outcome.
    unsafe { alarm(0); frankenlibc_abi::unistd_abi::alarm(0); }
    assert_eq!(f, g, "alarm sequence [alarm(100),alarm(30),alarm(0)]: fl={f:?} glibc={g:?}");
    assert_eq!(g, [0, 100, 30], "glibc reference: no-prior=0, then ceil(remaining)=100,30");
}
