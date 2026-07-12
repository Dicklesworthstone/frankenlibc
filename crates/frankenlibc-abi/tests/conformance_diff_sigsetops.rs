#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc sigset-op oracle

//! Differential gate for the GNU sigset operations sigandset / sigorset /
//! sigisemptyset (bd-ajnisi). These are pure functions over sigset_t (no
//! syscall, no process-state mutation) and had no differential gate. Builds
//! input sets with the host's sigemptyset/sigaddset, runs each op in fl and in
//! glibc, and compares the resulting sigset_t bytes (and the isempty return)
//! for exact equality. No mocks.

use std::ffi::c_int;

unsafe extern "C" {
    fn sigemptyset(set: *mut libc::sigset_t) -> c_int;
    fn sigaddset(set: *mut libc::sigset_t, sig: c_int) -> c_int;
    fn sigandset(
        dest: *mut libc::sigset_t,
        l: *const libc::sigset_t,
        r: *const libc::sigset_t,
    ) -> c_int;
    fn sigorset(
        dest: *mut libc::sigset_t,
        l: *const libc::sigset_t,
        r: *const libc::sigset_t,
    ) -> c_int;
    fn sigisemptyset(set: *const libc::sigset_t) -> c_int;
}

fn make_set(sigs: &[c_int]) -> libc::sigset_t {
    let mut s: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe { sigemptyset(&mut s) };
    for &sig in sigs {
        unsafe { sigaddset(&mut s, sig) };
    }
    s
}

fn bytes(s: &libc::sigset_t) -> Vec<u8> {
    let p = s as *const libc::sigset_t as *const u8;
    unsafe { std::slice::from_raw_parts(p, std::mem::size_of::<libc::sigset_t>()) }.to_vec()
}

#[test]
fn sigandset_sigorset_match_glibc() {
    let pairs: &[(&[c_int], &[c_int])] = &[
        (&[2, 11], &[11, 15]),      // overlap on SIGSEGV
        (&[1, 2, 3], &[4, 5, 6]),   // disjoint
        (&[34, 64], &[34, 50, 64]), // real-time signals
        (&[], &[2, 9]),             // empty vs non-empty
        (&[9], &[9]),               // identical
    ];
    for &(a, b) in pairs {
        let sa = make_set(a);
        let sb = make_set(b);

        // AND
        let mut fd: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut gd: libc::sigset_t = unsafe { std::mem::zeroed() };
        let fr = unsafe { frankenlibc_abi::signal_abi::sigandset(&mut fd, &sa, &sb) };
        let gr = unsafe { sigandset(&mut gd, &sa, &sb) };
        assert_eq!(fr, gr, "sigandset rc {a:?}&{b:?}");
        assert_eq!(bytes(&fd), bytes(&gd), "sigandset bytes {a:?}&{b:?}");

        // OR
        let mut fo: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut go: libc::sigset_t = unsafe { std::mem::zeroed() };
        let fr = unsafe { frankenlibc_abi::signal_abi::sigorset(&mut fo, &sa, &sb) };
        let gr = unsafe { sigorset(&mut go, &sa, &sb) };
        assert_eq!(fr, gr, "sigorset rc {a:?}|{b:?}");
        assert_eq!(bytes(&fo), bytes(&go), "sigorset bytes {a:?}|{b:?}");
    }
}

#[test]
fn sigisemptyset_matches_glibc() {
    for sigs in [&[][..], &[2][..], &[64][..], &[1, 2, 3][..]] {
        let s = make_set(sigs);
        let f = unsafe { frankenlibc_abi::signal_abi::sigisemptyset(&s) };
        let g = unsafe { sigisemptyset(&s) };
        assert_eq!(f, g, "sigisemptyset({sigs:?}): fl={f} glibc={g}");
    }
}
