#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc __libc_sa_len oracle
//! Differential gate for `__libc_sa_len` (bd-vw56nz).
//!
//! glibc's internal socket-address size table maps an address family to the
//! size of its `sockaddr` variant, and returns 0 for families it does not know.
//! fl reimplements that table, so every entry has to agree with the host's —
//! a wrong size here would silently corrupt any caller that uses it to bound a
//! copy.
//!
//! The symbol is internal, so it is resolved with `dlsym` on an explicit
//! `libc.so.6` handle rather than declared at link time.

use frankenlibc_abi::glibc_internal_abi as fl;
use std::ffi::{c_int, c_void};

type SaLenFn = unsafe extern "C" fn(u16) -> c_int;

union SaLenSymbol {
    raw: *mut c_void,
    function: SaLenFn,
}

fn host_sa_len() -> SaLenFn {
    // SAFETY: libc.so.6 is the process host libc; flags request a local handle.
    let handle = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen libc.so.6");
    // SAFETY: handle came from dlopen; the name is a NUL-terminated constant.
    let raw = unsafe { libc::dlsym(handle, c"__libc_sa_len".as_ptr()) };
    assert!(
        !raw.is_null(),
        "dlsym __libc_sa_len — the internal helper should exist in host glibc"
    );
    // SAFETY: the resolved symbol has glibc's documented __libc_sa_len signature.
    unsafe { SaLenSymbol { raw }.function }
}

#[test]
fn libc_sa_len_matches_glibc_for_known_and_unknown_families() {
    let host = host_sa_len();

    // The three families fl claims to know. Each is checked against the host AND
    // against the actual Rust struct size, so a table where BOTH implementations
    // drifted from the real layout still fails.
    let known: [(c_int, usize, &str); 3] = [
        (
            libc::AF_INET,
            std::mem::size_of::<libc::sockaddr_in>(),
            "AF_INET",
        ),
        (
            libc::AF_INET6,
            std::mem::size_of::<libc::sockaddr_in6>(),
            "AF_INET6",
        ),
        (
            libc::AF_UNIX,
            std::mem::size_of::<libc::sockaddr_un>(),
            "AF_UNIX",
        ),
    ];

    for (af, rust_size, name) in known {
        // SAFETY: the resolved symbol takes a u16 address family.
        let host_len = unsafe { host(af as u16) };
        // SAFETY: as above, against fl's implementation.
        let fl_len = unsafe { fl::__libc_sa_len(af as u16) };
        assert_eq!(
            fl_len, host_len,
            "{name}: fl reports {fl_len}, glibc reports {host_len}"
        );
        assert_eq!(
            host_len as usize, rust_size,
            "{name}: glibc reports {host_len} but the sockaddr struct is {rust_size} bytes — \
             the oracle and the layout disagree, so this arm cannot validate fl"
        );
    }

    // EVERY family in the u16 range, not a hand-picked few. Sweeping is what
    // caught the original defect: fl knew three families and returned glibc's
    // "unknown" sentinel of 0 for AF_AX25, AF_IPX, AF_APPLETALK, AF_ROSE,
    // AF_PACKET, AF_ASH and AF_ECONET, all of which glibc sizes. A gate that
    // probed only the families fl already handled would have stayed green.
    let mut mismatches = Vec::new();
    let mut nonzero = 0usize;
    for af in 0..=u16::MAX {
        // SAFETY: the resolved symbol takes a u16 address family.
        let host_len = unsafe { host(af) };
        // SAFETY: as above, against fl's implementation.
        let fl_len = unsafe { fl::__libc_sa_len(af) };
        if host_len != 0 {
            nonzero += 1;
        }
        if fl_len != host_len {
            mismatches.push(format!("  af={af}: fl={fl_len} glibc={host_len}"));
        }
    }

    // Positive fact: the sweep must actually have found the table, otherwise a
    // host whose symbol returned 0 for everything would make this vacuously green.
    assert!(
        nonzero >= 10,
        "oracle: expected glibc to size at least 10 families, saw {nonzero}"
    );
    assert!(
        mismatches.is_empty(),
        "__libc_sa_len diverges from glibc on {} of 65536 families:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
