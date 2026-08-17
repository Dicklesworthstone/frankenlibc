#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // host-differential calls through dlsym

//! `setfsuid`/`setfsgid` return the PREVIOUS id and never report failure
//! (bd-qy6if1).
//!
//! ## The contract, probed rather than assumed
//!
//! These two are the awkward corner of the credentials family: they cannot fail
//! observably. Probed on host glibc 2.42 as an unprivileged user (uid 1000):
//!
//! ```text
//! setfsuid(-1)         -> 1000, errno untouched   (the query form)
//! setfsuid(-1) again   -> 1000                    (stable; the query changes nothing)
//! setfsuid(0x7fffffff) -> 1000, errno untouched   (refused SILENTLY)
//! setfsuid(-1) after   -> 1000                    (the refusal changed nothing)
//! ```
//!
//! The third line is the trap. An unprivileged caller asking for a different id
//! is refused, but the call still returns the PREVIOUS id and sets NO errno — so
//! an implementation that returns -1, or sets `EPERM`, is wrong in a way no
//! return-value check would notice. The only way to detect the refusal is to
//! call the query form again and see the id unchanged, which is what a real
//! caller does and what this gate does.
//!
//! ## Why interleaving the two implementations is safe here
//!
//! Every call below either queries or requests a change that an unprivileged
//! process is refused, so neither arm can alter the state the other observes.
//! That is the reason this can be a same-process differential at all; a
//! privileged run would need fork isolation.

use std::ffi::c_int;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr_optional;

type SetFs = unsafe extern "C" fn(c_int) -> c_int;

fn errno_now() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default()
}

fn clear_errno() {
    // SAFETY: writing this thread's own errno slot through libc's accessor.
    unsafe { *libc::__errno_location() = 0 };
}

/// `(return value, errno)` — the whole observable result of one call.
fn call(f: SetFs, arg: c_int) -> (c_int, c_int) {
    clear_errno();
    // SAFETY: the resolved symbol takes one int and touches no memory.
    let rc = unsafe { f(arg) };
    (rc, errno_now())
}

#[test]
fn setfsuid_and_setfsgid_match_the_host() {
    let arms: &[(&std::ffi::CStr, *const ())] = &[
        (
            c"setfsuid",
            frankenlibc_abi::glibc_internal_abi::setfsuid as *const (),
        ),
        (
            c"setfsgid",
            frankenlibc_abi::glibc_internal_abi::setfsgid as *const (),
        ),
    ];

    let mut compared = 0usize;
    for (name, fl) in arms {
        let label = name.to_str().expect("ASCII symbol name");
        // `host_addr_optional` rejects a symbol that resolved back to fl, so a
        // collapsed oracle fails loudly instead of comparing fl with itself.
        let Some(addr) = (unsafe { host_addr_optional(name, *fl) }) else {
            panic!("host glibc does not export {label}; this gate needs an oracle");
        };
        // SAFETY: the resolved symbol has this signature.
        let host: SetFs = unsafe { std::mem::transmute(addr) };
        // SAFETY: fl's own definition, same signature.
        let mine: SetFs = unsafe { std::mem::transmute(*fl) };

        // The QUERY form. Both must report the same current id with no errno.
        let want_query = call(host, -1);
        let got_query = call(mine, -1);
        println!("{label}(-1): host {want_query:?}  fl {got_query:?}");
        assert_eq!(
            got_query, want_query,
            "{label}(-1) gave {got_query:?}, host glibc gave {want_query:?}"
        );
        assert_eq!(
            want_query.1, 0,
            "the host set errno {} on a query, so this gate's expectation is stale",
            want_query.1
        );
        compared += 1;

        // A REFUSED change. Unprivileged, so the id must not move — and the call
        // still returns the previous id with no errno rather than failing.
        let want_set = call(host, i32::MAX);
        let got_set = call(mine, i32::MAX);
        println!("{label}(i32::MAX): host {want_set:?}  fl {got_set:?}");
        assert_eq!(
            got_set, want_set,
            "{label}(i32::MAX) gave {got_set:?}, host glibc gave {want_set:?}"
        );
        compared += 1;

        // And the refusal really was a no-op: query again through BOTH.
        let want_after = call(host, -1);
        let got_after = call(mine, -1);
        assert_eq!(
            (got_after, want_after),
            (want_query, want_query),
            "{label}: the id moved after a refused change — host {want_after:?}, fl {got_after:?}, \
             it was {want_query:?} before"
        );
        compared += 1;
    }

    assert_eq!(compared, arms.len() * 3, "not every case ran");
    println!("compared {compared} setfs* cells against the host");
}
