#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // live host-glibc oracle via dlsym, exercised in a forked child

//! What does `__fgetws_chk` do at its bound, and can glibc arbitrate it?
//!
//! A conformance fixture calls `__fgetws_chk(NULL, 4, 2, NULL)` and expects the
//! child to die on `SIGABRT`. FrankenLibC's child exits 0 instead — its rule is
//! `if (n as usize) <= buflen { pass through }`, and 2 <= 4, so it never reaches
//! `__chk_fail` (bd-ud2wq0, split out of bd-u2daxd).
//!
//! Whether that is wrong turns on what `buflen` MEANS, and the source is not
//! self-consistent about it. glibc's `<bits/wchar2.h>` expands `fgetws` to
//! `__fgetws_chk (s, __bos (s) / sizeof (wchar_t), n, stream)`, i.e. a count of
//! WIDE CHARACTERS — on which reading fl's comparison is right and the fixture's
//! expectation is wrong. But fl's own comment beside that branch reasons in
//! BYTES ("n = 65 with buflen = 256 may write 260 bytes"), on which reading fl
//! under-aborts by a factor of four and the fixture is right.
//!
//! I wrote this expecting the host to settle it. IT CANNOT: glibc SIGSEGVs on
//! both argument sets, because the null stream faults before any `__chk_fail` is
//! reached. So the gate keeps the host call — as a tripwire, asserting that
//! glibc still faults, since the day it stops is the day this could become a
//! real differential — but its substantive assertions are about FrankenLibC's
//! own rule.
//!
//! The measurement also disposes of the question the fixture raises: fl aborts
//! for a request of 8 into a destination of 2, and does not for 2 into 4. The
//! fixture passes the latter under the name
//! `wide_request_exceeds_destlen`, which its own arguments contradict.
//!
//! Both arms run in a forked child because one of them may abort and a null
//! stream may fault.

use std::ffi::{c_int, c_void};

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;

type FgetwsChk = unsafe extern "C" fn(*mut c_int, usize, c_int, *mut c_void) -> *mut c_int;

/// Run `action` in a forked child and classify how it ended.
fn classify(action: impl FnOnce()) -> String {
    // SAFETY: fork in a test process; the child only runs `action` and _exit.
    let child = unsafe { libc::fork() };
    if child == 0 {
        action();
        // SAFETY: terminate the child without unwinding or flushing.
        unsafe { libc::_exit(0) };
    }
    if child < 0 {
        return "FORK_FAILED".to_string();
    }
    let mut status = 0;
    // SAFETY: targeted reap of the child just forked.
    let waited = unsafe { libc::waitpid(child, &mut status, 0) };
    if waited != child {
        return format!("WAITPID_{waited}");
    }
    if libc::WIFSIGNALED(status) {
        let signal = libc::WTERMSIG(status);
        return match signal {
            libc::SIGABRT => "ABORT_SIGABRT".to_string(),
            libc::SIGSEGV => "SIGSEGV".to_string(),
            other => format!("SIGNAL_{other}"),
        };
    }
    if libc::WIFEXITED(status) {
        return format!("EXIT_{}", libc::WEXITSTATUS(status));
    }
    "UNKNOWN".to_string()
}

#[test]
fn fgetws_chk_bound_is_pinned_and_glibc_cannot_arbitrate() {
    let host: FgetwsChk = unsafe {
        dlsym_oracle::host_fn(
            c"__fgetws_chk",
            frankenlibc_abi::fortify_abi::__fgetws_chk as *const (),
        )
    };

    // The fixture's own arguments: destination length 4, request 2, null stream.
    let host_outcome = classify(|| {
        // SAFETY: deliberately the fixture's degenerate arguments, in a child.
        unsafe { host(std::ptr::null_mut(), 4, 2, std::ptr::null_mut()) };
    });
    let fl_outcome = classify(|| {
        // SAFETY: as above, FrankenLibC's implementation.
        unsafe {
            frankenlibc_abi::fortify_abi::__fgetws_chk(
                std::ptr::null_mut(),
                4,
                2,
                std::ptr::null_mut(),
            )
        };
    });

    println!("FGETWS_CHK_BOUND args=(NULL,4,2,NULL) host_glibc={host_outcome} fl={fl_outcome}");

    // A request that clearly exceeds the destination on EITHER reading: 8 wide
    // characters into a destination of 2. Both arms must abort, and if they
    // disagree here the disagreement is about the check itself rather than about
    // the units.
    let host_clear = classify(|| {
        // SAFETY: over-large request, in a child.
        unsafe { host(std::ptr::null_mut(), 2, 8, std::ptr::null_mut()) };
    });
    let fl_clear = classify(|| {
        // SAFETY: as above.
        unsafe {
            frankenlibc_abi::fortify_abi::__fgetws_chk(
                std::ptr::null_mut(),
                2,
                8,
                std::ptr::null_mut(),
            )
        };
    });
    println!("FGETWS_CHK_BOUND args=(NULL,2,8,NULL) host_glibc={host_clear} fl={fl_clear}");

    // WHAT THIS GATE CAN AND CANNOT ASSERT.
    //
    // It CANNOT be a differential on these arguments. Measured: glibc SIGSEGVs
    // for BOTH (NULL,4,2,NULL) and (NULL,2,8,NULL), because a null stream faults
    // before any __chk_fail is reached. The host never exercises the bound, so
    // comparing abort classifications here would be comparing FrankenLibC
    // against a segfault. I wrote this test expecting glibc to arbitrate whether
    // `buflen` counts wide characters or bytes; it cannot, and pretending
    // otherwise would be worse than admitting it.
    //
    // What it CAN pin is FrankenLibC's own rule, which is what the conformance
    // fixture actually depends on: the check fires when the request exceeds the
    // destination and stays out of the way when it does not.
    assert_eq!(
        host_outcome, "SIGSEGV",
        "glibc no longer faults on a null stream, so it may now be usable as a \
         real oracle here -- re-read this gate's premise before trusting it"
    );
    assert_eq!(
        fl_clear, "ABORT_SIGABRT",
        "a request of 8 into a destination of 2 must trip __chk_fail"
    );
    assert_eq!(
        fl_outcome, "EXIT_0",
        "a request of 2 into a destination of 4 must NOT trip __chk_fail. The \
         conformance fixture wide_request_exceeds_destlen passes exactly these \
         arguments and expects an abort, which its own name contradicts -- the \
         request does not exceed the destination. See bd-ud2wq0."
    );
}
