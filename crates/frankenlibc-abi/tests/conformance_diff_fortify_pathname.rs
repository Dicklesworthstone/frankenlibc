#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // fork-isolated abort probing against a live host oracle

//! The path-name `*_chk` wrappers abort exactly when glibc does (bd-8aazre).
//!
//! ## What this family's rule turned out to be
//!
//! Unlike the wide wrappers — which count wide characters — and unlike
//! `__fgetws_chk`, whose abort depends on the bytes actually written, this
//! family is a plain STATIC comparison in bytes: `len > buflen` aborts, anything
//! else runs. Probed fork-isolated on host glibc 2.42:
//!
//! ```text
//! __getcwd_chk       len=64/256 -> ok    len=257/256 -> ABORT   len=1024/256 -> ABORT
//! __readlink_chk     len=64/256 -> ok    len=257/256 -> ABORT   len=1024/256 -> ABORT
//! __confstr_chk      len=64/256 -> ok    len=257/256 -> ABORT   len=1024/256 -> ABORT
//! __gethostname_chk  len=64/256 -> ok    len=257/256 -> ABORT   len=1024/256 -> ABORT
//! ```
//!
//! Three different rules in one header family is the reason this sweep asks the
//! host per function instead of generalising from the last one. Two of the three
//! defects it found came from assuming a neighbour's convention carried over.
//!
//! ## Non-vacuity
//!
//! Each wrapper is checked once where it must NOT abort and once where it must,
//! and the gate asserts a floor on how many real aborts were observed — without
//! that, a build with every check deleted would pass.

use std::ffi::{c_char, c_int, c_void};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Outcome {
    Ok,
    Aborted,
}

/// Run `body` in a forked child with a bounded wait, so an abort is an
/// observation and a wedged child fails the test instead of hanging the run.
fn run(body: impl FnOnce()) -> Outcome {
    // SAFETY: fork; the child runs `body` then `_exit`s.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        body();
        // SAFETY: child exiting without atexit handlers.
        unsafe { libc::_exit(0) };
    }
    let mut status = 0i32;
    let started = std::time::Instant::now();
    loop {
        // SAFETY: `pid` is this process's child.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r != 0 {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "child {pid} did not exit within 20s"
        );
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    if libc::WIFSIGNALED(status) {
        Outcome::Aborted
    } else {
        Outcome::Ok
    }
}

fn host(name: &std::ffi::CStr) -> *mut c_void {
    // SAFETY: the process's own libc.
    let h = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!h.is_null(), "dlopen libc.so.6");
    // SAFETY: handle from dlopen; NUL-terminated name.
    let p = unsafe { libc::dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "host glibc does not export {name:?}");
    p
}

/// A destination far larger than any claimed `buflen`, so only the check's
/// arithmetic is under test and a correct implementation cannot run off it.
fn dst() -> Vec<c_char> {
    vec![0 as c_char; 8192]
}

#[test]
fn pathname_chk_wrappers_abort_exactly_where_the_host_does() {
    type BufLen = unsafe extern "C" fn(*mut c_char, usize, usize) -> c_int;
    type BufLenPtr = unsafe extern "C" fn(*mut c_char, usize, usize) -> *mut c_char;
    type Link = unsafe extern "C" fn(*const c_char, *mut c_char, usize, usize) -> isize;
    type Confstr = unsafe extern "C" fn(c_int, *mut c_char, usize, usize) -> usize;

    let mut compared = 0usize;
    let mut aborts = 0usize;
    let mut bad: Vec<String> = Vec::new();

    macro_rules! cell {
        ($label:expr, $expect_abort:expr, $h:expr, $m:expr) => {{
            let hv = run($h);
            let mv = run($m);
            if hv == Outcome::Aborted {
                aborts += 1;
            }
            let expected = if $expect_abort { Outcome::Aborted } else { Outcome::Ok };
            if hv != expected {
                bad.push(format!(
                    "{}: HOST gave {hv:?} where the probe expected {expected:?}; the case \
                     no longer discriminates",
                    $label
                ));
            }
            if mv != hv {
                bad.push(format!("{}: fl {mv:?}, host {hv:?}", $label));
            }
            compared += 1;
        }};
    }

    // --- __getcwd_chk ---
    {
        // SAFETY: resolved symbol has this signature.
        let hf: BufLenPtr = unsafe { std::mem::transmute(host(c"__getcwd_chk")) };
        let mf = frankenlibc_abi::fortify_abi::__getcwd_chk;
        cell!("__getcwd_chk len=64 buflen=256", false,
            // SAFETY: 64 bytes into an 8192-byte destination.
            || { let mut d = dst(); unsafe { hf(d.as_mut_ptr(), 64, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(d.as_mut_ptr(), 64, 256) }; });
        cell!("__getcwd_chk len=1024 buflen=256", true,
            // SAFETY: the check fires before any write.
            || { let mut d = dst(); unsafe { hf(d.as_mut_ptr(), 1024, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(d.as_mut_ptr(), 1024, 256) }; });
    }

    // --- __readlink_chk ---
    {
        // SAFETY: resolved symbol has this signature.
        let hf: Link = unsafe { std::mem::transmute(host(c"__readlink_chk")) };
        let mf = frankenlibc_abi::fortify_abi::__readlink_chk;
        cell!("__readlink_chk len=64 buflen=256", false,
            // SAFETY: /proc/self/exe always resolves; 64 into 8192.
            || { let mut d = dst(); unsafe { hf(c"/proc/self/exe".as_ptr(), d.as_mut_ptr(), 64, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(c"/proc/self/exe".as_ptr(), d.as_mut_ptr(), 64, 256) }; });
        cell!("__readlink_chk len=1024 buflen=256", true,
            // SAFETY: the check fires before any write.
            || { let mut d = dst(); unsafe { hf(c"/proc/self/exe".as_ptr(), d.as_mut_ptr(), 1024, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(c"/proc/self/exe".as_ptr(), d.as_mut_ptr(), 1024, 256) }; });
    }

    // --- __confstr_chk ---
    {
        // SAFETY: resolved symbol has this signature.
        let hf: Confstr = unsafe { std::mem::transmute(host(c"__confstr_chk")) };
        let mf = frankenlibc_abi::fortify_abi::__confstr_chk;
        cell!("__confstr_chk len=64 buflen=256", false,
            // SAFETY: name 0 is _CS_PATH; 64 into 8192.
            || { let mut d = dst(); unsafe { hf(0, d.as_mut_ptr(), 64, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(0, d.as_mut_ptr(), 64, 256) }; });
        cell!("__confstr_chk len=1024 buflen=256", true,
            // SAFETY: the check fires before any write.
            || { let mut d = dst(); unsafe { hf(0, d.as_mut_ptr(), 1024, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(0, d.as_mut_ptr(), 1024, 256) }; });
    }

    // --- __gethostname_chk ---
    {
        // SAFETY: resolved symbol has this signature.
        let hf: BufLen = unsafe { std::mem::transmute(host(c"__gethostname_chk")) };
        let mf = frankenlibc_abi::fortify_abi::__gethostname_chk;
        cell!("__gethostname_chk len=64 buflen=256", false,
            // SAFETY: 64 into 8192.
            || { let mut d = dst(); unsafe { hf(d.as_mut_ptr(), 64, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(d.as_mut_ptr(), 64, 256) }; });
        cell!("__gethostname_chk len=1024 buflen=256", true,
            // SAFETY: the check fires before any write.
            || { let mut d = dst(); unsafe { hf(d.as_mut_ptr(), 1024, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(d.as_mut_ptr(), 1024, 256) }; });
    }

    // --- __getdomainname_chk ---
    {
        // SAFETY: resolved symbol has this signature.
        let hf: BufLen = unsafe { std::mem::transmute(host(c"__getdomainname_chk")) };
        let mf = frankenlibc_abi::fortify_abi::__getdomainname_chk;
        cell!("__getdomainname_chk len=64 buflen=256", false,
            // SAFETY: 64 into 8192.
            || { let mut d = dst(); unsafe { hf(d.as_mut_ptr(), 64, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(d.as_mut_ptr(), 64, 256) }; });
        cell!("__getdomainname_chk len=1024 buflen=256", true,
            // SAFETY: the check fires before any write.
            || { let mut d = dst(); unsafe { hf(d.as_mut_ptr(), 1024, 256) }; },
            // SAFETY: as above, against fl.
            || { let mut d = dst(); unsafe { mf(d.as_mut_ptr(), 1024, 256) }; });
    }

    println!("compared {compared} path-name cells, {aborts} host aborts");
    for b in &bad {
        println!("  {b}");
    }
    assert!(
        aborts >= 5,
        "only {aborts} host aborts observed; without them this gate would pass \
         against a build with every check deleted"
    );
    assert!(bad.is_empty(), "{} divergent cells:\n  {}", bad.len(), bad.join("\n  "));
}
