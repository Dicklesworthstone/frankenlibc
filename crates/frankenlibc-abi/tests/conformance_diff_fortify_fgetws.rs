#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // fork-isolated abort probing against a live host-glibc oracle
//! Differential gate for `__fgetws_chk` / `__fgetws_unlocked_chk` (bd-917hzv).
//!
//! WHAT WAS WRONG. fl used a STATIC rule — `n * 4 > buflen` implies `__chk_fail` —
//! and so aborted processes host glibc runs happily. `fgetws(buf, 1024, fp)` into a
//! 4096-byte buffer is the ordinary idiom, and fl killed it whenever `n * 4`
//! crossed the size no matter what the file actually contained.
//!
//! WHY THE EXISTING TEST DID NOT CATCH IT. `fortify_abi_test` asserts
//! `__fgetws_chk(buf, 32 * 4, 32, fp)`, which passes under fl's old rule AND under
//! glibc's, so it never discriminated. **Every case below is chosen because the two
//! rules disagree on it**, which is the only kind of case that could have caught
//! this and the only kind that can catch a regression of it.
//!
//! THE RULE, derived from the host rather than assumed. No static comparison fits
//! the data: `n = 257` against `size = 256` ABORTS for a 300-character line and
//! does NOT abort for a 12-character one, so the decision cannot be a function of
//! `n` and `size` alone. Two conditions fit every observed row — `n > buflen` AND
//! the content did not actually fit.
//!
//! Note the units look wrong and are not: `n` counts WIDE CHARACTERS while
//! `buflen` counts BYTES, and glibc compares them directly, the same shape as
//! `__fgets_chk`. fl now matches that.
//!
//! EVERY CASE RUNS IN A FORKED CHILD with a bounded wait, so a `__chk_fail` abort
//! is an observation rather than the end of the test binary, and the run cannot
//! hang if a child wedges.

use std::ffi::c_void;
use std::io::Write;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Outcome {
    Ok,
    Null,
    Aborted,
}

/// Run one call in a child and report what happened to it.
///
/// # Safety
/// `f` must be a real `__fgetws*_chk` and `path` a readable file.
unsafe fn probe(
    f: unsafe extern "C" fn(*mut i32, usize, i32, *mut c_void) -> *mut i32,
    path: &std::ffi::CStr,
    size_bytes: usize,
    n: i32,
) -> Outcome {
    let mut fds = [0i32; 2];
    // SAFETY: fresh pipe pair.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe");

    // SAFETY: forking; the child only writes a byte and _exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork");
    if pid == 0 {
        // SAFETY: child. Close the read end, run the call, report one byte.
        unsafe {
            libc::close(fds[0]);
            let fp = libc::fopen(path.as_ptr(), c"r".as_ptr());
            if fp.is_null() {
                libc::_exit(101);
            }
            // A generously sized real buffer: `size_bytes` is the CLAIMED size the
            // check reasons about, which is what varies between cases.
            let mut real = [0i32; 4096];
            let got = f(real.as_mut_ptr(), size_bytes, n, fp.cast::<c_void>());
            let byte = if got.is_null() { b"n" } else { b"o" };
            libc::write(fds[1], byte.as_ptr().cast::<c_void>(), 1);
            libc::_exit(0);
        }
    }
    // SAFETY: parent closes the write end so the read terminates.
    unsafe { libc::close(fds[1]) };
    let mut byte = [0u8; 1];
    // SAFETY: reading at most one byte from the pipe's read end.
    let got = unsafe { libc::read(fds[0], byte.as_mut_ptr().cast::<c_void>(), 1) };
    // SAFETY: closing the read end we own.
    unsafe { libc::close(fds[0]) };

    // Bounded wait: a wedged child must fail the test rather than hang the run.
    let mut status = 0i32;
    let started = std::time::Instant::now();
    loop {
        // SAFETY: `pid` is our child.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if r != 0 {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "child {pid} did not exit within 20s"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    if libc::WIFSIGNALED(status) {
        return Outcome::Aborted;
    }
    if got == 1 && byte[0] == b'n' {
        return Outcome::Null;
    }
    Outcome::Ok
}

fn write_temp(name: &str, content: &str) -> std::ffi::CString {
    let path = std::env::temp_dir().join(name);
    let mut f = std::fs::File::create(&path).expect("create temp");
    f.write_all(content.as_bytes()).expect("write temp");
    std::ffi::CString::new(path.to_str().unwrap()).unwrap()
}

type ChkFn = unsafe extern "C" fn(*mut i32, usize, i32, *mut c_void) -> *mut i32;

fn host_chk(name: &std::ffi::CStr) -> ChkFn {
    // SAFETY: libc.so.6 is the process host libc.
    let h = unsafe { libc::dlopen(c"libc.so.6".as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!h.is_null(), "dlopen libc.so.6");
    // SAFETY: handle from dlopen, name NUL-terminated.
    let p = unsafe { libc::dlsym(h, name.as_ptr()) };
    assert!(!p.is_null(), "dlsym {name:?}");
    // SAFETY: the resolved symbol has the documented __fgetws_chk signature.
    unsafe { std::mem::transmute::<*mut c_void, ChkFn>(p) }
}

/// The cases where fl's OLD static rule and glibc disagree, plus the boundary
/// rows that pin the two-condition rule.
const CASES: &[(&str, usize, i32)] = &[
    // (label, claimed size in BYTES, n in wide chars)
    ("large n, ample buffer", 4096, 2000), // old fl: 8000 > 4096 -> ABORT. glibc: ok.
    ("n just over size/4", 256, 65),       // old fl: 260 > 256 -> ABORT.  glibc: ok.
    ("n far over size/4", 256, 100),       // old fl: ABORT.               glibc: ok.
    ("n equals size", 256, 256),           // boundary: not > size.        glibc: ok.
    ("n one over size", 256, 257),         // > size: content decides.
    ("tiny buffer, large n", 8, 64),       // > size and cannot fit.       glibc: ABORT.
    ("negative n", 256, -1),               // NULL, never abort.
    ("zero n", 256, 0),                    // NULL, never abort.
];

#[test]
fn fgetws_chk_matches_host_glibc_on_cases_that_discriminate() {
    let short = write_temp("fl_fgetws_short.txt", "hello world\n");
    let long = write_temp("fl_fgetws_long.txt", &format!("{}\n", "x".repeat(300)));
    let host = host_chk(c"__fgetws_chk");

    let mut compared = 0usize;
    let mut aborts_seen = 0usize;
    for (content_label, path) in [("short(12)", &short), ("long(300)", &long)] {
        for &(label, size, n) in CASES {
            // SAFETY: both arms take the same readable file and claimed size.
            let host_out = unsafe { probe(host, path, size, n) };
            // SAFETY: as above, against fl.
            let fl_out = unsafe {
                probe(
                    frankenlibc_abi::fortify_abi::__fgetws_chk,
                    path,
                    size,
                    n,
                )
            };
            assert_eq!(
                fl_out, host_out,
                "{content_label} {label} (size={size} bytes, n={n}): fl={fl_out:?} \
                 glibc={host_out:?}"
            );
            compared += 1;
            if host_out == Outcome::Aborted {
                aborts_seen += 1;
            }
        }
    }

    // NON-VACUITY, asserted as the positive fact rather than a count of rows: if
    // no case aborted, the gate is only checking that nothing ever fails, and it
    // would pass against an implementation with the check deleted entirely.
    assert_eq!(compared, CASES.len() * 2, "not every case ran");
    assert!(
        aborts_seen >= 2,
        "host glibc aborted on only {aborts_seen} of {compared} cases — the matrix \
         no longer exercises the overflow path, so this gate proves nothing"
    );
}

#[test]
fn fgetws_unlocked_chk_matches_the_locked_form() {
    // The unlocked variant shares the rule; pin that it did not drift.
    let long = write_temp("fl_fgetws_unlocked.txt", &format!("{}\n", "x".repeat(300)));
    for &(label, size, n) in CASES {
        // SAFETY: same file and claimed size through both fl entry points.
        let locked = unsafe {
            probe(frankenlibc_abi::fortify_abi::__fgetws_chk, &long, size, n)
        };
        // SAFETY: as above.
        let unlocked = unsafe {
            probe(
                frankenlibc_abi::fortify_abi::__fgetws_unlocked_chk,
                &long,
                size,
                n,
            )
        };
        assert_eq!(
            locked, unlocked,
            "{label} (size={size}, n={n}): locked={locked:?} unlocked={unlocked:?}"
        );
    }
}
