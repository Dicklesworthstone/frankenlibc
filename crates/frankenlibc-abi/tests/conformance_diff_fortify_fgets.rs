#![cfg(target_os = "linux")]
#![allow(unsafe_code)] // fork isolation + deliberate fortify overflows

//! `__fgets_chk` must abort on a real overflow and NOT on a negative count.
//!
//! Closes bd-ig4hzw. The safe path was already covered; what was missing is the
//! path that kills the process, and it cannot be asserted in-process — an abort
//! takes the test runner with it. Each case therefore runs in a forked child and
//! the parent compares the child's exit status against the host's.
//!
//! ## The defect this found
//!
//! `n` is a SIGNED `int`, and the narrow wrappers computed `n as usize > buflen`.
//! For `n = -1` that is `usize::MAX > buflen`, so fl called `__chk_fail()` and
//! **aborted the process where glibc returns NULL**. Probed on host glibc 2.42:
//!
//! ```text
//! n=8,  buflen=64 -> non-NULL      (reads)
//! n=64, buflen=8  -> SIGABRT       ("buffer overflow detected")
//! n=-1, buflen=64 -> NULL, NO abort
//! n=0,  buflen=64 -> NULL, NO abort
//! ```
//!
//! A program that computes its length in signed arithmetic and lands on a
//! negative value survives on glibc and died on fl. The wide siblings
//! `__fgetws_chk`/`__fgetws_unlocked_chk` already special-cased `n <= 0`, so the
//! narrow pair was the outlier — which is also why reading the code alone would
//! have made the cast look deliberate.
//!
//! ## Why the wait is bounded
//!
//! A child that neither exits nor aborts would otherwise hang the whole
//! invocation at zero CPU, which is exactly what `unistd_abi_test` did for 4.2
//! hours. The wait below has a deadline and kills the child rather than blocking.

use std::ffi::{CStr, c_char, c_int, c_void};
use std::io::Write;

#[path = "common/dlsym_oracle.rs"]
mod dlsym_oracle;
use dlsym_oracle::host_addr_optional;

type FgetsChk = unsafe extern "C" fn(*mut c_char, usize, c_int, *mut c_void) -> *mut c_char;

/// What happened to a child that made one fortify call.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Returned a non-NULL pointer.
    Read,
    /// Returned NULL without dying.
    Null,
    /// Died on a signal — for a fortify failure, `SIGABRT`.
    Signal(c_int),
    /// Neither, within the deadline.
    Hung,
}

/// Reap `pid` with a deadline, killing it rather than blocking forever.
///
/// # Safety
/// `pid` must be an unreaped child of this process.
unsafe fn bounded_wait(pid: libc::pid_t) -> Outcome {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let mut status: c_int = 0;
        // SAFETY: `pid` is this process's child and `status` is a live local.
        let rc = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if rc == pid {
            if libc::WIFSIGNALED(status) {
                return Outcome::Signal(libc::WTERMSIG(status));
            }
            return if libc::WEXITSTATUS(status) == 0 {
                Outcome::Read
            } else {
                Outcome::Null
            };
        }
        if std::time::Instant::now() >= deadline {
            // SAFETY: killing a child this process owns.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                let mut sink: c_int = 0;
                libc::waitpid(pid, &mut sink, 0);
            }
            return Outcome::Hung;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// Run one fortify call in a forked child and report what became of it.
fn probe(f: FgetsChk, path: &CStr, buflen: usize, n: c_int) -> Outcome {
    // SAFETY: fork in a test that does no allocation in the child beyond libc.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // Child: make the call, encode the answer in the exit status. An abort
        // never reaches the exit.
        // SAFETY: the file exists and the buffer is 64 bytes; `buflen` is what
        // the wrapper is TOLD the buffer is, which is the point of the test.
        unsafe {
            let mode = c"r";
            let stream = libc::fopen(path.as_ptr(), mode.as_ptr());
            let mut buf = [0 as c_char; 64];
            let rc = f(buf.as_mut_ptr(), buflen, n, stream.cast());
            libc::_exit(if rc.is_null() { 1 } else { 0 });
        }
    }
    // SAFETY: `pid` is the child just forked.
    unsafe { bounded_wait(pid) }
}

#[test]
fn fortify_fgets_aborts_on_overflow_and_not_on_a_negative_count() {
    let dir = std::env::temp_dir().join("fl_fortify_fgets");
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let path = dir.join("input.txt");
    {
        let mut f = std::fs::File::create(&path).expect("create input");
        f.write_all(b"hello world\n").expect("write input");
    }
    let cpath = std::ffi::CString::new(path.to_str().expect("utf-8 path")).expect("path has NUL");

    let arms: &[(&CStr, *const ())] = &[
        (
            c"__fgets_chk",
            frankenlibc_abi::fortify_abi::__fgets_chk as *const (),
        ),
        (
            c"__fgets_unlocked_chk",
            frankenlibc_abi::fortify_abi::__fgets_unlocked_chk as *const (),
        ),
    ];

    // (label, buflen, n). The overflow case is the one that aborts; the negative
    // and zero cases are the ones fl got wrong.
    let cases: &[(&str, usize, c_int)] = &[
        ("safe", 64, 8),
        ("overflow", 8, 64),
        ("negative", 64, -1),
        ("zero", 64, 0),
    ];

    let mut compared = 0usize;
    let mut aborts = 0usize;
    for (name, fl) in arms {
        let label = name.to_str().expect("ASCII symbol name");
        // SAFETY: NUL-terminated name paired with fl's own definition.
        let Some(host) = (unsafe { host_addr_optional(name, *fl) }) else {
            println!("{label}: host does not export it; skipped");
            continue;
        };
        // SAFETY: both addresses have `__fgets_chk`'s C signature.
        let host_f: FgetsChk = unsafe { std::mem::transmute(host) };
        // SAFETY: same.
        let fl_f: FgetsChk = unsafe { std::mem::transmute(*fl) };

        for (case, buflen, n) in cases {
            let want = probe(host_f, &cpath, *buflen, *n);
            let got = probe(fl_f, &cpath, *buflen, *n);
            println!("{label} {case}: host {want:?}  fl {got:?}");
            assert_ne!(want, Outcome::Hung, "{label} {case}: the HOST child hung");
            assert_eq!(
                got, want,
                "{label}({case}: buflen={buflen}, n={n}) gave {got:?}, host glibc gave {want:?}"
            );
            if want == Outcome::Signal(libc::SIGABRT) {
                aborts += 1;
            }
            compared += 1;
        }
    }

    assert_eq!(compared, arms.len() * cases.len(), "not every case ran");
    // The positive fact: if NOTHING aborted, the harness cannot see an abort and
    // every "matched" above would be vacuous.
    assert!(
        aborts >= 1,
        "no case aborted on either implementation, so this gate cannot tell an \
         abort from a clean return and proves nothing"
    );
    println!("compared {compared} fortify fgets cases, {aborts} of them real aborts");
}
