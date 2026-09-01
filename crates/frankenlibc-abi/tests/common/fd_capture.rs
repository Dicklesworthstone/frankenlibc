//! Panic-safe restore for a redirected standard descriptor (bd-ug42ol).
//!
//! ## Why this exists
//!
//! Every gate in this suite that captures output does the same three things:
//!
//! ```ignore
//! let saved = libc::dup(2);
//! libc::dup2(pipe_write, 2);
//! body();                      // <-- a panic here skips everything below
//! libc::dup2(saved, 2);        // straight-line restore
//! libc::close(saved);
//! ```
//!
//! `body()` is the code under test, and an assertion or an `unwrap` inside it
//! panics. Straight-line restore code does not run on the unwind, so the
//! process's stderr — or stdout — stays pointed at a pipe or temp file **for the
//! rest of the run**. That does not merely leak a descriptor: it swallows
//! libtest's report of the very failure that caused it, and every later test's
//! output with it. The failure that destroys the evidence of itself is the worst
//! shape a harness can have, which is why bd-ug42ol calls this "the cheapest fix
//! and the one whose absence destroys the most evidence".
//!
//! ## What this does NOT fix
//!
//! Contamination of the capture itself. libtest writes `test <name> ... ok` and
//! its 60-second watchdog line to **fd 1** from its own threads, so a captured
//! fd 1 can hold bytes no implementation wrote (measured on bd-dq41u0). A guard
//! restores the descriptor; it cannot stop another thread writing through it
//! while it is redirected. fd 1 captures additionally need the single-`#[test]`
//! plus counted-bytes treatment bd-ug42ol prescribes.
//!
//! fd 2 is not written by libtest in the normal case — `eprintln!` and panic
//! messages go through Rust's per-thread output capture — so for fd 2 the
//! remaining exposure is another test in the SAME BINARY writing to C `stderr`
//! directly, which a per-file mutex does close.

#![allow(dead_code)] // each gate uses only what it needs

/// Restores a standard descriptor when dropped, including on unwind.
///
/// Construct it AFTER saving the original and BEFORE redirecting, then let it
/// fall out of scope; do not also restore by hand or the descriptor is closed
/// twice.
pub struct StdFdRestore {
    saved: libc::c_int,
    target: libc::c_int,
}

impl StdFdRestore {
    /// Duplicate `target` and take ownership of the copy.
    ///
    /// # Safety
    ///
    /// `target` must be a valid descriptor for the lifetime of the guard.
    pub unsafe fn new(target: libc::c_int) -> Self {
        // SAFETY: the caller supplies a live standard descriptor.
        let saved = unsafe { libc::dup(target) };
        assert!(saved >= 0, "dup({target}) failed; cannot guarantee restore");
        Self { saved, target }
    }
}

impl Drop for StdFdRestore {
    fn drop(&mut self) {
        // SAFETY: `saved` came from `dup` in `new` and is closed exactly once
        // here; `target` is the standard descriptor it was taken from.
        unsafe {
            libc::dup2(self.saved, self.target);
            libc::close(self.saved);
        }
    }
}
