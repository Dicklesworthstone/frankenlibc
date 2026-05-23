//! POSIX process control.
//!
//! Implements `<sys/wait.h>` and `<unistd.h>` process-control constants,
//! wait-status macros, and validators for fork/exec/wait families.

/// `WNOHANG` — return immediately if no child has exited.
pub const WNOHANG: i32 = 1;

/// `WUNTRACED` — also return if a child has stopped.
pub const WUNTRACED: i32 = 2;

/// `WCONTINUED` — also return if a stopped child has resumed via SIGCONT.
pub const WCONTINUED: i32 = 8;

// ---------------------------------------------------------------------------
// Wait-status decoding macros (match glibc bit layout)
// ---------------------------------------------------------------------------

/// True if the child terminated normally (via `_exit` or `exit`).
#[must_use]
pub const fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

/// Exit code of a normally-terminated child (valid only when `wifexited`).
#[must_use]
pub const fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// True if the child was killed by a signal.
#[must_use]
pub const fn wifsignaled(status: i32) -> bool {
    let low7 = status & 0x7f;
    low7 != 0 && low7 != 0x7f
}

/// Signal number that killed the child (valid only when `wifsignaled`).
#[must_use]
pub const fn wtermsig(status: i32) -> i32 {
    status & 0x7f
}

/// True if the child is currently stopped.
#[must_use]
pub const fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

/// Signal that stopped the child (valid only when `wifstopped`).
#[must_use]
pub const fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns true if `sig` is in the valid POSIX signal range [1, 64].
#[must_use]
pub const fn valid_signal(sig: i32) -> bool {
    sig >= 1 && sig <= 64
}

/// Mask of recognized wait option bits.
const WAIT_OPTS_MASK: i32 = WNOHANG | WUNTRACED | WCONTINUED;

/// Returns true if `opts` contains only recognized wait flags.
#[must_use]
pub const fn valid_wait_options(opts: i32) -> bool {
    (opts & !WAIT_OPTS_MASK) == 0
}

/// Sanitize wait options by masking to recognized bits.
#[must_use]
pub const fn sanitize_wait_options(opts: i32) -> i32 {
    opts & WAIT_OPTS_MASK
}

/// Clamp an exit status to the [0, 255] range used by `_exit`.
#[must_use]
pub const fn clamp_exit_status(status: i32) -> i32 {
    status & 0xff
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normal_exit_status_42() {
        // glibc encodes normal exit(42) as (42 << 8) | 0 = 0x2A00.
        let status = 42 << 8;
        assert!(wifexited(status));
        assert_eq!(wexitstatus(status), 42);
        assert!(!wifsignaled(status));
        assert!(!wifstopped(status));
    }

    #[test]
    fn killed_by_sigkill() {
        // Killed by signal 9 (SIGKILL): low 7 bits = 9.
        let status = 9;
        assert!(!wifexited(status));
        assert!(wifsignaled(status));
        assert_eq!(wtermsig(status), 9);
        assert!(!wifstopped(status));
    }

    #[test]
    fn stopped_by_sigstop() {
        // Stopped by signal 19 (SIGSTOP): 0x7f in low byte, signal in high byte.
        let status = (19 << 8) | 0x7f;
        assert!(!wifexited(status));
        assert!(!wifsignaled(status));
        assert!(wifstopped(status));
        assert_eq!(wstopsig(status), 19);
    }

    #[test]
    fn valid_signal_range() {
        assert!(!valid_signal(0));
        assert!(valid_signal(1));
        assert!(valid_signal(9));
        assert!(valid_signal(64));
        assert!(!valid_signal(65));
        assert!(!valid_signal(-1));
    }

    #[test]
    fn valid_wait_options_check() {
        assert!(valid_wait_options(0));
        assert!(valid_wait_options(WNOHANG));
        assert!(valid_wait_options(WUNTRACED));
        assert!(valid_wait_options(WNOHANG | WUNTRACED));
        assert!(valid_wait_options(WNOHANG | WUNTRACED | WCONTINUED));
        assert!(!valid_wait_options(0x100));
    }

    #[test]
    fn sanitize_strips_unknown_bits() {
        assert_eq!(sanitize_wait_options(0xff), WAIT_OPTS_MASK & 0xff);
        assert_eq!(sanitize_wait_options(WNOHANG), WNOHANG);
    }

    #[test]
    fn clamp_exit_status_range() {
        assert_eq!(clamp_exit_status(0), 0);
        assert_eq!(clamp_exit_status(255), 255);
        assert_eq!(clamp_exit_status(256), 0);
        assert_eq!(clamp_exit_status(-1), 255);
    }

    // ===== glibc parity tests =====
    // Verified against glibc <sys/wait.h>

    #[test]
    fn glibc_wait_option_constants() {
        // wait option flags must match glibc
        assert_eq!(WNOHANG, 1);
        assert_eq!(WUNTRACED, 2);
        assert_eq!(WCONTINUED, 8);
    }

    #[test]
    fn glibc_wait_status_macros() {
        // Test WIFEXITED/WEXITSTATUS encoding (glibc: exit_code << 8)
        let status_42 = 42 << 8;
        assert!(wifexited(status_42));
        assert_eq!(wexitstatus(status_42), 42);

        // Test WIFSIGNALED/WTERMSIG encoding (glibc: signal in low 7 bits)
        let killed_by_9 = 9; // SIGKILL
        assert!(wifsignaled(killed_by_9));
        assert_eq!(wtermsig(killed_by_9), 9);

        // Test WIFSTOPPED/WSTOPSIG encoding (glibc: 0x7f in low byte, signal in second byte)
        let stopped_by_19 = (19 << 8) | 0x7f; // SIGSTOP
        assert!(wifstopped(stopped_by_19));
        assert_eq!(wstopsig(stopped_by_19), 19);
    }
}
