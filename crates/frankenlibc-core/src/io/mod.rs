//! Low-level I/O — validators and constants.
//!
//! Implements POSIX I/O pure-logic helpers. Actual syscall invocations
//! (`dup`, `pipe`, `fcntl`, etc.) live in the ABI crate.

/// `fcntl` command constants.
pub const F_DUPFD: i32 = 0;
pub const F_GETFD: i32 = 1;
pub const F_SETFD: i32 = 2;
pub const F_GETFL: i32 = 3;
pub const F_SETFL: i32 = 4;
pub const F_DUPFD_CLOEXEC: i32 = 1030;

/// File descriptor flag constants.
pub const FD_CLOEXEC: i32 = 1;

/// Open flags used by multiple subsystems.
pub const O_NONBLOCK: i32 = 2048;
pub const O_CLOEXEC: i32 = 0x80000;

/// Returns `true` if `fd` is a plausibly valid file descriptor (non-negative).
#[inline]
pub fn valid_fd(fd: i32) -> bool {
    fd >= 0
}

/// Returns `true` if `cmd` is a known `fcntl` command.
#[inline]
pub fn valid_fcntl_cmd(cmd: i32) -> bool {
    matches!(
        cmd,
        F_DUPFD | F_GETFD | F_SETFD | F_GETFL | F_SETFL | F_DUPFD_CLOEXEC
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_fd() {
        assert!(valid_fd(0));
        assert!(valid_fd(1));
        assert!(valid_fd(1024));
        assert!(!valid_fd(-1));
        assert!(!valid_fd(i32::MIN));
    }

    #[test]
    fn test_valid_fcntl_cmd() {
        assert!(valid_fcntl_cmd(F_DUPFD));
        assert!(valid_fcntl_cmd(F_GETFD));
        assert!(valid_fcntl_cmd(F_SETFD));
        assert!(valid_fcntl_cmd(F_GETFL));
        assert!(valid_fcntl_cmd(F_SETFL));
        assert!(valid_fcntl_cmd(F_DUPFD_CLOEXEC));
        assert!(!valid_fcntl_cmd(-1));
        assert!(!valid_fcntl_cmd(999));
    }

    // ===== glibc parity tests =====
    // Verified against glibc <fcntl.h>

    #[test]
    fn glibc_fcntl_cmd_constants() {
        // fcntl command constants must match glibc values
        assert_eq!(F_DUPFD, 0);
        assert_eq!(F_GETFD, 1);
        assert_eq!(F_SETFD, 2);
        assert_eq!(F_GETFL, 3);
        assert_eq!(F_SETFL, 4);
        assert_eq!(F_DUPFD_CLOEXEC, 1030);
    }

    #[test]
    fn glibc_fd_flags() {
        // FD flags must match glibc values
        assert_eq!(FD_CLOEXEC, 1);
    }

    #[test]
    fn glibc_open_flags() {
        // Open flags must match glibc values
        assert_eq!(O_NONBLOCK, 2048); // 0x800
        assert_eq!(O_CLOEXEC, 0x80000);
    }
}
