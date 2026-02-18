//! Error number definitions.
//!
//! Implements `<errno.h>` support with thread-local errno storage.

use std::cell::Cell;

thread_local! {
    static ERRNO: Cell<i32> = const { Cell::new(0) };
}

/// Well-known errno constants.
pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const ENOTBLK: i32 = 15;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const ETXTBSY: i32 = 26;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;
pub const EDEADLK: i32 = 35;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const ENAMETOOLONG: i32 = 36;
pub const EOVERFLOW: i32 = 75;
pub const EAFNOSUPPORT: i32 = 97;
pub const EADDRINUSE: i32 = 98;
pub const EADDRNOTAVAIL: i32 = 99;
pub const ENETUNREACH: i32 = 101;
pub const ECONNABORTED: i32 = 103;
pub const ECONNRESET: i32 = 104;
pub const ENOBUFS: i32 = 105;
pub const EISCONN: i32 = 106;
pub const ENOTCONN: i32 = 107;
pub const ETIMEDOUT: i32 = 110;
pub const ECONNREFUSED: i32 = 111;
pub const EALREADY: i32 = 114;
pub const EINPROGRESS: i32 = 115;

/// Returns the error message string for the given errno value.
///
/// This is the safe core of C `strerror`. Returns a static string
/// describing the error, or a generic message for unknown errnos.
pub fn strerror_message(errnum: i32) -> &'static str {
    match errnum {
        0 => "Success",
        EPERM => "Operation not permitted",
        ENOENT => "No such file or directory",
        ESRCH => "No such process",
        EINTR => "Interrupted system call",
        EIO => "Input/output error",
        ENXIO => "No such device or address",
        E2BIG => "Argument list too long",
        ENOEXEC => "Exec format error",
        EBADF => "Bad file descriptor",
        ECHILD => "No child processes",
        EAGAIN => "Resource temporarily unavailable",
        ENOMEM => "Cannot allocate memory",
        EACCES => "Permission denied",
        EFAULT => "Bad address",
        ENOTBLK => "Block device required",
        EBUSY => "Device or resource busy",
        EEXIST => "File exists",
        EXDEV => "Invalid cross-device link",
        ENODEV => "No such device",
        ENOTDIR => "Not a directory",
        EISDIR => "Is a directory",
        EINVAL => "Invalid argument",
        ENFILE => "Too many open files in system",
        EMFILE => "Too many open files",
        ENOTTY => "Inappropriate ioctl for device",
        ETXTBSY => "Text file busy",
        EFBIG => "File too large",
        ENOSPC => "No space left on device",
        ESPIPE => "Illegal seek",
        EROFS => "Read-only file system",
        EMLINK => "Too many links",
        EPIPE => "Broken pipe",
        EDOM => "Numerical argument out of domain",
        ERANGE => "Numerical result out of range",
        EDEADLK => "Resource deadlock avoided",
        ENAMETOOLONG => "File name too long",
        ENOSYS => "Function not implemented",
        ENOTEMPTY => "Directory not empty",
        ELOOP => "Too many levels of symbolic links",
        EOVERFLOW => "Value too large for defined data type",
        EAFNOSUPPORT => "Address family not supported by protocol",
        EADDRINUSE => "Address already in use",
        EADDRNOTAVAIL => "Cannot assign requested address",
        ENETUNREACH => "Network is unreachable",
        ECONNABORTED => "Software caused connection abort",
        ECONNRESET => "Connection reset by peer",
        ENOBUFS => "No buffer space available",
        EISCONN => "Transport endpoint is already connected",
        ENOTCONN => "Transport endpoint is not connected",
        ETIMEDOUT => "Connection timed out",
        ECONNREFUSED => "Connection refused",
        EALREADY => "Operation already in progress",
        EINPROGRESS => "Operation now in progress",
        _ => "Unknown error",
    }
}

/// Returns the current thread-local errno value.
///
/// Equivalent to reading C `errno`.
pub fn get_errno() -> i32 {
    ERRNO.try_with(Cell::get).unwrap_or(0)
}

/// Sets the current thread-local errno value.
///
/// Equivalent to assigning to C `errno`.
pub fn set_errno(value: i32) {
    let _ = ERRNO.try_with(|cell| cell.set(value));
}

/// Helper to execute a closure that might set errno.
pub fn with_errno<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    f()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strerror_known() {
        assert_eq!(strerror_message(EINVAL), "Invalid argument");
        assert_eq!(strerror_message(ENOENT), "No such file or directory");
        assert_eq!(strerror_message(ENOMEM), "Cannot allocate memory");
        assert_eq!(strerror_message(0), "Success");
    }

    #[test]
    fn test_strerror_unknown() {
        assert_eq!(strerror_message(9999), "Unknown error");
    }

    #[test]
    fn test_errno_roundtrip() {
        set_errno(42);
        assert_eq!(get_errno(), 42);
        set_errno(0);
        assert_eq!(get_errno(), 0);
    }
}
