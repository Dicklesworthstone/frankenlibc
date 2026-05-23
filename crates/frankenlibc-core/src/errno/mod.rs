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
pub const EILSEQ: i32 = 84;
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
pub const ECANCELED: i32 = 125;

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
        EILSEQ => "Invalid or incomplete multibyte or wide character",
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
        ECANCELED => "Operation canceled",
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

    #[test]
    fn errno_is_thread_local_across_child_threads_and_join() -> Result<(), String> {
        set_errno(EACCES);

        let thread_a = std::thread::spawn(|| {
            set_errno(EINVAL);
            std::thread::yield_now();
            get_errno()
        });
        let thread_b = std::thread::spawn(|| {
            set_errno(ERANGE);
            std::thread::yield_now();
            get_errno()
        });

        let a_errno = thread_a
            .join()
            .map_err(|_| String::from("thread A panicked while checking errno isolation"))?;
        let b_errno = thread_b
            .join()
            .map_err(|_| String::from("thread B panicked while checking errno isolation"))?;

        assert_eq!(a_errno, EINVAL);
        assert_eq!(b_errno, ERANGE);
        assert_eq!(get_errno(), EACCES);

        set_errno(0);
        Ok(())
    }

    // ===== glibc parity tests =====
    // Verified against glibc via scripts/c_probes/probe_error_edge.c

    #[test]
    fn glibc_strerror_zero_is_success() {
        // strerror(0) = "Success"
        assert_eq!(strerror_message(0), "Success");
    }

    #[test]
    fn glibc_strerror_common_codes_match() {
        // Verify exact message text matches glibc
        assert_eq!(strerror_message(EPERM), "Operation not permitted");
        assert_eq!(strerror_message(ENOENT), "No such file or directory");
        assert_eq!(strerror_message(EIO), "Input/output error");
        assert_eq!(strerror_message(ENOMEM), "Cannot allocate memory");
        assert_eq!(strerror_message(EACCES), "Permission denied");
        assert_eq!(strerror_message(EEXIST), "File exists");
        assert_eq!(strerror_message(ENOTDIR), "Not a directory");
        assert_eq!(strerror_message(EISDIR), "Is a directory");
        assert_eq!(strerror_message(EINVAL), "Invalid argument");
        assert_eq!(strerror_message(EMFILE), "Too many open files");
        assert_eq!(strerror_message(ENOSPC), "No space left on device");
        assert_eq!(strerror_message(ERANGE), "Numerical result out of range");
    }

    #[test]
    fn glibc_strerror_eagain_ewouldblock_same() {
        // EAGAIN and EWOULDBLOCK are the same on Linux (11)
        assert_eq!(EAGAIN, 11);
        assert_eq!(strerror_message(EAGAIN), "Resource temporarily unavailable");
    }

    #[test]
    fn glibc_strerror_network_codes() {
        assert_eq!(strerror_message(ETIMEDOUT), "Connection timed out");
        assert_eq!(strerror_message(ECONNREFUSED), "Connection refused");
    }

    #[test]
    fn glibc_errno_constants_match() {
        // Verify errno constants match glibc values
        assert_eq!(EPERM, 1);
        assert_eq!(ENOENT, 2);
        assert_eq!(ESRCH, 3);
        assert_eq!(EINTR, 4);
        assert_eq!(EIO, 5);
        assert_eq!(ENXIO, 6);
        assert_eq!(E2BIG, 7);
        assert_eq!(EBADF, 9);
        assert_eq!(ECHILD, 10);
        assert_eq!(EAGAIN, 11);
        assert_eq!(ENOMEM, 12);
        assert_eq!(EINVAL, 22);
        assert_eq!(EDOM, 33);
        assert_eq!(ERANGE, 34);
        assert_eq!(EDEADLK, 35);
    }
}
