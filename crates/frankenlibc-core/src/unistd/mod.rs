//! POSIX operating system API.
//!
//! Safe validation helpers and constants for `<unistd.h>` and `<sys/stat.h>`
//! operations. The ABI layer handles actual syscalls; this module provides
//! argument validation and POSIX constant definitions only.

// ---------------------------------------------------------------------------
// lseek whence constants
// ---------------------------------------------------------------------------

/// Seek from beginning of file.
pub const SEEK_SET: i32 = 0;
/// Seek from current position.
pub const SEEK_CUR: i32 = 1;
/// Seek from end of file.
pub const SEEK_END: i32 = 2;

// ---------------------------------------------------------------------------
// access() mode constants
// ---------------------------------------------------------------------------

/// Test for existence of file.
pub const F_OK: i32 = 0;
/// Test for execute/search permission.
pub const X_OK: i32 = 1;
/// Test for write permission.
pub const W_OK: i32 = 2;
/// Test for read permission.
pub const R_OK: i32 = 4;

// ---------------------------------------------------------------------------
// Standard file descriptors
// ---------------------------------------------------------------------------

/// File descriptor for standard input.
pub const STDIN_FILENO: i32 = 0;
/// File descriptor for standard output.
pub const STDOUT_FILENO: i32 = 1;
/// File descriptor for standard error.
pub const STDERR_FILENO: i32 = 2;

// ---------------------------------------------------------------------------
// Miscellaneous limits
// ---------------------------------------------------------------------------

/// Maximum number of bytes in a pathname, including the terminating null.
pub const PATH_MAX: usize = 4096;

// ---------------------------------------------------------------------------
// File type mode bits (S_IF*)
// ---------------------------------------------------------------------------

/// Bit mask for the file type bit field.
pub const S_IFMT: u32 = 0o170000;
/// Regular file.
pub const S_IFREG: u32 = 0o100000;
/// Directory.
pub const S_IFDIR: u32 = 0o040000;
/// Symbolic link.
pub const S_IFLNK: u32 = 0o120000;
/// FIFO (named pipe).
pub const S_IFIFO: u32 = 0o010000;
/// Socket.
pub const S_IFSOCK: u32 = 0o140000;
/// Character device.
pub const S_IFCHR: u32 = 0o020000;
/// Block device.
pub const S_IFBLK: u32 = 0o060000;

// ---------------------------------------------------------------------------
// Permission and special bits
// ---------------------------------------------------------------------------

/// Set-user-ID on execution.
pub const S_ISUID: u32 = 0o4000;
/// Set-group-ID on execution.
pub const S_ISGID: u32 = 0o2000;
/// Sticky bit.
pub const S_ISVTX: u32 = 0o1000;

/// Owner read permission.
pub const S_IRUSR: u32 = 0o400;
/// Owner write permission.
pub const S_IWUSR: u32 = 0o200;
/// Owner execute permission.
pub const S_IXUSR: u32 = 0o100;

/// Group read permission.
pub const S_IRGRP: u32 = 0o040;
/// Group write permission.
pub const S_IWGRP: u32 = 0o020;
/// Group execute permission.
pub const S_IXGRP: u32 = 0o010;

/// Others read permission.
pub const S_IROTH: u32 = 0o004;
/// Others write permission.
pub const S_IWOTH: u32 = 0o002;
/// Others execute permission.
pub const S_IXOTH: u32 = 0o001;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Returns `true` if `fd` is a non-negative file descriptor.
#[inline]
pub fn valid_fd(fd: i32) -> bool {
    fd >= 0
}

/// Returns `true` if `whence` is a valid `lseek` whence value.
#[inline]
pub fn valid_whence(whence: i32) -> bool {
    matches!(whence, SEEK_SET | SEEK_CUR | SEEK_END)
}

/// Returns `true` if `mode` is a valid `access()` mode argument.
///
/// `F_OK` (0) is valid alone. Otherwise only bits `R_OK | W_OK | X_OK`
/// (i.e. bits 0, 1, 2) may be set, and at least one must be set.
#[inline]
pub fn valid_access_mode(mode: i32) -> bool {
    if mode == F_OK {
        return true;
    }
    // Only bits 0..=2 (X_OK=1, W_OK=2, R_OK=4) may be set, and at least one.
    let rwx_mask = R_OK | W_OK | X_OK; // 7
    mode > 0 && (mode & !rwx_mask) == 0
}

/// Returns `true` if a path buffer length is plausible.
///
/// A valid path must contain at least one byte and must not exceed `PATH_MAX`.
#[inline]
pub fn valid_path_ptr_heuristic(len: usize) -> bool {
    len > 0 && len <= PATH_MAX
}

// ---------------------------------------------------------------------------
// Stat mode helpers (pure bit manipulation)
// ---------------------------------------------------------------------------

/// Returns `true` if `mode` describes a regular file.
#[inline]
pub fn s_isreg(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFREG
}

/// Returns `true` if `mode` describes a directory.
#[inline]
pub fn s_isdir(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFDIR
}

/// Returns `true` if `mode` describes a symbolic link.
#[inline]
pub fn s_islnk(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFLNK
}

/// Returns `true` if `mode` describes a FIFO (named pipe).
#[inline]
pub fn s_isfifo(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFIFO
}

/// Returns `true` if `mode` describes a socket.
#[inline]
pub fn s_issock(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFSOCK
}

/// Returns `true` if `mode` describes a character device.
#[inline]
pub fn s_ischr(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFCHR
}

/// Returns `true` if `mode` describes a block device.
#[inline]
pub fn s_isblk(mode: u32) -> bool {
    (mode & S_IFMT) == S_IFBLK
}

// ---------------------------------------------------------------------------
// Path utilities
// ---------------------------------------------------------------------------

/// POSIX `basename` — extract the filename component of a path.
///
/// Returns `(start, end)` byte offsets into `path` giving the basename slice.
/// The result excludes any trailing slashes. Returns `"."` offsets if empty.
pub fn basename_range(path: &[u8]) -> (usize, usize) {
    if path.is_empty() {
        return (0, 0); // caller should substitute "."
    }

    // Strip trailing slashes
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }

    // All slashes → "/"
    if end == 0 {
        return (0, 1);
    }

    // Find last slash before the basename
    let mut start = end;
    while start > 0 && path[start - 1] != b'/' {
        start -= 1;
    }

    (start, end)
}

/// POSIX `dirname` — extract the directory component of a path.
///
/// Returns `(start, end)` byte offsets into `path` giving the dirname slice.
/// Returns `"."` offsets if there is no directory component.
pub fn dirname_range(path: &[u8]) -> (usize, usize) {
    if path.is_empty() {
        return (0, 0); // caller should substitute "."
    }

    // Strip trailing slashes
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }

    // All slashes → "/"
    if end == 0 {
        return (0, 1);
    }

    // Strip the basename (last component)
    while end > 0 && path[end - 1] != b'/' {
        end -= 1;
    }

    // No directory component → "."
    if end == 0 {
        return (0, 0); // caller should substitute "."
    }

    // Strip trailing slashes from the directory
    while end > 1 && path[end - 1] == b'/' {
        end -= 1;
    }

    (0, end)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Constant value tests -----------------------------------------------

    #[test]
    fn lseek_whence_values() {
        assert_eq!(SEEK_SET, 0);
        assert_eq!(SEEK_CUR, 1);
        assert_eq!(SEEK_END, 2);
    }

    #[test]
    fn access_mode_values() {
        assert_eq!(F_OK, 0);
        assert_eq!(X_OK, 1);
        assert_eq!(W_OK, 2);
        assert_eq!(R_OK, 4);
    }

    #[test]
    fn standard_fd_values() {
        assert_eq!(STDIN_FILENO, 0);
        assert_eq!(STDOUT_FILENO, 1);
        assert_eq!(STDERR_FILENO, 2);
    }

    #[test]
    fn path_max_value() {
        assert_eq!(PATH_MAX, 4096);
    }

    #[test]
    fn file_type_constant_values() {
        assert_eq!(S_IFMT, 0o170000);
        assert_eq!(S_IFREG, 0o100000);
        assert_eq!(S_IFDIR, 0o040000);
        assert_eq!(S_IFLNK, 0o120000);
        assert_eq!(S_IFIFO, 0o010000);
        assert_eq!(S_IFSOCK, 0o140000);
        assert_eq!(S_IFCHR, 0o020000);
        assert_eq!(S_IFBLK, 0o060000);
    }

    #[test]
    fn special_bit_values() {
        assert_eq!(S_ISUID, 0o4000);
        assert_eq!(S_ISGID, 0o2000);
        assert_eq!(S_ISVTX, 0o1000);
    }

    #[test]
    fn permission_bit_values() {
        assert_eq!(S_IRUSR, 0o400);
        assert_eq!(S_IWUSR, 0o200);
        assert_eq!(S_IXUSR, 0o100);
        assert_eq!(S_IRGRP, 0o040);
        assert_eq!(S_IWGRP, 0o020);
        assert_eq!(S_IXGRP, 0o010);
        assert_eq!(S_IROTH, 0o004);
        assert_eq!(S_IWOTH, 0o002);
        assert_eq!(S_IXOTH, 0o001);
    }

    // -- valid_fd tests -----------------------------------------------------

    #[test]
    fn valid_fd_accepts_non_negative() {
        assert!(valid_fd(0));
        assert!(valid_fd(1));
        assert!(valid_fd(2));
        assert!(valid_fd(1023));
        assert!(valid_fd(i32::MAX));
    }

    #[test]
    fn valid_fd_rejects_negative() {
        assert!(!valid_fd(-1));
        assert!(!valid_fd(-100));
        assert!(!valid_fd(i32::MIN));
    }

    // -- valid_whence tests -------------------------------------------------

    #[test]
    fn valid_whence_accepts_known() {
        assert!(valid_whence(SEEK_SET));
        assert!(valid_whence(SEEK_CUR));
        assert!(valid_whence(SEEK_END));
    }

    #[test]
    fn valid_whence_rejects_unknown() {
        assert!(!valid_whence(-1));
        assert!(!valid_whence(3));
        assert!(!valid_whence(100));
        assert!(!valid_whence(i32::MIN));
        assert!(!valid_whence(i32::MAX));
    }

    // -- valid_access_mode tests --------------------------------------------

    #[test]
    fn valid_access_mode_f_ok() {
        assert!(valid_access_mode(F_OK));
    }

    #[test]
    fn valid_access_mode_single_bits() {
        assert!(valid_access_mode(R_OK));
        assert!(valid_access_mode(W_OK));
        assert!(valid_access_mode(X_OK));
    }

    #[test]
    fn valid_access_mode_combinations() {
        assert!(valid_access_mode(R_OK | W_OK));
        assert!(valid_access_mode(R_OK | X_OK));
        assert!(valid_access_mode(W_OK | X_OK));
        assert!(valid_access_mode(R_OK | W_OK | X_OK));
    }

    #[test]
    fn valid_access_mode_rejects_invalid() {
        assert!(!valid_access_mode(-1));
        assert!(!valid_access_mode(8));
        assert!(!valid_access_mode(16));
        assert!(!valid_access_mode(0xFF));
        assert!(!valid_access_mode(R_OK | 8));
        assert!(!valid_access_mode(i32::MIN));
    }

    // -- valid_path_ptr_heuristic tests -------------------------------------

    #[test]
    fn valid_path_ptr_heuristic_accepts_valid() {
        assert!(valid_path_ptr_heuristic(1));
        assert!(valid_path_ptr_heuristic(255));
        assert!(valid_path_ptr_heuristic(PATH_MAX));
    }

    #[test]
    fn valid_path_ptr_heuristic_rejects_invalid() {
        assert!(!valid_path_ptr_heuristic(0));
        assert!(!valid_path_ptr_heuristic(PATH_MAX + 1));
        assert!(!valid_path_ptr_heuristic(usize::MAX));
    }

    // -- Stat mode helper tests ---------------------------------------------

    #[test]
    fn s_isreg_identifies_regular_file() {
        assert!(s_isreg(S_IFREG));
        assert!(s_isreg(S_IFREG | 0o644));
        assert!(!s_isreg(S_IFDIR));
        assert!(!s_isreg(S_IFLNK));
        assert!(!s_isreg(0));
    }

    #[test]
    fn s_isdir_identifies_directory() {
        assert!(s_isdir(S_IFDIR));
        assert!(s_isdir(S_IFDIR | 0o755));
        assert!(!s_isdir(S_IFREG));
        assert!(!s_isdir(S_IFLNK));
        assert!(!s_isdir(0));
    }

    #[test]
    fn s_islnk_identifies_symlink() {
        assert!(s_islnk(S_IFLNK));
        assert!(s_islnk(S_IFLNK | 0o777));
        assert!(!s_islnk(S_IFREG));
        assert!(!s_islnk(S_IFDIR));
        assert!(!s_islnk(0));
    }

    #[test]
    fn s_isfifo_identifies_named_pipe() {
        assert!(s_isfifo(S_IFIFO));
        assert!(s_isfifo(S_IFIFO | 0o600));
        assert!(!s_isfifo(S_IFREG));
        assert!(!s_isfifo(S_IFSOCK));
        assert!(!s_isfifo(0));
    }

    #[test]
    fn s_issock_identifies_socket() {
        assert!(s_issock(S_IFSOCK));
        assert!(s_issock(S_IFSOCK | 0o755));
        assert!(!s_issock(S_IFREG));
        assert!(!s_issock(S_IFIFO));
        assert!(!s_issock(0));
    }

    #[test]
    fn s_ischr_identifies_char_device() {
        assert!(s_ischr(S_IFCHR));
        assert!(s_ischr(S_IFCHR | 0o666));
        assert!(!s_ischr(S_IFREG));
        assert!(!s_ischr(S_IFBLK));
        assert!(!s_ischr(0));
    }

    #[test]
    fn s_isblk_identifies_block_device() {
        assert!(s_isblk(S_IFBLK));
        assert!(s_isblk(S_IFBLK | 0o660));
        assert!(!s_isblk(S_IFREG));
        assert!(!s_isblk(S_IFCHR));
        assert!(!s_isblk(0));
    }

    // -- Exhaustive mode type mutual exclusion ------------------------------

    #[test]
    fn stat_mode_helpers_mutually_exclusive() {
        let types = [
            S_IFREG, S_IFDIR, S_IFLNK, S_IFIFO, S_IFSOCK, S_IFCHR, S_IFBLK,
        ];
        let checkers: [fn(u32) -> bool; 7] = [
            s_isreg, s_isdir, s_islnk, s_isfifo, s_issock, s_ischr, s_isblk,
        ];

        for (i, &ty) in types.iter().enumerate() {
            let mode = ty | 0o755; // add permissions to verify they don't interfere
            for (j, checker) in checkers.iter().enumerate() {
                if i == j {
                    assert!(checker(mode), "checker {j} should match type {ty:#o}");
                } else {
                    assert!(!checker(mode), "checker {j} should NOT match type {ty:#o}");
                }
            }
        }
    }

    // -- Mode zero matches nothing ------------------------------------------

    #[test]
    fn zero_mode_matches_no_type() {
        assert!(!s_isreg(0));
        assert!(!s_isdir(0));
        assert!(!s_islnk(0));
        assert!(!s_isfifo(0));
        assert!(!s_issock(0));
        assert!(!s_ischr(0));
        assert!(!s_isblk(0));
    }

    // -- Permission bits do not affect type detection -----------------------

    #[test]
    fn permissions_do_not_affect_type() {
        let all_perms = S_ISUID | S_ISGID | S_ISVTX | 0o777;
        assert!(s_isreg(S_IFREG | all_perms));
        assert!(s_isdir(S_IFDIR | all_perms));
        assert!(s_islnk(S_IFLNK | all_perms));
        assert!(s_isfifo(S_IFIFO | all_perms));
        assert!(s_issock(S_IFSOCK | all_perms));
        assert!(s_ischr(S_IFCHR | all_perms));
        assert!(s_isblk(S_IFBLK | all_perms));
    }

    // -- S_IFMT mask extracts type correctly --------------------------------

    #[test]
    fn s_ifmt_mask_extracts_type() {
        let mode = S_IFREG | S_ISUID | S_ISGID | S_ISVTX | 0o777;
        assert_eq!(mode & S_IFMT, S_IFREG);
    }

    // -- basename/dirname tests -----------------------------------------------

    #[test]
    fn basename_normal_path() {
        let path = b"/usr/lib/libfoo.so";
        let (s, e) = basename_range(path);
        assert_eq!(&path[s..e], b"libfoo.so");
    }

    #[test]
    fn basename_trailing_slash() {
        let path = b"/usr/lib/";
        let (s, e) = basename_range(path);
        assert_eq!(&path[s..e], b"lib");
    }

    #[test]
    fn basename_root() {
        let path = b"/";
        let (s, e) = basename_range(path);
        assert_eq!(&path[s..e], b"/");
    }

    #[test]
    fn basename_no_slash() {
        let path = b"foo.txt";
        let (s, e) = basename_range(path);
        assert_eq!(&path[s..e], b"foo.txt");
    }

    #[test]
    fn dirname_normal_path() {
        let path = b"/usr/lib/libfoo.so";
        let (s, e) = dirname_range(path);
        assert_eq!(&path[s..e], b"/usr/lib");
    }

    #[test]
    fn dirname_trailing_slash() {
        let path = b"/usr/lib/";
        let (s, e) = dirname_range(path);
        assert_eq!(&path[s..e], b"/usr");
    }

    #[test]
    fn dirname_root() {
        let path = b"/";
        let (s, e) = dirname_range(path);
        assert_eq!(&path[s..e], b"/");
    }

    #[test]
    fn dirname_no_slash() {
        let (s, e) = dirname_range(b"foo.txt");
        assert_eq!(s, 0);
        assert_eq!(e, 0); // caller substitutes "."
    }
}
