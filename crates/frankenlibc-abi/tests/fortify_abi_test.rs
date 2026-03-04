#![cfg(target_os = "linux")]

//! Integration tests for `_FORTIFY_SOURCE` ABI entrypoints (`__*_chk` variants).
//!
//! Tests cover safe pass-through paths where buffer sizes are sufficient.
//! The abort paths (__chk_fail) cannot be tested in-process since they call abort().

use std::ffi::{c_char, c_int, c_long, CString};

// Re-export fortified functions from the ABI crate.
use frankenlibc_abi::fortify_abi::*;

// ===========================================================================
// Memory operations: __memcpy_chk, __memmove_chk, __memset_chk,
//                    __explicit_bzero_chk
// ===========================================================================

#[test]
fn memcpy_chk_safe() {
    let src = [1u8, 2, 3, 4, 5];
    let mut dest = [0u8; 8];
    let ret = unsafe {
        __memcpy_chk(
            dest.as_mut_ptr().cast(),
            src.as_ptr().cast(),
            5,
            8, // destlen >= len
        )
    };
    assert_eq!(ret, dest.as_mut_ptr().cast());
    assert_eq!(&dest[..5], &[1, 2, 3, 4, 5]);
}

#[test]
fn memcpy_chk_exact_fit() {
    let src = [0xAAu8; 4];
    let mut dest = [0u8; 4];
    unsafe {
        __memcpy_chk(dest.as_mut_ptr().cast(), src.as_ptr().cast(), 4, 4);
    }
    assert_eq!(dest, [0xAA; 4]);
}

#[test]
fn memmove_chk_overlapping() {
    let mut buf = [1u8, 2, 3, 4, 5, 0, 0, 0];
    // Move [1,2,3,4,5] two positions right within same buffer.
    unsafe {
        __memmove_chk(
            buf.as_mut_ptr().add(2).cast(),
            buf.as_ptr().cast(),
            5,
            6, // destlen covers positions 2..8
        );
    }
    assert_eq!(&buf[2..7], &[1, 2, 3, 4, 5]);
}

#[test]
fn memset_chk_fills() {
    let mut buf = [0u8; 16];
    unsafe {
        __memset_chk(buf.as_mut_ptr().cast(), 0x42, 10, 16);
    }
    assert_eq!(&buf[..10], &[0x42; 10]);
    assert_eq!(&buf[10..], &[0; 6]);
}

#[test]
fn explicit_bzero_chk_zeroes() {
    let mut buf = [0xFFu8; 8];
    unsafe {
        __explicit_bzero_chk(buf.as_mut_ptr().cast(), 8, 8);
    }
    assert_eq!(buf, [0; 8]);
}

#[test]
fn explicit_bzero_chk_partial() {
    let mut buf = [0xFFu8; 8];
    unsafe {
        __explicit_bzero_chk(buf.as_mut_ptr().cast(), 4, 8);
    }
    assert_eq!(&buf[..4], &[0; 4]);
    assert_eq!(&buf[4..], &[0xFF; 4]);
}

// ===========================================================================
// String operations: __strcpy_chk, __strncpy_chk, __strcat_chk,
//                    __strncat_chk, __stpcpy_chk, __stpncpy_chk
// ===========================================================================

#[test]
fn strcpy_chk_safe() {
    let src = CString::new("hello").unwrap();
    let mut dest = [0u8; 16];
    let ret = unsafe {
        __strcpy_chk(
            dest.as_mut_ptr().cast(),
            src.as_ptr(),
            16,
        )
    };
    assert_eq!(ret, dest.as_mut_ptr().cast::<c_char>());
    assert_eq!(&dest[..6], b"hello\0");
}

#[test]
fn strncpy_chk_safe() {
    let src = CString::new("world").unwrap();
    let mut dest = [0xFFu8; 10];
    unsafe {
        __strncpy_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 10, 10);
    }
    assert_eq!(&dest[..5], b"world");
    // strncpy pads with zeros
    assert_eq!(&dest[5..], &[0; 5]);
}

#[test]
fn strcat_chk_safe() {
    let mut dest = [0u8; 32];
    dest[0] = b'A';
    dest[1] = b'B';
    dest[2] = 0;
    let src = CString::new("CD").unwrap();
    unsafe {
        __strcat_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 32);
    }
    assert_eq!(&dest[..5], b"ABCD\0");
}

#[test]
fn strncat_chk_safe() {
    let mut dest = [0u8; 32];
    dest[0] = b'X';
    dest[1] = 0;
    let src = CString::new("YZWV").unwrap();
    // Append at most 2 chars
    unsafe {
        __strncat_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 2, 32);
    }
    assert_eq!(&dest[..4], b"XYZ\0");
}

#[test]
fn strncat_chk_shorter_src() {
    let mut dest = [0u8; 32];
    dest[0] = b'A';
    dest[1] = 0;
    let src = CString::new("B").unwrap();
    // n=10 but src is only "B" (1 char)
    unsafe {
        __strncat_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 10, 32);
    }
    assert_eq!(&dest[..3], b"AB\0");
}

#[test]
fn stpcpy_chk_returns_end() {
    let src = CString::new("test").unwrap();
    let mut dest = [0u8; 16];
    let end = unsafe { __stpcpy_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 16) };
    assert_eq!(&dest[..5], b"test\0");
    // end should point to the NUL terminator
    let offset = unsafe { end.offset_from(dest.as_ptr().cast::<c_char>()) };
    assert_eq!(offset, 4);
}

#[test]
fn stpncpy_chk_returns_position() {
    let src = CString::new("ab").unwrap();
    let mut dest = [0xFFu8; 8];
    let end = unsafe { __stpncpy_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 5, 8) };
    // "ab" fits in 5. Copied "ab\0\0\0", end should point to first \0 (position 2)
    let offset = unsafe { end.offset_from(dest.as_ptr().cast::<c_char>()) };
    assert_eq!(offset, 2);
    assert_eq!(&dest[..2], b"ab");
}

#[test]
fn stpncpy_chk_exact_fill() {
    let src = CString::new("abcde").unwrap();
    let mut dest = [0u8; 5];
    let end = unsafe { __stpncpy_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 5, 5) };
    // "abcde" fills all 5 bytes, no NUL within n
    let offset = unsafe { end.offset_from(dest.as_ptr().cast::<c_char>()) };
    assert_eq!(offset, 5);
    assert_eq!(&dest, b"abcde");
}

// ===========================================================================
// Wide string operations: __wcscpy_chk, __wcsncpy_chk, __wcscat_chk,
//                         __wcsncat_chk, __wmemcpy_chk, __wmemmove_chk,
//                         __wmemset_chk
// ===========================================================================

type WcharT = c_int;

#[test]
fn wcscpy_chk_safe() {
    let src: [WcharT; 4] = [b'H' as i32, b'i' as i32, b'!' as i32, 0];
    let mut dest = [0i32; 8];
    let ret = unsafe {
        __wcscpy_chk(
            dest.as_mut_ptr(),
            src.as_ptr(),
            8 * 4, // destlen in bytes
        )
    };
    assert_eq!(ret, dest.as_mut_ptr());
    assert_eq!(&dest[..4], &src);
}

#[test]
fn wcsncpy_chk_safe() {
    let src: [WcharT; 3] = [b'A' as i32, b'B' as i32, 0];
    let mut dest = [0xFFi32; 4];
    unsafe {
        __wcsncpy_chk(dest.as_mut_ptr(), src.as_ptr(), 4, 4 * 4);
    }
    assert_eq!(dest[0], b'A' as i32);
    assert_eq!(dest[1], b'B' as i32);
    assert_eq!(dest[2], 0); // null terminator from src
    assert_eq!(dest[3], 0); // padding
}

#[test]
fn wcscat_chk_safe() {
    let mut dest = [0i32; 8];
    dest[0] = b'X' as i32;
    dest[1] = 0;
    let src: [WcharT; 3] = [b'Y' as i32, b'Z' as i32, 0];
    unsafe {
        __wcscat_chk(dest.as_mut_ptr(), src.as_ptr(), 8 * 4);
    }
    assert_eq!(dest[0], b'X' as i32);
    assert_eq!(dest[1], b'Y' as i32);
    assert_eq!(dest[2], b'Z' as i32);
    assert_eq!(dest[3], 0);
}

#[test]
fn wcsncat_chk_safe() {
    let mut dest = [0i32; 8];
    dest[0] = b'A' as i32;
    dest[1] = 0;
    let src: [WcharT; 4] = [b'B' as i32, b'C' as i32, b'D' as i32, 0];
    // Append at most 2 wide chars
    unsafe {
        __wcsncat_chk(dest.as_mut_ptr(), src.as_ptr(), 2, 8 * 4);
    }
    assert_eq!(dest[0], b'A' as i32);
    assert_eq!(dest[1], b'B' as i32);
    assert_eq!(dest[2], b'C' as i32);
    assert_eq!(dest[3], 0);
}

#[test]
fn wmemcpy_chk_safe() {
    let src: [WcharT; 3] = [100, 200, 300];
    let mut dest = [0i32; 4];
    let ret = unsafe { __wmemcpy_chk(dest.as_mut_ptr(), src.as_ptr(), 3, 4 * 4) };
    assert_eq!(ret, dest.as_mut_ptr());
    assert_eq!(&dest[..3], &[100, 200, 300]);
}

#[test]
fn wmemmove_chk_safe() {
    let mut buf = [1i32, 2, 3, 4, 0, 0];
    // Overlapping move: shift right by 2
    unsafe {
        __wmemmove_chk(
            buf.as_mut_ptr().add(2),
            buf.as_ptr(),
            3,
            4 * 4, // destlen covers buf[2..6]
        );
    }
    assert_eq!(&buf[2..5], &[1, 2, 3]);
}

#[test]
fn wmemset_chk_safe() {
    let mut buf = [0i32; 5];
    let ret = unsafe { __wmemset_chk(buf.as_mut_ptr(), 42, 5, 5 * 4) };
    assert_eq!(ret, buf.as_mut_ptr());
    assert_eq!(buf, [42; 5]);
}

// ===========================================================================
// Printf family: __vsnprintf_chk, __vsprintf_chk, __snprintf_chk
// ===========================================================================

#[test]
fn vsnprintf_chk_safe() {
    let mut buf = [0u8; 64];
    let fmt = CString::new("value=%d").unwrap();
    // Use __snprintf_chk (variadic) since we can't easily construct va_list
    let ret = unsafe {
        __snprintf_chk(
            buf.as_mut_ptr().cast(),
            64,      // maxlen
            0,       // flag
            64,      // buflen
            fmt.as_ptr(),
            42i32,
        )
    };
    assert!(ret > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
    assert_eq!(s.to_str().unwrap(), "value=42");
}

#[test]
fn sprintf_chk_safe() {
    let mut buf = [0u8; 64];
    let fmt = CString::new("hello %s").unwrap();
    let arg = CString::new("world").unwrap();
    let ret = unsafe {
        __sprintf_chk(
            buf.as_mut_ptr().cast(),
            0,  // flag
            64, // buflen
            fmt.as_ptr(),
            arg.as_ptr(),
        )
    };
    assert_eq!(ret, 11); // "hello world"
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
    assert_eq!(s.to_str().unwrap(), "hello world");
}

#[test]
fn snprintf_chk_truncates() {
    let mut buf = [0u8; 8];
    let fmt = CString::new("longstring").unwrap();
    let ret = unsafe {
        __snprintf_chk(
            buf.as_mut_ptr().cast(),
            8,  // maxlen
            0,  // flag
            8,  // buflen
            fmt.as_ptr(),
        )
    };
    // vsnprintf returns full length even if truncated
    assert_eq!(ret, 10);
    // Buffer should have "longstr\0"
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
    assert_eq!(s.to_str().unwrap(), "longstr");
}

// ===========================================================================
// Read/pread operations: __read_chk, __pread_chk, __pread64_chk
// ===========================================================================

#[test]
fn read_chk_safe() {
    // Create a pipe to test read_chk
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

    let msg = b"test";
    unsafe { libc::write(fds[1], msg.as_ptr().cast(), 4) };
    unsafe { libc::close(fds[1]) };

    let mut buf = [0u8; 16];
    let n = unsafe { __read_chk(fds[0], buf.as_mut_ptr().cast(), 4, 16) };
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"test");

    unsafe { libc::close(fds[0]) };
}

#[test]
fn pread_chk_safe() {
    // Create a temp file
    let path = CString::new("/tmp/fortify_pread_test").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    assert!(fd >= 0);

    let data = b"ABCDEFGH";
    unsafe { libc::write(fd, data.as_ptr().cast(), 8) };

    let mut buf = [0u8; 8];
    let n = unsafe { __pread_chk(fd, buf.as_mut_ptr().cast(), 4, 2, 8) };
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"CDEF");

    unsafe {
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
}

#[test]
fn pread64_chk_safe() {
    let path = CString::new("/tmp/fortify_pread64_test").unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    assert!(fd >= 0);

    let data = b"0123456789";
    unsafe { libc::write(fd, data.as_ptr().cast(), 10) };

    let mut buf = [0u8; 16];
    let n = unsafe { __pread64_chk(fd, buf.as_mut_ptr().cast(), 3, 5, 16) };
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"567");

    unsafe {
        libc::close(fd);
        libc::unlink(path.as_ptr());
    }
}

// ===========================================================================
// Path/name operations: __getcwd_chk, __getwd_chk, __readlink_chk,
//                       __readlinkat_chk, __realpath_chk,
//                       __gethostname_chk, __confstr_chk
// ===========================================================================

#[test]
fn getcwd_chk_safe() {
    let mut buf = [0u8; 4096];
    let ret = unsafe { __getcwd_chk(buf.as_mut_ptr().cast(), 4096, 4096) };
    assert!(!ret.is_null());
    let cwd = unsafe { std::ffi::CStr::from_ptr(ret) };
    assert!(cwd.to_str().unwrap().starts_with('/'));
}

#[test]
fn getwd_chk_safe() {
    let mut buf = [0u8; 4096];
    let ret = unsafe { __getwd_chk(buf.as_mut_ptr().cast(), 4096) };
    assert!(!ret.is_null());
    let cwd = unsafe { std::ffi::CStr::from_ptr(ret) };
    assert!(cwd.to_str().unwrap().starts_with('/'));
}

#[test]
fn readlink_chk_safe() {
    let path = CString::new("/proc/self/exe").unwrap();
    let mut buf = [0u8; 4096];
    let n = unsafe { __readlink_chk(path.as_ptr(), buf.as_mut_ptr().cast(), 4096, 4096) };
    assert!(n > 0, "readlink /proc/self/exe should succeed");
}

#[test]
fn readlinkat_chk_safe() {
    let path = CString::new("/proc/self/exe").unwrap();
    let mut buf = [0u8; 4096];
    let n = unsafe {
        __readlinkat_chk(libc::AT_FDCWD, path.as_ptr(), buf.as_mut_ptr().cast(), 4096, 4096)
    };
    assert!(n > 0, "readlinkat /proc/self/exe should succeed");
}

#[test]
fn realpath_chk_safe() {
    let path = CString::new("/tmp").unwrap();
    let mut buf = [0u8; 4096];
    let ret = unsafe { __realpath_chk(path.as_ptr(), buf.as_mut_ptr().cast(), 4096) };
    assert!(!ret.is_null());
    let resolved = unsafe { std::ffi::CStr::from_ptr(ret) };
    // /tmp might be a symlink to /private/tmp on some systems, but should resolve
    assert!(resolved.to_str().unwrap().contains("tmp"));
}

#[test]
fn gethostname_chk_safe() {
    let mut buf = [0u8; 256];
    let ret = unsafe { __gethostname_chk(buf.as_mut_ptr().cast(), 256, 256) };
    assert_eq!(ret, 0);
    // Should have a non-empty hostname
    assert_ne!(buf[0], 0);
}

#[test]
fn confstr_chk_safe() {
    let mut buf = [0u8; 256];
    // _CS_PATH = 0 on Linux
    let n = unsafe { __confstr_chk(0, buf.as_mut_ptr().cast(), 256, 256) };
    // confstr returns the required size including NUL
    assert!(n > 0, "confstr(_CS_PATH) should return a path");
}

#[test]
fn getdomainname_chk_safe() {
    let mut buf = [0u8; 256];
    let ret = unsafe { __getdomainname_chk(buf.as_mut_ptr().cast(), 256, 256) };
    // May return 0 (success) or -1 (no domain set), both are valid
    assert!(ret == 0 || ret == -1);
}

// ===========================================================================
// Misc: __getgroups_chk, __ttyname_r_chk, __getlogin_r_chk
// ===========================================================================

#[test]
fn getgroups_chk_safe() {
    // First get count
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    assert!(n >= 0);
    if n > 0 {
        let mut groups = vec![0u32; n as usize];
        let listlen = (n as usize) * 4;
        let ret = unsafe { __getgroups_chk(n, groups.as_mut_ptr(), listlen) };
        assert_eq!(ret, n);
    }
}

#[test]
fn ttyname_r_chk_not_a_tty() {
    let mut buf = [0u8; 256];
    // fd=0 (stdin) in test environment is likely not a tty
    let ret = unsafe { __ttyname_r_chk(0, buf.as_mut_ptr().cast(), 256, 256) };
    // ENOTTY or success, either is valid
    assert!(ret == 0 || ret == libc::ENOTTY || ret == libc::EBADF);
}

// ===========================================================================
// Open variants: __open_2, __open64_2, __openat_2, __openat64_2
// ===========================================================================

#[test]
fn open_2_safe() {
    let path = CString::new("/dev/null").unwrap();
    let fd = unsafe { __open_2(path.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open /dev/null should succeed");
    unsafe { libc::close(fd) };
}

#[test]
fn open64_2_safe() {
    let path = CString::new("/dev/null").unwrap();
    let fd = unsafe { __open64_2(path.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "open64 /dev/null should succeed");
    unsafe { libc::close(fd) };
}

#[test]
fn openat_2_safe() {
    let path = CString::new("/dev/null").unwrap();
    let fd = unsafe { __openat_2(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "openat /dev/null should succeed");
    unsafe { libc::close(fd) };
}

#[test]
fn openat64_2_safe() {
    let path = CString::new("/dev/null").unwrap();
    let fd = unsafe { __openat64_2(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY) };
    assert!(fd >= 0, "openat64 /dev/null should succeed");
    unsafe { libc::close(fd) };
}

// ===========================================================================
// FD_SET check: __fdelt_chk
// ===========================================================================

#[test]
fn fdelt_chk_valid_fds() {
    // fd 0 => element 0 (0 / 64 on x86_64)
    let idx = unsafe { __fdelt_chk(0) };
    assert_eq!(idx, 0);

    // fd 63 => element 0
    let idx = unsafe { __fdelt_chk(63) };
    assert_eq!(idx, 0);

    // fd 64 => element 1
    let idx = unsafe { __fdelt_chk(64) };
    assert_eq!(idx, 1);

    // fd 1023 => element 15 (1023 / 64 on x86_64)
    let bits = 8 * std::mem::size_of::<c_long>() as c_long;
    let idx = unsafe { __fdelt_chk(1023) };
    assert_eq!(idx, 1023 / bits);
}

// ===========================================================================
// Poll: __poll_chk, __ppoll_chk
// ===========================================================================

#[test]
fn poll_chk_safe() {
    // Create a pipe and poll the read end
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

    let mut pfd = libc::pollfd {
        fd: fds[0],
        events: libc::POLLIN,
        revents: 0,
    };
    let fdslen = std::mem::size_of::<libc::pollfd>();
    let ret = unsafe {
        __poll_chk(
            (&mut pfd as *mut libc::pollfd).cast(),
            1,       // nfds
            0,       // timeout=0 (instant)
            fdslen,
        )
    };
    // Should return 0 (timeout, nothing ready) or >= 0
    assert!(ret >= 0);

    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

#[test]
fn ppoll_chk_safe() {
    let mut fds = [0i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);

    let mut pfd = libc::pollfd {
        fd: fds[0],
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let fdslen = std::mem::size_of::<libc::pollfd>();
    let ret = unsafe {
        __ppoll_chk(
            (&mut pfd as *mut libc::pollfd).cast(),
            1,
            &timeout,
            std::ptr::null(),
            fdslen,
        )
    };
    assert!(ret >= 0);

    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
}

// ===========================================================================
// Multibyte conversion: __mbstowcs_chk, __wcstombs_chk, __wctomb_chk
// ===========================================================================

#[test]
fn mbstowcs_chk_safe() {
    let src = CString::new("abc").unwrap();
    let mut dest = [0i32; 8];
    let n = unsafe {
        __mbstowcs_chk(dest.as_mut_ptr(), src.as_ptr(), 8, 8 * 4)
    };
    assert_eq!(n, 3);
    assert_eq!(dest[0], b'a' as i32);
    assert_eq!(dest[1], b'b' as i32);
    assert_eq!(dest[2], b'c' as i32);
}

#[test]
fn wcstombs_chk_safe() {
    let src: [WcharT; 4] = [b'x' as i32, b'y' as i32, b'z' as i32, 0];
    let mut dest = [0u8; 16];
    let n = unsafe {
        __wcstombs_chk(dest.as_mut_ptr().cast(), src.as_ptr(), 16, 16)
    };
    assert_eq!(n, 3);
    assert_eq!(&dest[..3], b"xyz");
}

#[test]
fn wctomb_chk_safe() {
    let mut buf = [0u8; 8];
    let n = unsafe { __wctomb_chk(buf.as_mut_ptr().cast(), b'Q' as WcharT, 8) };
    assert!(n > 0);
    assert_eq!(buf[0], b'Q');
}

#[test]
fn mbsrtowcs_chk_safe() {
    let src_str = CString::new("hi").unwrap();
    let mut src_ptr: *const c_char = src_str.as_ptr();
    let mut dest = [0i32; 8];
    let n = unsafe {
        __mbsrtowcs_chk(
            dest.as_mut_ptr(),
            &mut src_ptr,
            8,
            std::ptr::null_mut(), // NULL mbstate_t = initial state
            8 * 4,
        )
    };
    assert_eq!(n, 2);
    assert_eq!(dest[0], b'h' as i32);
    assert_eq!(dest[1], b'i' as i32);
}

#[test]
fn wcsrtombs_chk_safe() {
    let src_arr: [WcharT; 3] = [b'A' as i32, b'B' as i32, 0];
    let mut src_ptr: *const WcharT = src_arr.as_ptr();
    let mut dest = [0u8; 16];
    let n = unsafe {
        __wcsrtombs_chk(
            dest.as_mut_ptr().cast(),
            &mut src_ptr as *mut *const WcharT,
            16,
            std::ptr::null_mut(),
            16,
        )
    };
    assert_eq!(n, 2);
    assert_eq!(&dest[..2], b"AB");
}

// ===========================================================================
// Printf to buffer: edge cases
// ===========================================================================

#[test]
fn sprintf_chk_integer_formats() {
    let mut buf = [0u8; 128];
    let fmt = CString::new("%d + %d = %d").unwrap();
    let ret = unsafe {
        __sprintf_chk(buf.as_mut_ptr().cast(), 0, 128, fmt.as_ptr(), 3i32, 4i32, 7i32)
    };
    assert!(ret > 0);
    let s = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr().cast()) };
    assert_eq!(s.to_str().unwrap(), "3 + 4 = 7");
}

#[test]
fn snprintf_chk_zero_maxlen() {
    let mut buf = [0xFFu8; 8];
    let fmt = CString::new("anything").unwrap();
    // maxlen=0 means just measure
    let ret = unsafe {
        __snprintf_chk(buf.as_mut_ptr().cast(), 0, 0, 8, fmt.as_ptr())
    };
    assert_eq!(ret, 8); // "anything" is 8 chars
    // Buffer should be untouched
    assert_eq!(buf[0], 0xFF);
}
