#![cfg(target_os = "linux")]
//! Real SO_PEERPIDFD resource transfer and error-path ownership tests.
use std::ffi::{c_int, c_void};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::ptr;
use frankenlibc_abi::{errno_abi, malloc_abi, socket_abi};

const PEERPIDFD: c_int = 77;
const CHILD: &str = "FRANKENLIBC_PEER_DESCRIPTOR_CASE";
const SELECT: &str = "FRANKENLIBC_PEER_DESCRIPTOR_SELECT";
type Getter = unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void, *mut u32) -> c_int;

struct Page(*mut c_void, usize);
impl Page {
    fn readonly(value: u32) -> Self {
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert!(size > 0);
        let p = unsafe { libc::mmap(ptr::null_mut(), size as usize, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED);
        unsafe { p.cast::<u32>().write(value) };
        assert_eq!(unsafe { libc::mprotect(p, size as usize, libc::PROT_READ) }, 0);
        Self(p, size as usize)
    }
}
impl Drop for Page { fn drop(&mut self) { unsafe { libc::munmap(self.0, self.1) }; } }
fn descriptor_count() -> usize { std::fs::read_dir("/proc/self/fd").unwrap().count() }

#[test]
fn peer_descriptor_case() {
    let Ok(case) = std::env::var(CHILD) else { return; };
    malloc_abi::signal_runtime_ready_for_tests();
    let mut sockets = [-1; 2];
    assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
        0, sockets.as_mut_ptr()) }, 0);
    let sockets = unsafe { [OwnedFd::from_raw_fd(sockets[0]), OwnedFd::from_raw_fd(sockets[1])] };
    let get: Getter = if std::env::var("FRANKENLIBC_PEER_DESCRIPTOR_ALIAS").unwrap() == "yes" {
        socket_abi::__getsockopt
    } else { socket_abi::getsockopt };
    let mut storage = [0xa5u8; 128];
    let mut value = storage.as_mut_ptr().cast::<c_void>();
    let mut length = size_of::<c_int>() as u32;
    let mut length_ptr = &mut length as *mut u32;
    let page = Page::readonly(4);
    match case.as_str() {
        "oversized" => length = storage.len() as u32,
        "readonly-value" => value = page.0,
        "readonly-length" | "zero-fd-readonly-length" => length_ptr = page.0.cast(),
        "overlap" => length_ptr = storage.as_mut_ptr().cast(),
        "overlap-right" => length_ptr = storage.as_mut_ptr().wrapping_add(1).cast(),
        "overlap-left" => { value = storage.as_mut_ptr().wrapping_add(1).cast(); length_ptr = storage.as_mut_ptr().cast(); }
        "adjacent" => length_ptr = storage.as_mut_ptr().wrapping_add(4).cast(),
        "zero-length" => length = 0,
        "short-length" => length = 3,
        "valid" | "zero-fd" => {},
        _ => panic!("unknown case {case}"),
    }
    if matches!(case.as_str(), "overlap" | "overlap-left" | "overlap-right" | "adjacent") {
        unsafe { length_ptr.write_unaligned(4) };
    }
    let initial = storage;
    let before = descriptor_count();
    let zero_fd = case.starts_with("zero-fd");
    // Child process only. Save and restore stdin so a legitimate returned fd 0
    // is tested without treating zero as an empty ownership sentinel.
    let saved_stdin = if zero_fd {
        let saved = unsafe { libc::dup(0) }; assert!(saved >= 0);
        assert_eq!(unsafe { libc::close(0) }, 0); saved
    } else { -1 };
    let result = unsafe { get(sockets[0].as_raw_fd(), libc::SOL_SOCKET, PEERPIDFD, value, length_ptr) };
    let error = unsafe { *errno_abi::__errno_location() };
    let fd = unsafe { value.cast::<c_int>().read_unaligned() };
    if zero_fd {
        if case == "zero-fd" {
            assert_eq!(result, 0, "pidfd zero must be returned successfully: errno={error}");
            assert_eq!(fd, 0);
            assert_eq!(unsafe { libc::close(0) }, 0);
        } else {
            assert_eq!((result, error), (-1, libc::EFAULT));
            assert_eq!(fd, 0, "pidfd value must be copied before length publication");
            assert_eq!(unsafe { libc::fcntl(0, libc::F_GETFD) }, -1, "failed publication leaked descriptor zero");
            assert_eq!(unsafe { *libc::__errno_location() }, libc::EBADF);
        }
        assert_eq!(unsafe { libc::dup2(saved_stdin, 0) }, 0);
        assert_eq!(unsafe { libc::close(saved_stdin) }, 0);
    } else if case.starts_with("overlap") {
        assert_eq!((result, error), (-1, libc::EINVAL), "overlapping descriptor outputs were accepted");
        assert_eq!(storage, initial, "overlap rejection must precede output writes");
    } else if matches!(case.as_str(), "zero-length" | "short-length") {
        assert_eq!((result, error), (-1, libc::EINVAL));
        assert_eq!(storage, initial);
    } else if matches!(case.as_str(), "readonly-value" | "readonly-length") {
        assert_eq!((result, error), (-1, libc::EFAULT));
        if case == "readonly-length" {
            assert!(fd >= 0);
            assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1, "failed publication leaked its returned descriptor");
        }
    } else {
        assert_eq!(result, 0, "SO_PEERPIDFD must be supported by this kernel: errno={error}");
        assert!(fd >= 0);
        assert_eq!(unsafe { length_ptr.read_unaligned() }, 4);
        let descriptor_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(descriptor_flags >= 0 && descriptor_flags & libc::FD_CLOEXEC != 0);
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
    assert_eq!(descriptor_count(), before, "descriptor transfer leaked or closed unrelated storage");
    for socket in &sockets { assert!(unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFD) } >= 0); }
}

#[test]
fn peer_descriptors_are_process_isolated() {
    let exe = std::env::current_exe().unwrap();
    let selection = std::env::var(SELECT).ok();
    let mut count = 0;
    for mode in ["strict", "hardened"] {
        for alias in ["no", "yes"] {
            for case in ["valid", "oversized", "readonly-value", "readonly-length", "overlap", "overlap-left",
                "overlap-right", "adjacent", "zero-length", "short-length", "zero-fd", "zero-fd-readonly-length"] {
                if mode == "strict" && !matches!(case, "valid" | "oversized" | "readonly-value" | "readonly-length") { continue; }
                if selection.as_ref().is_some_and(|selected| selected != case) { continue; }
                let output = Command::new(&exe).args(["--exact", "peer_descriptor_case", "--nocapture"])
                    .env("FRANKENLIBC_MODE", mode).env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .env(CHILD, case).env("FRANKENLIBC_PEER_DESCRIPTOR_ALIAS", alias).output().unwrap();
                assert!(output.status.success(), "{mode}/{alias}/{case}: {:?}\n{}\n{}", output.status,
                    String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
                count += 1;
            }
        }
    }
    assert!(count > 0);
    println!("PEER DESCRIPTOR ABI: {count} isolated cases passed");
    if selection.is_none() { assert_eq!(count, 32); }
}
