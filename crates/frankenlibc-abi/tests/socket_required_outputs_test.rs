#![cfg(target_os = "linux")]
//! Real-ABI socket output regressions, isolated from adaptive-policy history.

use std::ffi::{c_int, c_void};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::ptr;

use frankenlibc_abi::socket_abi as socket;

mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(address as *const std::ffi::c_void)
    }
}
#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;
#[path = "../src/sockaddr_snapshot.rs"]
mod sockaddr_snapshot;

const SO_PEERGROUPS: c_int = 59;
const SO_PEERPIDFD: c_int = 77;
const CHILD: &str = "FRANKENLIBC_SOCKET_OUTPUT_CASE";

type OptionFn = unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void, *mut u32) -> c_int;
type NameFn = unsafe extern "C" fn(c_int, *mut libc::sockaddr, *mut u32) -> c_int;

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn pair() -> [OwnedFd; 2] {
    let mut fds = [-1; 2];
    assert_eq!(unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr())
    }, 0);
    unsafe { [OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])] }
}

struct Page {
    base: *mut c_void,
    bytes: usize,
}

impl Page {
    fn new(value: u32, protection: c_int) -> Self {
        let bytes = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let base = unsafe {
            libc::mmap(ptr::null_mut(), bytes, libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
        };
        assert_ne!(base, libc::MAP_FAILED);
        unsafe { base.cast::<u32>().write(value) };
        assert_eq!(unsafe { libc::mprotect(base, bytes, protection) }, 0);
        Self { base, bytes }
    }
}

impl Drop for Page {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.base, self.bytes) };
    }
}

struct Tracked(*mut c_void);

impl Tracked {
    fn new(bytes: usize) -> Self {
        let address = unsafe { frankenlibc_abi::malloc_abi::malloc(bytes) };
        assert!(!address.is_null());
        assert_eq!(malloc_abi::known_remaining(address as usize), Some(bytes));
        Self(address)
    }

    fn retire(&mut self) -> *mut c_void {
        let address = self.0;
        unsafe { frankenlibc_abi::malloc_abi::free(address) };
        self.0 = ptr::null_mut();
        assert_eq!(malloc_abi::known_remaining(address as usize), Some(0));
        address
    }
}

impl Drop for Tracked {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { frankenlibc_abi::malloc_abi::free(self.0) };
        }
    }
}

fn expect_error(result: c_int, expected: c_int) {
    let observed = errno();
    assert_eq!((result, observed), (-1, expected));
}

fn descriptor_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn peer_pidfd_supported(fd: c_int) -> bool {
    let mut received = -1;
    let mut length = size_of::<c_int>() as u32;
    let result = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, SO_PEERPIDFD,
            (&mut received as *mut c_int).cast(), &mut length)
    };
    if result == 0 {
        assert!(received >= 0);
        unsafe { libc::close(received) };
        true
    } else {
        let error = errno();
        assert!(matches!(error, libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::ENOSYS));
        println!("SKIP: host kernel does not support SO_PEERPIDFD ({error})");
        false
    }
}

#[test]
fn socket_output_case() {
    let Ok(case) = std::env::var(CHILD) else { return; };
    // Exercise the initialized allocator, not its startup bypass.
    frankenlibc_abi::malloc_abi::signal_runtime_ready_for_tests();
    let entry = std::env::var("FRANKENLIBC_SOCKET_OUTPUT_ENTRY").unwrap();
    let sockets = pair();
    let fd = sockets[0].as_raw_fd();
    let get: OptionFn = if entry == "alias" { socket::__getsockopt } else { socket::getsockopt };
    let name: NameFn = match entry.as_str() {
        "getsockname" => socket::getsockname,
        "__getsockname" => socket::__getsockname,
        "getpeername" => socket::getpeername,
        "__getpeername" => socket::__getpeername,
        _ => socket::getsockname,
    };
    let mut value: c_int = -1;
    let mut length = size_of::<c_int>() as u32;
    let value_ptr = (&mut value as *mut c_int).cast::<c_void>();

    match case.as_str() {
        "normal" => {
            unsafe { *libc::__errno_location() = libc::EDOM };
            assert_eq!(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, &mut length) }, 0);
            assert_eq!(errno(), libc::EDOM);
            assert_eq!((value, length), (libc::SOCK_STREAM, 4));
        }
        "truncated" => {
            let mut bytes = [0xa5u8; 8];
            length = 1;
            assert_eq!(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, bytes.as_mut_ptr().cast(), &mut length) }, 0);
            assert_eq!(length, 1);
            assert_eq!(bytes[0], libc::SOCK_STREAM.to_ne_bytes()[0]);
            assert!(bytes[1..].iter().all(|&byte| byte == 0xa5));
        }
        "zero-null" => {
            length = 0;
            assert_eq!(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, ptr::null_mut(), &mut length) }, 0);
            assert_eq!(length, 0);
        }
        "bad-fd" => {
            expect_error(unsafe { get(-1, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, &mut length) }, libc::EBADF);
            assert_eq!((value, length), (-1, 4));
        }
        "negative" => {
            length = u32::MAX;
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, &mut length) }, libc::EINVAL);
            assert_eq!((value, length), (-1, u32::MAX));
        }
        "bad-length" => {
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, ptr::without_provenance_mut(1)) }, libc::EFAULT);
            assert_eq!(value, -1);
        }
        "unreadable-length" => {
            let page = Page::new(4, libc::PROT_NONE);
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, page.base.cast()) }, libc::EFAULT);
            assert_eq!(value, -1);
        }
        "readonly-length" => {
            let page = Page::new(4, libc::PROT_READ);
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, page.base.cast()) }, libc::EFAULT);
            assert_eq!(value, libc::SOCK_STREAM, "no speculative length write before target I/O");
        }
        "bad-fd-readonly-length" => {
            let page = Page::new(4, libc::PROT_READ);
            expect_error(unsafe { get(-1, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, page.base.cast()) }, libc::EBADF);
            assert_eq!(value, -1);
        }
        "readonly-value" => {
            let page = Page::new(u32::MAX, libc::PROT_READ);
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, page.base, &mut length) }, libc::EFAULT);
            assert_eq!(length, 4);
        }
        "unaligned-length" => {
            let mut storage = [0xa5u8; 12];
            let shift = (5 - storage.as_ptr() as usize % 4) % 4;
            let pointer = storage.as_mut_ptr().wrapping_add(shift).cast::<u32>();
            unsafe { pointer.write_unaligned(4) };
            assert_eq!(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, pointer) }, 0);
            assert_eq!(value, libc::SOCK_STREAM);
            assert_eq!(unsafe { pointer.read_unaligned() }, 4);
            assert!(storage[..shift].iter().chain(storage[shift + 4..].iter()).all(|&byte| byte == 0xa5));
        }
        "short-value" => {
            let buffer = Tracked::new(1);
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, buffer.0, &mut length) }, libc::EFAULT);
        }
        "short-length" | "null-value-short-length" => {
            let scalar = Tracked::new(1);
            let output = if case.starts_with("null") { ptr::null_mut() } else { value_ptr };
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, output, scalar.0.cast()) }, libc::EFAULT);
            assert_eq!(value, -1);
        }
        "reallocated-length" => {
            // Strict free releases host storage; hardened free quarantines it.
            // Neither state may poison a subsequent, separately owned output.
            // Never dereference released strict storage to demand a UAF repair.
            let previous = Tracked::new(4);
            let address = previous.0 as usize;
            drop(previous);
            let expected = if std::env::var("FRANKENLIBC_MODE").unwrap() == "hardened" {
                Some(0)
            } else { None };
            assert_eq!(malloc_abi::known_remaining(address), expected);
            let scalar = Tracked::new(4);
            unsafe { scalar.0.cast::<u32>().write(4) };
            assert_eq!(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, scalar.0.cast()) }, 0);
            assert_eq!(value, libc::SOCK_STREAM);
            assert_eq!(unsafe { scalar.0.cast::<u32>().read() }, 4);
        }
        "stale-length" => {
            let mut scalar = Tracked::new(4);
            let retired = scalar.retire();
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, libc::SO_TYPE, value_ptr, retired.cast()) }, libc::EFAULT);
        }
        "groups-size" => {
            let mut native_length = 0;
            let native = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, SO_PEERGROUPS, ptr::null_mut(), &mut native_length) };
            let native_error = errno();
            length = 0;
            let result = unsafe { get(fd, libc::SOL_SOCKET, SO_PEERGROUPS, ptr::null_mut(), &mut length) };
            let error = errno();
            assert_eq!((result, length), (native, native_length));
            if native < 0 { assert_eq!(error, native_error); }
            if native_error == libc::ERANGE && native < 0 {
                assert!(length > 0);
                println!("ERANGE required-size publication exercised: {length} bytes");
            }
        }
        "groups-readonly-length" => {
            let page = Page::new(0, libc::PROT_READ);
            expect_error(unsafe { get(fd, libc::SOL_SOCKET, SO_PEERGROUPS, ptr::null_mut(), page.base.cast()) }, libc::EFAULT);
        }
        "pidfd" | "pidfd-readonly-length" | "pidfd-readonly-value" | "pidfd-short" => {
            if !peer_pidfd_supported(fd) { return; }
            let before = descriptor_count();
            match case.as_str() {
                "pidfd" => {
                    assert_eq!(unsafe { get(fd, libc::SOL_SOCKET, SO_PEERPIDFD, value_ptr, &mut length) }, 0);
                    assert!(value >= 0);
                    let returned = unsafe { OwnedFd::from_raw_fd(value) };
                    assert_ne!(unsafe { libc::fcntl(returned.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC, 0);
                    assert_eq!(length, 4);
                    drop(returned);
                }
                "pidfd-readonly-length" => {
                    let page = Page::new(4, libc::PROT_READ);
                    expect_error(unsafe { get(fd, libc::SOL_SOCKET, SO_PEERPIDFD, value_ptr, page.base.cast()) }, libc::EFAULT);
                    assert!(value >= 0, "descriptor value is copied before length publication");
                    assert_eq!(unsafe { libc::fcntl(value, libc::F_GETFD) }, -1, "failed publication leaked its pidfd");
                    assert_eq!(errno(), libc::EBADF);
                }
                "pidfd-readonly-value" => {
                    let page = Page::new(u32::MAX, libc::PROT_READ);
                    expect_error(unsafe { get(fd, libc::SOL_SOCKET, SO_PEERPIDFD, page.base, &mut length) }, libc::EFAULT);
                    assert_eq!(length, 4);
                }
                _ => {
                    length = 1;
                    expect_error(unsafe { get(fd, libc::SOL_SOCKET, SO_PEERPIDFD, value_ptr, &mut length) }, libc::EINVAL);
                    assert_eq!(value, -1);
                }
            }
            assert_eq!(descriptor_count(), before, "descriptor ownership was not discharged");
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0, "input socket was closed");
        }
        "name-null-zero" => {
            let mut native_length = 0;
            let native: NameFn = if entry.contains("peer") { libc::getpeername } else { libc::getsockname };
            assert_eq!(unsafe { native(fd, ptr::null_mut(), &mut native_length) }, 0);
            length = 0;
            assert_eq!(unsafe { name(fd, ptr::null_mut(), &mut length) }, 0);
            assert_eq!(length, native_length);
        }
        "name-null-short" => {
            let scalar = Tracked::new(1);
            expect_error(unsafe { name(fd, ptr::null_mut(), scalar.0.cast()) }, libc::EFAULT);
        }
        "name-null-stale" => {
            let mut scalar = Tracked::new(4);
            let retired = scalar.retire();
            expect_error(unsafe { name(fd, ptr::null_mut(), retired.cast()) }, libc::EFAULT);
        }
        "name-null-unreadable" => {
            let page = Page::new(0, libc::PROT_NONE);
            expect_error(unsafe { name(fd, ptr::null_mut(), page.base.cast()) }, libc::EFAULT);
        }
        "credentials" => {
            let mut uid = u32::MAX;
            let mut gid = u32::MAX;
            assert_eq!(unsafe { socket::getpeereid(fd, &mut uid, &mut gid) }, 0);
            assert_eq!((uid, gid), unsafe { (libc::geteuid(), libc::getegid()) });
        }
        "credentials-bad-uid" => {
            let mut gid = u32::MAX;
            expect_error(unsafe { socket::getpeereid(fd, ptr::without_provenance_mut(1), &mut gid) }, libc::EFAULT);
            assert_eq!(gid, u32::MAX);
        }
        "credentials-readonly-gid" => {
            let page = Page::new(u32::MAX, libc::PROT_READ);
            let mut uid = u32::MAX;
            expect_error(unsafe { socket::getpeereid(fd, &mut uid, page.base.cast()) }, libc::EFAULT);
            assert_eq!(uid, unsafe { libc::geteuid() }, "uid-before-gid publication order changed");
            assert_eq!(unsafe { page.base.cast::<u32>().read() }, u32::MAX);
        }
        _ => panic!("unknown case {case}"),
    }
}

#[test]
fn required_outputs_are_process_isolated() {
    let executable = std::env::current_exe().unwrap();
    let mut count = 0;
    let mut run = |mode: &str, entry: &str, case: &str| {
        let result = Command::new(&executable)
            .args(["--exact", "socket_output_case", "--nocapture"])
            .env("FRANKENLIBC_MODE", mode)
            .env(CHILD, case)
            .env("FRANKENLIBC_SOCKET_OUTPUT_ENTRY", entry)
            .output().unwrap();
        assert!(result.status.success(), "{mode}/{entry}/{case}: {:?}\n{}\n{}",
            result.status, String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
        println!("PASS {mode}/{entry}/{case}\n{}", String::from_utf8_lossy(&result.stdout));
        count += 1;
    };
    for mode in ["strict", "hardened"] {
        for entry in ["primary", "alias"] {
            for case in ["normal", "truncated", "zero-null", "bad-fd", "readonly-length",
                "bad-fd-readonly-length", "readonly-value", "short-value", "short-length",
                "null-value-short-length", "reallocated-length", "groups-size", "groups-readonly-length",
                "pidfd", "pidfd-readonly-length", "pidfd-readonly-value"] {
                run(mode, entry, case);
            }
            if mode == "hardened" {
                for case in ["negative", "bad-length", "unreadable-length", "unaligned-length", "pidfd-short", "stale-length"] {
                    run(mode, entry, case);
                }
            }
        }
        for entry in ["getsockname", "__getsockname", "getpeername", "__getpeername"] {
            run(mode, entry, "name-null-zero");
            if mode == "hardened" {
                for case in ["name-null-short", "name-null-stale", "name-null-unreadable"] {
                    run(mode, entry, case);
                }
            }
        }
        run(mode, "primary", "credentials");
    }
    for case in ["credentials-bad-uid", "credentials-readonly-gid"] {
        run("hardened", "primary", case);
    }
    assert_eq!(count, 100, "required-output matrix coverage changed");
    println!("Completed {count} process-isolated socket-output cases");
}

#[test]
fn required_capacity_is_not_reread_after_validation() {
    let sockets = pair();
    let mut bytes = [0xa5u8; 16];
    let mut length = 1;
    let mut output = sockaddr_snapshot::PreparedSockaddr::prepare_required(bytes.as_mut_ptr().cast(), &mut length).unwrap();
    length = 16;
    std::hint::black_box(&length);
    assert_eq!(unsafe {
        libc::getsockopt(sockets[0].as_raw_fd(), libc::SOL_SOCKET, libc::SO_TYPE,
            bytes.as_mut_ptr().cast(), output.as_mut_ptr())
    }, 0);
    unsafe { output.publish() }.unwrap();
    assert_eq!(length, 1);
    assert_eq!(bytes[0], libc::SOCK_STREAM.to_ne_bytes()[0]);
    assert!(bytes[1..].iter().all(|&byte| byte == 0xa5));
}

#[test]
fn null_buffer_does_not_make_a_required_length_optional() {
    for address in [0, 1, usize::MAX - 1] {
        assert!(matches!(sockaddr_snapshot::PreparedSockaddr::prepare_required(
            ptr::null_mut(), ptr::without_provenance_mut(address)), Err(libc::EFAULT)));
    }
    let mut length = 0;
    let mut output = sockaddr_snapshot::PreparedSockaddr::prepare_required(ptr::null_mut(), &mut length).unwrap();
    assert_ne!(output.as_mut_ptr(), &mut length as *mut u32);
    unsafe { output.as_mut_ptr().write(42); output.publish().unwrap(); }
    assert_eq!(length, 42);
}
