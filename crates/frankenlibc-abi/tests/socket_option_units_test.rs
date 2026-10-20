#![cfg(target_os = "linux")]
//! Real filter installation/retrieval through the ABI, not a mock syscall.
use frankenlibc_abi::{errno_abi, malloc_abi as allocator, socket_abi};
use std::ffi::{c_int, c_void};
use std::mem::size_of;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;
use std::ptr;

mod malloc_abi {
    pub(crate) fn known_remaining(address: usize) -> Option<usize> {
        frankenlibc_abi::malloc_abi::malloc_known_remaining_for_tests(
            address as *const std::ffi::c_void,
        )
    }
}
#[path = "../src/iov_snapshot.rs"]
mod iov_snapshot;
#[path = "../src/sockaddr_snapshot.rs"]
mod sockaddr_snapshot;

const CHILD: &str = "FRANKENLIBC_FILTER_CASE";
const SELECT: &str = "FRANKENLIBC_FILTER_SELECT";
type Getter = unsafe extern "C" fn(c_int, c_int, c_int, *mut c_void, *mut u32) -> c_int;

fn filter_socket() -> (OwnedFd, [libc::sock_filter; 2]) {
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    assert!(raw >= 0);
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // Load an immediate, then return a fixed packet limit. No privileged BPF.
    let mut code = [
        libc::sock_filter {
            code: 0x00,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0xffff,
        },
    ];
    let program = libc::sock_fprog {
        len: code.len() as u16,
        filter: code.as_mut_ptr(),
    };
    assert_eq!(
        unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                (&program as *const libc::sock_fprog).cast(),
                size_of::<libc::sock_fprog>() as u32,
            )
        },
        0
    );
    (fd, code)
}

#[test]
fn filter_option_case() {
    let Ok(case) = std::env::var(CHILD) else {
        return;
    };
    allocator::signal_runtime_ready_for_tests();
    let (fd, code) = filter_socket();
    let get: Getter = if std::env::var("FRANKENLIBC_FILTER_ALIAS").unwrap() == "yes" {
        socket_abi::__getsockopt
    } else {
        socket_abi::getsockopt
    };
    let bytes = match case.as_str() {
        "short" => 2,
        "partial" => 2 * size_of::<libc::sock_filter>() - 1,
        _ => 2 * size_of::<libc::sock_filter>(),
    };
    let storage = unsafe { allocator::malloc(bytes) }.cast::<u8>();
    assert!(!storage.is_null());
    assert_eq!(malloc_abi::known_remaining(storage as usize), Some(bytes));
    unsafe { storage.write_bytes(0xa5, bytes) };
    let mut value = storage.cast::<c_void>();
    let mut length = 2u32;
    let mut length_pointer = &mut length as *mut u32;
    match case.as_str() {
        "zero" => {
            length = 0;
            value = ptr::null_mut();
        }
        "too-few" => length = 1,
        "interior" => {
            value = storage.wrapping_add(9).cast();
            length = 1;
        }
        "quarantined" => {
            unsafe { allocator::free(storage.cast()) };
            assert_eq!(malloc_abi::known_remaining(storage as usize), Some(0));
        }
        "invalid-length" => length_pointer = ptr::without_provenance_mut(1),
        "negative" => length = u32::MAX,
        "valid" | "short" | "partial" | "bad-fd" => {}
        _ => panic!("unknown case {case}"),
    }
    let result = unsafe {
        get(
            if case == "bad-fd" { -1 } else { fd.as_raw_fd() },
            libc::SOL_SOCKET,
            libc::SO_GET_FILTER,
            value,
            length_pointer,
        )
    };
    let error = unsafe { *errno_abi::__errno_location() };
    match case.as_str() {
        "valid" => {
            assert_eq!(result, 0, "valid filter retrieval: errno={error}");
            assert_eq!(length, 2, "returned filter count must remain instructions");
            for (index, expected) in code.iter().enumerate() {
                let actual = unsafe {
                    storage
                        .cast::<libc::sock_filter>()
                        .add(index)
                        .read_unaligned()
                };
                assert_eq!(
                    (actual.code, actual.jt, actual.jf, actual.k),
                    (expected.code, expected.jt, expected.jf, expected.k)
                );
            }
        }
        "zero" => {
            assert_eq!(
                (result, length),
                (0, 2),
                "zero-capacity query must return the instruction count"
            );
        }
        "negative" | "too-few" => assert_eq!((result, error), (-1, libc::EINVAL)),
        "bad-fd" => assert_eq!((result, error), (-1, libc::EBADF)),
        _ => assert_eq!(
            (result, error),
            (-1, libc::EFAULT),
            "filter instruction span was not rejected"
        ),
    }
    if case != "quarantined" {
        assert_eq!(
            malloc_abi::known_remaining(storage as usize),
            Some(bytes),
            "filter write corrupted a canary"
        );
        if case != "valid" {
            assert!(
                unsafe { std::slice::from_raw_parts(storage, bytes) }
                    .iter()
                    .all(|&b| b == 0xa5)
            );
        }
        unsafe { allocator::free(storage.cast()) };
    }
    // Neither a failed query nor the membrane may alter the installed filter.
    let mut still_installed = 0;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_GET_FILTER,
                ptr::null_mut(),
                &mut still_installed,
            )
        },
        0
    );
    assert_eq!(still_installed, 2);
}

#[test]
fn filter_options_are_process_isolated() {
    let executable = std::env::current_exe().unwrap();
    let selection = std::env::var(SELECT).ok();
    let mut count = 0;
    for mode in ["strict", "hardened"] {
        for alias in ["no", "yes"] {
            for case in [
                "valid",
                "zero",
                "too-few",
                "bad-fd",
                "short",
                "partial",
                "interior",
                "quarantined",
                "invalid-length",
                "negative",
            ] {
                if mode == "strict" && !matches!(case, "valid" | "zero" | "too-few" | "bad-fd") {
                    continue;
                }
                if selection.as_ref().is_some_and(|selected| selected != case) {
                    continue;
                }
                let output = Command::new(&executable)
                    .args(["--exact", "filter_option_case", "--nocapture"])
                    .env("FRANKENLIBC_MODE", mode)
                    .env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .env(CHILD, case)
                    .env("FRANKENLIBC_FILTER_ALIAS", alias)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{mode}/{alias}/{case}: {:?}\n{}\n{}",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed;"));
                count += 1;
            }
        }
    }
    assert!(count > 0);
    println!("FILTER ABI: {count} isolated cases passed");
    if selection.is_none() {
        assert_eq!(count, 28);
    }
}

#[test]
fn imported_filter_counts_stay_counts_after_caller_changes() {
    let mut bytes = [0xa5u8; 16];
    let mut count = 2;
    let mut output = sockaddr_snapshot::PreparedSockaddr::prepare_option(
        bytes.as_mut_ptr().cast(),
        &mut count,
        libc::SOL_SOCKET,
        libc::SO_GET_FILTER,
    )
    .unwrap();
    count = 100;
    std::hint::black_box(&count);
    assert_eq!(unsafe { *output.as_mut_ptr() }, 2);
    unsafe {
        output.as_mut_ptr().write(1);
        output.publish().unwrap();
    }
    assert_eq!(count, 1);
    assert_eq!(bytes, [0xa5; 16]);
}

#[test]
fn instruction_span_wrap_is_rejected() {
    let mut count = 2;
    assert!(matches!(
        sockaddr_snapshot::PreparedSockaddr::prepare_option(
            ptr::without_provenance_mut(usize::MAX - 8),
            &mut count,
            libc::SOL_SOCKET,
            libc::SO_GET_FILTER
        ),
        Err(libc::EFAULT)
    ));
}

#[test]
fn scaling_is_confined_to_the_filter_option_and_socket_level() {
    allocator::signal_runtime_ready_for_tests();
    let value = unsafe { allocator::malloc(2) };
    assert!(!value.is_null());
    let mut count = 2;
    assert!(
        sockaddr_snapshot::PreparedSockaddr::prepare_option(
            value,
            &mut count,
            libc::SOL_SOCKET,
            libc::SO_TYPE
        )
        .is_ok()
    );
    assert!(
        sockaddr_snapshot::PreparedSockaddr::prepare_option(
            value,
            &mut count,
            libc::IPPROTO_TCP,
            libc::SO_GET_FILTER
        )
        .is_ok()
    );
    assert!(matches!(
        sockaddr_snapshot::PreparedSockaddr::prepare_option(
            value,
            &mut count,
            libc::SOL_SOCKET,
            libc::SO_GET_FILTER
        ),
        Err(libc::EFAULT)
    ));
    unsafe { allocator::free(value) };
}
