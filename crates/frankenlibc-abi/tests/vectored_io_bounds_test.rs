#![cfg(target_os = "linux")]

//! Execute actual file-vector ABI calls in fresh processes, since mode is
//! process-global. The descriptors are on the stack, payloads are tracked.

use frankenlibc_abi::{io_abi, malloc_abi};
use std::ffi::{c_int, c_void};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_VECTORED_BOUNDS_CHILD";
const SIZE: usize = 64;
const APIS: &[&str] = &[
    "readv", "writev", "preadv", "pwritev", "preadv2", "pwritev2",
];

unsafe fn invoke(api: &str, fd: c_int, iov: *const libc::iovec, count: c_int) -> isize {
    // SAFETY: this fixture deliberately includes invalid inputs to verify
    // kernel-style error returns. All payload fault injections remain in the
    // physically mapped hardened allocation or use quarantined storage.
    unsafe {
        match api {
            "readv" => io_abi::readv(fd, iov, count),
            "writev" => io_abi::writev(fd, iov, count),
            "preadv" => io_abi::preadv(fd, iov, count, 0),
            "pwritev" => io_abi::pwritev(fd, iov, count, 0),
            "preadv2" => io_abi::preadv2(fd, iov, count, 0, 0),
            "pwritev2" => io_abi::pwritev2(fd, iov, count, 0, 0),
            _ => panic!("unknown ABI {api}"),
        }
    }
}

fn run_case(api: &str, case: &str) {
    malloc_abi::signal_runtime_ready_for_tests();
    let hardened = std::env::var("FRANKENLIBC_MODE").as_deref() == Ok("hardened");
    let reading = api.contains("read");
    let fd =
        unsafe { libc::memfd_create(c"frankenlibc-vector-bounds".as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0);
    let original_file = [0x39u8; 128];
    assert_eq!(
        unsafe { libc::pwrite(fd, original_file.as_ptr().cast(), 128, 0) },
        128
    );
    assert_eq!(unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }, 0);

    if case == "zero" {
        let result = unsafe { invoke(api, fd, std::ptr::null(), 0) };
        let bad_fd = unsafe { invoke(api, -1, std::ptr::null(), 0) };
        let error = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
        unsafe { libc::close(fd) };
        assert_eq!(result, 0, "{api}: empty vectors are successful no-ops");
        assert_eq!(bad_fd, -1);
        assert_eq!(error, libc::EBADF);
        return;
    }

    let allocation = unsafe { malloc_abi::malloc(SIZE) }.cast::<u8>();
    assert!(!allocation.is_null());
    assert_eq!(
        malloc_abi::malloc_known_remaining_for_tests(allocation.cast()),
        Some(SIZE)
    );
    for i in 0..SIZE {
        unsafe { allocation.add(i).write_volatile(0x57) };
    }
    let mut descriptors = [libc::iovec {
        iov_base: allocation.cast::<c_void>(),
        iov_len: if case == "oversize" { SIZE + 1 } else { SIZE },
    }];
    // This is the important precondition missing from the old test coverage:
    // descriptor storage is untracked even though its buffer is tracked.
    assert_eq!(
        malloc_abi::malloc_known_remaining_for_tests(descriptors.as_ptr().cast()),
        None
    );

    let mut live = true;
    if case == "quarantine" {
        assert!(hardened);
        unsafe { malloc_abi::free(allocation.cast()) };
        live = false;
        assert_eq!(
            malloc_abi::malloc_known_remaining_for_tests(allocation.cast()),
            Some(0)
        );
    }
    let mut saved_canary = None;
    if case == "oversize" {
        assert!(hardened);
        assert!(!malloc_abi::malloc_segment_owned_for_tests(
            allocation.cast()
        ));
        assert!(!malloc_abi::malloc_is_bump_ptr_for_tests(allocation.cast()));
        // Restore the owned trailing byte even if the old implementation writes
        // beyond the user range. This is isolated metadata fault injection.
        saved_canary = Some(unsafe { allocation.add(SIZE).read_volatile() });
    }
    if case == "zero-element" {
        descriptors[0].iov_base = std::ptr::null_mut();
        descriptors[0].iov_len = 0;
    }
    let mut unaligned = [0u8; std::mem::size_of::<libc::iovec>() + 1];
    let iov = if case == "bad-descriptor" {
        std::ptr::without_provenance::<libc::iovec>(1)
    } else if case == "unaligned" {
        let target = unaligned.as_mut_ptr().wrapping_add(1).cast::<libc::iovec>();
        unsafe { target.write_unaligned(descriptors[0]) };
        target.cast_const()
    } else {
        descriptors.as_ptr()
    };
    let count = if case == "bad-count" { 1025 } else { 1 };
    let result = unsafe { invoke(api, fd, iov, count) };
    let error = unsafe { *frankenlibc_abi::errno_abi::__errno_location() };
    let offset = unsafe { libc::lseek(fd, 0, libc::SEEK_CUR) };
    let mut after_file = [0u8; 128];
    assert_eq!(
        unsafe { libc::pread(fd, after_file.as_mut_ptr().cast(), 128, 0) },
        128
    );
    let after_payload = if live {
        (0..SIZE)
            .map(|i| unsafe { allocation.add(i).read_volatile() })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let after_canary = saved_canary.map(|_| unsafe { allocation.add(SIZE).read_volatile() });
    if let Some(value) = saved_canary {
        unsafe { allocation.add(SIZE).write_volatile(value) };
    }
    if live {
        unsafe { malloc_abi::free(allocation.cast()) };
    }
    unsafe { libc::close(fd) };

    match case {
        "valid" | "unaligned" => {
            assert_eq!(result, SIZE as isize, "{api}: valid vector errno={error}");
            if reading {
                assert_eq!(after_payload, original_file[..SIZE]);
                assert_eq!(after_file, original_file);
            } else {
                assert_eq!(&after_file[..SIZE], &[0x57; SIZE]);
                assert_eq!(after_payload, [0x57; SIZE]);
            }
            assert_eq!(
                offset,
                if api == "readv" || api == "writev" {
                    SIZE as i64
                } else {
                    0
                }
            );
        }
        "zero-element" => {
            assert_eq!(result, 0);
            assert_eq!(offset, 0);
            assert_eq!(after_file, original_file);
            assert_eq!(after_payload, [0x57; SIZE]);
        }
        "oversize" | "quarantine" | "bad-descriptor" | "bad-count" => {
            assert_eq!(
                result, -1,
                "{api}/{case}: rejected input reached target I/O"
            );
            assert_eq!(
                error,
                if case == "bad-count" {
                    libc::EINVAL
                } else {
                    libc::EFAULT
                }
            );
            assert_eq!(offset, 0, "{api}/{case}: rejection changed file offset");
            assert_eq!(
                after_file, original_file,
                "{api}/{case}: rejection changed file content"
            );
            if live {
                assert_eq!(after_payload, [0x57; SIZE]);
            }
            assert_eq!(
                after_canary, saved_canary,
                "{api}/{case}: overflow reached canary"
            );
        }
        _ => panic!("unknown case {case}"),
    }
}

#[test]
fn vectored_io_bounds_matrix() {
    if let Ok(selection) = std::env::var(CHILD) {
        let (api, case) = selection.split_once(':').expect("API:case");
        run_case(api, case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    let mut executed = 0;
    for &api in APIS {
        for mode in ["strict", "hardened"] {
            let cases: &[&str] = if mode == "hardened" {
                &[
                    "valid",
                    "zero",
                    "zero-element",
                    "oversize",
                    "quarantine",
                    "bad-descriptor",
                    "bad-count",
                    "unaligned",
                ]
            } else {
                &[
                    "valid",
                    "zero",
                    "zero-element",
                    "bad-descriptor",
                    "bad-count",
                    "unaligned",
                ]
            };
            for &case in cases {
                let mut child = Command::new(&executable)
                    .args([
                        "--exact",
                        "vectored_io_bounds_matrix",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, format!("{api}:{case}"))
                    .env("FRANKENLIBC_MODE", mode)
                    .env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("start isolated vector ABI test");
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut timed_out = false;
                while child.try_wait().unwrap().is_none() {
                    if Instant::now() >= deadline {
                        timed_out = true;
                        let _ = child.kill();
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let output = child.wait_with_output().unwrap();
                executed += 1;
                let stdout = String::from_utf8_lossy(&output.stdout);
                if timed_out || !output.status.success() || !stdout.contains("1 passed;") {
                    failures.push(format!(
                        "{api}/{case}/{mode}: timeout={timed_out} status={}\n{stdout}\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
    }
    assert_eq!(executed, 84);
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    println!("84 isolated vectored-I/O cases passed");
}
