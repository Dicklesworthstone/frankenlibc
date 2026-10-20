#![cfg(target_os = "linux")]

//! Real vmsplice ABI regressions in both directions. In particular, descriptors
//! on the stack must not hide the bounds/lifetime of tracked heap payloads.
//! Drain or close the pipe before releasing any page-backed outgoing payload.

use frankenlibc_abi::{errno_abi, io_abi, malloc_abi};
use std::ffi::c_void;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_VMSPLICE_BOUNDS_CHILD";
const SIZE: usize = 64;
const EMPTY: libc::iovec = libc::iovec {
    iov_base: std::ptr::null_mut(),
    iov_len: 0,
};

fn run_case(direction: &str, case: &str) {
    malloc_abi::signal_runtime_ready_for_tests();
    let hardened = std::env::var("FRANKENLIBC_MODE").as_deref() == Ok("hardened");
    let incoming = direction == "from-pipe";
    assert!(incoming || direction == "to-pipe");
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    let source = [0x39u8; 128];
    if incoming {
        assert_eq!(
            unsafe { libc::write(fds[1], source.as_ptr().cast(), source.len()) },
            128
        );
    }
    let fd = fds[usize::from(!incoming)];
    let allocation = unsafe { malloc_abi::malloc(SIZE) }.cast::<u8>();
    assert!(!allocation.is_null());
    assert_eq!(
        malloc_abi::malloc_known_remaining_for_tests(allocation.cast()),
        Some(SIZE)
    );
    for index in 0..SIZE {
        unsafe { allocation.add(index).write_volatile(0x57) };
    }

    let mut descriptors = [EMPTY; 1024];
    descriptors[0] = libc::iovec {
        iov_base: allocation.cast::<c_void>(),
        iov_len: SIZE,
    };
    let mut count = 1;
    if case == "large-vector" {
        descriptors[1023] = descriptors[0];
        descriptors[0] = EMPTY;
        count = 1024;
    } else if case == "multiple" {
        descriptors[0].iov_len = 24;
        descriptors[1] = libc::iovec {
            iov_base: allocation.wrapping_add(24).cast(),
            iov_len: 40,
        };
        count = 2;
    } else if case == "zero-element" {
        descriptors[0] = EMPTY;
    } else if case == "zero" {
        count = 0;
    } else if case == "bad-count" {
        count = 1025;
    } else if case == "full-width-count" {
        count = usize::MAX;
    } else if case == "oversize" {
        descriptors[0].iov_len = SIZE + 1;
    }
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
    let saved_canary = if case == "oversize" {
        assert!(hardened);
        assert!(!malloc_abi::malloc_segment_owned_for_tests(
            allocation.cast()
        ));
        assert!(!malloc_abi::malloc_is_bump_ptr_for_tests(allocation.cast()));
        // Isolated fault injection: preserve the physically allocated trailing
        // byte even when a deliberately regressed implementation overwrites it.
        Some(unsafe { allocation.add(SIZE).read_volatile() })
    } else {
        None
    };

    let mut unaligned = [0u8; std::mem::size_of::<libc::iovec>() + 1];
    let mut short_descriptor = std::ptr::null_mut::<libc::iovec>();
    let iov = match case {
        "bad-descriptor" => std::ptr::without_provenance::<libc::iovec>(1),
        "zero" => std::ptr::null(),
        "unaligned" => {
            let pointer = unaligned.as_mut_ptr().wrapping_add(1).cast::<libc::iovec>();
            unsafe { pointer.write_unaligned(descriptors[0]) };
            pointer.cast_const()
        }
        "short-descriptor" => {
            assert!(hardened);
            short_descriptor =
                unsafe { malloc_abi::malloc(std::mem::size_of::<libc::iovec>()) }.cast();
            assert!(!short_descriptor.is_null());
            unsafe { short_descriptor.write(descriptors[0]) };
            assert_eq!(
                malloc_abi::malloc_known_remaining_for_tests(short_descriptor.cast()),
                Some(std::mem::size_of::<libc::iovec>())
            );
            count = 2;
            short_descriptor.cast_const()
        }
        _ => descriptors.as_ptr(),
    };

    let result = unsafe { io_abi::vmsplice(fd, iov, count, libc::SPLICE_F_NONBLOCK) };
    let error = unsafe { *errno_abi::__errno_location() };
    // Nonblocking drain is also the side-effect oracle: a denied pipe->user
    // operation must leave all source bytes queued, while user->pipe must leave
    // the pipe empty. This also releases all kernel references before free.
    let mut drained = [0u8; 128];
    let drain_count = unsafe { libc::read(fds[0], drained.as_mut_ptr().cast(), drained.len()) };
    let drain_error = unsafe { *libc::__errno_location() };
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }

    let mut after_payload = [0u8; SIZE];
    if live {
        for (index, byte) in after_payload.iter_mut().enumerate() {
            *byte = unsafe { allocation.add(index).read_volatile() };
        }
    }
    let after_canary = saved_canary.map(|_| unsafe { allocation.add(SIZE).read_volatile() });
    if let Some(value) = saved_canary {
        unsafe { allocation.add(SIZE).write_volatile(value) };
    }
    if live {
        unsafe { malloc_abi::free(allocation.cast()) };
    }
    if !short_descriptor.is_null() {
        unsafe { malloc_abi::free(short_descriptor.cast()) };
    }

    let success = matches!(case, "valid" | "unaligned" | "large-vector" | "multiple");
    if success {
        assert_eq!(
            result, SIZE as isize,
            "{direction}/{case}: valid transfer errno={error}"
        );
        assert_eq!(drain_count, SIZE as isize);
        if incoming {
            assert_eq!(after_payload, [0x39; SIZE]);
            assert_eq!(&drained[..SIZE], &[0x39; SIZE]);
        } else {
            assert_eq!(after_payload, [0x57; SIZE]);
            assert_eq!(&drained[..SIZE], &[0x57; SIZE]);
        }
    } else {
        if matches!(case, "zero" | "zero-element") {
            assert_eq!(
                result, 0,
                "{direction}/{case}: empty transfer errno={error}"
            );
        } else {
            assert_eq!(
                result, -1,
                "{direction}/{case}: rejected input reached pipe I/O"
            );
            let expected = if matches!(case, "bad-count" | "full-width-count") {
                libc::EINVAL
            } else {
                libc::EFAULT
            };
            assert_eq!(error, expected, "{direction}/{case}");
        }
        if incoming {
            assert_eq!(
                drain_count, 128,
                "{direction}/{case}: rejection consumed pipe data"
            );
            assert_eq!(drained, source);
        } else {
            assert_eq!(
                drain_count, -1,
                "{direction}/{case}: rejection enqueued pipe data"
            );
            assert_eq!(drain_error, libc::EAGAIN);
        }
        if live {
            assert_eq!(after_payload, [0x57; SIZE]);
        }
        assert_eq!(
            after_canary, saved_canary,
            "{direction}/{case}: canary overwritten"
        );
    }
    if case == "zero" {
        assert_eq!(unsafe { io_abi::vmsplice(-1, std::ptr::null(), 0, 0) }, -1);
        assert_eq!(unsafe { *errno_abi::__errno_location() }, libc::EBADF);
    }
}

#[test]
fn vmsplice_bounds_matrix() {
    if let Ok(selection) = std::env::var(CHILD) {
        let (direction, case) = selection.split_once(':').expect("direction:case");
        run_case(direction, case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    let mut executed = 0;
    for direction in ["to-pipe", "from-pipe"] {
        for mode in ["strict", "hardened"] {
            let cases: &[&str] = if mode == "hardened" {
                &[
                    "valid",
                    "zero",
                    "zero-element",
                    "bad-descriptor",
                    "bad-count",
                    "full-width-count",
                    "unaligned",
                    "large-vector",
                    "multiple",
                    "oversize",
                    "quarantine",
                    "short-descriptor",
                ]
            } else {
                &[
                    "valid",
                    "zero",
                    "zero-element",
                    "bad-descriptor",
                    "bad-count",
                    "full-width-count",
                    "unaligned",
                    "large-vector",
                    "multiple",
                ]
            };
            for &case in cases {
                let mut child = Command::new(&executable)
                    .args([
                        "--exact",
                        "vmsplice_bounds_matrix",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, format!("{direction}:{case}"))
                    .env("FRANKENLIBC_MODE", mode)
                    .env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("start isolated vmsplice test");
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
                        "{direction}/{case}/{mode}: timeout={timed_out} status={}\n{stdout}\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
    }
    assert_eq!(executed, 42);
    assert!(failures.is_empty(), "{}", failures.join("\n\n"));
    println!("42 isolated vmsplice cases passed");
}
