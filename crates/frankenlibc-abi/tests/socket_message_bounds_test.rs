#![cfg(target_os = "linux")]

//! Actual socket-message ABI tests. Each mode/case/alias gets a fresh process:
//! mode is immutable, quarantine must stay live, and seccomp cannot be undone.
use frankenlibc_abi::{errno_abi, malloc_abi, socket_abi};
use std::mem::{align_of, size_of, size_of_val};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD: &str = "FRANKENLIBC_SOCKET_MESSAGE_CHILD";
const SIZE: usize = 64;
const EMPTY: libc::iovec = libc::iovec {
    iov_base: std::ptr::null_mut(),
    iov_len: 0,
};
const COMMON: &[&str] = &[
    "valid",
    "split",
    "maximum",
    "zero",
    "zero-element",
    "bad-header",
    "null-header",
    "bad-iov",
    "null-iov",
    "bad-count",
    "full-width-count",
    "unaligned-header",
    "unaligned-iov",
    "readonly-header",
    "rights",
    "name",
];
const HARDENED: &[&str] = &[
    "oversize",
    "interior-overrun",
    "quarantine",
    "short-iov",
    "short-header",
    "control-overrun",
    "name-overrun",
    "fallback",
    "denied-copy",
];

struct Allocation {
    pointer: *mut u8,
    bytes: usize,
    live: bool,
}
impl Allocation {
    fn new(bytes: usize) -> Self {
        let pointer = unsafe { malloc_abi::malloc(bytes) }.cast::<u8>();
        assert!(!pointer.is_null());
        assert_eq!(
            malloc_abi::malloc_known_remaining_for_tests(pointer.cast()),
            Some(bytes)
        );
        unsafe { pointer.write_bytes(0, bytes) };
        Self {
            pointer,
            bytes,
            live: true,
        }
    }
    fn quarantine(&mut self) {
        unsafe { malloc_abi::free(self.pointer.cast()) };
        self.live = false;
        assert_eq!(
            malloc_abi::malloc_known_remaining_for_tests(self.pointer.cast()),
            Some(0)
        );
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if self.live {
            unsafe { malloc_abi::free(self.pointer.cast()) };
        }
    }
}
struct Sockets([libc::c_int; 2]);
impl Drop for Sockets {
    fn drop(&mut self) {
        for fd in self.0 {
            unsafe { libc::close(fd) };
        }
    }
}

fn deny_copy_routes(deny_pipe: bool) {
    // Load seccomp_data.nr; deny only the specified copy mechanisms. Nothing
    // about the caller's socket syscall is changed. Installed only in children.
    let mut filters = vec![libc::sock_filter {
        code: 0x20,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    for number in [
        libc::SYS_process_vm_readv,
        if deny_pipe { libc::SYS_pipe2 } else { -1 },
    ] {
        if number < 0 {
            continue;
        }
        filters.push(libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: number as u32,
        });
        filters.push(libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x0005_0000 | libc::EPERM as u32,
        });
    }
    filters.push(libc::sock_filter {
        code: 0x06,
        jt: 0,
        jf: 0,
        k: 0x7fff_0000,
    });
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) },
        0
    );
    assert_eq!(
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                2usize,
                &program as *const libc::sock_fprog,
            )
        },
        0
    );
}

fn run_send(entry: &str, case: &str) {
    malloc_abi::signal_runtime_ready_for_tests();
    let named = matches!(case, "name" | "name-overrun");
    let mut sockets = Sockets([-1; 2]);
    let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    if named {
        for fd in &mut sockets.0 {
            *fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            assert!(*fd >= 0);
        }
        address.sin_family = libc::AF_INET as _;
        address.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(
            unsafe {
                libc::bind(
                    sockets.0[1],
                    (&address as *const libc::sockaddr_in).cast(),
                    size_of::<libc::sockaddr_in>() as _,
                )
            },
            0
        );
        let mut length = size_of::<libc::sockaddr_in>() as libc::socklen_t;
        assert_eq!(
            unsafe {
                libc::getsockname(
                    sockets.0[1],
                    (&mut address as *mut libc::sockaddr_in).cast(),
                    &mut length,
                )
            },
            0
        );
    } else {
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
                    0,
                    sockets.0.as_mut_ptr(),
                )
            },
            0
        );
    }
    let mut payload = Allocation::new(SIZE);
    unsafe { payload.pointer.write_bytes(0x57, SIZE) };
    let mut vectors = [EMPTY; 1024];
    vectors[0] = libc::iovec {
        iov_base: payload.pointer.cast(),
        iov_len: SIZE,
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_iov = vectors.as_mut_ptr();
    header.msg_iovlen = 1;
    header.msg_flags = 0x1234; // sendmsg ignores this input field and must not change it.
    match case {
        "split" => {
            vectors[0].iov_len = 24;
            vectors[1] = libc::iovec {
                iov_base: payload.pointer.wrapping_add(24).cast(),
                iov_len: 40,
            };
            header.msg_iovlen = 2;
        }
        "maximum" => {
            vectors[1023] = vectors[0];
            vectors[0] = EMPTY;
            header.msg_iovlen = 1024;
        }
        "zero" => {
            header.msg_iov = std::ptr::null_mut();
            header.msg_iovlen = 0;
        }
        "zero-element" => {
            vectors[0] = EMPTY;
        }
        "bad-iov" => {
            header.msg_iov = std::ptr::without_provenance_mut(1);
        }
        "null-iov" => {
            header.msg_iov = std::ptr::null_mut();
        }
        "bad-count" => {
            header.msg_iovlen = 1025;
        }
        "full-width-count" => {
            header.msg_iovlen = usize::MAX;
        }
        "oversize" => {
            vectors[0].iov_len = SIZE + 1;
        }
        "interior-overrun" => {
            vectors[0].iov_base = payload.pointer.wrapping_add(16).cast();
        }
        "quarantine" => payload.quarantine(),
        _ => {}
    }
    assert_eq!(
        malloc_abi::malloc_known_remaining_for_tests((&header as *const libc::msghdr).cast()),
        None
    );
    assert_eq!(
        malloc_abi::malloc_known_remaining_for_tests(vectors.as_ptr().cast()),
        None
    );
    let mut short_iov = None;
    if case == "short-iov" {
        let allocation = Allocation::new(size_of::<libc::iovec>());
        unsafe { allocation.pointer.cast::<libc::iovec>().write(vectors[0]) };
        header.msg_iov = allocation.pointer.cast();
        header.msg_iovlen = 2;
        short_iov = Some(allocation);
    }
    let mut unaligned_iov = [0u8; size_of::<libc::iovec>() + align_of::<libc::iovec>()];
    if case == "unaligned-iov" {
        let shift = (align_of::<libc::iovec>() + 1
            - unaligned_iov.as_ptr() as usize % align_of::<libc::iovec>())
            % align_of::<libc::iovec>();
        let pointer = unaligned_iov
            .as_mut_ptr()
            .wrapping_add(shift)
            .cast::<libc::iovec>();
        assert_ne!(pointer as usize % align_of::<libc::iovec>(), 0);
        unsafe { pointer.write_unaligned(vectors[0]) };
        header.msg_iov = pointer;
    }
    let mut auxiliary = None;
    if matches!(case, "rights" | "control-overrun") {
        let bytes = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as _) } as usize;
        let allocation = Allocation::new(bytes);
        header.msg_control = allocation.pointer.cast();
        header.msg_controllen = bytes + usize::from(case == "control-overrun");
        let control = allocation.pointer.cast::<libc::cmsghdr>();
        unsafe {
            (*control).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as _) as usize;
            (*control).cmsg_level = libc::SOL_SOCKET;
            (*control).cmsg_type = libc::SCM_RIGHTS;
            libc::CMSG_DATA(control)
                .cast::<libc::c_int>()
                .write_unaligned(sockets.0[0]);
        }
        auxiliary = Some(allocation);
    } else if named {
        let allocation = Allocation::new(size_of::<libc::sockaddr_in>());
        unsafe {
            allocation
                .pointer
                .cast::<libc::sockaddr_in>()
                .write(address)
        };
        header.msg_name = allocation.pointer.cast();
        header.msg_namelen = (allocation.bytes + usize::from(case == "name-overrun")) as _;
        auxiliary = Some(allocation);
    }
    let mut unaligned_header = [0u8; size_of::<libc::msghdr>() + align_of::<libc::msghdr>()];
    let mut short_header = None;
    let mut readonly = std::ptr::null_mut::<libc::c_void>();
    let submitted = match case {
        "bad-header" => std::ptr::without_provenance::<libc::msghdr>(1),
        "null-header" => std::ptr::null(),
        "unaligned-header" => {
            let shift = (align_of::<libc::msghdr>() + 1
                - unaligned_header.as_ptr() as usize % align_of::<libc::msghdr>())
                % align_of::<libc::msghdr>();
            let pointer = unaligned_header
                .as_mut_ptr()
                .wrapping_add(shift)
                .cast::<libc::msghdr>();
            assert_ne!(pointer as usize % align_of::<libc::msghdr>(), 0);
            unsafe { pointer.write_unaligned(header) };
            pointer.cast_const()
        }
        "short-header" => {
            let allocation = Allocation::new(size_of::<libc::msghdr>() - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(
                    (&header as *const libc::msghdr).cast::<u8>(),
                    allocation.pointer,
                    allocation.bytes,
                )
            };
            let pointer = allocation.pointer.cast::<libc::msghdr>().cast_const();
            short_header = Some(allocation);
            pointer
        }
        "readonly-header" => {
            readonly = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(readonly, libc::MAP_FAILED);
            unsafe { readonly.cast::<libc::msghdr>().write(header) };
            assert_eq!(
                unsafe { libc::mprotect(readonly, 4096, libc::PROT_READ) },
                0
            );
            readonly.cast::<libc::msghdr>().cast_const()
        }
        _ => &header,
    };
    if matches!(case, "fallback" | "denied-copy") {
        deny_copy_routes(case == "denied-copy");
    }
    let result = unsafe {
        match entry {
            "sendmsg" => socket_abi::sendmsg(
                sockets.0[0],
                submitted,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            ),
            "__sendmsg" => socket_abi::__sendmsg(
                sockets.0[0],
                submitted,
                libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
            ),
            _ => panic!("unknown entry {entry}"),
        }
    };
    let error = unsafe { *errno_abi::__errno_location() };
    if !readonly.is_null() {
        assert_eq!(unsafe { libc::munmap(readonly, 4096) }, 0);
    }
    // Drain through the host kernel oracle, collecting and closing any rights.
    let mut received = [0u8; 128];
    let mut received_control = [0usize; 16];
    let mut receive_vector = libc::iovec {
        iov_base: received.as_mut_ptr().cast(),
        iov_len: received.len(),
    };
    let mut receive_header: libc::msghdr = unsafe { std::mem::zeroed() };
    receive_header.msg_iov = &mut receive_vector;
    receive_header.msg_iovlen = 1;
    receive_header.msg_control = received_control.as_mut_ptr().cast();
    receive_header.msg_controllen = size_of_val(&received_control);
    let received_count = unsafe {
        libc::recvmsg(
            sockets.0[1],
            &mut receive_header,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    let receive_error = unsafe { *libc::__errno_location() };
    let mut rights = 0;
    if received_count >= 0 {
        let mut control = unsafe { libc::CMSG_FIRSTHDR(&receive_header) };
        while !control.is_null() {
            unsafe {
                if (*control).cmsg_level == libc::SOL_SOCKET
                    && (*control).cmsg_type == libc::SCM_RIGHTS
                {
                    let bytes = (*control).cmsg_len - libc::CMSG_LEN(0) as usize;
                    for index in 0..bytes / size_of::<libc::c_int>() {
                        let fd = libc::CMSG_DATA(control)
                            .cast::<libc::c_int>()
                            .add(index)
                            .read_unaligned();
                        let fd_flags = libc::fcntl(fd, libc::F_GETFD);
                        libc::close(fd);
                        assert!(fd_flags >= 0 && fd_flags & libc::FD_CLOEXEC != 0);
                        rights += 1;
                    }
                }
                control = libc::CMSG_NXTHDR(&receive_header, control);
            }
        }
    }
    let success = matches!(
        case,
        "valid"
            | "split"
            | "maximum"
            | "zero"
            | "zero-element"
            | "unaligned-header"
            | "unaligned-iov"
            | "readonly-header"
            | "rights"
            | "name"
            | "fallback"
    );
    if success {
        let expected = if matches!(case, "zero" | "zero-element") {
            0
        } else {
            SIZE as isize
        };
        assert_eq!(result, expected, "{entry}/{case}: valid send errno={error}");
        assert_eq!(received_count, expected, "{entry}/{case}: datagram length");
        assert_eq!(
            &received[..expected as usize],
            &vec![0x57; expected as usize]
        );
        assert_eq!(rights, usize::from(case == "rights"));
    } else {
        assert_eq!(
            result, -1,
            "{entry}/{case}: rejected input reached socket I/O"
        );
        let expected_error = match case {
            "bad-count" | "full-width-count" => libc::EMSGSIZE,
            "denied-copy" => libc::EPERM,
            _ => libc::EFAULT,
        };
        assert_eq!(error, expected_error, "{entry}/{case}");
        assert_eq!(
            received_count, -1,
            "{entry}/{case}: rejection enqueued a datagram"
        );
        assert_eq!(receive_error, libc::EAGAIN);
        assert_eq!(rights, 0);
    }
    if payload.live {
        for index in 0..SIZE {
            assert_eq!(unsafe { payload.pointer.add(index).read() }, 0x57);
        }
    }
    assert_eq!(header.msg_flags, 0x1234);
    // Keep every descriptor/control backing allocation alive until after I/O.
    drop((short_iov, short_header, auxiliary));
}

#[test]
fn socket_message_bounds_matrix() {
    if let Ok(selection) = std::env::var(CHILD) {
        let (entry, case) = selection.split_once(':').expect("entry:case");
        run_send(entry, case);
        return;
    }
    let executable = std::env::current_exe().unwrap();
    let mut failures = Vec::new();
    let mut executed = 0;
    for entry in ["sendmsg", "__sendmsg"] {
        for mode in ["strict", "hardened"] {
            for &case in COMMON
                .iter()
                .chain(if mode == "hardened" { HARDENED } else { &[] }.iter())
            {
                let mut child = Command::new(&executable)
                    .args([
                        "--exact",
                        "socket_message_bounds_matrix",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(CHILD, format!("{entry}:{case}"))
                    .env("FRANKENLIBC_MODE", mode)
                    .env("FRANKENLIBC_RUNTIME_MATH", "off")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("start socket case");
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
                        "{entry}/{case}/{mode}: timeout={timed_out} status={}\n{stdout}\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert_eq!(executed, 82);
    println!("82 isolated socket-message cases passed");
}
